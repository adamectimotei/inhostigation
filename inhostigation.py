# -*- coding: utf-8 -*-

from burp import IBurpExtender, IScannerCheck, IScanIssue
from java.io import PrintWriter
from java.net import URL
import traceback

MAX_SAMPLE = 1024 * 1024  # don't parse bodies larger than this when looking for reflections

class BurpExtender(IBurpExtender, IScannerCheck):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self._stdout = PrintWriter(callbacks.getStdout(), True)
        self._stderr = PrintWriter(callbacks.getStderr(), True)
        self._callbacks.setExtensionName("Host Header Injection Scanner")
        self._callbacks.registerScannerCheck(self)
        self._stdout.println("Host Header Injection Scanner extension loaded.")
        # track which requests we've scanned to avoid re-running heavy checks for each insertion point
        self._already_scanned = set()

    # ---------------------------
    # Small helpers (DRY / safety)
    # ---------------------------

    def _decorate_detail_with_next_steps(self, title, detail, severity):
        """
        Append "Next steps" hints to specific Low/Information issues only.
        Does not alter other issues or severities.
        """
        try:
            if severity not in ("Low", "Information"):
                return detail

            hints = {
                "Host header accepted arbitrary value": [
                    "Check if reflected on other pages.",
                    "Try password reset / login flows (poisoned links).",
                ],
                "Host port accepted": [
                    "Check if reflected on other pages.",
                    "Could be leveraged in cache poisoning with crafted Host.",
                ],
                "Duplicate Host affected response": [
                    "Try fuzzing alternate values for hidden routes.",
                    "Could be leveraged in cache poisoning with duplicate Hosts.",
                ],
                "Absolute-URI response size change": [
                    "Check if reflected on other pages.",
                    "Could be leveraged in cache poisoning if absolute URIs are cached.",
                    "Try fuzzing alternate absolute URIs for hidden routes.",
                ],
                "Forwarded (RFC 7239) likely honored": [
                    "Try fuzzing internal hosts for hidden apps.",
                    "Test password reset / login flows for poisoning.",
                    "Consider SSRF payloads.",
                ],
                "Header likely processed by upstream": [
                    "Try fuzzing with internal targets.",
                    "Could be leveraged in cache poisoning.",
                ],
            }

            if title in hints:
                suffix = "\n\nNext steps:\n" + "\n".join("-" + h for h in hints[title])
                return detail + suffix
            return detail
        except:
            return detail

    def _mk_issue(self, baseRR, evidenceRR, title, detail, severity):
        # Decorate detail with optional "next steps" where applicable
        detail = self._decorate_detail_with_next_steps(title, detail, severity)

        msgs = [baseRR] + ([evidenceRR] if (evidenceRR and evidenceRR != baseRR) else [])
        try:
            return CustomScanIssue(
                baseRR.getHttpService(),
                self._helpers.analyzeRequest(baseRR).getUrl(),
                msgs,
                title, detail, severity
            )
        except Exception as e:
            # As a last resort, try to fall back to baseRR_fallback if analyzeRequest fails
            try:
                return CustomScanIssue(
                    self._baseRR_fallback.getHttpService(),
                    self._helpers.analyzeRequest(self._baseRR_fallback).getUrl(),
                    msgs,
                    title, detail, severity
                )
            except:
                self._stderr.println("mk_issue failed: " + str(e))
                return None

    def _add_cb_param_if_safe(self, reqline):
        """
        Append ?cb=<uuid> (or &cb=...) to the request-target of GET/HEAD only.
        Works for origin-form and absolute-form; keeps fragments intact.
        Leaves asterisk-form and CONNECT authority-form untouched.
        Avoids double-adding when cb= already present.
        """
        import uuid
        try:
            parts = reqline.split(" ", 2)
            if len(parts) != 3:
                return reqline
            method, target, version = parts[0], parts[1], parts[2]

            mu = method.upper()
            if mu not in ("GET", "HEAD"):
                return reqline
            if target == "*" or mu == "CONNECT":
                return reqline
            if "cb=" in target:
                return reqline

            # Split off fragment so we can insert before '#'
            frag = ""
            if "#" in target:
                target, frag = target.split("#", 1)
                frag = "#" + frag

            # Choose separator based on presence of an existing query
            if "?" in target:
                # Already has a query: if it ends with '?' or '&', no extra sep needed
                sep = "" if (target.endswith("?") or target.endswith("&")) else "&"
            else:
                sep = "?"

            token = uuid.uuid4().hex
            target = target + sep + "cb=" + token + frag
            return method + " " + target + " " + version
        except:
            return reqline

    def _safe_request(self, http_service, headers, body, title_on_fail, detail_on_fail):
        """
        Build+send a request. If it fails or returns no response, return (None, info_issue).
        Otherwise return (rr, None).
        Also: injects cache-busting controls (Cache-Control: no-cache and ?cb=<uuid> / &cb=<uuid> on GET/HEAD).
        """
        try:
            # Work on a copy of headers to avoid mutating caller's list
            h = list(headers) if headers else []
            if h:
                # 1) Smartly add ?cb= (or &cb=) only for GET/HEAD
                h[0] = self._add_cb_param_if_safe(h[0])

                # 2) Ensure Cache-Control contains no-cache (case-insensitive)
                found_idx = -1
                for i in range(1, len(h)):
                    try:
                        name = h[i].split(":", 1)[0].strip().lower()
                        if name == "cache-control":
                            found_idx = i
                            break
                    except:
                        pass
                if found_idx >= 0:
                    # Merge in no-cache if not present already
                    try:
                        head, val = h[found_idx].split(":", 1)
                        if "no-cache" not in val.lower():
                            # keep existing directives, append no-cache
                            newv = val.strip()
                            if newv and not newv.endswith(","):
                                newv = newv + ", no-cache"
                            else:
                                newv = newv + "no-cache"
                            h[found_idx] = head + ": " + newv
                    except:
                        # If parsing failed, just replace it conservatively
                        h[found_idx] = "Cache-Control: no-cache"
                else:
                    h.append("Cache-Control: no-cache")

            req = self._helpers.buildHttpMessage(h, body)
            rr  = self._callbacks.makeHttpRequest(http_service, req)
            resp = rr.getResponse()
            if not resp:
                return None, self._mk_issue(self._baseRR_fallback, rr, title_on_fail, detail_on_fail, "Information")
            return rr, None
        except Exception as e:
            return None, self._mk_issue(self._baseRR_fallback, None, title_on_fail, str(e), "Information")

    def _reflects(self, token, resp_bytes, resp_info):
        if not token or not resp_bytes or not resp_info:
            return False
        try:
            if len(resp_bytes) >= MAX_SAMPLE:
                return False
            sample = self._helpers.bytesToString(resp_bytes)
            if token in sample[:4096]:
                return True
            hdrs = "\n".join(resp_info.getHeaders())
            return token in hdrs
        except:
            return False

    def _delta(self, base_info, base_body_bytes, resp_info, resp_bytes):
        """
        Return ("code"/"len"/"same"/"noresp", changed_bool)
        """
        if resp_info is None or resp_bytes is None:
            return ("noresp", False)
        code_changed = (resp_info.getStatusCode() != base_info.getStatusCode())
        len_changed  = (len(resp_bytes[resp_info.getBodyOffset():]) != len(base_body_bytes))
        if code_changed:
            return ("code", True)
        if len_changed:
            return ("len", True)
        return ("same", False)

    def _replace_host_header(self, headers, new_host):
        new_headers = []
        host_set = False
        for h in headers:
            if h.lower().startswith("host:"):
                new_headers.append("Host: " + new_host)
                host_set = True
            else:
                new_headers.append(h)
        if not host_set:
            new_headers.append("Host: " + new_host)
        return new_headers

    def _build_headers_excluding(self, headers, names_lower_set):
        """Return headers without any whose name (before ':') is in names_lower_set (case-insensitive)."""
        if not headers:
            return []
        req_line = headers[0]
        rest = headers[1:]
        out = [req_line]
        for h in rest:
            try:
                name = h.split(":", 1)[0].strip().lower()
                if name in names_lower_set:
                    continue
            except:
                pass
            out.append(h)
        return out

    def _proto_is_http11(self, headers):
        try:
            if not headers:
                return False
            return headers[0].endswith("HTTP/1.1")
        except:
            return False

    def _absolute_uri_reqline(self, method, scheme_host, path_or_slash):
        # Ensure absolute-form: METHOD scheme://host/path HTTP/1.1
        uri = scheme_host
        if not scheme_host.endswith("/") and not path_or_slash.startswith("/"):
            uri += "/"
        uri += path_or_slash if path_or_slash.startswith("/") else path_or_slash
        return method + " " + uri + " HTTP/1.1"

    # ---------- NEW: status-class helpers ----------
    def _is_success(self, info):
        try:
            c = info.getStatusCode()
            return 200 <= c < 400
        except:
            return False

    def _is_error(self, info):
        try:
            return info.getStatusCode() >= 400
        except:
            return False

    def _both_success(self, info_a, info_b):
        return self._is_success(info_a) and self._is_success(info_b)

    def _both_error(self, info_a, info_b):
        return self._is_error(info_a) and self._is_error(info_b)

    def _success_only(self, base_info, new_info):
        # both must be 2xx/3xx
        return self._both_success(base_info, new_info)

    def _success_or_both_error(self, base_info, new_info):
        # either both 2xx/3xx OR both error (handles your parenthetical case)
        return self._both_success(base_info, new_info) or self._both_error(base_info, new_info)
    # ------------------------------------------------

    # ---------------------------
    # Active scan
    # ---------------------------

    def doActiveScan(self, baseRequestResponse, insertionPoint):
        self._baseRR_fallback = baseRequestResponse  # used by _safe_request for error issues

        # --- Dedupe: run heavy scan only once per (host, method, path, query)
        try:
            http_service_tmp = baseRequestResponse.getHttpService()
            req_tmp = baseRequestResponse.getRequest()
            req_info_tmp = self._helpers.analyzeRequest(http_service_tmp, req_tmp)
            url_tmp = req_info_tmp.getUrl()
            # some analyzeRequest variants provide getMethod; fall back to parsing if missing
            try:
                method_tmp = req_info_tmp.getMethod()
            except:
                # fallback: parse from request-line
                hdrs_tmp = list(req_info_tmp.getHeaders())
                method_tmp = hdrs_tmp[0].split(" ")[0] if hdrs_tmp else "GET"
            key = "{}|{}|{}|{}".format(url_tmp.getHost(), method_tmp, url_tmp.getPath() or "/", url_tmp.getQuery() or "")
            if key in self._already_scanned:
                return None
            self._already_scanned.add(key)
        except Exception:
            # if our cheap dedupe fails for any reason, just continue and run the scan.
            pass

        issues = []

        try:
            http_service = baseRequestResponse.getHttpService()

            # --- Baseline request/response
            original_request = baseRequestResponse.getRequest()
            request_info = self._helpers.analyzeRequest(http_service, original_request)
            headers = list(request_info.getHeaders())
            body = original_request[request_info.getBodyOffset():]

            # Extract Host + basic parts
            original_host = None
            for h in headers:
                if h.lower().startswith("host:"):
                    original_host = h.split(":", 1)[1].strip()
                    break
            if not original_host:
                return None

            req_line = headers[0] if headers else "GET / HTTP/1.1"
            method = req_line.split(" ")[0] if " " in req_line else "GET"
            original_url = request_info.getUrl()
            original_domain = original_url.getHost()
            original_path = original_url.getPath() or "/"
            if original_url.getQuery():
                original_path = (original_path if original_path else "/") + "?" + original_url.getQuery()

            original_resp = baseRequestResponse.getResponse()
            if not original_resp:
                return None
            original_info = self._helpers.analyzeResponse(original_resp)
            original_body = original_resp[original_info.getBodyOffset():]

            # --------------------------
            # Step 1: Invalid Host header
            # --------------------------
            try:
                inv_token = "InvalidHostHeaderxyz123"
                inv_headers = self._replace_host_header(headers, inv_token)
                rr, err = self._safe_request(
                    http_service, inv_headers, body,
                    "Invalid Host header produced no response",
                    "Setting Host=%s produced no response (protocol/handshake error?)." % inv_token
                )
                if err:
                    issues.append(err)
                elif rr:
                    info = self._helpers.analyzeResponse(rr.getResponse())
                    kind, changed = self._delta(original_info, original_body, info, rr.getResponse())
                    if changed and kind == "code" and str(info.getStatusCode()).startswith("30"):
                        issues.append(self._mk_issue(baseRequestResponse, rr,
                            "Response code changed - Redirect (invalid Host)",
                            "Setting Host to an invalid value caused a redirect.", "Low"))
                    elif not changed:
                        issues.append(self._mk_issue(baseRequestResponse, rr,
                            "Host header probably ignored",
                            "Setting an invalid Host produced an identical response.", "Information"))
                    elif changed and kind == "len":
                        issues.append(self._mk_issue(baseRequestResponse, rr,
                            "Response length changed (invalid Host)",
                            "Body length changed after invalid Host.", "Low"))
                    if self._reflects(inv_token, rr.getResponse(), info):
                        issues.append(self._mk_issue(baseRequestResponse, rr,
                            "Host header reflection (invalid value)",
                            "Injected invalid Host value is reflected.", "Medium"))
            except Exception as e:
                issues.append(self._mk_issue(baseRequestResponse, None, "Exception in invalid Host test", str(e), "Information"))

            # --------------------------------
            # Step 2: Collaborator Host injection
            # --------------------------------
            try:
                collab_ctx = self._callbacks.createBurpCollaboratorClientContext()
                collab_token = collab_ctx.generatePayload(True)
                collab_headers = self._replace_host_header(headers, collab_token)
                rr, err = self._safe_request(
                    http_service, collab_headers, body,
                    "Collaborator Host probe failed", "No response to Host=<collab>."
                )
                if err:
                    issues.append(err)
                elif rr:
                    info = self._helpers.analyzeResponse(rr.getResponse())
                    kind, changed = self._delta(original_info, original_body, info, rr.getResponse())
                    if changed and kind == "code" and str(info.getStatusCode()).startswith("30"):
                        issues.append(self._mk_issue(baseRequestResponse, rr,
                            "Response code changed - Redirect",
                            "Changed to redirect after Host=<collab>.", "Low"))
                    elif changed and kind == "len":
                        issues.append(self._mk_issue(baseRequestResponse, rr,
                            "Response length changed",
                            "Body length changed after Host=<collab>.", "Low"))
                    else:
                        # Host header accepted arbitrary value -> only when both success or both error (your rule)
                        if self._success_or_both_error(original_info, info):
                            issues.append(self._mk_issue(baseRequestResponse, rr,
                                "Host header accepted arbitrary value",
                                "Response unchanged after Host=<collab>.", "Information"))
                    if self._reflects(collab_token, rr.getResponse(), info):
                        issues.append(self._mk_issue(baseRequestResponse, rr,
                            "Host header reflection",
                            "Collaborator token reflected in response.", "Medium"))
                # SSRF
                try:
                    inter = collab_ctx.fetchAllCollaboratorInteractions()
                    if inter and len(inter) > 0:
                        issues.append(self._mk_issue(baseRequestResponse, rr if rr else baseRequestResponse,
                            "Host Header SSRF",
                            "Collaborator interaction detected via Host header.", "High"))
                except Exception as e:
                    self._stderr.println("Collab check error: " + str(e))
            except Exception as e:
                issues.append(self._mk_issue(baseRequestResponse, None, "Exception in Collaborator Host test", str(e), "Information"))

            # ----------------------------------------------
            # Step 2b: Loopback Host probes (no 4xx flagging, no 'accepted' noise)
            # ----------------------------------------------
            try:
                # include common loopback encodings often accepted by parsers
                loopback_values = ["127.0.0.1", "localhost", "0x7f000001", "2130706433"]
                for hostval in loopback_values:
                    lb_headers = self._replace_host_header(headers, hostval)
                    rr, err = self._safe_request(
                        http_service, lb_headers, body,
                        "Loopback Host probe failed",
                        "No response when Host was set to a loopback value (%s)." % hostval
                    )
                    if err:
                        issues.append(err)
                        continue
                    info = self._helpers.analyzeResponse(rr.getResponse())
                    kind, changed = self._delta(original_info, original_body, info, rr.getResponse())

                    # Reflection is reported regardless of status class
                    if self._reflects(hostval, rr.getResponse(), info):
                        issues.append(self._mk_issue(baseRequestResponse, rr,
                            "Host internal value reflected",
                            "Injected loopback Host value '%s' is reflected." % hostval, "Medium"))

                    # Do not flag pure 4xx changes
                    if changed and kind == "code":
                        scode = str(info.getStatusCode())
                        if scode.startswith("30") or scode.startswith("50") or info.getStatusCode() == 200:
                            issues.append(self._mk_issue(baseRequestResponse, rr,
                                "Loopback Host changed status",
                                "Setting Host='%s' changed status to %s." % (hostval, scode), "Low"))
                        # else: 4xx or other not allowed -> skip
                    elif changed and kind == "len":
                        issues.append(self._mk_issue(baseRequestResponse, rr,
                            "Response length changed (loopback Host)",
                            "Body length changed after Host was set to '%s'." % hostval, "Low"))
                    # else: unchanged -> intentionally no issue to avoid noise
            except Exception as e:
                issues.append(self._mk_issue(baseRequestResponse, None, "Exception in loopback Host tests", str(e), "Information"))

            # ------------------------------------------
            # Step 3: Host header with port manipulation
            # ------------------------------------------
            try:
                for host_payload, label in [
                    (original_host + ":12345", "numeric port"),
                    (original_host + ":InvalidHostHeaderxyz123", "string port"),
                ]:
                    p_headers = self._replace_host_header(headers, host_payload)
                    rr, err = self._safe_request(
                        http_service, p_headers, body,
                        "Port probe failed (%s)" % label,
                        "Using %s in Host caused no response." % label
                    )
                    if err:
                        issues.append(err)
                    elif rr:
                        info = self._helpers.analyzeResponse(rr.getResponse())
                        kind, changed = self._delta(original_info, original_body, info, rr.getResponse())
                        if changed and kind == "code" and str(info.getStatusCode()).startswith("30"):
                            issues.append(self._mk_issue(baseRequestResponse, rr,
                                "Response code changed - Redirect (port)",
                                "Redirect after using %s in Host header." % label, "Low"))
                        elif changed and kind == "len":
                            issues.append(self._mk_issue(baseRequestResponse, rr,
                                "Response length changed (port)",
                                "Body size changed after %s in Host header." % label, "Low"))
                        else:
                            # Host port accepted -> only when BOTH baseline & variant are success
                            if self._success_only(original_info, info):
                                issues.append(self._mk_issue(baseRequestResponse, rr,
                                    "Host port accepted",
                                    "Arbitrary %s accepted without visible change." % label, "Information"))
                        # reflection
                        search_for = host_payload if label == "numeric port" else "InvalidHostHeaderxyz123"
                        if self._reflects(search_for, rr.getResponse(), info):
                            issues.append(self._mk_issue(baseRequestResponse, rr,
                                "Host with arbitrary port reflected",
                                "Host header with %s reflected in response." % label, "Medium"))

                # Collab via port tokens
                try:
                    collab_ctx2 = self._callbacks.createBurpCollaboratorClientContext()
                    collab_domain2 = collab_ctx2.generatePayload(True)
                    for p in [original_host + ":@" + collab_domain2, original_host + ":" + collab_domain2]:
                        ph = self._replace_host_header(headers, p)
                        rr, _ = self._safe_request(
                            http_service, ph, body,
                            "Port-collab probe failed", "No response for collab port payload."
                        )
                    inter2 = collab_ctx2.fetchAllCollaboratorInteractions()
                    if inter2 and len(inter2) > 0:
                        issues.append(self._mk_issue(baseRequestResponse, rr if rr else baseRequestResponse,
                            "Host Header SSRF via Port",
                            "Collaborator interaction via Host port injection payloads.", "High"))
                except Exception as e:
                    self._stderr.println("Port-collab error: " + str(e))
            except Exception as e:
                issues.append(self._mk_issue(baseRequestResponse, None, "Exception in port manipulation", str(e), "Information"))

            # --------------------------------------------------
            # Step 4: Flawed Host validation with domain combine
            # --------------------------------------------------
            try:
                collab_ctx3 = self._callbacks.createBurpCollaboratorClientContext()
                collab_domain3 = collab_ctx3.generatePayload(True)
                flawed_payloads = [collab_domain3 + original_host, original_host + "." + collab_domain3]
                for p in flawed_payloads:
                    ph = self._replace_host_header(headers, p)
                    rr, err = self._safe_request(
                        http_service, ph, body,
                        "Combined-domain Host probe failed",
                        "No response when Host set to combined-domain payload."
                    )
                    if err:
                        issues.append(err)
                        continue
                    info = self._helpers.analyzeResponse(rr.getResponse())
                    if self._reflects(collab_domain3, rr.getResponse(), info):
                        issues.append(self._mk_issue(baseRequestResponse, rr,
                            "Flawed Host header validation (reflected)",
                            "Combined-domain Host value reflected.", "Medium"))
                    kind, changed = self._delta(original_info, original_body, info, rr.getResponse())
                    if changed and kind == "code" and str(info.getStatusCode()).startswith("30"):
                        issues.append(self._mk_issue(baseRequestResponse, rr,
                            "Redirect via domain combination",
                            "Redirect after injecting domain combo into Host header.", "Low"))
                    elif changed and kind == "len":
                        issues.append(self._mk_issue(baseRequestResponse, rr,
                            "Response length changed (domain combo)",
                            "Body size changed after domain combo.", "Low"))
                    else:
                        # Host domain combo accepted -> only when BOTH baseline & variant are success
                        if self._success_only(original_info, info):
                            issues.append(self._mk_issue(baseRequestResponse, rr,
                                "Host domain combo accepted",
                                "Combined-domain Host accepted without change.", "Information"))
            except Exception as e:
                issues.append(self._mk_issue(baseRequestResponse, None, "Exception in domain-combo", str(e), "Information"))

            # ------------------------------------------
            # Step 5: Absolute URI tests (bucketed)
            # ------------------------------------------
            try:
                sev_rank = {"High": 3, "Medium": 2, "Low": 1, "Information": 0}
                scheme_pref = {"https": 3, "http": 2, "hTtPs": 1, "HtTp": 0}
                buckets = {}  # key -> {"best": {...}, "tried": [(scheme, sev, ev)], }
                def bucket_key(family, target_label, with_path_bool):
                    return family + "|" + target_label + "|" + ("path" if with_path_bool else "root")
                def record_variant(bkey, scheme, abs_uri, resp_obj, candidate_sev, title, detail, evidence):
                    if bkey not in buckets:
                        buckets[bkey] = {"best": None, "tried": []}
                    buckets[bkey]["tried"].append((scheme, candidate_sev, evidence))
                    best = buckets[bkey]["best"]
                    if best is None:
                        buckets[bkey]["best"] = {
                            "sev": candidate_sev, "title": title, "detail": detail,
                            "scheme": scheme, "abs_uri": abs_uri, "resp_obj": resp_obj
                        }
                    else:
                        if sev_rank[candidate_sev] > sev_rank[best["sev"]]:
                            buckets[bkey]["best"].update({"sev": candidate_sev, "title": title,
                                "detail": detail, "scheme": scheme, "abs_uri": abs_uri, "resp_obj": resp_obj})
                        elif sev_rank[candidate_sev] == sev_rank[best["sev"]]:
                            if scheme_pref.get(scheme, -1) > scheme_pref.get(best["scheme"], -1):
                                buckets[bkey]["best"].update({"sev": candidate_sev, "title": title,
                                    "detail": detail, "scheme": scheme, "abs_uri": abs_uri, "resp_obj": resp_obj})

                def send_abs(base_headers, base_body, new_host_value, scheme_host, include_path):
                    new_headers = self._replace_host_header(base_headers, new_host_value)
                    if include_path:
                        path = original_path if original_path.startswith("/") else "/" + original_path
                        abs_req_line = self._absolute_uri_reqline(method, scheme_host, path)
                    else:
                        abs_req_line = self._absolute_uri_reqline(method, scheme_host, "/")
                    new_headers[0] = abs_req_line
                    return self._safe_request(
                        http_service, new_headers, base_body,
                        "Absolute-URI request failed", "No response to absolute-URI request."
                    )

                collab_ctx_abs = self._callbacks.createBurpCollaboratorClientContext()
                token_to_bucket = {}
                schemes = ["http", "https", "hTtPs", "HtTp"]

                # A) abs-uri host varies; Host stays original
                for host_token, label in [("COLLAB", "collab"), ("127.0.0.1", "loopback"), ("localhost", "localhost")]:
                    for with_path in [False, True]:
                        for sch in schemes:
                            try:
                                if host_token == "COLLAB":
                                    t = collab_ctx_abs.generatePayload(True)
                                    scheme_host = sch + "://" + t
                                    bkey = bucket_key("A", "collab", with_path)
                                    rr, err = send_abs(headers, body, original_host, scheme_host, with_path)
                                    token_to_bucket[t] = bkey
                                    injected_indicator = t
                                else:
                                    scheme_host = sch + "://" + host_token
                                    bkey = bucket_key("A", label, with_path)
                                    rr, err = send_abs(headers, body, original_host, scheme_host, with_path)
                                    injected_indicator = host_token
                                if err:
                                    # Record a low-weight info in the bucket, but don't emit yet
                                    record_variant(bkey, sch, scheme_host, baseRequestResponse, "Information",
                                        "Absolute-URI no response", "No response for " + scheme_host, "noresp")
                                    continue
                                info = self._helpers.analyzeResponse(rr.getResponse())
                                rbody = rr.getResponse()[info.getBodyOffset():]
                                reflected = self._reflects(injected_indicator, rr.getResponse(), info)
                                candidate = None; title = ""; detail = ""; evidence = ""
                                if info.getStatusCode() != original_info.getStatusCode():
                                    code = str(info.getStatusCode())
                                    allowed = code.startswith("30") or code.startswith("50") or info.getStatusCode() == 200
                                    if allowed:
                                        candidate, title = "Low", "Absolute-URI caused status change"
                                        detail, evidence = "Different status (%s) using absolute URI: %s" % (code, scheme_host), "status"
                                    else:
                                        if reflected:
                                            candidate, title = "Medium", "Absolute-URI reflection"
                                            detail, evidence = "Injected absolute host reflected: %s" % injected_indicator, "reflected"
                                        else:
                                            continue
                                else:
                                    if len(rbody) != len(original_body):
                                        # Absolute-URI response size change -> only when both success OR both error
                                        if self._success_or_both_error(original_info, info):
                                            candidate, title = "Low", "Absolute-URI response size change"
                                            detail, evidence = "Body length differs using absolute URI: %s" % scheme_host, "length"
                                        else:
                                            candidate = None
                                    else:
                                        if reflected:
                                            candidate, title = "Medium", "Absolute-URI reflection"
                                            detail, evidence = "Injected absolute host reflected: %s" % injected_indicator, "reflected"
                                        else:
                                            candidate, title = "Information", "Server accepts absolute URIs"
                                            detail, evidence = "Response unchanged using absolute URI: %s" % scheme_host, "same"
                                if candidate:
                                    record_variant(bkey, sch, scheme_host, rr, candidate, title, detail, evidence)
                            except Exception as e:
                                self._stderr.println("Abs A error: " + str(e))

                # B) Host set to collab token; abs-uri host varies
                for host_token, label in [(original_domain, "original"), ("127.0.0.1", "loopback"), ("localhost", "localhost")]:
                    for with_path in [False, True]:
                        for sch in schemes:
                            try:
                                t = collab_ctx_abs.generatePayload(True)
                                scheme_host = sch + "://" + host_token
                                bkey = bucket_key("B", label, with_path)
                                rr, err = send_abs(headers, body, t, scheme_host, with_path)
                                token_to_bucket[t] = bkey
                                if err:
                                    record_variant(bkey, sch, scheme_host, baseRequestResponse, "Information",
                                                   "Absolute-URI no response (B)", "No response for " + scheme_host, "noresp")
                                    continue
                                info = self._helpers.analyzeResponse(rr.getResponse())
                                rbody = rr.getResponse()[info.getBodyOffset():]
                                reflected = self._reflects(t, rr.getResponse(), info)
                                candidate = None; title = ""; detail = ""; evidence = ""
                                if info.getStatusCode() != original_info.getStatusCode():
                                    code = str(info.getStatusCode())
                                    allowed = code.startswith("30") or code.startswith("50") or info.getStatusCode() == 200
                                    if allowed:
                                        candidate, title = "Low", "Host header + absolute-URI changed status"
                                        detail, evidence = "Different status (%s) with Host=<collab> and absolute URI: %s" % (code, scheme_host), "status"
                                    else:
                                        if reflected:
                                            candidate, title = "Medium", "Host injection (absolute-URI test)"
                                            detail, evidence = "Host=<collab> reflected while using absolute URI.", "reflected"
                                        else:
                                            continue
                                else:
                                    if len(rbody) != len(original_body):
                                        # Host header + absolute-URI size change -> only when both success OR both error
                                        if self._success_or_both_error(original_info, info):
                                            candidate, title = "Low", "Host header + absolute-URI size change"
                                            detail, evidence = "Body length differs with Host=<collab> and absolute URI: %s" % scheme_host, "length"
                                        else:
                                            candidate = None
                                    else:
                                        if reflected:
                                            candidate, title = "Medium", "Host injection (absolute-URI test)"
                                            detail, evidence = "Host=<collab> reflected while using absolute URI.", "reflected"
                                        else:
                                            candidate, title = "Information", "Host header + absolute-URI accepted"
                                            detail, evidence = "No change with Host=<collab> and absolute URI: %s" % scheme_host, "same"
                                if candidate:
                                    record_variant(bkey, sch, scheme_host, rr, candidate, title, detail, evidence)
                            except Exception as e:
                                self._stderr.println("Abs B error: " + str(e))

                # Correlate collaborator hits to buckets -> promote to High
                try:
                    inter_abs = collab_ctx_abs.fetchAllCollaboratorInteractions()
                except Exception:
                    inter_abs = None
                if inter_abs:
                    for it in inter_abs:
                        try:
                            s = str(it)
                        except:
                            s = ""
                        if not s:
                            continue
                        for tok, bkey in list(token_to_bucket.items()):
                            if tok in s and bkey in buckets:
                                best = buckets[bkey]["best"]
                                if best is None or sev_rank["High"] > sev_rank[best["sev"]]:
                                    buckets[bkey]["best"] = {
                                        "sev": "High",
                                        "title": "SSRF via Absolute URI" if bkey.startswith("A|") else "Host header injection - SSRF",
                                        "detail": "Collaborator interaction matched token used in this absolute-URI bucket.",
                                        "scheme": (best["scheme"] if best else "https"),
                                        "abs_uri": (best["abs_uri"] if best else ""),
                                        "resp_obj": (best["resp_obj"] if best else baseRequestResponse)
                                    }

                # Emit one per bucket
                for bkey, data in buckets.items():
                    best = data.get("best")
                    if not best:
                        continue
                    tried_schemes = [t[0] for t in data.get("tried", [])]
                    tried_summary = "Tried schemes: " + ", ".join(sorted(set(tried_schemes),
                                               key=lambda s: {"https":3,"http":2,"hTtPs":1,"HtTp":0}.get(s,-1), reverse=True))
                    detail = best["detail"] + "\n" + tried_summary + "\nBucket: " + bkey
                    issues.append(self._mk_issue(baseRequestResponse, best["resp_obj"], best["title"], detail, best["sev"]))
            except Exception as e:
                issues.append(self._mk_issue(baseRequestResponse, None, "Absolute-URI block failed", str(e), "Information"))

            # -------------------------------------------------------
            # Step 6: Line folding / duplicate Host tests (HTTP/1.1)
            # -------------------------------------------------------
            try:
                is_http11 = self._proto_is_http11(headers)

                def send_two_hosts(first_line, second_line):
                    req_line_local = headers[0] if headers else (method + " / HTTP/1.1")
                    rest = headers[1:] if len(headers) > 1 else []
                    rest_no_host = [hh for hh in rest if not hh.lower().startswith("host:")]
                    new_headers = [req_line_local, first_line, second_line] + rest_no_host
                    return self._safe_request(
                        http_service, new_headers, body,
                        "Folded/duplicate Host probe failed", "No response for folded/duplicate Host test."
                    )

                # (a) Indented/folded Host variants (two header lines where second starts with SP)
                collab_ctx_fold = self._callbacks.createBurpCollaboratorClientContext()
                fold_a = collab_ctx_fold.generatePayload(True)
                rrA, errA = send_two_hosts("Host: " + original_host, " Host: " + fold_a)
                if errA:
                    issues.append(errA)
                elif rrA:
                    infoA = self._helpers.analyzeResponse(rrA.getResponse())
                    if self._reflects(fold_a, rrA.getResponse(), infoA):
                        issues.append(self._mk_issue(baseRequestResponse, rrA,
                            "Line-folding Host injection (reflected)",
                            "Indented Host value was reflected (variant A).", "Medium"))
                    kindA, changedA = self._delta(original_info, original_body, infoA, rrA.getResponse())
                    if changedA and kindA == "len":
                        issues.append(self._mk_issue(baseRequestResponse, rrA,
                            "Line-folding - response length changed (A)",
                            "Body length differs with indented Host (A).", "Low"))

                fold_b = collab_ctx_fold.generatePayload(True)
                rrB, errB = send_two_hosts(" Host: " + fold_b, "Host: " + original_host)
                if errB:
                    issues.append(errB)
                elif rrB:
                    infoB = self._helpers.analyzeResponse(rrB.getResponse())
                    if self._reflects(fold_b, rrB.getResponse(), infoB):
                        issues.append(self._mk_issue(baseRequestResponse, rrB,
                            "Line-folding Host injection (reflected)",
                            "Indented Host value was reflected (variant B).", "Medium"))
                    kindB, changedB = self._delta(original_info, original_body, infoB, rrB.getResponse())
                    if changedB and kindB == "len":
                        issues.append(self._mk_issue(baseRequestResponse, rrB,
                            "Line-folding - response length changed (B)",
                            "Body length differs with indented Host (B).", "Low"))

                # (b) Duplicate Host only if HTTP/1.1
                if is_http11:
                    dup_token = collab_ctx_fold.generatePayload(True)
                    req_line_local = headers[0] if headers else (method + " / HTTP/1.1")
                    rest = headers[1:] if len(headers) > 1 else []
                    rest_no_host = [hh for hh in rest if not hh.lower().startswith("host:")]
                    two_hosts = [req_line_local, "Host: " + original_host, "Host: " + dup_token] + rest_no_host
                    rrD, errD = self._safe_request(
                        http_service, two_hosts, body,
                        "Duplicate Host probe failed",
                        "No response when sending duplicate Host headers (HTTP/1.1 only)."
                    )
                    if errD:
                        issues.append(errD)
                    elif rrD:
                        infoD = self._helpers.analyzeResponse(rrD.getResponse())
                        if self._reflects(dup_token, rrD.getResponse(), infoD):
                            issues.append(self._mk_issue(baseRequestResponse, rrD,
                                "Duplicate Host injection (reflected)",
                                "Second Host value appears reflected.", "Medium"))
                        kindD, changedD = self._delta(original_info, original_body, infoD, rrD.getResponse())
                        if changedD:
                            # Duplicate host affected response -> only when both success
                            if (kindD in ("code", "len")) and self._success_only(original_info, infoD):
                                sev = "Low" if kindD in ("code", "len") else "Information"
                                issues.append(self._mk_issue(baseRequestResponse, rrD,
                                    "Duplicate Host affected response",
                                    "Duplicate Host changed response (%s)." % kindD, sev))

                # SSRF check: any new interactions after folded/duplicate block
                try:
                    before_len = 0
                    try:
                        b = collab_ctx_fold.fetchAllCollaboratorInteractions()
                        before_len = len(b) if b else 0
                    except:
                        pass
                    a = collab_ctx_fold.fetchAllCollaboratorInteractions()
                    after_len = len(a) if a else 0
                    if after_len > before_len:
                        issues.append(self._mk_issue(baseRequestResponse, baseRequestResponse,
                            "Host header injection - SSRF (folded/duplicate)",
                            "Collaborator interaction observed after folded/duplicate Host tests.", "High"))
                except Exception as e:
                    self._stderr.println("Folded/dup SSRF check failed: " + str(e))
            except Exception as e:
                issues.append(self._mk_issue(baseRequestResponse, None, "Line folding/duplicate block failed", str(e), "Information"))

            # ------------------------------------------------------
            # Step 7: Host Override Headers (spray -> isolate)
            # Now treats ANY status delta (incl. 4xx) as interesting.
            # ------------------------------------------------------
            try:
                hostish_header_names = [
                    "Base-Url","Client-IP","Http-Url","Proxy-Host","Proxy-Url",
                    "Real-Ip","Redirect","Referer","Referrer","Refferer",
                    "Request-Uri","Uri","Url","X-Client-IP","X-Custom-IP-Authorization",
                    "X-Forward-For","X-Forwarded-By","X-Forwarded-For-Original",
                    "X-Forwarded-For","X-Forwarded-Host","X-Forwarded-Server",
                    "X-Forwarded","X-Forwarder-For","X-Host","X-Http-Destinationurl",
                    "X-Http-Host-Override","X-Original-Remote-Addr","X-Original-Url",
                    "X-Originating-IP","X-Proxy-Url","X-Real-Ip","X-Remote-Addr",
                    "X-Remote-IP","X-Rewrite-Url","X-True-IP","True-Client-IP","Cluster-Client-IP",
                    "X-ProxyUser-Ip","Forwarded-For","X-Envoy-External-Address","X-Envoy-Internal",
                    "X-Envoy-Original-Dst-Host","X-Forwarded-Prefix"  # important for reflection cases
                ]
                fixed_port_headers = [("X-Forwarded-Port", p) for p in ["443","4443","80","8080","8443"]]
                fixed_scheme_headers = [("X-Forwarded-Scheme", s) for s in ["http","https"]]

                def headers_with_overrides(base_headers, kv_pairs):
                    names = set([k.lower() for (k, _) in kv_pairs])
                    base_no_dupes = self._build_headers_excluding(base_headers, names)
                    out = list(base_no_dupes)
                    for (k, v) in kv_pairs:
                        out.append(k + ": " + v)
                    return out

                def make_and_compare(extra_headers):
                    rr, err = self._safe_request(
                        http_service, extra_headers, body,
                        "Host override probe failed", "No response to hostish override probe."
                    )
                    if err:
                        # Return the error so the caller can treat 'spray failed' as interesting.
                        return None, None, None, None, err
                    if not rr:
                        return None, None, None, None, None
                    resp = rr.getResponse()
                    info = self._helpers.analyzeResponse(resp)
                    rbody = resp[info.getBodyOffset():]
                    return rr, resp, info, rbody, None

                # Consider ANY status delta (incl. 4xx) as interesting in the spray pass
                def differs_any_status(info_r, body_r):
                    if info_r and (info_r.getStatusCode() != original_info.getStatusCode()):
                        return True, "status"
                    elif body_r is not None and (len(body_r) != len(original_body)):
                        return True, "length"
                    return False, ""

                # ---- Spray pass (localhost set) ----
                spray_local_pairs = [(n, "127.0.0.1") for n in hostish_header_names] + fixed_port_headers + fixed_scheme_headers
                spray_local_headers = headers_with_overrides(headers, spray_local_pairs)
                sl_rr, sl_resp, sl_info, sl_body, sl_err = make_and_compare(spray_local_headers)

                # ---- Spray pass (collaborator set) ----
                collab_ctx_ov = self._callbacks.createBurpCollaboratorClientContext()
                collab_override = collab_ctx_ov.generatePayload(True)
                spray_collab_pairs = [(n, collab_override) for n in hostish_header_names] + fixed_port_headers + fixed_scheme_headers
                spray_collab_headers = headers_with_overrides(headers, spray_collab_pairs)
                sc_rr, sc_resp, sc_info, sc_body, sc_err = make_and_compare(spray_collab_headers)

                sl_diff, sl_reason = differs_any_status(sl_info, sl_body)
                sc_diff, sc_reason = differs_any_status(sc_info, sc_body)

                # Treat spray error or no-rr as interesting too
                spray_local_interesting  = sl_diff or (sl_err is not None) or (sl_rr is None)
                spray_collab_interesting = sc_diff or (sc_err is not None) or (sc_rr is None)

                def isolate_and_report(host_value, reason_label, probe_name):
                    try:
                        # For SSRF deltas (only matters for collab host_value)
                        before_len = 0
                        try:
                            b = collab_ctx_ov.fetchAllCollaboratorInteractions()
                            before_len = len(b) if b else 0
                        except:
                            pass

                        for name in hostish_header_names:
                            try:
                                s_pairs = [(name, host_value)]
                                s_headers = headers_with_overrides(headers, s_pairs)
                                rr, err = self._safe_request(
                                    http_service, s_headers, body,
                                    "Isolation override failed", "No response for header '%s' override." % name
                                )
                                if err:
                                    # Single header alone caused failure — valuable signal (could be honored but rejects value)
                                    issues.append(self._mk_issue(baseRequestResponse, None,
                                        "Host override header caused failure",
                                        "Header '%s' with value '%s' caused request failure during isolation." % (name, host_value),
                                        "Information"))
                                    continue
                                if not rr:
                                    continue

                                info = self._helpers.analyzeResponse(rr.getResponse())
                                rbody = rr.getResponse()[info.getBodyOffset():]

                                # Reflection (headers or small body window)
                                reflected = False
                                try:
                                    hdrs = "\n".join(info.getHeaders())
                                    sample = self._helpers.bytesToString(rr.getResponse())
                                    if (len(rr.getResponse()) < MAX_SAMPLE) and (host_value in hdrs or host_value in sample[:4096]):
                                        reflected = True
                                except:
                                    pass

                                flagged = False
                                code = info.getStatusCode()
                                if code != original_info.getStatusCode():
                                    scode = str(code)
                                    # Report 4xx as well (Low) for proxy header isolation
                                    issues.append(self._mk_issue(baseRequestResponse, rr,
                                        "Host override header changed status",
                                        "Header '%s' with value '%s' changed status to %s." % (name, host_value, scode), "Low"))
                                    flagged = True
                                else:
                                    if len(rbody) != len(original_body):
                                        issues.append(self._mk_issue(baseRequestResponse, rr,
                                            "Host override header size change",
                                            "Header '%s' with value '%s' changed body length." % (name, host_value), "Low"))
                                        flagged = True

                                if reflected:
                                    issues.append(self._mk_issue(baseRequestResponse, rr,
                                        "Host override header reflected",
                                        "Header '%s' value reflected in response." % name, "Medium"))
                                    flagged = True

                                if host_value == collab_override:
                                    # SSRF correlation (per-header)
                                    after_len = 0
                                    try:
                                        a = collab_ctx_ov.fetchAllCollaboratorInteractions()
                                        after_len = len(a) if a else 0
                                    except:
                                        after_len = before_len
                                    if after_len > before_len:
                                        issues.append(self._mk_issue(baseRequestResponse, rr,
                                            "Host override header - SSRF",
                                            "Collaborator interaction observed for header '%s'." % name, "High"))
                                        flagged = True
                                        before_len = after_len

                                if flagged:
                                    issues.append(self._mk_issue(baseRequestResponse, rr,
                                        "Header likely processed by upstream",
                                        "Header '%s' influences upstream behavior in probe '%s'." % (name, probe_name), "Information"))

                            except Exception as e:
                                self._stderr.println("Isolation for '%s' failed: %s" % (name, str(e)))
                    except Exception as e:
                        self._stderr.println("isolate_and_report failed: " + str(e))

                # Spray says “interesting” → isolate
                if spray_local_interesting:
                    isolate_and_report("127.0.0.1", sl_reason or "error", "spray-localhost")
                if spray_collab_interesting:
                    isolate_and_report(collab_override, sc_reason or "error", "spray-collab")

            except Exception as e:
                issues.append(self._mk_issue(baseRequestResponse, None, "Host override headers block failed", str(e), "Information"))

            # ---------------------------------------------------------
            # Step 8: Forwarded (RFC 7239) — one header per request
            # ---------------------------------------------------------
            try:
                def build_headers_with_forwarded(base_headers, fwd_value):
                    req_line_local = base_headers[0] if base_headers else (method + " " + original_path + " HTTP/1.1")
                    rest = base_headers[1:] if len(base_headers) > 1 else []
                    rest_no_fwd = [hh for hh in rest if not (hh.split(":",1)[0].strip().lower() == "forwarded")]
                    new_headers = [req_line_local] + rest_no_fwd + ["Forwarded: " + fwd_value]
                    return new_headers

                def send_forwarded_and_eval(fwd_value, indicator, is_collab):
                    fwd_headers = build_headers_with_forwarded(headers, fwd_value)
                    before_len = 0
                    collab_ctx_fwd = None
                    if is_collab:
                        try:
                            collab_ctx_fwd = self._callbacks.createBurpCollaboratorClientContext()
                            b = collab_ctx_fwd.fetchAllCollaboratorInteractions()
                            before_len = len(b) if b else 0
                        except:
                            before_len = 0

                    rr, err = self._safe_request(
                        http_service, fwd_headers, body,
                        "Forwarded header probe failed", "No response to Forwarded header."
                    )
                    if err:
                        issues.append(err); return
                    resp = rr.getResponse(); info = self._helpers.analyzeResponse(resp)
                    rbody = resp[info.getBodyOffset():]
                    hdrs = "\n".join(info.getHeaders())
                    reflected = (len(resp) < MAX_SAMPLE) and (indicator in hdrs or indicator in self._helpers.bytesToString(resp)[:4096])

                    flagged = False
                    code = info.getStatusCode()
                    if code != original_info.getStatusCode():
                        scode = str(code)
                        if scode.startswith("30") or scode.startswith("50") or code == 200:
                            issues.append(self._mk_issue(baseRequestResponse, rr,
                                "Forwarded (RFC 7239) changed status",
                                "Forwarded header changed status to %s (value: %s)." % (scode, fwd_value), "Low"))
                            flagged = True
                    elif len(rbody) != len(original_body):
                        issues.append(self._mk_issue(baseRequestResponse, rr,
                            "Forwarded (RFC 7239) size change",
                            "Body length differs with Forwarded header (value: %s)." % fwd_value, "Low"))
                        flagged = True

                    if reflected:
                        issues.append(self._mk_issue(baseRequestResponse, rr,
                            "Forwarded (RFC 7239) reflected",
                            "Injected Forwarded value appears in response (value: %s)." % indicator, "Medium"))
                        # keep flagged True if reflection seen
                        flagged = True

                    if is_collab and collab_ctx_fwd:
                        try:
                            a = collab_ctx_fwd.fetchAllCollaboratorInteractions()
                            after_len = len(a) if a else 0
                        except:
                            after_len = before_len
                        if after_len > before_len:
                            issues.append(self._mk_issue(baseRequestResponse, rr,
                                "Forwarded (RFC 7239) – SSRF",
                                "Collaborator interaction observed when using Forwarded header.", "High"))
                            flagged = True

                    if flagged:
                        issues.append(self._mk_issue(baseRequestResponse, rr,
                            "Forwarded (RFC 7239) likely honored",
                            "Behavior changed or reflected when using the Forwarded header.", "Information"))

                # Localhost / 127.0.0.1 probes
                send_forwarded_and_eval('for=127.0.0.1;host=127.0.0.1;proto=http', '127.0.0.1', False)
                send_forwarded_and_eval('for=127.0.0.1;host=127.0.0.1;proto=https', '127.0.0.1', False)
                send_forwarded_and_eval('for=localhost;host=localhost;proto=http', 'localhost', False)
                send_forwarded_and_eval('for=localhost;host=localhost;proto=https', 'localhost', False)
                # Collaborator probe (quoted)
                collab_ctx_fwd_main = self._callbacks.createBurpCollaboratorClientContext()
                fwd_actual = collab_ctx_fwd_main.generatePayload(True)
                send_forwarded_and_eval('for="%s";host="%s";proto=http' % (fwd_actual, fwd_actual), fwd_actual, True)
            except Exception as e:
                issues.append(self._mk_issue(baseRequestResponse, None, "Forwarded (RFC 7239) block failed", str(e), "Information"))

            # ---------------------------------------------------------------
            # Step 9: Malformed Request-Line SSRF ("@userinfo") — bucketed
            # ---------------------------------------------------------------
            try:
                sev_rank = {"High": 3, "Medium": 2, "Low": 1, "Information": 0}
                mp_buckets = {}
                mode_pref = {"ORIG": 1, "ROOT": 0}
                def mp_bucket_key(target_label, mode_label):
                    return "malformed-path|" + target_label + "|" + mode_label
                def mp_record(bkey, mode_label, resp_obj, sev, title, detail, malformed_path):
                    if bkey not in mp_buckets:
                        mp_buckets[bkey] = {"best": None, "tried_modes": set()}
                    mp_buckets[bkey]["tried_modes"].add(mode_label)
                    best = mp_buckets[bkey]["best"]
                    cand = {"sev": sev, "title": title, "detail": detail, "resp_obj": resp_obj, "mode": mode_label, "malformed": malformed_path}
                    if best is None:
                        mp_buckets[bkey]["best"] = cand
                    else:
                        if sev_rank[sev] > sev_rank[best["sev"]]:
                            mp_buckets[bkey]["best"] = cand
                        elif sev_rank[sev] == sev_rank[best["sev"]]:
                            if mode_pref.get(mode_label, -1) > mode_pref.get(best["mode"], -1):
                                mp_buckets[bkey]["best"] = cand

                def send_malformed_path(base_headers, base_body, malformed_path):
                    new_headers = list(base_headers) if base_headers else []
                    new_headers[0] = method + " " + malformed_path + " HTTP/1.1"
                    # Ensure Host remains original (single header)
                    fixed = []
                    host_set = False
                    for hh in new_headers:
                        if hh.lower().startswith("host:"):
                            fixed.append("Host: " + original_host); host_set = True
                        else:
                            fixed.append(hh)
                    if not host_set:
                        fixed.append("Host: " + original_host)
                    return self._safe_request(
                        http_service, fixed, base_body,
                        "Malformed request-line probe failed", "No response to '@userinfo' malformed path."
                    )

                collab_ctx_mp = self._callbacks.createBurpCollaboratorClientContext()
                mp_targets = ["ORIG", "COLLAB", "127.0.0.1", "localhost"]
                mp_token_map = {}

                for target in mp_targets:
                    for mode_label in ["ROOT", "ORIG"]:
                        try:
                            if target == "COLLAB":
                                tok = collab_ctx_mp.generatePayload(True)
                                injected = tok; target_label = "collab"
                            elif target == "ORIG":
                                injected = original_domain; target_label = "original"
                            else:
                                injected = target; target_label = target

                            if mode_label == "ROOT":
                                malformed_path = "@" + injected + "/"
                            else:
                                if original_path.startswith("/"):
                                    malformed_path = "@" + injected + original_path
                                else:
                                    malformed_path = "@" + injected + "/" + original_path

                            rr, err = send_malformed_path(headers, body, malformed_path)
                            if err:
                                # non-fatal; just skip adding bucket entry
                                continue
                            if not rr:
                                continue
                            resp = rr.getResponse()
                            info = self._helpers.analyzeResponse(resp)
                            rbody = resp[info.getBodyOffset():]
                            code = info.getStatusCode()
                            hdrs_str = "\n".join(info.getHeaders())
                            sample = self._helpers.bytesToString(resp)
                            reflected = False
                            if len(resp) < MAX_SAMPLE:
                                if (injected in hdrs_str) or (injected in sample[:4096]):
                                    reflected = True

                            candidate = None; title = ""; detail = ""
                            if code != original_info.getStatusCode():
                                scode = str(code)
                                allowed = scode.startswith("30") or scode.startswith("50") or code == 200
                                is4xx = scode.startswith("4")
                                if allowed:
                                    candidate = "Low"; title = "Malformed request-line changed status"
                                    detail = "Status changed from %s to %s with path '%s'." % (original_info.getStatusCode(), scode, malformed_path)
                                else:
                                    if is4xx:
                                        if reflected:
                                            candidate = "Medium"; title = "Malformed request-line host reflection ('@userinfo')"
                                            detail = "Target '%s' appears in headers/body with path '%s' (status %s)." % (injected, malformed_path, scode)
                                        else:
                                            continue
                                    else:
                                        candidate = "Low"; title = "Malformed request-line status anomaly"
                                        detail = "Unexpected status %s vs baseline %s using path '%s'." % (scode, original_info.getStatusCode(), malformed_path)
                            else:
                                if len(rbody) != len(original_body):
                                    candidate = "Low"; title = "Malformed request-line size change"
                                    detail = "Body length differs from baseline using path '%s'." % malformed_path
                                else:
                                    if reflected:
                                        candidate = "Medium"; title = "Malformed request-line host reflection ('@userinfo')"
                                        detail = "Target '%s' appears in headers/body with path '%s'." % (injected, malformed_path)
                                    else:
                                        continue

                            bkey = mp_bucket_key(target_label, mode_label)
                            mp_record(bkey, mode_label, rr, candidate, title, detail, malformed_path)
                            if target == "COLLAB":
                                mp_token_map[injected] = (bkey, malformed_path, rr)
                        except Exception as e:
                            self._stderr.println("Malformed path variant failed: " + str(e))

                # Collaborator correlation
                try:
                    mp_inter = collab_ctx_mp.fetchAllCollaboratorInteractions()
                except Exception:
                    mp_inter = None
                if mp_inter:
                    for it in mp_inter:
                        try:
                            s = str(it)
                        except:
                            s = ""
                        if not s:
                            continue
                        for tok, (bkey, mpath, robj) in list(mp_token_map.items()):
                            if tok in s and bkey in mp_buckets:
                                best = mp_buckets[bkey]["best"]
                                if best is None or sev_rank["High"] > sev_rank[best["sev"]]:
                                    mp_buckets[bkey]["best"] = {
                                        "sev": "High",
                                        "title": "SSRF via malformed request-line ('@userinfo')",
                                        "detail": "Collaborator interaction observed. Crafted path: '%s'." % mpath,
                                        "resp_obj": robj,
                                        "mode": bkey.split("|")[-1],
                                        "malformed": mpath
                                    }

                # Emit one per malformed-path bucket
                for bkey, data in mp_buckets.items():
                    best = data.get("best")
                    if not best:
                        continue
                    tried_modes = sorted(list(data.get("tried_modes", [])), key=lambda m: mode_pref.get(m, -1), reverse=True)
                    tried_summary = "Tried modes: " + (", ".join(tried_modes) if tried_modes else "<none>")
                    detail = best["detail"] + "\n" + tried_summary + "\nBucket: " + bkey + "\nRequest-line used: " + best.get("malformed", "")
                    issues.append(self._mk_issue(baseRequestResponse, best["resp_obj"], best["title"], detail, best["sev"]))
            except Exception as e:
                issues.append(self._mk_issue(baseRequestResponse, None, "Malformed request-line SSRF block failed", str(e), "Information"))

        except Exception as e:
            self._stderr.println("Top-level scan error: " + str(e) + "\n" + traceback.format_exc())
            issues.append(self._mk_issue(baseRequestResponse, None, "Extension internal error", str(e), "Information"))

        # ---------------
        # FLUSH ONCE
        # ---------------
        issues = [i for i in issues if i is not None]
        if issues:
            for iss in issues:
                self._callbacks.addScanIssue(iss)  # Target → Issues
            return issues                           # Active Scan Issues
        return None

    # Passive scan unused
    def doPassiveScan(self, baseRequestResponse):
        return None

    # de-dup policy: let Burp manage
    def consolidateDuplicateIssues(self, existingIssue, newIssue):
        return -1


class CustomScanIssue(IScanIssue):
    def __init__(self, http_service, url, http_messages, name, detail, severity):
        self._http_service = http_service
        self._url = url
        self._http_messages = http_messages
        self._name = name
        self._detail = detail
        self._severity = severity

    def getUrl(self): return self._url
    def getIssueName(self): return self._name
    def getIssueType(self): return 0
    def getSeverity(self): return self._severity
    def getConfidence(self): return "Firm"
    def getIssueBackground(self): return None
    def getRemediationBackground(self): return None
    def getIssueDetail(self): return self._detail
    def getRemediationDetail(self): return None
    def getHttpMessages(self): return self._http_messages
    def getHttpService(self): return self._http_service
