# Checks performed by the Host Header Injection Scanner

This document lists checks the extension performs and what they mean.

## 1) Baseline / invalid host checks
- Set `Host: InvalidHostHeaderxyz123` and compare response code/body.
- Detects: Host ignored, different routing, or reflection (simple sanity check).

## 2) Collaborator Host injection (OOB SSRF detection)
- Set `Host: <burp-collab-payload>` and check:
  - Response differences (status / body length)
  - Reflection of token in response
  - Burp Collaborator interactions (external OOB)
- Detects: server-side resolution/requests, SSRF/back-end connectivity.

## 2b) Loopback / internal host checks
- Host values: `127.0.0.1`, `localhost`, `0x7f000001`, `2130706433`
- Detects internal-host routing, local-service exposure, or port blind effects.

## 3) Host header with port manipulations
- Host values including `domain:12345`, `domain:InvalidHostHeaderxyz123`, `domain:@<collab>`
- Detects: parser handling of ports, downstream port interpolation, SSRF via host:port.

## 4) Combined-domain / flawed validation
- Host values like `<collab>original.com` and `original.com.<collab>`
- Detects: brittle host validation where backend concatenation or suffix checks are flawed.

## 5) Absolute-URI (absolute-form request-line) tests
- Send request-lines in absolute-form: `GET http://host/path HTTP/1.1`
- Vary the scheme (`http`, `https`, case mixes) and host (collab, localhost, etc).
- Detects: routing based on absolute form, SSRF, proxy misrouting, scheme-based access control bypass.

## 6) Line folding / duplicate Host tests (HTTP/1.1)
- Line-folded Host (second header line starts with space): tests parser folding
- Duplicate Host header: `Host: original` + `Host: <token>`
- Detects: ambiguous header parsing, duplicate header precedence issues, reflection.

## 7) Header override spray → isolate
- Spray many header names with `127.0.0.1` and a collaborator token to see if any cause changes.
- If spray shows interesting behavior, isolate per-header to identify precisely which header triggers it.
- Detects: proxies or upstream components honoring non-standard host-like headers.

## 8) Forwarded (RFC 7239) header tests
- `Forwarded: for=...;host=...;proto=...` with internal values and collaborator tokens.
- Detects: components honoring RFC 7239 fields and possible SSRF or host routing issues.

## 9) Malformed request-line SSRF ("@userinfo")
- Request-line with `@host` or `@host/path` (e.g., `GET @<collab>/... HTTP/1.1`)
- Detects: servers that treat the `@userinfo` or malformed path as routing to another host.
