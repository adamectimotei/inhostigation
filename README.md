# InHostigation
Burp extension for automated detection of **Host header injection** vulnerabilities

## Description
- A Burp Suite extension written in Python
- Automates Host checks
- Runs automatically via Active Scan
- Performs all checks except connection-reuse (keep-alive) validation
- Cache-busting built in to avoid false positives from cached responses
- Per-issue hints
- Flags only when there is a meaningful behavior

---

## High-level checks
- **Host value manipulation:** arbitrary host, `Host:port` (numeric & non-numeric), subdomain, pre/post concatenation  
- **Precedence quirks:** **duplicate** `Host` headers, **indented/folded** `Host` (leading space)  
- **Override/proxy headers:** `X-Forwarded-Host`, `Forwarded` (RFC 7239), `X-Original-Host`, `X-Forwarded-Server`, etc. (full list in [proxy_headers.txt](proxy_headers.txt))  
- **Absolute-URI request line:** `GET https://host/... HTTP/1.1` 
- **Malformed request line:** to detect routing-based SSRF behavior  
- **Body/header reflection:** to highlight cache-poisoning / link-poisoning potential
- **SSRF confirmation via Collaborator:** auto-detects outbound DNS/HTTP interactions
- **Full list of performed checks:** see the [checks.md](checks.md) file.

> 📝 **Note:** Connection-reuse host stickiness is **not** automated

---

## What other tools often miss
- **Body reflection paths** that can turn harmless reflections into **cache poisoning**
- **RFC 7239 `Forwarded`** header handling (not just `X-Forwarded-Host`)
- **Alternate proxy/override headers** beyond the usual headers
- **Flawed Host validation** (ports, concatenations, mixed casing, subdomain tricks)
- **Absolute or malformed request lines** that change routing at the edge
- **Duplicate / indented `Host`**

---

## Installation
- Install the extension manually from a file
- Extensions → Installed → Add → Extension type: Python → Extension file (.py): inhostigation.py

---

## Usage
1) Run **Active Scan** on your target
2) Findings appear under **Scan → Issues** or **Target → Issues**

---

## Comparison with other tools

| Lab | Active scan | Active scan++ | Inchecktion | InHostigation |
|---|:---:|:---:|:---:|---|
| Basic password reset poisoning | ❌ | ❌ | ❌ | ❌ — reports “Host/Host:port accepted”; suggests next steps (reflection, link-poisoning) |
| Password reset poisoning via middleware | ❌ | ❌ | ❌ | ❌ |
| Host header authentication bypass | ❌ | ❌ | ✅ | ✅ |
| Routing-based SSRF | ✅ | ✅ | ✅ | ✅ |
| SSRF via flawed request parsing | ❌ | ❌ | ✅ | ✅ |
| Web cache poisoning via ambiguous requests | ✅ | ✅ | ✅ | ✅ |
| Host validation bypass via connection state attack | ❌ | ❌ | ❌ | ❌ — flags interesting status-code changes (stickiness) |
| Password reset poisoning via dangling markup | ❌ | ❌ | ❌ | ❌ — reports “Host/Host:port accepted”; suggests checking reflection / link-poisoning |
| Custom Forwarded header lab | ❌ | ❌ | ❌ | ✅ — includes “Next steps” guidance |
| Custom malformed request line lab | ❌ | ✅ | ✅ | ✅ |

---

## Safety
Use only on systems you’re authorized to test.

