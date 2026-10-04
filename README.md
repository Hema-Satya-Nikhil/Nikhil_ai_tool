# NIKHIL AI — Scope-First Ethical Security Assessment Toolkit

NIKHIL AI is an extensible Python assessment assistant for systems you own, localhost/lab environments, explicitly authorized penetration tests, and bug-bounty assets that are in scope. It retains the original five scanners and the existing Flask dashboard while adding a mandatory Scope Guard, conservative read-only checks, project history, evidence redaction, and HTML/JSON reporting.

**This is not an exploitation framework.** Safe Mode is enabled by default. It does not dump databases, brute-force credentials, spray passwords, establish persistence, run destructive OS commands, modify target data, mass-exploit targets, or automatically confirm a finding. Automated results are leads that require human validation. The tool does not promise to find all vulnerabilities.

> The repository's actual entry point/package names are `nikhil_toolkit.py` and `nikhil_ai_modules/`. The `VAPT-Toolkit-Pro-Python-` name and `vapt.py` layout sometimes used in planning notes are not the current checkout; this upgrade extends the existing repository instead of replacing it.

## Requirements

- Python **3.10 or newer**
- Windows, Linux, or macOS
- Internet access only for authorized targets and (optionally) the public certificate-transparency source `crt.sh`
- Required Python packages are listed in `requirements.txt`; no database server or external scanner is required

## Installation

### Windows PowerShell

```powershell
py -3.10 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python nikhil_toolkit.py
```

If PowerShell blocks activation, use Command Prompt:

```bat
py -3.10 -m venv .venv
.venv\Scripts\activate.bat
python -m pip install -r requirements.txt
python nikhil_toolkit.py
```

### Linux

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python nikhil_toolkit.py
```

### macOS

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python nikhil_toolkit.py
```

`python install_deps.py` is also provided as a cross-platform wrapper. It uses the active interpreter and does not force-reinstall packages. Nmap and SSLyze are optional; native checks work without them, and external-tool scans are disabled in Safe Mode.

## Quick start: define scope before scanning

On first run there is **no authorized target**, so scans are refused until scope is configured:

1. Choose **[1] Scope Manager**.
2. Add explicit targets, for example:
   - `example.com` — that exact host only
   - `api.example.com` — that exact subdomain only
   - `*.example.com` — subdomains of `example.com`, not the apex
   - `203.0.113.12` or `203.0.113.0/24` — explicit IP/CIDR scope
3. Add explicit exclusions, e.g. `admin.example.com`. Exclusions always take precedence.
4. Choose **[3] Show current scope** and verify it before running a scanner.

Example program scope:

```text
IN-SCOPE
*.example.com
api.example.com

OUT-OF-SCOPE / EXCLUSIONS
admin.example.com
payments.example.com
```

The scope is saved locally in `projects/<project-slug>.json`; project/global settings and generated data are local and ignored by Git. Rules are not sent to a remote service. Redirects are revalidated before each follow-up request. A discovered asset is never actively probed unless it also matches the current allowlist and is not excluded.

### Localhost / lab scope

Private and loopback addresses require explicit IP/CIDR authorization as well as target scope. For the included local lab, add:

```text
127.0.0.1/32
```

For a `localhost` hostname that resolves to IPv6 as well, add `::1/128` and the exact hostname `localhost`. Link-local, multicast, reserved, and unspecified addresses are always blocked.

## Safe Mode

Safe Mode is `ON` by default in `config.example.json` and the built-in defaults. Conservative defaults include:

- One outbound HTTP request per second (shared limiter), 6-second timeout, one retry for safe requests
- 3 scan workers by default (hard-capped at 5)
- Bounded response capture (1 MiB by default) and a limited redirect count
- HTTP methods restricted to `GET`, `HEAD`, and `OPTIONS`; no POST unless a dedicated one-shot test-account flow explicitly asks for confirmation
- No automatic file uploads, destructive tests, command payloads, SQL time-delay probes, database extraction, GraphQL introspection, credential guessing, or logout invocation
- Scope validation before every HTTP request and redirect; the connected HTTP peer IP is checked against the validated DNS answers to reduce DNS-rebinding risk, and socket checks validate scope and resolved addresses too
- Sensitive headers, credentials, cookie values, common tokens, and email addresses are redacted before evidence, logs, and reports

Do not disable Safe Mode or increase scan intensity on a public target without explicit authorization and a documented test plan. A target hostname resolving to a private address also requires an explicit IP/CIDR rule. Link-local metadata ranges remain blocked.

## CLI menu

```text
[ 1] Scope Manager
[ 2] Subdomain Enumeration
[ 3] HTTP / HTTPS Probing
[ 4] Technology Detection
[ 5] Endpoint / URL Discovery
[ 6] JavaScript Analysis
[ 7] HTTP Security Headers
[ 8] DNS / Origin Exposure
[ 9] SSL/TLS Audit
[10] Open Port Scanner
[11] CORS Misconfiguration
[12] Cookie Security Analysis
[13] SQL Injection Detection Assistant
[14] NoSQL Injection Detection Assistant
[15] Command Injection Detection Assistant
[16] Path Traversal Detection Assistant
[17] Authentication / Session Analysis
[18] Authorization Testing (two owned accounts)
[19] API Security Analysis
[20] File Upload Security Checks
[21] Sensitive Exposure Detection
[22] Scan History
[23] Findings
[24] Generate Report
[25] Exit
```

`clear`, `exit`, and Ctrl+C are handled. A failure in one menu action returns to the menu instead of crashing the program.

## Scanner guide

| Menu | What it does | Safety boundary |
|---|---|---|
| 2 Subdomain Enumeration | Optional passive `crt.sh` certificate-transparency lookup, deduplication, and in-scope status probing | Public-source use asks for consent; candidates outside scope are skipped; no default wordlist brute force |
| 3 HTTP/HTTPS Probing | Captures status, final URL, redirects, sanitized headers, content type/size, title and server hint | Bounded response capture and scope-checked redirects |
| 4 Technology Detection | Reports Apache/Nginx/IIS, PHP/Express, WordPress, React/Next.js, CDN and related indicators | Includes evidence and confidence; indicators are not proof |
| 5 Endpoint Discovery | Inventory from the page, links, scripts, `robots.txt`, sitemap and a small set of API-doc locations | No automatic exploitation or broad path brute force |
| 6 JavaScript Analysis | Extracts API-like paths, parameter names, environment variable names and source-map references | Source maps are not fetched; candidate secrets are labelled **POSSIBLE SECRET / REVIEW REQUIRED**, values are withheld |
| 7 HTTP Security Headers | Checks CSP, HSTS, framing, MIME sniffing and referrer-policy headers | Returns structured results and review-required findings |
| 8 DNS / Origin Exposure | Resolves an in-scope hostname and optionally checks direct-IP visibility | A direct-IP request happens only if that IP/CIDR is explicitly in scope |
| 9 SSL/TLS Audit | Certificate/negotiated TLS snapshot and a constrained TLS 1.0–1.3 support check | Optional external tools are disabled in Safe Mode; results are not automatically confirmed |
| 10 Open Port Scanner | Checks the fixed 13 common TCP ports in `config.json` | Low worker cap and shared rate limiter; not a full network inventory |
| 11 CORS | Sends one request with a non-existent origin and reviews CORS headers | Does not read cross-origin data; browser/account impact needs manual validation |
| 12 Cookies | Reviews Secure, HttpOnly, SameSite, Domain and Path hints | Cookie values are never displayed or stored |
| 13 SQLi assistant | Optional baseline vs. one quote-only parameter comparison | Requires a researcher confirmation that the GET endpoint is read-only; no extraction, writes, or time-delay payloads |
| 14 NoSQL assistant | Looks for baseline database/parser signals and candidate query parameters | Passive only; no operators, document access, or database enumeration |
| 15 Command injection assistant | Reviews normal response for shell-error indicators and operation-like parameters | Passive only; sends no shell metacharacters, commands, or callbacks |
| 16 Path traversal assistant | Identifies file/path-like parameters from an ordinary request | Sends no traversal strings and retrieves no OS files |
| 17 Authentication/session | Reviews login forms, cookies, rate-limit headers and logout references | Optional single POST only for a researcher-controlled account after explicit confirmation; no brute force; logout is not invoked |
| 18 Authorization | Compares a resource created by Account A using two researcher-controlled bearer tokens | GET-only; requires explicit confirmation, stores neither token nor response body; never use unrelated users' resources |
| 19 API security | Reviews GET/OPTIONS, JSON/GraphQL/OpenAPI hints, authentication and rate-limit headers | No mutating method or GraphQL introspection |
| 20 Upload checks | Inventories HTML upload forms and advertised accept hints | No file is uploaded; use a harmless file and manual approval for further validation |
| 21 Exposure | Checks public security files and uses HEAD for sensitive-path candidates | Sensitive config/backup bodies are not fetched; 200 responses may be application fallbacks |

All modules use shared configuration, scope validation, HTTP session/rate limiting, logging, database, evidence redaction, and the finding lifecycle. Modules return structured Python dictionaries instead of printing-only results.

## Example safe scan

Start the local lab in terminal 1:

```bash
python tests/lab_app.py
```

It binds only to `127.0.0.1:5001`. In terminal 2:

```bash
python nikhil_toolkit.py
```

Then choose **Scope Manager → Add in-scope IP/CIDR** and enter `127.0.0.1/32`. Choose **[7] HTTP Security Headers** and enter `http://127.0.0.1:5001/`. The tool should show observed missing headers and store them as `NEEDS_REVIEW`, not `CONFIRMED`.

Example output (target response varies):

```text
[+] Content-Security-Policy missing
[!] X-Frame-Options missing
[i] Potential detections require manual verification.
Finding IDs (NEEDS_REVIEW): F-...
```

The lab intentionally has weak headers and permissive CORS for local practice. It does not execute commands, access a database, accept uploaded files, or contact public targets.

## Findings lifecycle

Every finding follows the model in `nikhil_ai_modules/findings.py`:

- Finding ID, title, category, target, endpoint, parameter
- Severity, confidence, description, impact, evidence, observed behavior
- Reproduction notes, remediation, references, status

Allowed statuses are `NEW`, `NEEDS_REVIEW`, `CONFIRMED`, `FALSE_POSITIVE`, `REPORTED`, and `RESOLVED`. Scanner-created findings are always `NEEDS_REVIEW`; the **Findings** menu requires the researcher to type `HUMAN VERIFIED` to mark a finding confirmed. Similar findings on one host are grouped with affected endpoints.

## History, SQLite, evidence, and reports

SQLite is created at `output/nikhil.sqlite3` and contains projects, target rules, assets, endpoints, scans, findings, and evidence. Use **[22] Scan History** and **[23] Findings** to inspect data. Logs go to `logs/scanner.log`; passwords, session cookies and tokens are not logged.

Choose **[24] Generate Report**, then `html`, `json`, or `pdf` (PDF requires optional `reportlab`). Reports are saved in `output/reports/` and separate **AUTOMATED DETECTION** from **HUMAN VERIFIED FINDING**. Credentials and candidate secret values are redacted or withheld.

## Web dashboard

The existing Flask dashboard is retained:

```bash
python app.py
# open http://127.0.0.1:5000
```

The dashboard uses the same local Scope Guard. Add scope using the CLI before scanning in the browser. The API returns structured data; it no longer fabricates fallback scan results. The Flask app has no user authentication and is intended for local use only—**do not expose it publicly** without adding strong authentication, authorization, CSRF protection, and deployment-specific controls. CORS is not opened globally.

## Tests and local lab

Run unit and local HTTP integration tests:

```bash
python -m unittest discover -s tests -v
```

`tests/lab_app.py` is an intentionally misconfigured local fixture for practice. Tests do not scan random public websites.

## Developer guide: adding a scanner

1. Add `nikhil_ai_modules/<name>.py`; do not put scanner logic in `nikhil_toolkit.py`.
2. Accept a target and optional `context=None`; resolve shared services with `resolve_context(context)`.
3. Before HTTP use `context.http` (`get`, `head`, `options`) rather than `requests` directly. It validates scope on every redirect, applies rate limits and caps response size. For sockets, call `context.scope.validate_host(..., resolve=True)` and use the shared limiter before each connection.
4. Return a serializable dictionary; put tentative results in `potential_findings` with status `NEEDS_REVIEW`. Never set `CONFIRMED` in scanner code.
5. Avoid storing raw bodies, credentials, cookie values or secrets. Use `context.evidence.record(...)` and `nikhil_ai_modules.evidence` sanitizers when evidence is needed.
6. Add the menu dispatch in `nikhil_toolkit.py` and unit tests that use the local lab/loopback scope.

Central services live in `config.py`, `scope.py`, `http_client.py`, `logging_setup.py`, `database.py`, `findings.py`, `evidence.py`, `context.py`, `scan_runner.py`, and `report.py`.

## Legal / authorization notice

Only use this toolkit against assets that you own or have explicit written authorization to assess, and follow each bug bounty program's published scope, rate limits, and rules. Written authorization does not automatically permit every technique. Stop if scope is unclear, respect exclusions, and do not access real users' data. You are responsible for your actions and compliance with applicable laws. This software is provided "as is" under the MIT License.
