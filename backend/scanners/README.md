# Scanners

Each file here wraps one security tool. It runs the tool, reads the tool's
own output format, and returns findings in one shared shape.

| File | Tool | Target | Finds |
|---|---|---|---|
| `nmap_scanner.py` | Nmap (`-sV -Pn -F --script "vuln and safe"`, XML) | hostname | open ports rated by risk, service versions, safe NSE vulnerability checks |
| `nuclei_scanner.py` | Nuclei (`-as`, rate limited, JSONL) | website | known CVEs and misconfigurations |
| `wapiti_scanner.py` | Wapiti (passive and read-only modules, JSON) | website | missing security headers, cookie flags, CSP, TLS, outdated software |
| `osv_scanner.py` | OSV-Scanner (JSON) | lock file or code folder | vulnerable dependencies |
| `wapiti_safe.py` | - | - | launcher that stops Wapiti's crawler submitting forms |
| `common.py` | - | - | `ScannerError`, `ScanResult`, shared helpers |
| `worker.py` | - | - | runs a dashboard website scan (Nuclei, Wapiti, Nmap) |
| `scan_runner.py` | - | - | runs every scanner, for lab and manual use |

The tools are installed by the `Website scan` GitHub workflow
(`.github/workflows/scan.yml`) and in `Dockerfile.scan-worker`, not in the
API image. Python packages for them are in [requirements.txt](requirements.txt).

## Adapter contract

Each adapter exposes `run_<name>_scan(target, ...) -> ScanResult` and a pure
`parse_...(output, target)` function that the tests run on saved output.

- **Failure is explicit.** A tool that is missing, times out, exits with an
  unexpected code, or writes output that can't be parsed raises
  `ScannerError(tool, reason)`. A `ScanResult` with no findings is a clean
  scan. The two never look the same.
- `ScanResult` carries the findings plus the tool's raw output and a file
  name for it (`nmap.xml`, `nuclei.jsonl`, `wapiti.json`, `osv.json`).

Every finding has these fields:

| Field | Meaning |
|---|---|
| `tool` | `"nmap"`, `"nuclei"`, `"wapiti"` or `"osv-scanner"` |
| `target` | the asset: the hostname (Nmap), the website `scheme://host[:port]` (Nuclei, Wapiti), or the lock file (OSV) |
| `finding_type` | `open_port`, `vulnerability`, `web_vulnerability`, `web_misconfiguration`, `vulnerable_software`, `vulnerable_dependency` or `information` |
| `severity` | `low`, `medium`, `high` or `critical` |
| `title`, `description` | short and longer text; the OSV title names the vulnerability |
| `evidence` | the specific proof: port state and service version, matched URL, request, or advisory IDs |
| `raw_output_ref` | where the raw output is kept, set by the backend (see below) |
| `cve_id` | CVE where there is one, always in capitals |
| `found_at` | ISO 8601 UTC time the output was parsed |

### Information-only results

Technologies detected, web ports open and similar results are not
vulnerabilities. Each adapter collapses them into **one** `information`
finding per asset, with severity `low`, listing what was found.

## Severity rules

- **Nmap**, by port and by the service `-sV` identifies:
  - **high:** FTP, Telnet, SMB/NetBIOS, Remote Desktop, VNC, Docker API,
    and databases (MySQL, PostgreSQL, SQL Server, Oracle, MongoDB, Redis,
    Elasticsearch, CouchDB, Memcached) reachable from the internet. A
    database on an unusual port is still recognised by its service name.
  - **medium:** SSH, mail (SMTP, POP3, IMAP), and 8080/8443.
  - **information only:** 80 and 443.
  - **low:** any other open port.
  - A `vuln and safe` NSE script that reports `VULNERABLE` is a **high**
    `vulnerability` finding, with its CVE.
- **Nuclei:** the template's severity. `info` and `unknown` are information.
- **Wapiti:** Wapiti's own level (0 information, 1 low, 2 medium, 3 high,
  4 critical). "Vulnerable software" becomes one finding per product, with
  the highest level among its CVEs.
- **OSV:** the group's CVSS score (`max_severity`: 9+ critical, 7+ high,
  4+ medium, else low), else the advisory's own rating, else medium.

## What each tool sends to a customer's website

- **Wapiti** runs only modules that read: `http_headers`, `cookieflags`,
  `csp`, `https_redirect`, `information_disclosure`,
  `stacktrace_disclosure`, `unsecure_password`, `inconsistent_redirection`
  (passive), plus `ssl` and `wapp`. The passive modules aren't shown by
  `wapiti --list-modules` but are enabled with `-m` by name (checked on
  wapiti3 3.3.2). The attack modules (`sql`, `xss`, `permanentxss`,
  `upload`, `exec`, `file`, `ssrf`, ...) and `methods` (which sends PUT and
  DELETE) are off. Wapiti's crawler normally submits every form it finds,
  so it runs through `wapiti_safe.py`, which drops everything but GET.
  Tested on a local site: only GET requests reached it.
- **Nmap** connects to the top 100 ports, identifies services, and runs
  only NSE scripts in both the `vuln` and `safe` categories, each capped
  at 60 seconds. Plain `--script vuln` includes checks that can disrupt a
  server.
- **Nuclei** runs its automatic scan with templates tagged `intrusive`,
  `dos` or `fuzz` excluded, at 50 requests per second. It still sends
  some POST detection probes (for example XML-RPC calls).

There are no DVWA defaults any more. `run_wapiti_scan` takes `cookie_file`
and `exclusions` only when you pass them, for the security lab.

## Raw output

The worker gzips each tool's raw output and sends it with the findings. The
backend stores it in the private Supabase Storage bucket `scan-raw-output`
(migration `20261123100000_scan_raw_output_bucket.sql`) at
`<organization_id>/<scan_id>/<file>.gz`, and sets each finding's
`raw_output_ref` to `scan-raw-output/<that path>`.

It is not kept as a GitHub artifact, because the repository is public, so
its artifacts would be too. A failed upload is logged and skipped; it never
fails the scan. A raw file over 2 MB (the backend's per-file limit), or
past about 3 MB in total, is not kept, and the scan's warning says so; the
findings are still sent.

## Website scans from the dashboard

Org admins add a website on the Scans page and tick "I own this website or
have permission to scan it". TROJAN records who added it and when. "Scan
now" creates a row in `scans` and starts the `Website scan` GitHub
workflow, which runs `python -m scanners.worker <scan_id>`:

1. Reads the target from `/v1/worker/scans/<id>/start`.
2. Runs Nuclei (10 minutes), Wapiti (7) and Nmap (7). The job stops at 40
   minutes, and installing the tools takes about 4.
3. Sends findings, raw output and a summary to `/v1/worker/scans/<id>/finish`.
   Both calls use `SCAN_WORKER_SECRET`.

A tool that didn't finish is named in the scan's warning, with the reason.
If none finished, the scan fails. The public log shows only tool names and
counts: never the target, a failure reason or raw output.

Setup:

- Vercel: `GITHUB_DISPATCH_TOKEN` (fine-grained token for this repository
  with Actions read and write) and `SCAN_WORKER_SECRET`.
- GitHub repository secret: `SCAN_WORKER_SECRET` (same value).
- Supabase: apply `20261123100000_scan_raw_output_bucket.sql`.

Limits: one running scan per website, 10 scans per organization per day,
and scans not finished after 45 minutes are marked failed.

## OSV-Scanner

OSV-Scanner is meant for a business's **code**, not its website: an
uploaded lock file (`requirements.txt`, `package-lock.json`, ...) or a
checked-out repository. `run_osv_scan(path)` takes either. Nothing in the
dashboard calls it yet. The next step is an upload on the Findings page
that sends a lock file to a worker.

## Tests

`backend/test_scanners.py` runs every parser on saved output in
[`testdata/`](testdata/):

| File | Source |
|---|---|
| `nmap_services.xml` | real `nmap -sV` against local test services |
| `wapiti_report.json` | real Wapiti run (this configuration) against a local test site |
| `osv_requests.json` | real OSV-Scanner output for `requests==2.19.0`, trimmed |
| `nmap_vuln_scripts.xml`, `nmap_no_host.xml` | hand-written in Nmap's XML format |
| `nuclei_results.jsonl` | hand-written in Nuclei's JSONL format |

The tests also check failure handling, the worker's summary and raw-output
packing, and the backend's raw-output storage. The `wapiti_safe` test runs
only where wapiti3 is installed; CI skips it.

## Adding a tool

1. Create `<name>_scanner.py` with a `parse_...` function and a
   `run_<name>_scan` that returns `ScanResult` or raises `ScannerError`.
2. Save sample output in `testdata/` and test the parser.
3. Add it to `SCANNERS` in `scan_runner.py`, or to `TOOLS` in `worker.py`
   for website scans, within the job's 40-minute limit.
4. Install the tool in `scan.yml` and `Dockerfile.scan-worker`.
