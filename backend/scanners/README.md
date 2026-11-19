# Scanners

Each file here wraps one security tool. It runs the tool against a
target, reads the tool's own output format, and returns a list of
findings in one shared shape. No adapter shells out to `jq`, `xml2json`
or any other post-processor.

| File | Tool | Target | Finds |
|---|---|---|---|
| `nmap_scanner.py` | Nmap (`-F`, XML to stdout) | host or IP | open TCP ports |
| `wapiti_scanner.py` | Wapiti (JSON report) | URL | web application vulnerabilities |
| `nuclei_scanner.py` | Nuclei (JSONL) | URL | CVEs and misconfigurations from templates |
| `osv_scanner.py` | OSV-Scanner (JSON) | folder | vulnerable dependencies |
| `scan_runner.py` | - | - | runs every registered scanner |

The tools are installed in the scan-worker image
([Dockerfile.scan-worker](../../Dockerfile.scan-worker)), not in the API
image. Python packages for that image are in
[requirements.txt](requirements.txt).

## Adapter contract

Each adapter exposes one function, `run_<name>_scan(target) -> list[dict]`.
Every dict in the list has exactly these fields:

| Field | Type | Meaning |
|---|---|---|
| `tool` | str | `"nmap"`, `"wapiti"`, `"nuclei"` or `"osv-scanner"` |
| `target` | str | the host, URL or file that was scanned (nuclei uses the exact matched URL) |
| `finding_type` | str | `"open_port"`, `"web_vulnerability"` or `"vulnerable_dependency"` |
| `severity` | str | `"low"`, `"medium"`, `"high"` or `"critical"` |
| `title` | str | short description |
| `description` | str | longer description |
| `evidence` | str | the specific proof (see below) |
| `raw_output_ref` | str or null | path to the tool's saved raw output. Always `null` for now |
| `cve_id` | str or null | CVE or advisory ID if the tool reports one |
| `found_at` | str | ISO 8601 UTC time the finding was parsed, e.g. `2026-11-16T21:16:12Z` |

What `evidence` contains for each tool:

| Tool | Evidence |
|---|---|
| nmap | `state=open reason=syn-ack` |
| wapiti | `path=/vulnerabilities/sqli/ parameter=id` |
| nuclei | the matched URL (`matched-at`) |
| osv-scanner | `vuln_id=GHSA-... summary=...` |

`raw_output_ref` is `null` because the raw output is read and then
thrown away. Filling it in means the scan worker saves the raw file
first (for example `/tmp/scan-<id>/nmap.xml`). That's a worker change,
not an adapter change.

Severity rules:

- **nmap:** every open port is `medium`.
- **wapiti:** set by category, using the `CRITICAL_`, `HIGH_` and
  `MEDIUM_CATEGORIES` sets in the file. Anything else is `low`.
- **nuclei:** the template's own severity. `info` and `unknown` become `low`.
- **osv-scanner:** every vulnerable dependency is `high`.

## Running all scanners

```python
from scanners.scan_runner import run_all_scans

results = run_all_scans(host="10.0.0.5",
                        url="http://10.0.0.5/",
                        code_dir="/srv/app")
# {"nmap": [...], "wapiti": [...], "nuclei": [...], "osv": [...]}
```

`SCANNERS` in `scan_runner.py` maps each tool name to its function and
to the kind of target it takes (`"host"`, `"url"` or `"dir"`). If a
scanner raises, the runner logs the error and stores `[]` for that tool.
The other tools still run.

## Adding a tool

1. Create `<name>_scanner.py` with a `run_<name>_scan(target)` function
   that returns dicts with the fields above.
2. In `scan_runner.py`, import the module and add one line to `SCANNERS`:
   `"<name>": (<name>_scanner.run_<name>_scan, "host" | "url" | "dir")`.
3. Install the tool in `Dockerfile.scan-worker`.

No other file needs editing.

## Known gaps

- **A failed scan looks like a clean scan.** On a timeout, a non-zero
  exit code or bad output, each adapter prints a message and returns the
  findings it has so far, usually `[]`. The adapters don't raise, so the
  runner's error handling never runs. The plan is for adapters to raise
  on failure, so the worker can record `status = 'failed'` instead of a
  scan with zero findings.
- **Wapiti always uses the DVWA lab settings.** It loads
  `dvwa_cookies.json` and skips the DVWA logout, setup, security and
  CSRF pages on every run. That suits the test lab, not a real client
  site. The cookies and exclusions need to become optional.
  If Wapiti crawls only one page, the session cookie has probably
  expired. Log in to DVWA again and replace `dvwa_cookies.json`.
- **Targets aren't checked.** The adapters scan whatever they're given.
  Checking against an approved-targets list belongs in the scan API and
  worker, which don't exist yet.
- **Nothing calls the scanners yet.** No API route or worker runs
  them, and findings aren't saved to the `findings` table.

## Website scans from the dashboard

Org admins add a website on the Scans page and prove they own it by
uploading `/.well-known/trojan-verify.txt` with the code TROJAN shows.
"Scan now" creates a row in `scans` and starts the `Website scan` GitHub
workflow, which runs `python -m scanners.worker <scan_id>`: Nuclei
(`-as`, rate limited) on the website and Nmap on its hostname. The worker
reads the target from `/v1/worker/scans/<id>/start` and sends findings to
`/v1/worker/scans/<id>/finish`, both protected by `SCAN_WORKER_SECRET`.
The repository is public, so the worker masks the target in the logs and
prints only counts.

Setup:

- Vercel: `GITHUB_DISPATCH_TOKEN` (fine-grained token for this repository
  with Actions read and write) and `SCAN_WORKER_SECRET`.
- GitHub repository secret: `SCAN_WORKER_SECRET` (same value).

Limits: one running scan per website, 10 scans per organization per day,
and scans not finished after 45 minutes are marked failed.
