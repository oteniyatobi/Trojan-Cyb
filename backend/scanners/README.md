# Scanner plug-in contract

Every scanner is a Python module in `backend/scanners/` that exposes two
things:

- `NAME` — a short string used as the `tool` field in findings.
- `run(target) -> list[Finding]` — scan the target and return findings.

`Finding` is a plain dict with exactly these fields:

| field | type | meaning |
|---|---|---|
| `tool` | str | `NAME`, e.g. `"nmap"` |
| `target` | str | the host, URL, or folder scanned |
| `finding_type` | str | e.g. `"open_port"`, `"web_vulnerability"`, `"vulnerable_dependency"` |
| `severity` | str | `"low"`, `"medium"`, `"high"`, `"critical"` |
| `title` | str | short description |
| `description` | str | longer description |
| `evidence` | str | the specific artifact: port line, matched response, parameter+payload, CVE summary |
| `raw_output_ref` | str \| null | path to the tool's saved raw output, e.g. `/tmp/scan-<id>/nmap.xml` |
| `cve_id` | str \| null | CVE identifier if the tool reports one |
| `found_at` | str | ISO 8601 UTC, when the scanner detected it |

## Adding a tool

1. Create `backend/scanners/<name>_scanner.py` exposing `NAME` and `run`.
2. Import it in `scan_runner.py` and add one line to `SCANNERS`.
3. Add the tool to the `tools` list in the scan API's request schema (when the scan API exists).

No other file needs editing. The registry in `scan_runner.py` maps tool
names to functions; the worker iterates it; the API passes the list to
the worker; the dashboard groups findings by `tool`.

## Failure vs no findings

A scan that raises is a **failed scan**. A scan that returns `[]` is a
**clean scan**. The two are different:

- Failed: the tool did not run to completion, or the target was
  unreachable, or the tool returned non-zero exit with no report. The
  worker records `status = 'failed'` on the scan and does not mark the
  findings as empty.
- Clean: the tool ran and found nothing. The worker records
  `status = 'completed'` with zero findings.

Returning `[]` on failure is the bug the reviewer flagged. Every adapter
here raises on failure instead of swallowing it.

## Implementations

- `nmap_scanner.py` — open TCP ports via Nmap XML output.
- `wapiti_scanner.py` — web application vulnerabilities via Wapiti JSON output.
- `nuclei_scanner.py` — CVE and misconfiguration templates via Nuclei JSONL output.
- `osv_scanner.py` — vulnerable dependencies via OSV-Scanner JSON output.

Each reads the tool's documented output format; none of them shell out
to `jq`, `xml2json`, or any other post-processor.
