"""Run one website scan requested from TROJAN and send the results back.

Usage: python -m scanners.worker <scan_id>
Needs TROJAN_API_URL and SCAN_WORKER_SECRET. The repository is public, so
the log shows only tool names and counts: never the target, a failure
reason (it can name the website) or the raw output.

Time budget: the GitHub job stops at 40 minutes (scan.yml) and installing
the tools takes about 4, so the tools get at most 10 + 7 + 7 = 24 minutes,
leaving room for a slow site. The backend marks a scan failed after 45.
"""
import base64
import contextlib
import gzip
import json
import os
import sys
import urllib.request

from scanners.common import MAX_RAW_FILE_CHARS, ScannerError
from scanners.nmap_scanner import run_nmap_scan
from scanners.nuclei_scanner import run_nuclei_scan
from scanners.wapiti_scanner import run_wapiti_scan

TOOLS = (
    ("Nuclei", lambda target: run_nuclei_scan(target["url"], timeout=600)),
    ("Wapiti", lambda target: run_wapiti_scan(target["url"], max_scan_time=300, timeout=420)),
    ("Nmap", lambda target: run_nmap_scan(target["hostname"], timeout=420)),
)
# The backend runs on Vercel, which rejects request bodies over 4.5 MB, and
# rejects any one raw file over MAX_RAW_FILE_CHARS (2 MB). A file over either
# limit is left out rather than losing the whole scan.
MAX_RAW_BYTES = 3_000_000


def call(path, body=None):
    request = urllib.request.Request(
        f"{os.environ['TROJAN_API_URL'].rstrip('/')}/v1/worker/scans/{path}",
        data=json.dumps(body or {}).encode(),
        headers={
            "Authorization": f"Bearer {os.environ['SCAN_WORKER_SECRET']}",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=60) as response:
        return json.load(response)


def pack_raw_outputs(results):
    """Gzip and base64 each tool's raw output, within the size limits.

    Returns (packed, skipped): tools whose output is too large are named in
    skipped, and their findings are still sent.
    """
    packed, used, skipped = [], 0, []
    for result in results:
        if not result.raw_output:
            continue
        content = base64.b64encode(gzip.compress(result.raw_output.encode())).decode()
        if len(content) > MAX_RAW_FILE_CHARS or used + len(content) > MAX_RAW_BYTES:
            skipped.append(result.tool)
            continue
        used += len(content)
        packed.append({"tool": result.tool, "name": result.raw_name, "content": content})
    return packed, skipped


def run_tools(target, tools=None):
    """Run each tool. Returns (results, failures) where failures maps name -> reason."""
    tools = TOOLS if tools is None else tools  # read at call time, not import time
    results, failures = [], {}
    for name, scan in tools:
        try:
            result = scan(target)
        except ScannerError as error:
            failures[name] = error.reason
            print(f"{name}: did not finish")
            continue
        except Exception as error:
            failures[name] = f"crashed ({type(error).__name__})"
            print(f"{name}: crashed")
            continue
        results.append(result)
        print(f"{name}: {len(result.findings)} findings")
    return results, failures


def summarize(results, failures, tool_count):
    """(error, warning) for the scan record."""
    if failures and len(failures) == tool_count:
        return "No scanner finished. " + " ".join(f"{n}: {r}." for n, r in failures.items()), None
    if failures:
        return None, " ".join(f"{n} did not finish: {r}." for n, r in failures.items())
    return None, None


def main(scan_id):
    target = call(f"{scan_id}/start")
    print(f"::add-mask::{target['url']}")
    print(f"::add-mask::{target['hostname']}")

    results, failures = run_tools(target)
    findings = [item for result in results for item in result.findings]
    raw_outputs, skipped = pack_raw_outputs(results)
    error, warning = summarize(results, failures, len(TOOLS))
    if skipped:
        note = f"Raw output not kept for {', '.join(skipped)} (too large)."
        warning = f"{warning} {note}" if warning else note

    body = {"findings": findings, "error": error, "warning": warning, "raw_outputs": raw_outputs}
    result = call(f"{scan_id}/finish", body)
    print(f"stored {result['stored']} findings")


if __name__ == "__main__":
    scan_id = sys.argv[1]
    try:
        main(scan_id)
    except Exception as exc:
        print(f"worker error: {type(exc).__name__}")
        with contextlib.suppress(Exception):
            call(f"{scan_id}/finish", {"error": "The scan worker crashed."})
        sys.exit(1)
