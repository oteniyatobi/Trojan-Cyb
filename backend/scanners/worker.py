"""Run one website scan requested from TROJAN and send the results back.

Usage: python -m scanners.worker <scan_id>
Needs TROJAN_API_URL and SCAN_WORKER_SECRET. TROJAN_FALLBACK_API_URL is
tried too: when the scanned website shares a host with the API, its attack
protection can block the runner, so results go to the other host first.
The repository is public, so nothing about the target is printed beyond
what GitHub masks.
"""
import contextlib
import io
import json
import os
import sys
import urllib.request
from urllib.parse import urlsplit

from scanners.nmap_scanner import run_nmap_scan
from scanners.nuclei_scanner import run_nuclei_scan

PROBLEM_WORDS = ("timed out", "failed", "exited")


def api_urls(avoid_host=None):
    urls = [os.environ["TROJAN_API_URL"], os.getenv("TROJAN_FALLBACK_API_URL", "")]
    urls = [url.rstrip("/") for url in urls if url]
    return sorted(urls, key=lambda url: urlsplit(url).hostname == avoid_host)


def call(path, body=None, avoid_host=None):
    error = None
    for base in api_urls(avoid_host):
        try:
            return post(base, path, body)
        except Exception as exc:
            error = exc
    raise error


def post(base, path, body):
    request = urllib.request.Request(
        f"{base}/v1/worker/scans/{path}",
        data=json.dumps(body or {}).encode(),
        headers={
            "Authorization": f"Bearer {os.environ['SCAN_WORKER_SECRET']}",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=60) as response:
        return json.load(response)


def run_tool(name, scan):
    output = io.StringIO()
    with contextlib.redirect_stdout(output):
        findings = scan()
    problem = any(word in output.getvalue() for word in PROBLEM_WORDS)
    print(f"{name}: {len(findings)} findings{' (did not finish)' if problem else ''}")
    return findings, problem


def main(scan_id):
    target = call(f"{scan_id}/start")
    print(f"::add-mask::{target['url']}")
    print(f"::add-mask::{target['hostname']}")

    findings, failed = [], []
    tools = {
        "Nuclei": lambda: run_nuclei_scan(target["url"], ("-as", "-rl", "50"), timeout=900),
        "Nmap": lambda: run_nmap_scan(target["hostname"]),
    }
    for name, scan in tools.items():
        try:
            tool_findings, problem = run_tool(name, scan)
        except Exception:
            tool_findings, problem = [], True
        findings.extend(tool_findings)
        if problem:
            failed.append(name)

    error = "No scanner finished." if len(failed) == len(tools) and not findings else None
    warning = f"{', '.join(failed)} did not finish." if failed and not error else None
    result = call(
        f"{scan_id}/finish",
        {"findings": findings, "error": error, "warning": warning},
        avoid_host=target["hostname"],
    )
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
