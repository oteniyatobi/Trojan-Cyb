"""Shared pieces for the scanner adapters.

Every adapter returns a ScanResult or raises ScannerError. A scan that
raises did not finish; a ScanResult with no findings is a clean scan.
The two must never look the same.
"""
import os
import subprocess
from dataclasses import dataclass
from datetime import datetime, timezone
from urllib.parse import urlsplit

SEVERITIES = ("low", "medium", "high", "critical")
SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
# Largest base64 raw output file the backend accepts from the worker, so the
# worker skips a file the backend would reject. Must equal
# scan_store.MAX_RAW_CONTENT (test_scanners checks it).
MAX_RAW_FILE_CHARS = 2_000_000
BACKEND_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class ScannerError(Exception):
    """The tool did not run to completion. Never a clean result.

    `reason` is shown to the business that owns the website. It can name
    their website, so the worker doesn't print it in the public GitHub log.
    """

    def __init__(self, tool: str, reason: str):
        super().__init__(f"{tool}: {reason}")
        self.tool = tool
        self.reason = reason


@dataclass
class ScanResult:
    tool: str
    findings: list
    raw_output: str = ""
    raw_name: str = ""


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def site_of(url: str) -> str:
    """scheme://host[:port] of a URL, so findings on one website share an asset."""
    parts = urlsplit(url or "")
    if not parts.scheme or not parts.hostname:
        return url
    site = f"{parts.scheme}://{parts.hostname.lower()}"
    if parts.port:
        site += f":{parts.port}"
    return site


def run_tool(tool: str, command: list, timeout: int, ok_codes=(0,), cwd=None):
    """Run a scanner binary; raise ScannerError unless it exits with an ok code."""
    try:
        result = subprocess.run(
            command, capture_output=True, text=True, timeout=timeout, cwd=cwd,
        )
    except FileNotFoundError:
        raise ScannerError(tool, f"{command[0]} is not installed")
    except subprocess.TimeoutExpired:
        raise ScannerError(tool, f"did not finish within {timeout} seconds")
    if result.returncode not in ok_codes:
        detail = (result.stderr or "").strip()[-300:]
        raise ScannerError(tool, f"exited with code {result.returncode}" + (f": {detail}" if detail else ""))
    return result


def finding(tool, target, finding_type, severity, title, description, evidence, cve_id=None) -> dict:
    """One finding in the shape /v1/findings accepts. CVE IDs are upper case."""
    return {
        "tool": tool,
        "target": target,
        "finding_type": finding_type,
        "severity": severity,
        "title": str(title)[:500],
        "description": str(description or "No description provided.")[:2000],
        "evidence": str(evidence or "")[:2000],
        "raw_output_ref": None,
        "cve_id": cve_id.upper() if isinstance(cve_id, str) and cve_id else None,
        "found_at": now_iso(),
    }


def collapse_info(findings: list, tool: str, title: str) -> list:
    """Replace information-only findings with one summary per asset.

    Information (technologies detected, web ports open) isn't a
    vulnerability, but is still useful context, so it is kept as one
    low-severity "information" finding per website instead of many.
    """
    kept, info_by_asset = [], {}
    for item in findings:
        if item["severity"] == "info":
            info_by_asset.setdefault(item["target"], []).append(item)
        else:
            kept.append(item)
    for asset, items in info_by_asset.items():
        names = sorted({item["title"] for item in items})
        kept.append(finding(
            tool, asset, "information", "low", title,
            "Not a vulnerability. Found: " + "; ".join(names[:30]),
            "\n".join(sorted({item["evidence"] for item in items if item["evidence"]})[:30]),
        ))
    return kept
