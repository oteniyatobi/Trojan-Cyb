"""Nuclei: known vulnerabilities and misconfigurations on a website.

Runs Nuclei's automatic scan (`-as`: picks templates for the detected
technologies), rate limited, and parses its JSONL output (one JSON object
per line, one per match).

- The asset is the website (scheme://host[:port]), not each matched URL,
  so one problem on one site is one finding.
- Information-only results (technology detection, missing headers) are
  collapsed into one "information" finding per website.
- CVE IDs are written in capitals (Nuclei emits "cve-2021-41773").
- Templates tagged intrusive, dos or fuzz are excluded.
"""
import json

from scanners.common import ScanResult, ScannerError, collapse_info, finding, run_tool, site_of

TOOL = "nuclei"
SEVERITY_MAP = {"critical": "critical", "high": "high", "medium": "medium", "low": "low"}
DEFAULT_ARGS = ("-as", "-rl", "50", "-etags", "intrusive,dos,fuzz")


def _evidence(data: dict) -> str:
    parts = [data.get("matched-at") or data.get("host") or ""]
    if data.get("matcher-name"):
        parts.append(f"matcher={data['matcher-name']}")
    extracted = data.get("extracted-results") or []
    if extracted:
        parts.append("extracted=" + ", ".join(str(value) for value in extracted[:5]))
    return " ".join(part for part in parts if part)


def _asset(data: dict, target_url: str) -> str:
    matched = data.get("matched-at") or data.get("host") or target_url
    if "://" not in matched:
        # Network templates report host:port; keep the website's scheme.
        return site_of(target_url)
    return site_of(matched)


def parse_nuclei_jsonl(text: str, target_url: str) -> list:
    findings = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            continue
        info = data.get("info") or {}
        severity = SEVERITY_MAP.get(str(info.get("severity", "info")).lower(), "info")
        cve_ids = (info.get("classification") or {}).get("cve-id") or []
        name = info.get("name") or data.get("template-id") or "Nuclei finding"
        if severity == "info" and data.get("matcher-name"):
            name = f"{name}: {data['matcher-name']}"
        findings.append(finding(
            TOOL, _asset(data, target_url), "web_vulnerability", severity, name,
            info.get("description"), _evidence(data), cve_ids[0] if cve_ids else None,
        ))
    return collapse_info(findings, TOOL, "Website information found by Nuclei")


def run_nuclei_scan(target_url: str, extra_args=DEFAULT_ARGS, timeout: int = 600) -> ScanResult:
    command = ["nuclei", "-u", target_url, "-jsonl", "-silent", "-no-color", *extra_args]
    result = run_tool(TOOL, command, timeout)
    if not result.stdout.strip() and "[FTL]" in (result.stderr or ""):
        raise ScannerError(TOOL, (result.stderr or "").strip()[-300:])
    return ScanResult(TOOL, parse_nuclei_jsonl(result.stdout, target_url), result.stdout, "nuclei.jsonl")
