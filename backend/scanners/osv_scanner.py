"""OSV-Scanner: known-vulnerable dependencies in a business's code.

Intended use: scan an uploaded lock file (requirements.txt,
package-lock.json, ...) or a checked-out code repository. It is not run
against websites. Nothing calls it from the dashboard yet.

- OSV lists the same vulnerability under several IDs (PYSEC-... and
  GHSA-...). Its `groups` say which IDs are the same, so there is one
  finding per group, not per ID.
- The title names the vulnerability (the CVE where there is one).
- Severity comes from OSV's own data: the group's CVSS score
  (max_severity), else the advisory's rating (CRITICAL/HIGH/MODERATE/LOW).
"""
import json
import os

from scanners.common import ScanResult, ScannerError, finding, run_tool

TOOL = "osv-scanner"
ADVISORY_SEVERITY = {"CRITICAL": "critical", "HIGH": "high", "MODERATE": "medium", "MEDIUM": "medium", "LOW": "low"}
NO_PACKAGES_EXIT = 128


def _cvss_severity(score):
    try:
        score = float(score)
    except (TypeError, ValueError):
        return None
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    return "low" if score > 0 else None


def _fixed_version(vulns: list, package_name: str):
    for vuln in vulns:
        for affected in vuln.get("affected") or []:
            if (affected.get("package") or {}).get("name") != package_name:
                continue
            for version_range in affected.get("ranges") or []:
                for event in version_range.get("events") or []:
                    if event.get("fixed"):
                        return event["fixed"]
    return None


def _group_finding(source, name, version, group, vulns):
    ids = set(group.get("ids") or [])
    aliases = set(ids)
    for vuln in vulns:
        aliases.update(vuln.get("aliases") or [])
    cve = next((alias.upper() for alias in sorted(aliases) if alias.upper().startswith("CVE-")), None)
    shown_id = cve or next((i for i in sorted(ids) if i.startswith("GHSA-")), None) or sorted(ids)[0]

    severity = _cvss_severity(group.get("max_severity"))
    if not severity:
        ratings = [ADVISORY_SEVERITY.get(str((v.get("database_specific") or {}).get("severity")).upper())
                   for v in vulns]
        severity = next((rating for rating in ratings if rating), "medium")

    summary = next((v["summary"] for v in vulns if v.get("summary")), "Known vulnerability")
    fixed = _fixed_version(vulns, name)
    advice = f" Upgrade {name} to {fixed} or later." if fixed else f" Upgrade {name} to a fixed version."
    return finding(
        TOOL, source, "vulnerable_dependency", severity, f"{shown_id}: {name} {version}",
        summary + advice, "ids=" + ",".join(sorted(ids)), cve,
    )


def parse_osv_json(data: dict, root: str = "") -> list:
    findings = []
    for result in data.get("results") or []:
        source = (result.get("source") or {}).get("path") or root
        if root and source.startswith(root.rstrip("/") + "/"):
            source = os.path.relpath(source, root)
        for package in result.get("packages") or []:
            info = package.get("package") or {}
            name, version = info.get("name", "unknown"), info.get("version", "unknown")
            vulns = package.get("vulnerabilities") or []
            by_id = {vuln.get("id"): vuln for vuln in vulns}
            groups = package.get("groups") or [{"ids": [vuln.get("id")]} for vuln in vulns]
            for group in groups:
                group_vulns = [by_id[i] for i in group.get("ids") or [] if i in by_id]
                if group_vulns:
                    findings.append(_group_finding(source, name, version, group, group_vulns))
    return findings


def run_osv_scan(path: str, timeout: int = 300) -> ScanResult:
    """Scan a lock file, or a folder recursively."""
    if os.path.isdir(path):
        command = ["osv-scanner", "scan", "source", "--format", "json", "-r", path]
    else:
        command = ["osv-scanner", "scan", "source", "--format", "json", "-L", path]
    # 0 = no vulnerabilities, 1 = vulnerabilities found, 128 = no packages found.
    result = run_tool(TOOL, command, timeout, ok_codes=(0, 1, NO_PACKAGES_EXIT))
    if result.returncode == NO_PACKAGES_EXIT:
        raise ScannerError(TOOL, "no dependency files were found")
    try:
        data = json.loads(result.stdout) if result.stdout.strip() else {}
    except json.JSONDecodeError:
        raise ScannerError(TOOL, "output was not valid JSON")
    root = path if os.path.isdir(path) else os.path.dirname(path)
    return ScanResult(TOOL, parse_osv_json(data, root), result.stdout, "osv.json")
