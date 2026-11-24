"""Wapiti: passive website checks that look but don't attack.

Runs Wapiti through scanners.wapiti_safe, which stops the crawler from
submitting forms, with only modules that read responses:

- passive: http_headers (X-Frame-Options, X-Content-Type-Options, HSTS),
  cookieflags (HttpOnly, Secure), csp, https_redirect,
  information_disclosure, stacktrace_disclosure, unsecure_password,
  inconsistent_redirection
- active but read-only: ssl (TLS configuration), wapp (technologies and
  known-vulnerable versions)

The attack modules (sql, xss, permanentxss, upload, exec, file, ssrf...)
send payloads that can write junk into a real customer's database, and
`methods` sends PUT and DELETE, so none of them run. Names checked
against wapiti3 3.3.2: passive modules aren't shown by --list-modules but
are enabled with -m by name.

Severity comes from Wapiti's own level (0 info .. 4 critical).
"""
import json
import os
import re
import sys
import tempfile

from scanners.common import (
    BACKEND_DIR, ScanResult, ScannerError, collapse_info, finding, run_tool, site_of,
)

TOOL = "wapiti"
MODULES = ",".join((
    "http_headers", "cookieflags", "csp", "https_redirect", "information_disclosure",
    "stacktrace_disclosure", "unsecure_password", "inconsistent_redirection",
    "ssl", "wapp",
))
LEVELS = {0: "info", 1: "low", 2: "medium", 3: "high", 4: "critical"}
SOFTWARE_PATTERN = re.compile(r"^(?P<product>.+?)\s+(?P<cve>CVE-\d{4}-\d{4,})", re.IGNORECASE)


def _severity(issue: dict, category: str) -> str:
    if category.startswith("Fingerprint"):
        return "info"
    return LEVELS.get(issue.get("level"), "low")


def _vulnerable_software(asset: str, issues: list) -> list:
    """One finding per outdated product instead of one per CVE."""
    by_product = {}
    for issue in issues:
        # Each entry reads "<product> CVE-YYYY-NNNN: <description>"; the
        # description can mention other CVEs, so only the leading ID counts.
        match = SOFTWARE_PATTERN.match(issue.get("info") or "")
        product = match.group("product") if match else "software"
        cve = match.group("cve").upper() if match else None
        by_product.setdefault(product, []).append((issue, cve))
    found = []
    for product, entries in by_product.items():
        product_issues = [issue for issue, _cve in entries]
        cves = sorted({cve for _issue, cve in entries if cve})
        level = max(i.get("level", 1) for i in product_issues)
        found.append(finding(
            TOOL, asset, "vulnerable_software", LEVELS.get(level, "high"),
            f"Outdated software: {product}",
            f"The version of {product} this website reports has {len(cves) or len(product_issues)} known "
            "vulnerabilities. Update it to a supported version.",
            "ids=" + ",".join(cves[:30]) + (" ..." if len(cves) > 30 else ""),
            cves[-1] if cves else None,
        ))
    return found


def parse_wapiti_report(data: dict, target_url: str) -> list:
    asset = site_of(target_url)
    findings = []
    for category, issues in (data.get("vulnerabilities") or {}).items():
        if not issues:
            continue
        if category == "Vulnerable software":
            findings.extend(_vulnerable_software(asset, issues))
            continue
        for issue in issues:
            evidence = f"{issue.get('method', 'GET')} {issue.get('path', '/')}"
            if issue.get("parameter"):
                evidence += f" parameter={issue['parameter']}"
            title = category
            if category.startswith("Fingerprint"):
                try:
                    title = f"{category}: {json.loads(issue['info'])['name']}"
                except (KeyError, TypeError, ValueError):
                    pass
            findings.append(finding(
                TOOL, asset, "web_misconfiguration", _severity(issue, category), title,
                issue.get("info"), evidence,
            ))
    return collapse_info(findings, TOOL, "Website technologies detected by Wapiti")


def run_wapiti_scan(target_url: str, cookie_file=None, exclusions=(), max_scan_time=300, timeout=420) -> ScanResult:
    """Scan a website. cookie_file and exclusions are for lab use only (e.g. DVWA)."""
    handle, report_path = tempfile.mkstemp(suffix=".json")
    os.close(handle)
    command = [
        sys.executable, "-m", "scanners.wapiti_safe",
        "-u", target_url, "-m", MODULES,
        "--scope", "domain", "-d", "3", "--max-links-per-page", "50",
        "--max-scan-time", str(max_scan_time), "--max-attack-time", "120",
        "--flush-session", "-f", "json", "-o", report_path,
    ]
    if cookie_file:
        command += ["-c", cookie_file]
    for url in exclusions:
        command += ["-x", url]
    try:
        run_tool(TOOL, command, timeout, cwd=BACKEND_DIR)
        try:
            with open(report_path) as report_file:
                raw = report_file.read()
            data = json.loads(raw)
        except (OSError, ValueError):
            raise ScannerError(TOOL, "did not write a readable report")
    finally:
        if os.path.exists(report_path):
            os.remove(report_path)
    if not (data.get("infos") or {}).get("crawled_pages_nbr"):
        raise ScannerError(TOOL, "could not load any page of the website")
    return ScanResult(TOOL, parse_wapiti_report(data, target_url), raw, "wapiti.json")
