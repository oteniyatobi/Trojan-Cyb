"""
OSV Scanner:
Runs OSV-Scanner against a directory and parses its JSON output into
unified findings. OSV-Scanner walks the directory for dependency files
and checks each package against its vulnabilities database.
"""


import json
import subprocess


def run_osv_scan(directory: str) -> list:
    findings = []

    command = [
        "osv-scanner",
        "--format",
        "json",
        "-r",
        directory
    ]

    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=300)
        #fro osv-scanner, exit code of 1 is a success when vulnerabilities are found,
        #0 when clean, and >1 on error
        if result.returncode > 1:
            print(f"osv-scanner exited {result.returncode}: {result.stderr[-500:]}")
            return findings

        try:
            data = json.loads(result.stdout) if result.stdout.strip() else {}
        except json.JSONDecodeError:
            print(f"osv-scanner output was not JSON: {result.stdout[-500:]}")
            return findings

        for result_item in data.get("results", []):
            source = result_item.get("source", {}).get("path", directory)
            for package in result_item.get("packages", []):
                pkg = package.get("package", {})
                pkg_name = pkg.get("name", "unknown")
                pkg_version = pkg.get("version", "unknown")
                for vuln in package.get("vulnerabilities", []):
                    findings.append({
                        "tool": "osv-scanner",
                        "target": source,
                        "finding_type": "vulnerability_dependency",
                        "severity": "high",
                        "title": f"Vulnerable dependency: {pkg_name} {pkg_version}",
                        "description": vuln.get("summary", vuln.get("details", "known vulnerability")),
                        "cve_id": vuln.get("id"),
                    })
    except subprocess.TimeoutExpired:
        print(f"osv-scanner scan for {directory} timed out")
    except Exception as e:
        print(f"osv-scanner scan failed: {e}")

    return findings