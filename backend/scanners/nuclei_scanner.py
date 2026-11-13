"""
Nuclei scanner:
Runs nuclei against a target URL and parses its JSONL output into
unified findings. Nuclei emits one JSON object per line, one per finding.
"""

import json
import subprocess


def run_nuclei_scan(target_url: str) -> list:
    findings = []

    command = [
        "nuclei",
        "-u", target_url,
        "-jsonl",
        "-silent"
    ]

    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=300)
        if result.returncode != 0:
            print(f"nuclei exited {result.returncode}: {result.stderr[-500:]}")
            return findings


        for line in result.stdout.strip().split("\n"):
            if not line:
                continue
            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                continue

            info = data.get("info", {})
            severity_raw = info.get("severity", "info").lower()
            severity_map = {
                "critical": "critical",
                "high": "high",
                "medium": "medium",
                "low": "low",
                "info": "low",
                "unknown": "low",
            }

            severity = severity_map.get(severity_raw, "low")

            cve_ids = info.get("classification", {}).get("cve-id") or []
            cve_id = cve_ids[0] if cve_ids else None

            findings.append({
                "tool": "nuclei",
                "target": data.get("matched-at", target_url),
                "finding_type": "web_vulnerability",
                "severity": severity,
                "title": info.get("name", "Unknown Nuclei finding"),
                "description": info.get("description", "No description provided."),
                "cve_id": cve_id,
            })

    except subprocess.TimeoutExpired:
        print(f"nuclei scan for {target_url} timed out!!")
    except Exception as e:
        print(f"nuclei scan failed: {e}")


    return findings