import subprocess
import json
import tempfile
import os


CRITICAL_CATEGORIES = {
    "Command execution",
    "SQL Injection",
    "Blind SQL Injection",
    "Unrestricted File Upload",
    "Log4Shell",
    "Spring4Shell",
    "Path Traversal",
    "Server Side Request Forgery",
}

HIGH_CATEGORIES = {
    "Reflected Cross Site Scripting",
    "Stored Cross Site Scripting",
    "Cross Site Request Forgery",
    "LDAP Injection",
    "CRLF Injection",
    "Htaccess Bypass",
    "Open Redirect",
    "Subdomain takeover",
    "NS takeover",
}

MEDIUM_CATEGORIES = {
    "Backup file",
    "Potentially dangerous file",
    "Weak credentials",
    "Cleartext Submission of Password",
    "Information Disclosure - Full Path",
    "Stack Trace Disclosure",
    "HTML Injection",
    "Stored HTML Injection",
    "MIME Type Confusion",
    "Vulnerable software",
    "CVE-2024-55591",
    "Internal Server Error",
}

def run_wapiti_scan(target_url: str) -> list:
    findings = []

    #wapiti writes to temporary file
    temp_report = tempfile.NamedTemporaryFile(delete=False, suffix=".json")
    temp_report_path = temp_report.name
    temp_report.close()

    COOKIE_FILE = "/tmp/dvwa_cookies.json"

    command = [
        "wapiti",
        "-u", target_url,
        "-f", "json",
        "-o", temp_report_path,
        "-m", "all",
        "--flush-session",
        "-c", COOKIE_FILE
    ]

    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=300)
        if result.returncode != 0:
            print(f"Wapiti exited {result.returncode}: {result.stderr[-500:]}")
            return findings

        if os.path.exists(temp_report_path) and os.path.getsize(temp_report_path) > 0:
            with open(temp_report_path, 'r') as report_file:
                data = json.load(report_file)

                vulnerabirities = data.get("vulnerabilities", {})
                for category, issues in vulnerabirities.items():
                    #wapiti categories
                    if category in CRITICAL_CATEGORIES:
                        severity = "critical"
                    elif category in HIGH_CATEGORIES:
                        severity = "high"
                    elif category in MEDIUM_CATEGORIES:
                        severity = "medium"
                    else:
                        severity = "low"
                        
                    for issue in issues:
                        findings.append({
                            "tool": "wapiti",
                            "target": target_url,
                            "finding_type": "web_vulnerability",
                            "severity": severity,
                            "title": f"{category}",
                            "description": issue.get("info", "No description provided."),
                            "cve_id": None
                        })

    except subprocess.TimeoutExpired:
        print(f"Wapiti scan for {target_url} timed out!!")
    except Exception as e:
        print(f"Wapiti scan failed: {e}")
    finally:
        if os.path.exists(temp_report_path):
            os.remove(temp_report_path)


    return findings

