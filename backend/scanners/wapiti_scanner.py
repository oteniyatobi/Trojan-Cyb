import subprocess
import json
import tempfile
import os
from urllib.parse import urlparse


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

COOKIE_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "dvwa_cookies.json")

# Wapiti's default attack modules. "-m all" also enables buster, nikto,
# brute_login_form and timesql, which brute-force thousands of paths and
# never finished within the timeout, so no report was ever produced.
MODULES = "xss,exec,redirect,ssl,file,upload,sql,ssrf,permanentxss"

# Pages that must never be requested during an authenticated scan:
# logout.php destroys the session, setup.php resets the database,
# security.php changes the security level, and csrf/ changes the
# admin password (Wapiti fills it with its default value "Letm3in_").
DVWA_EXCLUSIONS = ("/logout.php", "/setup.php", "/security.php", "/vulnerabilities/csrf/*")


def run_wapiti_scan(target_url: str, exclusions=DVWA_EXCLUSIONS) -> list:
    findings = []

    #wapiti writes to temporary file
    temp_report = tempfile.NamedTemporaryFile(delete=False, suffix=".json")
    temp_report_path = temp_report.name
    temp_report.close()


    command = [
        "wapiti",
        "-u", target_url,
        "-f", "json",
        "-o", temp_report_path,
        "-m", MODULES,
        "--flush-session",
        "-c", COOKIE_FILE
    ]
    if exclusions:
        parsed = urlparse(target_url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        for path in exclusions:
            command.extend(["-x", origin + path])

    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=1200)
        if result.returncode != 0:
            print(f"Wapiti exited {result.returncode}: {result.stderr[-500:]}")
            return findings

        if os.path.exists(temp_report_path) and os.path.getsize(temp_report_path) > 0:
            with open(temp_report_path, 'r') as report_file:
                data = json.load(report_file)

                info = data.get("infos", {})
                pages = info.get("crawled_pages_nbr", 0)
                #auth = info.get("auth")
                if pages <= 1:
                    print(f"WARNING: Wapiti crawled only {pages} page(s). The session is "
                        f"likely expired or the target redirected to a login page. "
                        f"Regenerate dvwa_cookies.json and re-run.")
                    return findings

                vulnerabilities = data.get("vulnerabilities", {})
                for category, issues in vulnerabilities.items():
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

