"""Nmap: open ports and services on a host, rated by how risky they are.

Runs `nmap -sV -Pn -F --script "vuln and safe"` and parses the XML.

- Each open port is a finding rated by risk: web ports (80, 443) are
  information only; databases, remote desktop, file sharing, Telnet and
  FTP reachable from the internet are high.
- `-sV` identifies the service and version, so a database on an unusual
  port is still recognised.
- Only NSE scripts in both the "vuln" and "safe" categories run. Plain
  `--script vuln` includes checks that can crash or disrupt a server.
- `-Pn` scans even when the host ignores ping, which most internet hosts
  do; otherwise Nmap reports the host down and the scan looks clean.
"""
import re
import xml.etree.ElementTree as ET

from scanners.common import ScanResult, ScannerError, collapse_info, finding, run_tool

TOOL = "nmap"
SCRIPTS = "vuln and safe"

# Port -> what it is. Reachable from the internet, these are high risk.
HIGH_RISK_PORTS = {
    21: "FTP file transfer",
    23: "Telnet remote login",
    139: "NetBIOS file sharing",
    445: "SMB file sharing",
    1433: "Microsoft SQL Server database",
    1521: "Oracle database",
    2375: "Docker API (unencrypted)",
    3306: "MySQL database",
    3389: "Remote Desktop",
    5432: "PostgreSQL database",
    5900: "VNC remote desktop",
    5984: "CouchDB database",
    6379: "Redis database",
    9200: "Elasticsearch database",
    11211: "Memcached",
    27017: "MongoDB database",
}
# The same services found by -sV on a non-standard port.
HIGH_RISK_SERVICES = {
    "ftp": "FTP file transfer",
    "telnet": "Telnet remote login",
    "netbios-ssn": "NetBIOS file sharing",
    "microsoft-ds": "SMB file sharing",
    "ms-sql-s": "Microsoft SQL Server database",
    "oracle-tns": "Oracle database",
    "docker": "Docker API",
    "mysql": "MySQL database",
    "ms-wbt-server": "Remote Desktop",
    "postgresql": "PostgreSQL database",
    "vnc": "VNC remote desktop",
    "couchdb": "CouchDB database",
    "redis": "Redis database",
    "elasticsearch": "Elasticsearch database",
    "memcache": "Memcached",
    "mongodb": "MongoDB database",
    "mongod": "MongoDB database",
}
MEDIUM_RISK_PORTS = {
    22: "SSH remote login",
    25: "SMTP mail server",
    110: "POP3 mail (often unencrypted)",
    143: "IMAP mail (often unencrypted)",
    8080: "alternative web server or admin panel",
    8443: "alternative HTTPS server or admin panel",
}
INFO_PORTS = {80: "web server (HTTP)", 443: "web server (HTTPS)"}
CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)


def rate_port(port: int, service: str):
    """(severity, label) for an open port."""
    if port in HIGH_RISK_PORTS:
        return "high", HIGH_RISK_PORTS[port]
    if service in HIGH_RISK_SERVICES:
        return "high", HIGH_RISK_SERVICES[service]
    if port in INFO_PORTS:
        return "info", INFO_PORTS[port]
    if port in MEDIUM_RISK_PORTS:
        return "medium", MEDIUM_RISK_PORTS[port]
    return "low", f"'{service}' service"


def _service(port_el):
    service_el = port_el.find("service")
    if service_el is None:
        return "unknown", ""
    name = service_el.get("name") or "unknown"
    version = " ".join(v for v in (service_el.get("product"), service_el.get("version")) if v)
    return name, version


def _port_finding(target, port_el, port, protocol, state_el):
    service, version = _service(port_el)
    severity, label = rate_port(port, service)
    description = f"{label[0].upper()}{label[1:]} is reachable from the internet on port {port}/{protocol}"
    description += f" ({version})." if version else "."
    if severity == "high":
        description += " Services like this should not be open to the internet: limit access with a firewall or VPN."
    return finding(
        TOOL, target, "open_port", severity, f"Open port {port}/{protocol}: {label}", description,
        f"state={state_el.get('state')} reason={state_el.get('reason', 'unknown')} service={service}"
        + (f" version={version}" if version else ""),
    )


def _script_findings(target, scope, script_els):
    found = []
    for script in script_els:
        output = script.get("output") or ""
        states = [elem.text or "" for elem in script.iter("elem") if elem.get("key") == "state"]
        if not (any("VULNERABLE" in state for state in states) or "State: VULNERABLE" in output):
            continue
        cves = sorted({match.upper() for match in CVE_PATTERN.findall(output)})
        titles = [elem.text for elem in script.iter("elem") if elem.get("key") == "title" and elem.text]
        found.append(finding(
            TOOL, target, "vulnerability", "high",
            f"{titles[0] if titles else script.get('id')} ({scope})",
            " ".join(output.split())[:1500],
            f"script={script.get('id')} {scope}" + (f" ids={','.join(cves)}" if cves else ""),
            cves[0] if cves else None,
        ))
    return found


def parse_nmap_xml(xml_text: str, target: str) -> list:
    """Findings from Nmap XML. Raises ScannerError if no host was scanned."""
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as error:
        raise ScannerError(TOOL, f"output was not valid XML ({error})")
    hosts = root.findall("host")
    if not hosts:
        raise ScannerError(TOOL, "no host was scanned; the name may not resolve")

    findings = []
    for host in hosts:
        for port_el in host.findall("./ports/port"):
            state_el = port_el.find("state")
            if state_el is None or state_el.get("state") != "open":
                continue
            port, protocol = int(port_el.get("portid")), port_el.get("protocol")
            findings.append(_port_finding(target, port_el, port, protocol, state_el))
            findings.extend(_script_findings(target, f"port {port}/{protocol}", port_el.findall("script")))
        findings.extend(_script_findings(target, "host", host.findall("./hostscript/script")))
    return collapse_info(findings, TOOL, "Web server ports open")


def run_nmap_scan(target: str, timeout: int = 420) -> ScanResult:
    command = [
        "nmap", "-sV", "-Pn", "-F",
        "--script", SCRIPTS, "--script-timeout", "60s",
        "-oX", "-", target,
    ]
    result = run_tool(TOOL, command, timeout)
    return ScanResult(TOOL, parse_nmap_xml(result.stdout, target), result.stdout, "nmap.xml")
