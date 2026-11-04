"""
Nmap scanner module for network scanning:

Runs Nmap against a target and parse its XML output into unified findings.
Only open ports are reported as findings: Closed ports are ignored
Each port is one finding with medium severity
"""

import subprocess
import xml.etree.ElementTree as ET


def run_nmap_scan(target: str) -> list:
    # return a list of findings dicts afte scanning target
    findings = []

    #-F scans top 100 ports, -oX outputs XML to stdout
    command = ["nmap", "-F", "-oX", "-", target]

    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=120)
        if result.returncode != 0:
            print(f"nmap exited {result.returncode}: {result.stderr[-500:]}")
            return findings

        #parse XML output
        root = ET.fromstring(result.stdout)
        for host in root.findall("host"):
            for port in host.findall("./ports/port"):
                port_id = port.get("portid")
                protocol = port.get("protocol")
                state_el = port.find("state")
                if state_el is None or state_el.get("state") != "open":
                    continue
                service_el = port.find("service")
                service = service_el.get("name") if service_el is not None else "unknown"

                findings.append({
                    "tool": "nmap",
                    "target": target,
                    "finding_type": "open_port",
                    "severity": "medium",
                    "title": f"Open Port: {port_id}/{protocol}",
                    "description": f"Service '{service}' is listening on port {port_id}/{protocol}.",
                    "cve_id": None,
                })

    except subprocess.TimeoutExpired:
        print(f"nmap scan for {target} timed out")
    except Exception as e:
        print(f"nmap scan failed: {e}")
    
    return findings