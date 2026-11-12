"""
Runs all Trojan scanners and returns a combined list of findings
"""


from scanners.nmap_scanner import run_nmap_scan
from scanners.wapiti_scanner import run_wapiti_scan
from scanners.nuclei_scanner import run_nuclei_scan
from scanners.osv_scanner import run_osv_scan


def run_all_scans(host: str, url: str, code_dir: str) -> dict:
    """
    Run all scanners and return a dictionary of findings
    :param host: target host for nmap scan
    :param url: target URL for wapiti and nuclei scans
    :param code_dir: directory containing code for osv scan
    :return: dictionary of findings from each scanner
    """
    return {
        "nmap": run_nmap_scan(host),
        "wapiti": run_wapiti_scan(url),
        "nuclei": run_nuclei_scan(url),
        "osv": run_osv_scan(code_dir),
    }