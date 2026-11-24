"""Run every registered scanner against its target (lab and manual use).

The dashboard's website scans use scanners/worker.py instead.
"""
import logging

from scanners import nmap_scanner, nuclei_scanner, osv_scanner, wapiti_scanner
from scanners.common import ScannerError

logger = logging.getLogger(__name__)

SCANNERS = {
    "nmap": (nmap_scanner.run_nmap_scan, "host"),
    "wapiti": (wapiti_scanner.run_wapiti_scan, "url"),
    "nuclei": (nuclei_scanner.run_nuclei_scan, "url"),
    "osv": (osv_scanner.run_osv_scan, "dir"),
}


def run_all_scans(host, url, code_dir):
    """Return {tool: {"findings": [...], "error": None or reason}}.

    A tool with an error did not finish; one with no findings and no error
    is a clean scan.
    """
    targets = {"host": host, "url": url, "dir": code_dir}
    results = {}
    for name, (scan, kind) in SCANNERS.items():
        try:
            results[name] = {"findings": scan(targets[kind]).findings, "error": None}
        except ScannerError as error:
            logger.warning("scan %s failed: %s", name, error.reason)
            results[name] = {"findings": [], "error": error.reason}
    return results
