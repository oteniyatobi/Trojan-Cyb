"""Run every registered scanner against its target."""

import logging

from scanners import nmap_scanner, wapiti_scanner, nuclei_scanner, osv_scanner

logger = logging.getLogger(__name__)

SCANNERS = {
    "nmap": (nmap_scanner.run_nmap_scan, "host"),
    "wapiti": (wapiti_scanner.run_wapiti_scan, "url"),
    "nuclei": (nuclei_scanner.run_nuclei_scan, "url"),
    "osv": (osv_scanner.run_osv_scan, "dir"),
}


def run_all_scans(host, url, code_dir):
    """Run every registered scanner and return {tool: [findings]}.

    A scanner that raises is a failed scan: the key is present in the
    result with an empty list, and the exception is logged. A scanner
    that returns [] is a clean scan.
    """
    targets = {"host": host, "url": url, "dir": code_dir}
    results = {}
    for name, (fn, kind) in SCANNERS.items():
        target = targets[kind]
        try:
            results[name] = fn(target)
        except Exception:
            logger.exception("scan %s failed on %s", name, target)
            results[name] = []
    return results
