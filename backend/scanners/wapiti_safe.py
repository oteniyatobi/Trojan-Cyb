"""Run Wapiti so it only reads a website, never submits to it.

Usage: python -m scanners.wapiti_safe <wapiti arguments>

Wapiti's crawler submits every form it finds (POST with default values),
even when no attack module is enabled. On a customer's real site that can
send contact forms, create orders or write junk into their database. This
launcher keeps only GET requests from what the crawler queues, then starts
Wapiti normally. Search forms that use GET are still followed; they only
read.

Tested against wapiti3==3.3.2 (pinned in requirements.txt). If an upgrade
removes Explorer.extract_links, this module fails on import and the worker
reports Wapiti as crashed instead of running it without the guard.
"""
import sys

from wapitiCore.main.wapiti import wapiti_asyncio_wrapper
from wapitiCore.net.explorer import Explorer

_extract_links = Explorer.extract_links


def _get_requests_only(self, response, request):
    return [link for link in _extract_links(self, response, request) if link.method == "GET"]


Explorer.extract_links = _get_requests_only


if __name__ == "__main__":
    sys.argv[0] = "wapiti"
    sys.exit(wapiti_asyncio_wrapper())
