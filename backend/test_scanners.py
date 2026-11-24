"""Parser and failure tests for the scanner adapters.

The parsers run on saved output in scanners/testdata:
- nmap_services.xml, osv_requests.json, wapiti_report.json: real output,
  captured on a local machine (Nmap and Wapiti against 127.0.0.1 only;
  OSV for requests==2.19.0), with local paths removed.
- nmap_vuln_scripts.xml, nmap_no_host.xml, nuclei_results.jsonl:
  hand-written in each tool's documented output format.
"""
import base64
import gzip
import importlib.util
import json
import os
import subprocess
import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import scan_store
from scanners import common, nmap_scanner, nuclei_scanner, osv_scanner, wapiti_scanner, worker
from scanners.common import ScanResult, ScannerError

HAS_WAPITI = importlib.util.find_spec("wapitiCore") is not None
TESTDATA = os.path.join(os.path.dirname(os.path.abspath(__file__)), "scanners", "testdata")


def fixture(name):
    with open(os.path.join(TESTDATA, name)) as handle:
        return handle.read()


def by_title(findings):
    return {item["title"]: item for item in findings}


class CommonTests(unittest.TestCase):
    def test_missing_binary_is_a_failure(self):
        with self.assertRaises(ScannerError) as raised:
            common.run_tool("nmap", ["definitely-not-a-real-binary-xyz"], timeout=5)
        self.assertIn("not installed", raised.exception.reason)

    @patch("scanners.common.subprocess.run", side_effect=subprocess.TimeoutExpired("nmap", 5))
    def test_timeout_is_a_failure(self, _run):
        with self.assertRaises(ScannerError) as raised:
            common.run_tool("nmap", ["nmap"], timeout=5)
        self.assertIn("did not finish", raised.exception.reason)

    @patch("scanners.common.subprocess.run", return_value=SimpleNamespace(returncode=2, stdout="", stderr="bad"))
    def test_unexpected_exit_code_is_a_failure(self, _run):
        with self.assertRaises(ScannerError):
            common.run_tool("nmap", ["nmap"], timeout=5)

    def test_site_of_keeps_scheme_host_and_port(self):
        self.assertEqual(common.site_of("https://Shop.Example.com/a/b?c=1"), "https://shop.example.com")
        self.assertEqual(common.site_of("http://example.com:8080/x"), "http://example.com:8080")

    def test_finding_writes_cve_in_capitals(self):
        item = common.finding("t", "a", "x", "low", "title", "d", "e", "cve-2021-41773")
        self.assertEqual(item["cve_id"], "CVE-2021-41773")
        self.assertTrue(item["found_at"].endswith("Z"))


class NmapParserTests(unittest.TestCase):
    def test_real_service_scan_rates_ports_by_risk(self):
        findings = nmap_scanner.parse_nmap_xml(fixture("nmap_services.xml"), "127.0.0.1")
        titles = by_title(findings)

        mysql = titles["Open port 3306/tcp: MySQL database"]
        self.assertEqual(mysql["severity"], "high")
        self.assertIn("MySQL 8.0.36", mysql["description"])
        self.assertEqual(titles["Open port 3389/tcp: Remote Desktop"]["severity"], "high")
        # 58088 is not a known port: rated low, with the -sV product named.
        self.assertIn("Apache httpd 2.4.49", titles["Open port 58088/tcp: 'http' service"]["description"])
        # Port 9 is closed, so it is not a finding.
        self.assertFalse(any(title.startswith("Open port 9/tcp") for title in titles))
        for item in findings:
            self.assertIn(item["severity"], common.SEVERITIES)

    def test_web_ports_are_information_and_vuln_scripts_are_findings(self):
        findings = nmap_scanner.parse_nmap_xml(fixture("nmap_vuln_scripts.xml"), "shop.example.com")
        titles = by_title(findings)

        info = titles["Web server ports open"]
        self.assertEqual((info["severity"], info["finding_type"]), ("low", "information"))
        self.assertIn("443/tcp", info["description"])
        self.assertEqual(titles["Open port 22/tcp: SSH remote login"]["severity"], "medium")
        heartbleed = next(item for item in findings if item["finding_type"] == "vulnerability")
        self.assertEqual((heartbleed["severity"], heartbleed["cve_id"]), ("high", "CVE-2014-0160"))
        self.assertIn("port 443/tcp", heartbleed["title"])
        # A script that ran but found nothing (http-csrf) is not a finding,
        # and a filtered port (23) is not open.
        self.assertEqual(sum(item["finding_type"] == "vulnerability" for item in findings), 1)
        self.assertFalse(any(title.startswith("Open port 23/tcp") for title in titles))

    def test_service_on_unusual_port_is_recognised(self):
        self.assertEqual(nmap_scanner.rate_port(13306, "mysql"), ("high", "MySQL database"))
        self.assertEqual(nmap_scanner.rate_port(443, "http")[0], "info")
        self.assertEqual(nmap_scanner.rate_port(5000, "upnp")[0], "low")

    def test_no_host_is_a_failure_not_a_clean_scan(self):
        with self.assertRaises(ScannerError):
            nmap_scanner.parse_nmap_xml(fixture("nmap_no_host.xml"), "no-such-name.example")

    def test_garbage_output_is_a_failure(self):
        with self.assertRaises(ScannerError):
            nmap_scanner.parse_nmap_xml("not xml", "host")

    @patch("scanners.nmap_scanner.run_tool")
    def test_run_uses_service_detection_and_only_safe_vuln_scripts(self, run_tool):
        run_tool.return_value = SimpleNamespace(stdout=fixture("nmap_services.xml"))

        result = nmap_scanner.run_nmap_scan("127.0.0.1")

        command = run_tool.call_args.args[1]
        self.assertIn("-sV", command)
        self.assertIn("-Pn", command)
        self.assertEqual(command[command.index("--script") + 1], "vuln and safe")
        self.assertEqual((result.raw_name, result.raw_output), ("nmap.xml", fixture("nmap_services.xml")))


class NucleiParserTests(unittest.TestCase):
    def setUp(self):
        self.findings = nuclei_scanner.parse_nuclei_jsonl(fixture("nuclei_results.jsonl"), "https://shop.example.com")
        self.titles = by_title(self.findings)

    def test_asset_is_the_website_and_cve_is_capitalised(self):
        traversal = self.titles["Apache 2.4.49 - Path Traversal"]
        self.assertEqual(traversal["target"], "https://shop.example.com")
        self.assertEqual(traversal["severity"], "critical")
        self.assertEqual(traversal["cve_id"], "CVE-2021-41773")
        self.assertIn("/cgi-bin/", traversal["evidence"])

    def test_network_match_uses_the_website_scheme(self):
        self.assertEqual(self.titles["Weak Cipher Suites Detection"]["target"], "https://shop.example.com")

    def test_information_is_collapsed_to_one_finding_per_site(self):
        info = [item for item in self.findings if item["finding_type"] == "information"]
        self.assertEqual(len(info), 1)
        self.assertEqual(info[0]["severity"], "low")
        for name in ("Wappalyzer Technology Detection: nginx",
                     "HTTP Missing Security Headers: content-security-policy",
                     "robots.txt endpoint"):
            self.assertIn(name, info[0]["description"])
        # 3 real problems + 1 information summary; the bad line is skipped.
        self.assertEqual(len(self.findings), 4)

    @patch("scanners.nuclei_scanner.run_tool")
    def test_fatal_error_with_no_output_is_a_failure(self, run_tool):
        run_tool.return_value = SimpleNamespace(stdout="", stderr="[FTL] Could not create runner")
        with self.assertRaises(ScannerError):
            nuclei_scanner.run_nuclei_scan("https://shop.example.com")

    @patch("scanners.nuclei_scanner.run_tool")
    def test_run_excludes_intrusive_templates(self, run_tool):
        run_tool.return_value = SimpleNamespace(stdout="", stderr="")
        result = nuclei_scanner.run_nuclei_scan("https://shop.example.com")
        self.assertIn("intrusive,dos,fuzz", run_tool.call_args.args[1])
        self.assertEqual(result.findings, [])


class WapitiParserTests(unittest.TestCase):
    def setUp(self):
        data = json.loads(fixture("wapiti_report.json"))
        self.findings = wapiti_scanner.parse_wapiti_report(data, "http://127.0.0.1:58088/")
        self.titles = by_title(self.findings)

    def test_passive_header_and_cookie_checks_are_reported(self):
        for title in ("Content Security Policy Configuration", "Clickjacking Protection",
                      "HttpOnly Flag cookie", "Secure Flag cookie"):
            self.assertEqual(self.titles[title]["severity"], "low")
        self.assertEqual(self.titles["Unencrypted Channels"]["severity"], "medium")

    def test_vulnerable_software_is_one_finding_per_product(self):
        software = [item for item in self.findings if item["finding_type"] == "vulnerable_software"]
        self.assertEqual(len(software), 1)
        self.assertEqual(software[0]["title"], "Outdated software: apache")
        # The highest Wapiti level among apache's CVEs in the report is 4.
        self.assertEqual(software[0]["severity"], "critical")
        self.assertTrue(software[0]["cve_id"].startswith("CVE-"))
        self.assertIn("29 known vulnerabilities", software[0]["description"])

    def test_fingerprints_are_collapsed_information(self):
        info = [item for item in self.findings if item["finding_type"] == "information"]
        self.assertEqual(len(info), 1)
        self.assertIn("Apache HTTP Server", info[0]["description"])
        self.assertEqual(info[0]["target"], "http://127.0.0.1:58088")

    def test_only_read_only_modules_are_enabled(self):
        modules = set(wapiti_scanner.MODULES.split(","))
        attacks = {"sql", "timesql", "xss", "permanentxss", "upload", "exec", "file", "ssrf",
                   "xxe", "crlf", "ldap", "methods", "csrf", "htaccess", "buster", "nikto",
                   "brute_login_form", "backup", "shellshock", "log4shell", "spring4shell"}
        self.assertFalse(modules & attacks)
        self.assertTrue({"http_headers", "cookieflags", "csp", "ssl"} <= modules)

    @patch("scanners.wapiti_scanner.run_tool")
    def test_run_has_no_dvwa_defaults_and_uses_the_safe_launcher(self, run_tool):
        def write_report(_tool, command, _timeout, cwd=None):
            with open(command[command.index("-o") + 1], "w") as handle:
                handle.write(fixture("wapiti_report.json"))
        run_tool.side_effect = write_report

        result = wapiti_scanner.run_wapiti_scan("http://127.0.0.1:58088/")

        command = run_tool.call_args.args[1]
        self.assertIn("scanners.wapiti_safe", command)
        self.assertNotIn("-c", command)
        self.assertNotIn("-x", command)
        self.assertEqual(result.raw_name, "wapiti.json")
        self.assertTrue(result.findings)

    @patch("scanners.wapiti_scanner.run_tool")
    def test_missing_report_is_a_failure(self, _run_tool):
        with self.assertRaises(ScannerError):
            wapiti_scanner.run_wapiti_scan("https://shop.example.com")

    @patch("scanners.wapiti_scanner.run_tool")
    def test_no_page_loaded_is_a_failure(self, run_tool):
        def write_report(_tool, command, _timeout, cwd=None):
            with open(command[command.index("-o") + 1], "w") as handle:
                json.dump({"vulnerabilities": {}, "infos": {"crawled_pages_nbr": 0}}, handle)
        run_tool.side_effect = write_report
        with self.assertRaises(ScannerError):
            wapiti_scanner.run_wapiti_scan("https://shop.example.com")

    @unittest.skipUnless(HAS_WAPITI, "wapiti3 is installed only in the scan worker")
    def test_safe_launcher_drops_post_requests(self):
        from wapitiCore.net import Request
        from wapitiCore.net.explorer import Explorer
        from scanners import wapiti_safe

        links = [Request("https://shop.example.com/about"),
                 Request("https://shop.example.com/contact", method="POST", post_params=[["msg", "hi"]])]
        with patch.object(wapiti_safe, "_extract_links", return_value=links):
            kept = Explorer.extract_links(object(), None, None)
        self.assertEqual([link.method for link in kept], ["GET"])


class OsvParserTests(unittest.TestCase):
    def setUp(self):
        self.findings = osv_scanner.parse_osv_json(json.loads(fixture("osv_requests.json")), "/scan")

    def test_one_finding_per_vulnerability_not_per_alias(self):
        # requests 2.19.0 has 5 vulnerabilities, each listed under 2 IDs.
        self.assertEqual(len(self.findings), 5)

    def test_title_names_the_vulnerability_and_severity_comes_from_osv(self):
        titles = by_title(self.findings)
        cred = titles["CVE-2018-18074: requests 2.19.0"]
        self.assertEqual(cred["severity"], "high")      # group max_severity 7.5
        self.assertEqual(cred["cve_id"], "CVE-2018-18074")
        self.assertEqual(cred["target"], "requirements.txt")
        self.assertIn("Upgrade requests to", cred["description"])
        self.assertEqual(titles["CVE-2023-32681: requests 2.19.0"]["severity"], "medium")  # 6.1

    def test_advisory_rating_is_used_when_there_is_no_score(self):
        data = json.loads(fixture("osv_requests.json"))
        for group in data["results"][0]["packages"][0]["groups"]:
            group.pop("max_severity", None)
        titles = by_title(osv_scanner.parse_osv_json(data))
        self.assertEqual(titles["CVE-2018-18074: requests 2.19.0"]["severity"], "high")   # GHSA HIGH
        self.assertEqual(titles["CVE-2023-32681: requests 2.19.0"]["severity"], "medium")  # MODERATE

    @patch("scanners.osv_scanner.run_tool")
    def test_no_dependency_files_is_a_failure(self, run_tool):
        run_tool.return_value = SimpleNamespace(returncode=128, stdout="", stderr="")
        with self.assertRaises(ScannerError):
            osv_scanner.run_osv_scan("/scan/requirements.txt")


class WorkerTests(unittest.TestCase):
    TARGET = {"url": "https://shop.example.com", "hostname": "shop.example.com"}

    def test_a_failing_tool_is_reported_not_treated_as_clean(self):
        def failing(_target):
            raise ScannerError("nmap", "did not finish within 420 seconds")
        tools = (("Nuclei", lambda _t: ScanResult("nuclei", [{"tool": "nuclei"}], "raw", "nuclei.jsonl")),
                 ("Nmap", failing))

        results, failures = worker.run_tools(self.TARGET, tools)
        error, warning = worker.summarize(results, failures, len(tools))

        self.assertEqual(len(results), 1)
        self.assertIsNone(error)
        self.assertIn("Nmap did not finish: did not finish within 420 seconds", warning)

    def test_all_tools_failing_fails_the_scan(self):
        error, warning = worker.summarize([], {"Nuclei": "x", "Nmap": "y"}, 2)
        self.assertTrue(error.startswith("No scanner finished."))
        self.assertIsNone(warning)

    def test_clean_scan_has_no_error_or_warning(self):
        self.assertEqual(worker.summarize([ScanResult("nmap", [])], {}, 1), (None, None))

    def test_raw_output_is_gzipped_and_size_limited(self):
        small = ScanResult("nmap", [], "<nmaprun/>", "nmap.xml")
        packed, skipped = worker.pack_raw_outputs([small, ScanResult("nuclei", [], "", "nuclei.jsonl")])
        self.assertEqual(len(packed), 1)
        self.assertEqual(gzip.decompress(base64.b64decode(packed[0]["content"])), b"<nmaprun/>")

        with patch.object(worker, "MAX_RAW_BYTES", 10):
            packed, skipped = worker.pack_raw_outputs([small])
        self.assertEqual((packed, skipped), ([], ["nmap"]))

    def test_a_raw_file_over_the_backend_limit_is_skipped_not_sent(self):
        # 2.5 MB of random text: it stays over 2 MB even after gzip and base64.
        big = ScanResult("nuclei", [], base64.b64encode(os.urandom(1_900_000)).decode(), "nuclei.jsonl")
        self.assertGreater(len(big.raw_output), 2_500_000)
        small = ScanResult("nmap", [], "<nmaprun/>", "nmap.xml")

        packed, skipped = worker.pack_raw_outputs([big, small])

        self.assertEqual([item["tool"] for item in packed], ["nmap"])
        self.assertEqual(skipped, ["nuclei"])
        # What is sent passes the backend's own check.
        self.assertIsNone(scan_store.raw_outputs_error(packed))

    @patch("scanners.worker.call")
    def test_findings_are_still_sent_when_raw_output_is_too_big(self, call):
        call.side_effect = [{"url": "https://shop.example.com", "hostname": "shop.example.com"}, {"stored": 1}]
        big = ScanResult("nuclei", [{"tool": "nuclei", "title": "x", "severity": "high", "target": "t"}],
                         base64.b64encode(os.urandom(1_900_000)).decode(), "nuclei.jsonl")

        fake_tool = MagicMock(return_value=big)
        with patch.object(worker, "TOOLS", (("Nuclei", fake_tool),)):
            worker.main("scan-1")

        fake_tool.assert_called_once()  # no real scanner ran

        body = call.call_args.args[1]
        self.assertEqual(len(body["findings"]), 1)
        self.assertEqual(body["raw_outputs"], [])
        self.assertIn("Raw output not kept for nuclei (too large).", body["warning"])
        self.assertIsNone(body["error"])


class RawOutputStorageTests(unittest.TestCase):
    def test_worker_and_backend_agree_on_the_raw_file_limit(self):
        self.assertEqual(scan_store.MAX_RAW_CONTENT, common.MAX_RAW_FILE_CHARS)

    def test_raw_outputs_are_validated(self):
        ok = {"tool": "nmap", "name": "nmap.xml", "content": "abc="}
        self.assertIsNone(scan_store.raw_outputs_error([ok]))
        self.assertIsNotNone(scan_store.raw_outputs_error("nope"))
        self.assertIsNotNone(scan_store.raw_outputs_error([{**ok, "name": "../../etc/passwd"}]))
        self.assertIsNotNone(scan_store.raw_outputs_error([ok] * 6))

    @patch("scan_store._finish")
    @patch("scan_store.persist_findings", return_value=1)
    @patch("scan_store.get_supabase_client")
    def test_raw_output_is_stored_privately_and_linked(self, get_client, persist, _finish):
        client = MagicMock()
        client.table.return_value.select.return_value.eq.return_value.limit.return_value.execute.return_value = (
            SimpleNamespace(data=[{"organization_id": "org-1", "status": "running"}])
        )
        get_client.return_value = client
        content = base64.b64encode(gzip.compress(b"<nmaprun/>")).decode()
        findings = [{"tool": "nmap", "title": "Open port", "severity": "high", "target": "h"}]

        scan_store.complete_scan("scan-1", findings, None, None,
                                 [{"tool": "nmap", "name": "nmap.xml", "content": content}])

        client.storage.from_.assert_called_with("scan-raw-output")
        path = client.storage.from_.return_value.upload.call_args.args[0]
        self.assertEqual(path, "org-1/scan-1/nmap.xml.gz")
        stored = persist.call_args.args[1][0]
        self.assertEqual(stored["raw_output_ref"], "scan-raw-output/org-1/scan-1/nmap.xml.gz")

    @patch("scan_store._finish")
    @patch("scan_store.persist_findings", return_value=1)
    @patch("scan_store.get_supabase_client")
    def test_failed_upload_does_not_fail_the_scan(self, get_client, persist, finish):
        client = MagicMock()
        client.table.return_value.select.return_value.eq.return_value.limit.return_value.execute.return_value = (
            SimpleNamespace(data=[{"organization_id": "org-1", "status": "running"}])
        )
        client.storage.from_.return_value.upload.side_effect = RuntimeError("storage down")
        get_client.return_value = client

        stored = scan_store.complete_scan(
            "scan-1", [{"tool": "nmap", "title": "t", "severity": "low", "target": "h"}], None, None,
            [{"tool": "nmap", "name": "nmap.xml", "content": base64.b64encode(b"x").decode()}],
        )

        self.assertEqual(stored, 1)
        self.assertNotIn("raw_output_ref", persist.call_args.args[1][0])
        self.assertEqual(finish.call_args.args[1], "completed")


if __name__ == "__main__":
    unittest.main()
