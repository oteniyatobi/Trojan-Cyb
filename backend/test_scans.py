import os
import unittest
from types import SimpleNamespace
from unittest.mock import patch

import scan_store
from api import app

ORG = "11111111-1111-1111-1111-111111111111"
TARGET = "22222222-2222-2222-2222-222222222222"
SCAN = "33333333-3333-3333-3333-333333333333"


def target(verified=True):
    return {
        "id": TARGET,
        "organization_id": ORG,
        "url": "https://example.com",
        "hostname": "example.com",
        "verification_token": "abc123",
        "verified_at": "2026-11-20T10:00:00+00:00" if verified else None,
        "created_at": "2026-11-20T09:00:00+00:00",
    }


class NormalizeUrlTests(unittest.TestCase):
    def test_adds_scheme_and_drops_path(self):
        self.assertEqual(
            scan_store.normalize_url("Example.com/login?x=1"),
            ("https://example.com", "example.com"),
        )

    def test_keeps_port(self):
        self.assertEqual(
            scan_store.normalize_url("http://example.com:8080/"),
            ("http://example.com:8080", "example.com"),
        )

    def test_rejects_ip_addresses_and_local_names(self):
        for value in ("10.0.0.5", "http://127.0.0.1", "localhost", "printer.local", "ftp://example.com"):
            with self.assertRaises(scan_store.ScanError, msg=value):
                scan_store.normalize_url(value)


class ScanStoreTests(unittest.TestCase):
    @patch("scan_store.get_supabase_client")
    @patch("scan_store._fetch_verification", return_value="other\nabc123\n")
    @patch("scan_store._public_host", return_value=True)
    @patch("scan_store._visible_target", return_value=target(verified=False))
    def test_verify_marks_target_verified(self, _visible, _public, _fetch, get_client):
        update = get_client.return_value.table.return_value.update
        update.return_value.eq.return_value.execute.return_value = SimpleNamespace(data=[target()])

        self.assertTrue(scan_store.verify_target("token", TARGET)["verified_at"])
        self.assertIn("verified_at", update.call_args.args[0])

    @patch("scan_store._fetch_verification", return_value="wrong-code")
    @patch("scan_store._public_host", return_value=True)
    @patch("scan_store._visible_target", return_value=target(verified=False))
    def test_verify_rejects_missing_code(self, *_):
        with self.assertRaises(scan_store.ScanError):
            scan_store.verify_target("token", TARGET)

    @patch("scan_store._public_host", return_value=False)
    @patch("scan_store._visible_target", return_value=target(verified=False))
    def test_verify_refuses_private_hosts(self, *_):
        with self.assertRaises(scan_store.ScanError):
            scan_store.verify_target("token", TARGET)

    @patch("scan_store._visible_target", return_value=target(verified=False))
    def test_unverified_target_cannot_be_scanned(self, _):
        with self.assertRaises(scan_store.ScanError):
            scan_store.start_scan("token", TARGET)

    @patch.dict(os.environ, {"GITHUB_DISPATCH_TOKEN": ""})
    @patch("scan_store._finish")
    @patch("scan_store.get_user_client")
    @patch("scan_store.get_supabase_client")
    @patch("scan_store._expire_stale_scans")
    @patch("scan_store._visible_target", return_value=target())
    def test_missing_dispatch_token_fails_the_scan(self, _visible, _expire, service, user, finish):
        table = service.return_value.table.return_value
        table.select.return_value.eq.return_value.in_.return_value.limit.return_value.execute.return_value = (
            SimpleNamespace(data=[])
        )
        table.select.return_value.eq.return_value.gte.return_value.execute.return_value = SimpleNamespace(count=0)
        user.return_value.table.return_value.insert.return_value.execute.return_value = SimpleNamespace(
            data=[{"id": SCAN}],
        )

        with self.assertRaises(scan_store.ScanError) as raised:
            scan_store.start_scan("token", TARGET)
        self.assertEqual(raised.exception.status, 503)
        finish.assert_called_once()
        self.assertEqual(finish.call_args.args[:2], (SCAN, "failed"))

    @patch("scan_store._finish")
    @patch("scan_store.persist_findings", return_value=1)
    @patch("scan_store.get_supabase_client")
    def test_complete_stores_findings_with_scan_id(self, get_client, persist, finish):
        select = get_client.return_value.table.return_value.select.return_value
        select.eq.return_value.limit.return_value.execute.return_value = SimpleNamespace(
            data=[{"organization_id": ORG, "status": "running"}],
        )
        finding = {"target": "https://example.com", "title": "x", "severity": "low"}

        self.assertEqual(scan_store.complete_scan(SCAN, [finding], None, "Nmap did not finish."), 1)
        self.assertEqual(persist.call_args.args[1][0]["scan_id"], SCAN)
        finish.assert_called_once_with(SCAN, "completed", findings_count=1, error="Nmap did not finish.")


class ScanRouteTests(unittest.TestCase):
    def setUp(self):
        self.client = app.test_client()

    def test_scan_routes_need_sign_in(self):
        self.assertEqual(self.client.get(f"/v1/scans?organization_id={ORG}").status_code, 401)
        self.assertEqual(self.client.post("/v1/scans", json={"target_id": TARGET}).status_code, 401)

    def test_scan_errors_keep_their_status(self):
        with patch("scan_store.start_scan", side_effect=scan_store.ScanError("busy", 409)):
            response = self.client.post(
                "/v1/scans", json={"target_id": TARGET}, headers={"Authorization": "Bearer t"},
            )
        self.assertEqual(response.status_code, 409)
        self.assertEqual(response.get_json()["error"], "busy")

    @patch.dict(os.environ, {"SCAN_WORKER_SECRET": "worker-secret"})
    def test_worker_routes_need_the_worker_secret(self):
        url = f"/v1/worker/scans/{SCAN}/start"
        self.assertEqual(self.client.post(url).status_code, 401)
        self.assertEqual(self.client.post(url, headers={"Authorization": "Bearer nope"}).status_code, 401)
        with patch("scan_store.claim_scan", return_value={"url": "https://example.com"}):
            response = self.client.post(url, headers={"Authorization": "Bearer worker-secret"})
        self.assertEqual(response.status_code, 200)

    @patch.dict(os.environ, {"SCAN_WORKER_SECRET": ""})
    def test_worker_routes_closed_without_secret(self):
        response = self.client.post(f"/v1/worker/scans/{SCAN}/start", headers={"Authorization": "Bearer "})
        self.assertEqual(response.status_code, 401)

    @patch.dict(os.environ, {"SCAN_WORKER_SECRET": "worker-secret"})
    def test_worker_finish_validates_findings(self):
        response = self.client.post(
            f"/v1/worker/scans/{SCAN}/finish",
            json={"findings": [{"title": "no target", "severity": "low"}]},
            headers={"Authorization": "Bearer worker-secret"},
        )
        self.assertEqual(response.status_code, 422)


if __name__ == "__main__":
    unittest.main()
