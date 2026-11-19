import os
import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from api import app
import supabase_store


INGESTION_ENV = {
    "TROJAN_INGESTION_API_KEY": "test-ingestion-key",
    "TROJAN_ORGANIZATION_ID": "11111111-1111-1111-1111-111111111111",
}
AUTH_HEADERS = {"Authorization": "Bearer test-ingestion-key"}
ALERT = {"id": "event-1", "description": "Test alert"}
REVIEW = {
    "attack_type": "Other",
    "severity": "medium",
    "headline": "Test alert review",
    "what_happened": "Test.",
    "why_it_matters": "Test.",
    "steps": ["Review the event."],
    "when_to_escalate": "If it continues.",
}


class SupabaseIngestionTests(unittest.TestCase):
    def setUp(self):
        app.config["TESTING"] = True
        self.client = app.test_client()
        self.environment = patch.dict(os.environ, INGESTION_ENV, clear=False)
        self.environment.start()
        self.addCleanup(self.environment.stop)

    def test_analysis_requires_ingestion_key(self):
        response = self.client.post("/v1/analyze", json={"alerts": [ALERT]})

        self.assertEqual(response.status_code, 401)

    @patch("api.persist_alert", return_value="22222222-2222-2222-2222-222222222222")
    @patch("api.check_review", return_value=[])
    @patch("api.get_review", return_value=REVIEW.copy())
    def test_analysis_stores_alert_in_configured_organization(
        self,
        _get_review,
        _check_review,
        persist,
    ):
        response = self.client.post(
            "/v1/analyze",
            json={"alerts": [ALERT]},
            headers=AUTH_HEADERS,
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json["results"][0]["alert_id"], "22222222-2222-2222-2222-222222222222")
        persist.assert_called_once_with(ALERT, {**REVIEW, "status": "done"})

    @patch("api.persist_alert", side_effect=RuntimeError("database unavailable"))
    @patch("api.check_review", return_value=[])
    @patch("api.get_review", return_value=REVIEW.copy())
    def test_analysis_reports_storage_failure(
        self,
        _get_review,
        _check_review,
        _persist,
    ):
        response = self.client.post(
            "/v1/analyze",
            json={"alerts": [ALERT]},
            headers=AUTH_HEADERS,
        )

        self.assertEqual(response.status_code, 503)
        self.assertIn("Supabase storage failed", response.json["error"])

    @patch("api.persist_findings", return_value=1)
    def test_findings_are_stored(self, persist):
        finding = {
            "target": "host-1",
            "title": "Open port",
            "severity": "medium",
        }
        response = self.client.post(
            "/v1/findings",
            json={"findings": [finding]},
            headers=AUTH_HEADERS,
        )

        self.assertEqual(response.status_code, 201)
        self.assertEqual(response.json["stored"], 1)
        persist.assert_called_once_with([finding])


USER_HEADERS = {"Authorization": "Bearer user-access-token"}
ORGANIZATION_ID = "11111111-1111-1111-1111-111111111111"


class ReadEndpointTests(unittest.TestCase):
    def setUp(self):
        app.config["TESTING"] = True
        self.client = app.test_client()

    def test_alerts_require_sign_in(self):
        response = self.client.get(f"/v1/alerts?organization_id={ORGANIZATION_ID}")

        self.assertEqual(response.status_code, 401)

    def test_alerts_require_valid_organization(self):
        response = self.client.get("/v1/alerts?organization_id=nope", headers=USER_HEADERS)

        self.assertEqual(response.status_code, 422)

    @patch("api.list_alerts", return_value=[{"id": "a1"}])
    def test_alerts_are_read_with_user_token(self, list_alerts):
        response = self.client.get(
            f"/v1/alerts?organization_id={ORGANIZATION_ID}&limit=5",
            headers=USER_HEADERS,
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json["alerts"], [{"id": "a1"}])
        list_alerts.assert_called_once_with("user-access-token", ORGANIZATION_ID, 5)

    @patch("api.get_alert", return_value=None)
    def test_missing_alert_returns_404(self, _get_alert):
        response = self.client.get(
            "/v1/alerts/22222222-2222-2222-2222-222222222222",
            headers=USER_HEADERS,
        )

        self.assertEqual(response.status_code, 404)

    @patch("api.list_findings", side_effect=RuntimeError("down"))
    def test_findings_read_failure_returns_502(self, _list_findings):
        response = self.client.get(
            f"/v1/findings?organization_id={ORGANIZATION_ID}",
            headers=USER_HEADERS,
        )

        self.assertEqual(response.status_code, 502)


class SupabaseStoreTests(unittest.TestCase):
    def setUp(self):
        self.environment = patch.dict(
            os.environ,
            {"TROJAN_ORGANIZATION_ID": INGESTION_ENV["TROJAN_ORGANIZATION_ID"]},
            clear=False,
        )
        self.environment.start()
        self.addCleanup(self.environment.stop)

    @patch("supabase_store.get_supabase_client")
    def test_alert_storage_uses_configured_organization(self, get_client):
        client = MagicMock()
        client.rpc.return_value.execute.return_value = SimpleNamespace(data=[{
            "alert_id": "22222222-2222-2222-2222-222222222222",
            "inserted": True,
        }])
        get_client.return_value = client

        alert_id = supabase_store.persist_alert(ALERT, REVIEW)

        self.assertEqual(alert_id, "22222222-2222-2222-2222-222222222222")
        rpc_args = client.rpc.call_args.args
        self.assertEqual(rpc_args[0], "ingest_alert")
        self.assertEqual(rpc_args[1]["p_organization_id"], INGESTION_ENV["TROJAN_ORGANIZATION_ID"])
        self.assertEqual(rpc_args[1]["p_source_payload"], {
            "event_id": "event-1",
            "timestamp": None,
        })
        self.assertNotIn("description", rpc_args[1]["p_source_payload"])

    @patch("supabase_store.get_supabase_client")
    def test_findings_storage_sets_configured_organization(self, get_client):
        client = MagicMock()
        client.table.return_value.insert.return_value.execute.return_value = SimpleNamespace(
            data=[{"id": "finding-1"}],
        )
        get_client.return_value = client
        finding = {
            "target": "host-1",
            "title": "Open port",
            "severity": "medium",
        }

        stored = supabase_store.persist_findings([finding])

        self.assertEqual(stored, 1)
        row = client.table.return_value.insert.call_args.args[0][0]
        self.assertEqual(row["organization_id"], INGESTION_ENV["TROJAN_ORGANIZATION_ID"])


if __name__ == "__main__":
    unittest.main()
