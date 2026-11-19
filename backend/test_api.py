import hashlib
import os
import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from api import app
import supabase_store


INSTALL_ORG = "11111111-1111-1111-1111-111111111111"
OTHER_ORG = "33333333-3333-3333-3333-333333333333"
ALERT_ID = "22222222-2222-2222-2222-222222222222"
INGESTION_ENV = {
    "TROJAN_INGESTION_API_KEY": "test-ingestion-key",
    "TROJAN_ORGANIZATION_ID": INSTALL_ORG,
    "GROQ_REVIEWS_PER_HOUR": "100",
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
WAZUH_ALERT = {
    "id": "1793699715.140171",
    "timestamp": "2026-11-03T09:55:15.767+0000",
    "rule": {"id": "86601", "level": 10, "description": "Suricata: fake SQL injection",
             "groups": ["ids", "suricata"], "firedtimes": 70},
    "agent": {"id": "001", "name": "lab-host"},
    "manager": {"name": "wazuh.manager"},
    "decoder": {"name": "json"},
    "data": {"src_ip": "172.30.0.20", "dest_ip": "172.30.0.10", "dest_port": "80", "proto": "TCP",
             "alert": {"signature_id": "1000002", "signature": "TROJAN fake SQL injection", "severity": "3"}},
    "full_log": "GET /?id=1' OR '1'='1 password=hunter2",
    "location": "/var/log/suricata/eve.json",
}


class IngestionTestCase(unittest.TestCase):
    def setUp(self):
        app.config["TESTING"] = True
        self.client = app.test_client()
        self.environment = patch.dict(os.environ, INGESTION_ENV, clear=False)
        self.environment.start()
        self.addCleanup(self.environment.stop)

    def post_alerts(self, alerts, headers=AUTH_HEADERS):
        return self.client.post("/v1/analyze", json={"alerts": alerts}, headers=headers)


@patch("api.reviews_in_last_hour", return_value=0)
@patch("api.record_review")
@patch("api.store_pending_alert", return_value=(ALERT_ID, True))
class AnalyzeTests(IngestionTestCase):
    def test_analysis_requires_ingestion_key(self, store, *_):
        response = self.client.post("/v1/analyze", json={"alerts": [ALERT]})

        self.assertEqual(response.status_code, 401)
        store.assert_not_called()

    @patch("api.check_review", return_value=[])
    @patch("api.get_review", return_value=REVIEW.copy())
    def test_alert_is_stored_before_review_and_review_is_recorded(
        self, get_review, _check, store, record, _count,
    ):
        response = self.post_alerts([ALERT])

        self.assertEqual(response.status_code, 200)
        result = response.json["results"][0]
        self.assertEqual(result["alert_id"], ALERT_ID)
        self.assertEqual(result["review_status"], "done")
        store.assert_called_once_with(INSTALL_ORG, ALERT)
        record.assert_called_once_with(INSTALL_ORG, ALERT_ID, {**REVIEW, "status": "done"}, "done")

    @patch("api.get_review", side_effect=RuntimeError("Groq down"))
    def test_alert_is_kept_when_groq_fails(self, _get_review, store, record, _count):
        response = self.post_alerts([ALERT])

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json["results"][0]["review_status"], "unavailable")
        store.assert_called_once()
        self.assertEqual(record.call_args.args[3], "unavailable")

    @patch("api.get_review")
    def test_duplicate_alert_is_not_reviewed_again(self, get_review, store, record, _count):
        store.return_value = (ALERT_ID, False)

        response = self.post_alerts([ALERT])

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json["results"][0]["review_status"], "duplicate")
        get_review.assert_not_called()
        record.assert_not_called()

    @patch("api.get_review")
    def test_hourly_limit_skips_groq(self, get_review, _store, record, count):
        count.return_value = 100

        response = self.post_alerts([ALERT])

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json["results"][0]["review_status"], "rate_limited")
        get_review.assert_not_called()
        self.assertEqual(record.call_args.args[3], "rate_limited")

    def test_storage_failure_returns_503(self, store, record, _count):
        store.side_effect = RuntimeError("database unavailable")

        response = self.post_alerts([ALERT])

        self.assertEqual(response.status_code, 503)
        self.assertIn("Supabase storage failed", response.json["error"])
        self.assertEqual(response.json["stored_count"], 0)
        record.assert_not_called()


@patch("api.reviews_in_last_hour", return_value=100)
@patch("api.record_review")
@patch("api.store_pending_alert", return_value=(ALERT_ID, True))
class IngestKeyTests(IngestionTestCase):
    @patch("api.organization_for_ingest_key", return_value=OTHER_ORG)
    def test_per_business_key_stores_in_that_business(self, lookup, store, *_):
        response = self.post_alerts([ALERT], headers={"Authorization": "Bearer org-key"})

        self.assertEqual(response.status_code, 200)
        lookup.assert_called_once_with("org-key")
        store.assert_called_once_with(OTHER_ORG, ALERT)

    @patch("api.organization_for_ingest_key", return_value=None)
    def test_unknown_key_is_rejected(self, _lookup, store, *_):
        response = self.post_alerts([ALERT], headers={"Authorization": "Bearer wrong"})

        self.assertEqual(response.status_code, 401)
        store.assert_not_called()

    @patch("api.organization_for_ingest_key")
    def test_install_key_does_not_query_ingest_keys(self, lookup, store, *_):
        self.post_alerts([ALERT])

        lookup.assert_not_called()
        store.assert_called_once_with(INSTALL_ORG, ALERT)


class FindingsTests(IngestionTestCase):
    @patch("api.persist_findings", return_value=1)
    def test_findings_are_stored(self, persist):
        finding = {"target": "host-1", "title": "Open port", "severity": "medium"}

        response = self.client.post("/v1/findings", json={"findings": [finding]}, headers=AUTH_HEADERS)

        self.assertEqual(response.status_code, 201)
        self.assertEqual(response.json["stored"], 1)
        persist.assert_called_once_with(INSTALL_ORG, [finding])


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
    @patch("supabase_store.get_supabase_client")
    def test_pending_alert_keeps_dashboard_fields_but_not_raw_log(self, get_client):
        client = MagicMock()
        client.rpc.return_value.execute.return_value = SimpleNamespace(
            data=[{"alert_id": ALERT_ID, "inserted": True}],
        )
        get_client.return_value = client

        alert_id, inserted = supabase_store.store_pending_alert(INSTALL_ORG, WAZUH_ALERT)

        self.assertEqual((alert_id, inserted), (ALERT_ID, True))
        name, args = client.rpc.call_args.args
        self.assertEqual(name, "ingest_alert")
        self.assertEqual(args["p_organization_id"], INSTALL_ORG)
        self.assertEqual(args["p_severity"], "high")  # rule level 10
        self.assertEqual(args["p_ai_review"], {})
        payload = args["p_source_payload"]
        self.assertEqual(payload["src_ip"], "172.30.0.20")
        self.assertEqual(payload["agent_name"], "lab-host")
        self.assertEqual(payload["rule_id"], "86601")
        self.assertEqual(payload["signature"], "TROJAN fake SQL injection")
        self.assertNotIn("full_log", payload)
        self.assertNotIn("hunter2", str(payload))

    @patch("supabase_store.get_supabase_client")
    def test_duplicate_is_reported(self, get_client):
        client = MagicMock()
        client.rpc.return_value.execute.return_value = SimpleNamespace(
            data=[{"alert_id": ALERT_ID, "inserted": False}],
        )
        get_client.return_value = client

        self.assertEqual(supabase_store.store_pending_alert(INSTALL_ORG, ALERT), (ALERT_ID, False))

    @patch("supabase_store.get_supabase_client")
    def test_done_review_updates_severity_title_and_reviewed_at(self, get_client):
        client = MagicMock()
        get_client.return_value = client

        supabase_store.record_review(INSTALL_ORG, ALERT_ID, {**REVIEW, "status": "done"}, "done")

        update = client.table.return_value.update.call_args.args[0]
        self.assertEqual(update["review_status"], "done")
        self.assertEqual(update["severity"], "medium")
        self.assertEqual(update["title"], "Test alert review")
        self.assertIn("reviewed_at", update)

    @patch("supabase_store.get_supabase_client")
    def test_ingest_key_lookup_uses_hash(self, get_client):
        client = MagicMock()
        query = client.table.return_value.select.return_value
        query.eq.return_value.is_.return_value.limit.return_value.execute.return_value = SimpleNamespace(
            data=[{"organization_id": OTHER_ORG}],
        )
        get_client.return_value = client

        self.assertEqual(supabase_store.organization_for_ingest_key("org-key"), OTHER_ORG)
        query.eq.assert_called_once_with("key_hash", hashlib.sha256(b"org-key").hexdigest())

    @patch("supabase_store.get_supabase_client")
    def test_findings_storage_sets_organization(self, get_client):
        client = MagicMock()
        client.table.return_value.insert.return_value.execute.return_value = SimpleNamespace(
            data=[{"id": "finding-1"}],
        )
        get_client.return_value = client
        finding = {"target": "host-1", "title": "Open port", "severity": "medium"}

        stored = supabase_store.persist_findings(OTHER_ORG, [finding])

        self.assertEqual(stored, 1)
        row = client.table.return_value.insert.call_args.args[0][0]
        self.assertEqual(row["organization_id"], OTHER_ORG)


if __name__ == "__main__":
    unittest.main()
