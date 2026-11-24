import hashlib
import json
from datetime import datetime, timezone
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

    @patch("api.alert_review_status", return_value="done")
    @patch("api.get_review")
    def test_duplicate_alert_is_not_reviewed_again(self, get_review, _status, store, record, _count):
        store.return_value = (ALERT_ID, False)

        response = self.post_alerts([ALERT])

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json["results"][0]["review_status"], "duplicate")
        get_review.assert_not_called()
        record.assert_not_called()

    @patch("api.alert_review_status", return_value="unavailable")
    @patch("api.check_review", return_value=[])
    @patch("api.get_review", return_value=REVIEW.copy())
    def test_resent_alert_without_a_review_is_reviewed_again(
        self, get_review, _check, _status, store, record, _count,
    ):
        store.return_value = (ALERT_ID, False)

        response = self.post_alerts([ALERT])

        self.assertEqual(response.json["results"][0]["review_status"], "done")
        get_review.assert_called_once()
        self.assertEqual(record.call_args.args[3], "done")

    @patch("api.alert_review_status", side_effect=RuntimeError("Supabase down"))
    @patch("api.get_review")
    def test_duplicate_stays_duplicate_when_status_lookup_fails(self, get_review, _status, store, record, _count):
        store.return_value = (ALERT_ID, False)

        response = self.post_alerts([ALERT])

        self.assertEqual(response.json["results"][0]["review_status"], "duplicate")
        get_review.assert_not_called()

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


@patch("api.reviews_in_last_hour", return_value=0)
@patch("api.record_review")
@patch("api.store_pending_alert", return_value=(ALERT_ID, True))
class GroqInputTests(IngestionTestCase):
    @patch("api.check_review", return_value=[])
    @patch("api.get_review", return_value=REVIEW.copy())
    def test_groq_gets_only_the_stored_fields_not_the_raw_log(self, get_review, *_):
        self.post_alerts([WAZUH_ALERT])

        sent = get_review.call_args.args[0]
        self.assertIn("172.30.0.20", sent)
        self.assertIn("TROJAN fake SQL injection", sent)
        self.assertNotIn("full_log", sent)
        self.assertNotIn("hunter2", sent)
        self.assertEqual(json.loads(sent), supabase_store.alert_source_payload(WAZUH_ALERT))


RETRY_HEADERS = {"Authorization": "Bearer worker-secret"}
DUE = [
    {"id": "a1", "organization_id": INSTALL_ORG, "source_payload": {"rule_id": "5712"},
     "review_status": "unavailable", "review_attempts": 2},
    {"id": "a2", "organization_id": OTHER_ORG, "source_payload": {"rule_id": "86601"},
     "review_status": "rate_limited", "review_attempts": 0},
]


@patch.dict(os.environ, {"SCAN_WORKER_SECRET": "worker-secret"})
class ReviewRetryTests(unittest.TestCase):
    def setUp(self):
        self.client = app.test_client()

    def test_needs_the_worker_secret(self):
        self.assertEqual(self.client.post("/v1/worker/reviews/retry").status_code, 401)
        wrong = {"Authorization": "Bearer nope"}
        self.assertEqual(self.client.post("/v1/worker/reviews/retry", headers=wrong).status_code, 401)

    @patch("api.count_failed_review_attempt")
    @patch("api.review_stored_alert", side_effect=[({}, "unavailable"), ({}, "done")])
    @patch("api.alerts_due_for_review", return_value=DUE)
    def test_retries_due_alerts_from_their_stored_fields(self, due, review, count_failed):
        response = self.client.post("/v1/worker/reviews/retry", headers=RETRY_HEADERS)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json, {"retried": 2, "outcomes": {"unavailable": 1, "done": 1}})
        self.assertEqual(review.call_args_list[0].args, (INSTALL_ORG, "a1", {"rule_id": "5712"}))
        # Only a failed retry counts towards the 5-attempt cap.
        count_failed.assert_called_once_with(DUE[0])
        due.assert_called_once_with(3)

    @patch("api.review_stored_alert", side_effect=[RuntimeError("Supabase down"), ({}, "done")])
    @patch("api.alerts_due_for_review", return_value=DUE)
    def test_one_failure_doesnt_stop_the_batch(self, _due, _review):
        response = self.client.post("/v1/worker/reviews/retry", headers=RETRY_HEADERS)
        self.assertEqual(response.json["outcomes"], {"error": 1, "done": 1})

    @patch("api.alerts_due_for_review", side_effect=RuntimeError("Supabase down"))
    def test_listing_failure_is_reported(self, _due):
        response = self.client.post("/v1/worker/reviews/retry", headers=RETRY_HEADERS)
        self.assertEqual(response.status_code, 502)


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

    def _key_client(self, row):
        client = MagicMock()
        query = client.table.return_value.select.return_value
        query.eq.return_value.limit.return_value.execute.return_value = SimpleNamespace(
            data=[row] if row else [],
        )
        return client, query

    @patch("supabase_store.get_supabase_client")
    def test_ingest_key_lookup_uses_hash(self, get_client):
        client, query = self._key_client({
            "id": "k1", "organization_id": OTHER_ORG, "revoked_at": None, "last_used_at": None,
        })
        get_client.return_value = client

        self.assertEqual(supabase_store.organization_for_ingest_key("org-key"), OTHER_ORG)
        query.eq.assert_called_once_with("key_hash", hashlib.sha256(b"org-key").hexdigest())
        client.table.return_value.update.assert_called_once()

    @patch("supabase_store.get_supabase_client")
    def test_revoked_key_is_rejected_but_recorded(self, get_client):
        client, _ = self._key_client({
            "id": "k1", "organization_id": OTHER_ORG, "revoked_at": "2026-11-19T10:00:00+00:00",
            "last_used_at": None,
        })
        get_client.return_value = client

        self.assertIsNone(supabase_store.organization_for_ingest_key("org-key"))
        client.table.return_value.update.assert_called_once()

    @patch("supabase_store.get_supabase_client")
    def test_recent_use_is_not_rewritten(self, get_client):
        recent = datetime.now(timezone.utc).isoformat()
        client, _ = self._key_client({
            "id": "k1", "organization_id": OTHER_ORG, "revoked_at": None, "last_used_at": recent,
        })
        get_client.return_value = client

        supabase_store.organization_for_ingest_key("org-key")
        client.table.return_value.update.assert_not_called()

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

    @patch("supabase_store.get_supabase_client")
    def test_rescan_skips_findings_that_are_already_open(self, get_client):
        client = MagicMock()
        existing = client.table.return_value.select.return_value.eq.return_value.neq.return_value.in_.return_value
        existing.execute.return_value = SimpleNamespace(data=[{"asset": "host-1", "title": "Open port"}])
        client.table.return_value.insert.return_value.execute.return_value = SimpleNamespace(
            data=[{"id": "finding-2"}],
        )
        get_client.return_value = client
        findings = [
            {"target": "host-1", "title": "Open port", "severity": "medium"},
            {"target": "host-1", "title": "Outdated server", "severity": "high"},
            {"target": "host-1", "title": "Outdated server", "severity": "high"},
        ]

        stored = supabase_store.persist_findings(OTHER_ORG, findings)

        self.assertEqual(stored, 1)
        rows = client.table.return_value.insert.call_args.args[0]
        self.assertEqual([row["title"] for row in rows], ["Outdated server"])

    @patch("supabase_store.get_supabase_client")
    def test_nothing_is_inserted_when_every_finding_is_already_open(self, get_client):
        client = MagicMock()
        existing = client.table.return_value.select.return_value.eq.return_value.neq.return_value.in_.return_value
        existing.execute.return_value = SimpleNamespace(data=[{"asset": "host-1", "title": "Open port"}])
        get_client.return_value = client

        stored = supabase_store.persist_findings(
            OTHER_ORG, [{"target": "host-1", "title": "Open port", "severity": "medium"}],
        )

        self.assertEqual(stored, 0)
        client.table.return_value.insert.assert_not_called()


class ReviewRetryQueryTests(unittest.TestCase):
    @patch("supabase_store.get_supabase_client")
    def test_due_query_caps_failed_attempts_and_rotates_fairly(self, get_client):
        query = get_client.return_value.table.return_value.select.return_value
        filtered = query.or_.return_value.not_.is_.return_value
        filtered.order.return_value.limit.return_value.execute.return_value = SimpleNamespace(data=DUE)

        self.assertEqual(supabase_store.alerts_due_for_review(3), DUE)
        # Old alerts that kept only event_id and timestamp are never retried.
        query.or_.return_value.not_.is_.assert_called_once_with("source_payload->>description", "null")

        filters = query.or_.call_args.args[0]
        self.assertIn("review_status.eq.rate_limited", filters)
        self.assertIn("and(review_status.eq.unavailable,review_attempts.lt.5)", filters)
        self.assertIn("and(review_status.eq.pending,created_at.lt.", filters)
        filtered.order.assert_called_once_with("updated_at")

    @patch("supabase_store.get_supabase_client")
    def test_failed_attempt_is_counted(self, get_client):
        supabase_store.count_failed_review_attempt(DUE[0])
        update = get_client.return_value.table.return_value.update
        update.assert_called_once_with({"review_attempts": 3})


if __name__ == "__main__":
    unittest.main()
