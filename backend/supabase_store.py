import hashlib
import logging
import os
import uuid
from datetime import datetime, timedelta, timezone
from functools import lru_cache

from supabase import Client, create_client

SEVERITIES = {"low", "medium", "high", "critical"}


class SupabaseConfigurationError(RuntimeError):
    pass


@lru_cache(maxsize=1)
def get_supabase_client() -> Client:
    url = os.getenv("SUPABASE_URL")
    service_key = os.getenv("SUPABASE_SERVICE_ROLE_KEY")
    if not url or not service_key:
        raise SupabaseConfigurationError(
            "SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY must be configured on the backend"
        )
    return create_client(url, service_key)


def get_user_client(access_token: str) -> Client:
    url = os.getenv("SUPABASE_URL")
    publishable_key = os.getenv("SUPABASE_PUBLISHABLE_KEY") or os.getenv(
        "VITE_SUPABASE_PUBLISHABLE_KEY"
    )
    if not url or not publishable_key:
        raise SupabaseConfigurationError(
            "SUPABASE_URL and SUPABASE_PUBLISHABLE_KEY must be configured on the backend"
        )
    client = create_client(url, publishable_key)
    client.postgrest.auth(access_token)
    return client


ALERT_COLUMNS = (
    "id, organization_id, source_event_id, title, severity, status, "
    "source_payload, ai_review, review_status, reviewed_at, created_at"
)
FINDING_COLUMNS = (
    "id, organization_id, asset, title, cve_id, severity, status, details, created_at"
)


def list_alerts(access_token: str, organization_id: str, limit: int) -> list[dict]:
    response = (
        get_user_client(access_token)
        .table("alerts")
        .select(ALERT_COLUMNS)
        .eq("organization_id", organization_id)
        .order("created_at", desc=True)
        .limit(limit)
        .execute()
    )
    return response.data or []


def get_alert(access_token: str, alert_id: str) -> dict | None:
    response = (
        get_user_client(access_token)
        .table("alerts")
        .select(ALERT_COLUMNS)
        .eq("id", alert_id)
        .limit(1)
        .execute()
    )
    return response.data[0] if response.data else None


def list_findings(access_token: str, organization_id: str, limit: int) -> list[dict]:
    response = (
        get_user_client(access_token)
        .table("vulnerability_findings")
        .select(FINDING_COLUMNS)
        .eq("organization_id", organization_id)
        .order("created_at", desc=True)
        .limit(limit)
        .execute()
    )
    return response.data or []


def get_organization_id() -> str:
    organization_id = os.getenv("TROJAN_ORGANIZATION_ID")
    if not organization_id:
        raise SupabaseConfigurationError(
            "TROJAN_ORGANIZATION_ID must be configured for this installation"
        )
    try:
        return str(uuid.UUID(organization_id))
    except ValueError as error:
        raise SupabaseConfigurationError(
            "TROJAN_ORGANIZATION_ID must be a valid UUID"
        ) from error


def organization_for_ingest_key(raw_key: str):
    """Business that owns an ingest key, or None.

    Only the SHA-256 hash is stored in ingest_keys, and revoked keys don't
    match. Each use is recorded in last_used_at, at most every 5 minutes.
    """
    if not raw_key:
        return None
    key_hash = hashlib.sha256(raw_key.encode()).hexdigest()
    client = get_supabase_client()
    response = (
        client.table("ingest_keys")
        .select("id, organization_id, revoked_at, last_used_at")
        .eq("key_hash", key_hash)
        .limit(1)
        .execute()
    )
    if not response.data:
        return None
    key = response.data[0]
    _record_key_use(client, key)
    return None if key["revoked_at"] else key["organization_id"]


def _record_key_use(client, key):
    now = datetime.now(timezone.utc)
    last_used = key.get("last_used_at")
    if last_used and now - datetime.fromisoformat(last_used) < timedelta(minutes=5):
        return
    try:
        client.table("ingest_keys").update({"last_used_at": now.isoformat()}).eq("id", key["id"]).execute()
    except Exception:
        logging.getLogger(__name__).exception("Could not record ingest key use")


def _obj(value):
    return value if isinstance(value, dict) else {}


def _severity_from_rule_level(rule_level):
    try:
        level = int(rule_level)
    except (TypeError, ValueError):
        return "low"
    if level >= 12:
        return "critical"
    if level >= 8:
        return "high"
    if level >= 4:
        return "medium"
    return "low"


def alert_source_payload(alert: dict) -> dict:
    """The alert fields kept in Supabase.

    A fixed list, not the raw event: enough for the dashboard and for a
    later re-review, without full log lines that can hold secrets or
    personal data.
    """
    rule = _obj(alert.get("rule"))
    data = _obj(alert.get("data"))
    suricata = _obj(data.get("alert"))
    agent = _obj(alert.get("agent"))
    source_event_id = alert.get("id")
    payload = {
        "event_id": str(source_event_id) if source_event_id is not None else None,
        "timestamp": alert.get("timestamp"),
        "rule_id": rule.get("id"),
        "rule_level": rule.get("level"),
        "rule_groups": rule.get("groups"),
        "fired_times": rule.get("firedtimes"),
        "description": rule.get("description"),
        "signature_id": suricata.get("signature_id"),
        "signature": suricata.get("signature"),
        "suricata_severity": suricata.get("severity"),
        "src_ip": data.get("src_ip") or data.get("srcip"),
        "src_port": data.get("src_port") or data.get("srcport"),
        "dest_ip": data.get("dest_ip") or data.get("dstip"),
        "dest_port": data.get("dest_port") or data.get("dstport"),
        "proto": data.get("proto") or data.get("protocol"),
        "agent_id": agent.get("id"),
        "agent_name": agent.get("name"),
        "manager_name": _obj(alert.get("manager")).get("name"),
        "decoder_name": _obj(alert.get("decoder")).get("name"),
        "location": alert.get("location"),
    }
    return {key: value for key, value in payload.items() if value is not None}


def store_pending_alert(organization_id: str, alert: dict):
    """Store an alert before it is reviewed.

    Returns (alert_id, inserted). inserted is False when the business
    already has this event id, so the caller can skip a second review.
    """
    rule = _obj(alert.get("rule"))
    title = rule.get("description") or alert.get("description") or "Security alert"
    source_event_id = alert.get("id")
    if source_event_id is not None:
        source_event_id = str(source_event_id)

    response = get_supabase_client().rpc(
        "ingest_alert",
        {
            "p_organization_id": organization_id,
            "p_source_event_id": source_event_id,
            "p_title": str(title)[:500],
            "p_severity": _severity_from_rule_level(rule.get("level")),
            "p_source_payload": alert_source_payload(alert),
            "p_ai_review": {},
        },
    ).execute()

    if not response.data or not response.data[0].get("alert_id"):
        raise RuntimeError("Supabase did not return an ID for the stored alert")
    row = response.data[0]
    return row["alert_id"], bool(row.get("inserted", True))


def alert_review_status(organization_id: str, alert_id: str) -> str | None:
    """review_status of a stored alert ('pending', 'done', ...), or None."""
    response = (
        get_supabase_client()
        .table("alerts")
        .select("review_status")
        .eq("id", alert_id)
        .eq("organization_id", organization_id)
        .limit(1)
        .execute()
    )
    return response.data[0]["review_status"] if response.data else None


MAX_REVIEW_ATTEMPTS = 5
STUCK_PENDING = timedelta(minutes=10)


def alerts_due_for_review(limit: int) -> list[dict]:
    """Alerts, across every business, whose review should be tried again.

    rate_limited ones; unavailable ones with fewer than MAX_REVIEW_ATTEMPTS
    failed retries; and pending ones older than STUCK_PENDING (the request
    reviewing them died). Least recently updated first, so a business that
    is still over its hourly limit can't hold back everyone else.

    Alerts without a stored description are skipped: those stored before
    21 Nov 2026 kept only event_id and timestamp, and reviewing them would
    send Groq an almost empty alert and save a meaningless "done" review.
    """
    stuck_before = (datetime.now(timezone.utc) - STUCK_PENDING).strftime("%Y-%m-%dT%H:%M:%SZ")
    response = (
        get_supabase_client()
        .table("alerts")
        .select("id, organization_id, source_payload, review_status, review_attempts")
        .or_(
            "review_status.eq.rate_limited,"
            f"and(review_status.eq.unavailable,review_attempts.lt.{MAX_REVIEW_ATTEMPTS}),"
            f"and(review_status.eq.pending,created_at.lt.{stuck_before})"
        )
        .not_.is_("source_payload->>description", "null")
        .order("updated_at")
        .limit(limit)
        .execute()
    )
    return response.data or []


def count_failed_review_attempt(row: dict):
    """Record one more failed retry, so a review that always fails stops."""
    (
        get_supabase_client()
        .table("alerts")
        .update({"review_attempts": (row.get("review_attempts") or 0) + 1})
        .eq("id", row["id"])
        .eq("organization_id", row["organization_id"])
        .execute()
    )


def record_review(organization_id: str, alert_id: str, review: dict, review_status: str):
    """Save the review outcome on a stored alert."""
    update = {"ai_review": review, "review_status": review_status}
    if review_status == "done":
        update["reviewed_at"] = datetime.now(timezone.utc).isoformat()
        if review.get("severity") in SEVERITIES:
            update["severity"] = review["severity"]
        if review.get("headline"):
            update["title"] = str(review["headline"])[:500]
    (
        get_supabase_client()
        .table("alerts")
        .update(update)
        .eq("id", alert_id)
        .eq("organization_id", organization_id)
        .execute()
    )


def reviews_in_last_hour(organization_id: str) -> int:
    since = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
    response = (
        get_supabase_client()
        .table("alerts")
        .select("id", count="exact", head=True)
        .eq("organization_id", organization_id)
        .eq("review_status", "done")
        .gte("reviewed_at", since)
        .execute()
    )
    return response.count or 0


def _open_finding_keys(client, organization_id: str, assets: set) -> set:
    """(asset, title) of findings already open or acknowledged for these assets."""
    response = (
        client.table("vulnerability_findings")
        .select("asset, title")
        .eq("organization_id", organization_id)
        .neq("status", "resolved")
        .in_("asset", sorted(assets))
        .execute()
    )
    return {(row["asset"], row["title"]) for row in response.data or []}


def persist_findings(organization_id: str, findings: list[dict]) -> int:
    """Store new findings and return how many were added.

    A finding already open for the same asset and title (from an earlier
    scan) is skipped, so rescanning a website doesn't duplicate it.
    """
    rows, seen = [], set()
    for finding in findings:
        row = {
            "organization_id": organization_id,
            "asset": str(finding.get("target") or finding.get("asset"))[:500],
            "title": str(finding["title"])[:500],
            "cve_id": finding.get("cve_id"),
            "severity": finding["severity"],
            "details": finding,
        }
        if (row["asset"], row["title"]) not in seen:
            seen.add((row["asset"], row["title"]))
            rows.append(row)

    if not rows:
        return 0

    client = get_supabase_client()
    existing = _open_finding_keys(client, organization_id, {row["asset"] for row in rows})
    rows = [row for row in rows if (row["asset"], row["title"]) not in existing]
    if not rows:
        return 0

    response = client.table("vulnerability_findings").insert(rows).execute()
    if response.data is None or len(response.data) != len(rows):
        raise RuntimeError("Supabase did not confirm every vulnerability finding")
    return len(response.data)
