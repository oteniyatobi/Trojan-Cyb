import os
import uuid
from functools import lru_cache

from supabase import Client, create_client


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
    "source_payload, ai_review, created_at"
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


def persist_alert(alert: dict, review: dict) -> str:
    organization_id = get_organization_id()
    severity = review.get("severity")
    rule = alert.get("rule")
    rule_level = rule.get("level") if isinstance(rule, dict) else None
    if severity not in {"low", "medium", "high", "critical"} and rule_level is not None:
        try:
            level = int(rule_level)
            if level >= 12:
                severity = "critical"
            elif level >= 8:
                severity = "high"
            elif level >= 4:
                severity = "medium"
            else:
                severity = "low"
        except (TypeError, ValueError):
            severity = None
    if severity not in {"low", "medium", "high", "critical"}:
        severity = "low"
    title = review.get("headline") or (
        rule.get("description") if isinstance(rule, dict) else None
    ) or alert.get("description") or "Security alert"
    source_event_id = alert.get("id")
    if source_event_id is not None:
        source_event_id = str(source_event_id)
    source_reference = {
        "event_id": source_event_id,
        "timestamp": alert.get("timestamp"),
    }

    response = get_supabase_client().rpc(
        "ingest_alert",
        {
            "p_organization_id": organization_id,
            "p_source_event_id": source_event_id,
            "p_title": str(title)[:500],
            "p_severity": severity,
            "p_source_payload": source_reference,
            "p_ai_review": review,
        },
    ).execute()

    if not response.data or not response.data[0].get("alert_id"):
        raise RuntimeError("Supabase did not return an ID for the stored alert")
    return response.data[0]["alert_id"]


def persist_findings(findings: list[dict]) -> int:
    organization_id = get_organization_id()
    rows = []
    for finding in findings:
        severity = finding["severity"]
        rows.append({
            "organization_id": organization_id,
            "asset": str(finding.get("target") or finding.get("asset"))[:500],
            "title": str(finding["title"])[:500],
            "cve_id": finding.get("cve_id"),
            "severity": severity,
            "details": finding,
        })

    if not rows:
        return 0

    response = get_supabase_client().table("vulnerability_findings").insert(rows).execute()
    if response.data is None or len(response.data) != len(rows):
        raise RuntimeError("Supabase did not confirm every vulnerability finding")
    return len(response.data)
