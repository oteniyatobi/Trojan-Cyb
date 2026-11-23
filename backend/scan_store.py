import ipaddress
import os
import socket
from datetime import datetime, timedelta, timezone
from urllib.parse import urlsplit

import requests
from postgrest.exceptions import APIError

from supabase_store import get_supabase_client, get_user_client, persist_findings

TARGET_COLUMNS = "id, organization_id, url, hostname, verified_at, created_at"
SCAN_COLUMNS = (
    "id, organization_id, target_id, status, findings_count, error, created_at, started_at, finished_at"
)
SCAN_TIMEOUT = timedelta(minutes=45)
SCANS_PER_DAY = 10
DEFAULT_REPOSITORY = "oteniyatobi/Trojan-Cyb"


class ScanError(Exception):
    def __init__(self, message, status=400):
        super().__init__(message)
        self.status = status


def _now():
    return datetime.now(timezone.utc)


def _rejected(error: APIError):
    if error.code == "42501":
        return ScanError("Only organization admins can do this.", 403)
    if error.code == "23505":
        return ScanError("This website has already been added.", 409)
    return error


def normalize_url(raw: str) -> tuple[str, str]:
    value = (raw or "").strip()
    if "://" not in value:
        value = f"https://{value}"
    parts = urlsplit(value)
    hostname = (parts.hostname or "").lower().rstrip(".")
    if parts.scheme not in ("http", "https") or not hostname:
        raise ScanError("Enter a website address like https://example.com.")
    try:
        ipaddress.ip_address(hostname)
        raise ScanError("Enter a domain name, not an IP address.")
    except ValueError:
        pass
    if "." not in hostname or hostname.endswith((".local", ".internal", ".localhost")):
        raise ScanError("Enter a public website address.")
    origin = f"{parts.scheme}://{hostname}"
    if parts.port:
        origin += f":{parts.port}"
    return origin, hostname


def _public_host(hostname: str) -> bool:
    try:
        addresses = {info[4][0] for info in socket.getaddrinfo(hostname, None)}
    except socket.gaierror:
        return False
    return bool(addresses) and all(ipaddress.ip_address(a).is_global for a in addresses)


def _expire_stale_scans(organization_id: str):
    cutoff = (_now() - SCAN_TIMEOUT).isoformat()
    (
        get_supabase_client().table("scans")
        .update({"status": "failed", "error": "The scan timed out.", "finished_at": _now().isoformat()})
        .eq("organization_id", organization_id)
        .in_("status", ["queued", "running"])
        .lt("created_at", cutoff)
        .execute()
    )


def list_scans(token: str, organization_id: str) -> dict:
    _expire_stale_scans(organization_id)
    client = get_user_client(token)
    targets = (
        client.table("scan_targets").select(TARGET_COLUMNS)
        .eq("organization_id", organization_id).order("created_at").execute()
    )
    scans = (
        client.table("scans").select(SCAN_COLUMNS)
        .eq("organization_id", organization_id).order("created_at", desc=True).limit(50).execute()
    )
    return {"targets": targets.data or [], "scans": scans.data or []}


def add_target(token: str, organization_id: str, raw_url: str, confirmed: bool) -> dict:
    if confirmed is not True:
        raise ScanError("Confirm you own this website or have permission to scan it.")
    url, hostname = normalize_url(raw_url)
    if not _public_host(hostname):
        raise ScanError("That website isn't reachable on the public internet.")
    try:
        response = (
            get_user_client(token).table("scan_targets")
            .insert({"organization_id": organization_id, "url": url, "hostname": hostname})
            .execute()
        )
    except APIError as error:
        raise _rejected(error)
    target = response.data[0]
    confirmed_at = (
        get_supabase_client().table("scan_targets")
        .update({"verified_at": _now().isoformat()}).eq("id", target["id"]).execute()
    )
    return confirmed_at.data[0]


def _visible_target(token: str, target_id: str) -> dict:
    response = (
        get_user_client(token).table("scan_targets").select(TARGET_COLUMNS)
        .eq("id", target_id).limit(1).execute()
    )
    if not response.data:
        raise ScanError("Website not found.", 404)
    return response.data[0]


def remove_target(token: str, target_id: str):
    _visible_target(token, target_id)
    response = get_user_client(token).table("scan_targets").delete().eq("id", target_id).execute()
    if not response.data:
        raise ScanError("Only organization admins can do this.", 403)


def _dispatch(scan_id: str):
    token = os.getenv("GITHUB_DISPATCH_TOKEN")
    if not token:
        raise ScanError("Scanning isn't set up yet (GITHUB_DISPATCH_TOKEN is missing).", 503)
    repository = os.getenv("SCAN_REPOSITORY", DEFAULT_REPOSITORY)
    response = requests.post(
        f"https://api.github.com/repos/{repository}/actions/workflows/scan.yml/dispatches",
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
        },
        json={"ref": os.getenv("SCAN_REF", "main"), "inputs": {"scan_id": scan_id}},
        timeout=15,
    )
    if response.status_code != 204:
        raise ScanError("Couldn't start the scan worker.", 502)


def _finish(scan_id: str, status: str, findings_count=None, error=None):
    (
        get_supabase_client().table("scans")
        .update({
            "status": status,
            "findings_count": findings_count,
            "error": error,
            "finished_at": _now().isoformat(),
        })
        .eq("id", scan_id).execute()
    )


def start_scan(token: str, target_id: str) -> dict:
    target = _visible_target(token, target_id)
    if not target["verified_at"]:
        raise ScanError("Remove this website and add it again to confirm you may scan it.")
    organization_id = target["organization_id"]
    _expire_stale_scans(organization_id)
    service = get_supabase_client()
    active = (
        service.table("scans").select("id").eq("target_id", target_id)
        .in_("status", ["queued", "running"]).limit(1).execute()
    )
    if active.data:
        raise ScanError("A scan of this website is already running.", 409)
    recent = (
        service.table("scans").select("id", count="exact", head=True)
        .eq("organization_id", organization_id)
        .gte("created_at", (_now() - timedelta(days=1)).isoformat()).execute()
    )
    if (recent.count or 0) >= SCANS_PER_DAY:
        raise ScanError(f"Limit reached: {SCANS_PER_DAY} scans per day.", 429)
    try:
        response = (
            get_user_client(token).table("scans")
            .insert({"organization_id": organization_id, "target_id": target_id}).execute()
        )
    except APIError as error:
        raise _rejected(error)
    scan = response.data[0]
    try:
        _dispatch(scan["id"])
    except ScanError as error:
        _finish(scan["id"], "failed", error=str(error))
        raise
    except requests.RequestException:
        _finish(scan["id"], "failed", error="Couldn't start the scan worker.")
        raise ScanError("Couldn't start the scan worker.", 502)
    return scan


def claim_scan(scan_id: str) -> dict:
    service = get_supabase_client()
    response = (
        service.table("scans").update({"status": "running", "started_at": _now().isoformat()})
        .eq("id", scan_id).eq("status", "queued").execute()
    )
    if not response.data:
        raise ScanError("Scan is not waiting to run.", 409)
    target = (
        service.table("scan_targets").select("url, hostname")
        .eq("id", response.data[0]["target_id"]).limit(1).execute()
    )
    if not target.data:
        _finish(scan_id, "failed", error="The website was removed.")
        raise ScanError("The website was removed.", 409)
    return target.data[0]


def complete_scan(scan_id: str, findings: list, error: str | None, warning: str | None = None) -> int:
    service = get_supabase_client()
    scan = (
        service.table("scans").select("organization_id, status")
        .eq("id", scan_id).limit(1).execute()
    )
    if not scan.data or scan.data[0]["status"] != "running":
        raise ScanError("Scan is not running.", 409)
    for finding in findings:
        finding["scan_id"] = scan_id
    stored = persist_findings(scan.data[0]["organization_id"], findings) if findings else 0
    _finish(scan_id, "failed" if error else "completed", findings_count=stored, error=error or warning)
    return stored
