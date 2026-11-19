import hashlib
import secrets
from datetime import datetime, timezone

from supabase_store import get_supabase_client, get_user_client

ROLES = ("org_admin", "analyst", "viewer")


class AdminError(Exception):
    def __init__(self, message, status=400):
        super().__init__(message)
        self.status = status


def platform_admin_id(access_token: str) -> str | None:
    allowed = get_user_client(access_token).rpc("current_user_is_platform_admin").execute()
    if allowed.data is not True:
        return None
    response = get_supabase_client().auth.get_user(access_token)
    return response.user.id if response and response.user else None


def _users_by_id() -> dict:
    users = {}
    page = 1
    while True:
        batch = get_supabase_client().auth.admin.list_users(page=page, per_page=1000)
        for user in batch:
            users[user.id] = user
        if len(batch) < 1000:
            return users
        page += 1


def _user_id_for_email(email: str) -> str | None:
    email = email.strip().lower()
    for user in _users_by_id().values():
        if (user.email or "").lower() == email:
            return user.id
    return None


def _audit(actor_id, organization_id, action, entity_type, entity_id, details=None):
    get_supabase_client().table("audit_logs").insert({
        "actor_id": actor_id,
        "organization_id": organization_id,
        "action": action,
        "entity_type": entity_type,
        "entity_id": entity_id,
        "details": details or {},
    }).execute()


def list_organizations() -> list[dict]:
    client = get_supabase_client()
    organizations = client.table("organizations").select("id, name, created_at").order("name").execute().data
    memberships = client.table("organization_memberships").select(
        "organization_id, user_id, role, created_at"
    ).execute().data
    profiles = {
        row["id"]: row["display_name"]
        for row in client.table("profiles").select("id, display_name").execute().data
    }
    keys = client.table("ingest_keys").select(
        "id, organization_id, label, created_at, revoked_at"
    ).order("created_at", desc=True).execute().data
    alert_counts = {
        organization["id"]: client.table("alerts").select("id", count="exact", head=True)
        .eq("organization_id", organization["id"]).execute().count or 0
        for organization in organizations
    }
    users = _users_by_id()

    result = []
    for organization in organizations:
        members = []
        for membership in memberships:
            if membership["organization_id"] != organization["id"]:
                continue
            user = users.get(membership["user_id"])
            members.append({
                "user_id": membership["user_id"],
                "email": user.email if user else None,
                "display_name": profiles.get(membership["user_id"], ""),
                "role": membership["role"],
                "joined_at": membership["created_at"],
            })
        result.append({
            **organization,
            "members": members,
            "alert_count": alert_counts[organization["id"]],
            "keys": [key for key in keys if key["organization_id"] == organization["id"]],
        })
    return result


def create_organization(actor_id: str, name: str, admin_email: str) -> dict:
    name = name.strip()
    if not name or len(name) > 120:
        raise AdminError("Organization name must be 1 to 120 characters")
    admin_id = None
    if admin_email.strip():
        admin_id = _user_id_for_email(admin_email)
        if not admin_id:
            raise AdminError("No TROJAN account uses that email. Ask them to sign up first.", 404)

    client = get_supabase_client()
    organization = client.table("organizations").insert({"name": name}).execute().data[0]
    if admin_id:
        client.table("organization_memberships").insert({
            "organization_id": organization["id"],
            "user_id": admin_id,
            "role": "org_admin",
        }).execute()
    _audit(actor_id, organization["id"], "organization.created", "organization", organization["id"],
           {"name": name, "admin_user_id": admin_id})
    return organization


def set_member_role(actor_id: str, organization_id: str, user_id: str, role: str) -> None:
    if role not in ROLES:
        raise AdminError("Role must be org_admin, analyst or viewer")
    response = (
        get_supabase_client()
        .table("organization_memberships")
        .update({"role": role})
        .eq("organization_id", organization_id)
        .eq("user_id", user_id)
        .execute()
    )
    if not response.data:
        raise AdminError("That user is not a member of this organization", 404)
    _audit(actor_id, organization_id, "membership.role_changed", "membership", user_id, {"role": role})


def create_ingest_key(actor_id: str, organization_id: str, label: str) -> dict:
    client = get_supabase_client()
    exists = client.table("organizations").select("id").eq("id", organization_id).execute().data
    if not exists:
        raise AdminError("Organization not found", 404)
    raw_key = secrets.token_urlsafe(32)
    row = client.table("ingest_keys").insert({
        "organization_id": organization_id,
        "key_hash": hashlib.sha256(raw_key.encode()).hexdigest(),
        "label": label.strip()[:120],
    }).execute().data[0]
    _audit(actor_id, organization_id, "ingest_key.created", "ingest_key", row["id"], {"label": row["label"]})
    return {"id": row["id"], "label": row["label"], "created_at": row["created_at"], "key": raw_key}


def revoke_ingest_key(actor_id: str, key_id: str) -> None:
    response = (
        get_supabase_client()
        .table("ingest_keys")
        .update({"revoked_at": datetime.now(timezone.utc).isoformat()})
        .eq("id", key_id)
        .is_("revoked_at", "null")
        .execute()
    )
    if not response.data:
        raise AdminError("Key not found or already revoked", 404)
    _audit(actor_id, response.data[0]["organization_id"], "ingest_key.revoked", "ingest_key", key_id)
