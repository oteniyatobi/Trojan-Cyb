import hashlib
import os
import re
import secrets
from datetime import datetime, timezone

from supabase_store import get_supabase_client, get_user_client

ROLES = ("org_admin", "analyst", "viewer")
EMAIL = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


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
        "id, organization_id, label, created_at, revoked_at, last_used_at"
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


def _invite(email: str) -> str:
    redirect = os.getenv("TROJAN_APP_URL", "https://trojan-cyb.vercel.app")
    response = get_supabase_client().auth.admin.invite_user_by_email(email, {"redirect_to": redirect})
    return response.user.id


def add_member(actor_id: str, organization_id: str, email: str, role: str) -> dict:
    email = (email or "").strip().lower()
    if not EMAIL.match(email):
        raise AdminError("Enter a valid email address")
    if role not in ROLES:
        raise AdminError("Role must be org_admin, analyst or viewer")
    client = get_supabase_client()
    if not client.table("organizations").select("id").eq("id", organization_id).limit(1).execute().data:
        raise AdminError("Organization not found", 404)

    user_id = _user_id_for_email(email)
    invited = False
    if not user_id:
        try:
            user_id = _invite(email)
        except Exception:
            raise AdminError("Couldn't send an invite to that email. Try again later.", 502)
        invited = True

    existing = (
        client.table("organization_memberships").select("role")
        .eq("organization_id", organization_id).eq("user_id", user_id).limit(1).execute().data
    )
    if existing:
        raise AdminError(f"{email} is already in this organization", 409)
    client.table("organization_memberships").insert({
        "organization_id": organization_id,
        "user_id": user_id,
        "role": role,
    }).execute()
    _audit(actor_id, organization_id, "membership.added", "membership", user_id,
           {"email": email, "role": role, "invited": invited})
    return {"user_id": user_id, "email": email, "role": role, "invited": invited}


def organization_members(organization_id: str) -> list[dict]:
    client = get_supabase_client()
    rows = (
        client.table("organization_memberships").select("user_id, role, created_at")
        .eq("organization_id", organization_id).order("created_at").execute().data
    )
    users = _users_by_id()
    return [
        {
            "user_id": row["user_id"],
            "email": users[row["user_id"]].email if row["user_id"] in users else None,
            "role": row["role"],
            "joined_at": row["created_at"],
        }
        for row in rows
    ]


def organization_role(access_token: str, organization_id: str) -> tuple[str, str]:
    response = get_supabase_client().auth.get_user(access_token)
    user = response.user if response else None
    if not user:
        raise AdminError("Sign in required", 401)
    membership = (
        get_supabase_client().table("organization_memberships").select("role")
        .eq("organization_id", organization_id).eq("user_id", user.id).limit(1).execute().data
    )
    if not membership:
        raise AdminError("You are not a member of this organization", 403)
    return user.id, membership[0]["role"]


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


def overview() -> dict:
    client = get_supabase_client()

    def count(table, **filters):
        query = client.table(table).select("id", count="exact", head=True)
        for column, value in filters.items():
            query = query.eq(column, value)
        return query.execute().count or 0

    organizations = client.table("organizations").select("id, name").order("name").execute().data
    latest = []
    for organization in organizations:
        rows = (
            client.table("alerts")
            .select("title, severity, created_at")
            .eq("organization_id", organization["id"])
            .order("created_at", desc=True)
            .limit(1)
            .execute()
            .data
        )
        latest.append({
            "organization_id": organization["id"],
            "organization": organization["name"],
            "alerts": count("alerts", organization_id=organization["id"]),
            "latest_alert": rows[0] if rows else None,
        })
    active_keys = (
        client.table("ingest_keys").select("id", count="exact", head=True)
        .is_("revoked_at", "null").execute().count or 0
    )
    return {
        "organizations": len(organizations),
        "users": len(_users_by_id()),
        "alerts": count("alerts"),
        "open_critical_alerts": count("alerts", severity="critical", status="open"),
        "active_keys": active_keys,
        "by_organization": latest,
    }


def list_users() -> list[dict]:
    client = get_supabase_client()
    names = {row["id"]: row["name"] for row in client.table("organizations").select("id, name").execute().data}
    admins = {row["user_id"] for row in client.table("platform_admins").select("user_id").execute().data}
    memberships = {}
    for row in client.table("organization_memberships").select("organization_id, user_id, role").execute().data:
        memberships.setdefault(row["user_id"], []).append({
            "organization_id": row["organization_id"],
            "organization": names.get(row["organization_id"], "Unknown"),
            "role": row["role"],
        })
    users = []
    for user in _users_by_id().values():
        users.append({
            "id": user.id,
            "email": user.email,
            "created_at": str(user.created_at) if user.created_at else None,
            "last_sign_in_at": str(user.last_sign_in_at) if user.last_sign_in_at else None,
            "platform_admin": user.id in admins,
            "organizations": memberships.get(user.id, []),
        })
    return sorted(users, key=lambda user: (user["email"] or "").lower())


def list_platform_admins() -> list[dict]:
    rows = get_supabase_client().table("platform_admins").select("user_id, added_at, added_by").execute().data
    users = _users_by_id()

    def email(user_id):
        user = users.get(user_id)
        return user.email if user else None

    return [
        {**row, "email": email(row["user_id"]), "added_by_email": email(row["added_by"])}
        for row in rows
    ]


def add_platform_admin(actor_id: str, email: str) -> dict:
    user_id = _user_id_for_email(email)
    if not user_id:
        raise AdminError("No TROJAN account uses that email. Ask them to sign up first.", 404)
    client = get_supabase_client()
    if client.table("platform_admins").select("user_id").eq("user_id", user_id).execute().data:
        raise AdminError("That account is already a TROJAN admin", 409)
    client.table("platform_admins").insert({"user_id": user_id, "added_by": actor_id}).execute()
    _audit(actor_id, None, "platform_admin.added", "user", user_id, {"email": email.strip().lower()})
    return {"user_id": user_id}


def remove_platform_admin(actor_id: str, user_id: str) -> None:
    if user_id == actor_id:
        raise AdminError("You can't remove your own admin access", 409)
    response = get_supabase_client().table("platform_admins").delete().eq("user_id", user_id).execute()
    if not response.data:
        raise AdminError("That account is not a TROJAN admin", 404)
    _audit(actor_id, None, "platform_admin.removed", "user", user_id)


def audit_log(limit: int) -> list[dict]:
    client = get_supabase_client()
    rows = (
        client.table("audit_logs")
        .select("id, organization_id, actor_id, action, entity_type, entity_id, details, created_at")
        .order("created_at", desc=True)
        .limit(limit)
        .execute()
        .data
    )
    names = {row["id"]: row["name"] for row in client.table("organizations").select("id, name").execute().data}
    users = _users_by_id()
    for row in rows:
        actor = users.get(row["actor_id"])
        row["actor_email"] = actor.email if actor else None
        row["organization"] = names.get(row["organization_id"])
    return rows
