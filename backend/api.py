import hmac
import json
import os
import uuid

from dotenv import load_dotenv
from flask import Flask, g, jsonify, request
import admin_store
import scan_store
from groq_review import check_review, get_review
from supabase_store import (
    SupabaseConfigurationError,
    alert_review_status,
    alert_source_payload,
    alerts_due_for_review,
    count_failed_review_attempt,
    get_alert,
    get_organization_id,
    list_alerts,
    list_findings,
    organization_for_ingest_key,
    persist_findings,
    record_review,
    reviews_in_last_hour,
    store_pending_alert,
)

load_dotenv()

app = Flask(__name__)
MAX_ALERTS = 1000


def resolve_ingest_organization():
    """Set g.organization_id from the bearer token, or return an error response.

    The token is either TROJAN_INGESTION_API_KEY (the single-install key,
    mapped to TROJAN_ORGANIZATION_ID) or a per-business key in ingest_keys.
    The caller never chooses the business.
    """
    authorization = request.headers.get("Authorization", "")
    if not authorization.startswith("Bearer "):
        return jsonify({"error": "Unauthorized"}), 401
    supplied_key = authorization.removeprefix("Bearer ")

    try:
        install_key = os.getenv("TROJAN_INGESTION_API_KEY")
        if install_key and hmac.compare_digest(supplied_key, install_key):
            g.organization_id = get_organization_id()
            return None
        organization_id = organization_for_ingest_key(supplied_key)
    except SupabaseConfigurationError:
        app.logger.exception("Ingestion is not configured")
        return jsonify({"error": "Ingestion API is not configured"}), 503
    except Exception:
        app.logger.exception("Ingest key lookup failed")
        return jsonify({"error": "Ingest key lookup failed"}), 503

    if organization_id is None:
        return jsonify({"error": "Unauthorized"}), 401
    g.organization_id = str(organization_id)
    return None


def user_token():
    authorization = request.headers.get("Authorization", "")
    if not authorization.startswith("Bearer "):
        return None
    return authorization.removeprefix("Bearer ").strip() or None


def valid_uuid(value):
    try:
        return str(uuid.UUID(str(value)))
    except ValueError:
        return None


def read_limit():
    try:
        return max(1, min(int(request.args.get("limit", 200)), MAX_ALERTS))
    except ValueError:
        return 200


def read_rows(loader, *args):
    token = user_token()
    if not token:
        return jsonify({"error": "Sign in required"}), 401
    try:
        return loader(token, *args)
    except SupabaseConfigurationError as error:
        return jsonify({"error": str(error)}), 503
    except Exception:
        app.logger.exception("Supabase read failed")
        return jsonify({"error": "Could not read from Supabase"}), 502


@app.route("/v1/alerts", methods=["GET"])
def alerts_list():
    organization_id = valid_uuid(request.args.get("organization_id", ""))
    if not organization_id:
        return jsonify({"error": "A valid organization_id is required"}), 422
    rows = read_rows(list_alerts, organization_id, read_limit())
    if isinstance(rows, tuple):
        return rows
    return jsonify({"alerts": rows}), 200


@app.route("/v1/alerts/<alert_id>", methods=["GET"])
def alert_detail(alert_id):
    alert_id = valid_uuid(alert_id)
    if not alert_id:
        return jsonify({"error": "Alert not found"}), 404
    row = read_rows(get_alert, alert_id)
    if isinstance(row, tuple):
        return row
    if row is None:
        return jsonify({"error": "Alert not found"}), 404
    return jsonify(row), 200


@app.route("/v1/findings", methods=["GET"])
def findings_list():
    organization_id = valid_uuid(request.args.get("organization_id", ""))
    if not organization_id:
        return jsonify({"error": "A valid organization_id is required"}), 422
    rows = read_rows(list_findings, organization_id, read_limit())
    if isinstance(rows, tuple):
        return rows
    return jsonify({"findings": rows}), 200


def reviews_per_hour_limit():
    return int(os.getenv("GROQ_REVIEWS_PER_HOUR", "100"))


def review_alert(payload):
    """Ask Groq for a review of the stored alert fields. Returns (review, review_status).

    Groq gets only what is kept in source_payload, never the raw Wazuh
    event, so log lines that can hold passwords don't leave TROJAN and the
    review matches what the dashboard shows.
    """
    try:
        review = get_review(json.dumps(payload))
        problems = check_review(review)
    except Exception as error:
        app.logger.exception("Groq analysis failed")
        problems = [str(error)]
        review = {}
    if problems:
        return {"status": "unavailable", "problems": problems}, "unavailable"
    review["status"] = "done"
    return review, "done"


def review_stored_alert(organization_id, alert_id, payload):
    """Review a stored alert's fields within the hourly limit and save the outcome."""
    limit = reviews_per_hour_limit()
    if reviews_in_last_hour(organization_id) >= limit:
        review = {"status": "rate_limited", "limit_per_hour": limit}
        review_status = "rate_limited"
    else:
        review, review_status = review_alert(payload)
    record_review(organization_id, alert_id, review, review_status)
    return review, review_status


def needs_another_review(organization_id, alert_id):
    """True if a re-sent alert's first review didn't finish (pending,
    unavailable or rate limited), so resending it retries the review."""
    try:
        return alert_review_status(organization_id, alert_id) not in ("done", None)
    except Exception:
        app.logger.exception("Could not read the review status of alert %s", alert_id)
        return False


def admin_action(action):
    token = user_token()
    if not token:
        return jsonify({"error": "Sign in required"}), 401
    try:
        actor_id = admin_store.platform_admin_id(token)
        if not actor_id:
            return jsonify({"error": "TROJAN platform admin access required"}), 403
        return action(actor_id)
    except admin_store.AdminError as error:
        return jsonify({"error": str(error)}), error.status
    except SupabaseConfigurationError as error:
        return jsonify({"error": str(error)}), 503
    except Exception:
        app.logger.exception("Admin request failed")
        return jsonify({"error": "Admin request failed"}), 502


def json_body():
    body = request.get_json(silent=True)
    return body if isinstance(body, dict) else {}


@app.route("/v1/admin/organizations", methods=["GET"])
def admin_organizations():
    return admin_action(lambda _actor: (
        jsonify({"organizations": admin_store.list_organizations()}), 200
    ))


@app.route("/v1/admin/organizations", methods=["POST"])
def admin_create_organization():
    body = json_body()
    return admin_action(lambda actor: (
        jsonify(admin_store.create_organization(
            actor, str(body.get("name", "")), str(body.get("admin_email", "")),
        )),
        201,
    ))


@app.route("/v1/admin/organizations/<organization_id>/members/<user_id>", methods=["PATCH"])
def admin_set_role(organization_id, user_id):
    if not valid_uuid(organization_id) or not valid_uuid(user_id):
        return jsonify({"error": "Member not found"}), 404
    body = json_body()

    def action(actor):
        admin_store.set_member_role(actor, organization_id, user_id, str(body.get("role", "")))
        return jsonify({"role": body.get("role")}), 200
    return admin_action(action)


@app.route("/v1/admin/organizations/<organization_id>/keys", methods=["POST"])
def admin_create_key(organization_id):
    if not valid_uuid(organization_id):
        return jsonify({"error": "Organization not found"}), 404
    body = json_body()
    return admin_action(lambda actor: (
        jsonify(admin_store.create_ingest_key(actor, organization_id, str(body.get("label", "")))),
        201,
    ))


@app.route("/v1/admin/organizations/<organization_id>/members", methods=["POST"])
def admin_add_member(organization_id):
    if not valid_uuid(organization_id):
        return jsonify({"error": "Organization not found"}), 404
    body = json_body()
    return admin_action(lambda actor: (
        jsonify(admin_store.add_member(
            actor, organization_id, str(body.get("email", "")), str(body.get("role", "viewer")),
        )),
        201,
    ))


def member_action(organization_id, action):
    token = user_token()
    if not token:
        return jsonify({"error": "Sign in required"}), 401
    if not valid_uuid(organization_id):
        return jsonify({"error": "Organization not found"}), 404
    try:
        user_id, role = admin_store.organization_role(token, organization_id)
        return action(user_id, role)
    except admin_store.AdminError as error:
        return jsonify({"error": str(error)}), error.status
    except SupabaseConfigurationError as error:
        return jsonify({"error": str(error)}), 503
    except Exception:
        app.logger.exception("Member request failed")
        return jsonify({"error": "Member request failed"}), 502


@app.route("/v1/organizations/<organization_id>/members", methods=["GET"])
def members_list(organization_id):
    return member_action(organization_id, lambda _user, _role: (
        jsonify({"members": admin_store.organization_members(organization_id)}), 200
    ))


@app.route("/v1/organizations/<organization_id>/members", methods=["POST"])
def members_add(organization_id):
    body = json_body()

    def add(user_id, role):
        if role != "org_admin":
            return jsonify({"error": "Only organization admins can add people"}), 403
        return jsonify(admin_store.add_member(
            user_id, organization_id, str(body.get("email", "")), str(body.get("role", "viewer")),
        )), 201
    return member_action(organization_id, add)


@app.route("/v1/admin/keys/<key_id>/revoke", methods=["POST"])
def admin_revoke_key(key_id):
    if not valid_uuid(key_id):
        return jsonify({"error": "Key not found"}), 404

    def action(actor):
        admin_store.revoke_ingest_key(actor, key_id)
        return jsonify({"revoked": True}), 200
    return admin_action(action)


@app.route("/v1/admin/overview", methods=["GET"])
def admin_overview():
    return admin_action(lambda _actor: (jsonify(admin_store.overview()), 200))


@app.route("/v1/admin/users", methods=["GET"])
def admin_users():
    return admin_action(lambda _actor: (jsonify({"users": admin_store.list_users()}), 200))


@app.route("/v1/admin/platform-admins", methods=["GET"])
def admin_platform_admins():
    return admin_action(lambda _actor: (
        jsonify({"admins": admin_store.list_platform_admins()}), 200
    ))


@app.route("/v1/admin/platform-admins", methods=["POST"])
def admin_add_platform_admin():
    body = json_body()
    return admin_action(lambda actor: (
        jsonify(admin_store.add_platform_admin(actor, str(body.get("email", "")))), 201
    ))


@app.route("/v1/admin/platform-admins/<user_id>", methods=["DELETE"])
def admin_remove_platform_admin(user_id):
    if not valid_uuid(user_id):
        return jsonify({"error": "That account is not a TROJAN admin"}), 404

    def action(actor):
        admin_store.remove_platform_admin(actor, user_id)
        return jsonify({"removed": True}), 200
    return admin_action(action)


@app.route("/v1/admin/audit", methods=["GET"])
def admin_audit():
    return admin_action(lambda _actor: (
        jsonify({"entries": admin_store.audit_log(read_limit())}), 200
    ))


@app.route("/v1/health", methods=["GET"])
def health():
    return jsonify({
        "status": "ok",
        "groq": "set" if os.getenv("GROQ_API_KEY") else "not set",
        "supabase": "configured" if (
            os.getenv("SUPABASE_URL")
            and os.getenv("SUPABASE_SERVICE_ROLE_KEY")
        ) else "not configured",
        "scanning": "configured" if (
            os.getenv("GITHUB_DISPATCH_TOKEN") and os.getenv("SCAN_WORKER_SECRET")
        ) else "not configured",
    }), 200


def alert_batch_error(data):
    if data is None:
        return jsonify({"error": "Invalid JSON"}), 400
    if not isinstance(data, dict) or "alerts" not in data:
        return jsonify({"error": 'Missing "alerts" field in request body'}), 422
    if not isinstance(data["alerts"], list):
        return jsonify({"error": '"alerts" field must be a list'}), 422
    if not data["alerts"]:
        return jsonify({"error": '"alerts" field must be a non-empty list'}), 422
    if len(data["alerts"]) > MAX_ALERTS:
        return jsonify({
            "error": f'"alerts" field must contain no more than {MAX_ALERTS} items',
        }), 413
    if any(not isinstance(alert, dict) for alert in data["alerts"]):
        return jsonify({"error": "Each alert must be a JSON object"}), 422
    return None


@app.route("/v1/analyze", methods=["POST"])
def analyze():
    auth_error = resolve_ingest_organization()
    if auth_error:
        return auth_error

    data = request.get_json(silent=True)
    batch_error = alert_batch_error(data)
    if batch_error:
        return batch_error

    organization_id = g.organization_id
    results = []
    for index, alert in enumerate(data["alerts"]):
        # Store first, so the alert is kept even if the review fails.
        try:
            alert_id, inserted = store_pending_alert(organization_id, alert)
        except Exception:
            app.logger.exception("Supabase could not store alert %s", index)
            return jsonify({
                "error": "Supabase storage failed",
                "alert_index": index,
                "stored_count": index,
                "results": results,
            }), 503

        if not inserted and not needs_another_review(organization_id, alert_id):
            # Already stored and reviewed for this business: don't spend another review.
            results.append({"alert_id": alert_id, "review_status": "duplicate"})
            continue

        try:
            review, review_status = review_stored_alert(
                organization_id, alert_id, alert_source_payload(alert),
            )
        except Exception:
            app.logger.exception("Could not save the review for alert %s", index)
            return jsonify({
                "error": "Alert stored but its review could not be saved",
                "alert_index": index,
                "stored_count": index + 1,
                "results": results,
            }), 503

        results.append({
            "alert_id": alert_id,
            "review_status": review_status,
            "llm_review": review,
        })
    return jsonify({"results": results}), 200


def findings_batch_error(data):
    if not isinstance(data, dict) or not isinstance(data.get("findings"), list):
        return jsonify({"error": "Request body must contain a findings list"}), 422
    if not data["findings"]:
        return jsonify({"error": "findings must be a non-empty list"}), 422
    if len(data["findings"]) > MAX_ALERTS:
        return jsonify({
            "error": f"findings must contain no more than {MAX_ALERTS} items",
        }), 413

    valid_severities = {"low", "medium", "high", "critical"}
    for finding in data["findings"]:
        if not isinstance(finding, dict):
            return jsonify({"error": "Each finding must be a JSON object"}), 422
        if not (finding.get("target") or finding.get("asset")):
            return jsonify({"error": "Each finding must include a target or asset"}), 422
        if not finding.get("title"):
            return jsonify({"error": "Each finding must include a title"}), 422
        if finding.get("severity") not in valid_severities:
            return jsonify({"error": "Each finding must include a valid severity"}), 422
    return None


@app.route("/v1/findings", methods=["POST"])
def ingest_findings():
    auth_error = resolve_ingest_organization()
    if auth_error:
        return auth_error

    data = request.get_json(silent=True)
    batch_error = findings_batch_error(data)
    if batch_error:
        return batch_error

    try:
        inserted_count = persist_findings(g.organization_id, data["findings"])
    except Exception:
        app.logger.exception("Supabase could not store vulnerability findings")
        return jsonify({"error": "Supabase storage failed"}), 503

    return jsonify({"stored": inserted_count}), 201


def scan_action(action):
    token = user_token()
    if not token:
        return jsonify({"error": "Sign in required"}), 401
    try:
        return action(token)
    except scan_store.ScanError as error:
        return jsonify({"error": str(error)}), error.status
    except SupabaseConfigurationError as error:
        return jsonify({"error": str(error)}), 503
    except Exception:
        app.logger.exception("Scan request failed")
        return jsonify({"error": "Scan request failed"}), 502


@app.route("/v1/scans", methods=["GET"])
def scans_list():
    organization_id = valid_uuid(request.args.get("organization_id"))
    if not organization_id:
        return jsonify({"error": "organization_id must be a UUID"}), 422
    return scan_action(lambda token: (jsonify(scan_store.list_scans(token, organization_id)), 200))


@app.route("/v1/scan-targets", methods=["POST"])
def scan_target_add():
    body = json_body()
    organization_id = valid_uuid(body.get("organization_id"))
    if not organization_id:
        return jsonify({"error": "organization_id must be a UUID"}), 422
    return scan_action(lambda token: (
        jsonify(scan_store.add_target(token, organization_id, body.get("url"), body.get("confirmed"))), 201
    ))


@app.route("/v1/scan-targets/<target_id>/confirm", methods=["POST"])
def scan_target_confirm(target_id):
    if not valid_uuid(target_id):
        return jsonify({"error": "Website not found"}), 404
    confirmed = json_body().get("confirmed")
    return scan_action(lambda token: (jsonify(scan_store.confirm_target(token, target_id, confirmed)), 200))


@app.route("/v1/scan-targets/<target_id>", methods=["DELETE"])
def scan_target_remove(target_id):
    if not valid_uuid(target_id):
        return jsonify({"error": "Website not found"}), 404

    def remove(token):
        scan_store.remove_target(token, target_id)
        return jsonify({"removed": True}), 200
    return scan_action(remove)


@app.route("/v1/scans", methods=["POST"])
def scan_start():
    target_id = valid_uuid(json_body().get("target_id"))
    if not target_id:
        return jsonify({"error": "target_id must be a UUID"}), 422
    return scan_action(lambda token: (jsonify(scan_store.start_scan(token, target_id)), 201))


def worker_authorized():
    secret = os.getenv("SCAN_WORKER_SECRET")
    supplied = request.headers.get("Authorization", "").removeprefix("Bearer ")
    return bool(secret) and hmac.compare_digest(supplied, secret)


def worker_action(scan_id, action):
    if not worker_authorized():
        return jsonify({"error": "Unauthorized"}), 401
    if not valid_uuid(scan_id):
        return jsonify({"error": "Scan not found"}), 404
    try:
        return action()
    except scan_store.ScanError as error:
        return jsonify({"error": str(error)}), error.status
    except Exception:
        app.logger.exception("Scan worker request failed")
        return jsonify({"error": "Scan worker request failed"}), 502


@app.route("/v1/worker/scans/<scan_id>/start", methods=["POST"])
def worker_scan_start(scan_id):
    return worker_action(scan_id, lambda: (jsonify(scan_store.claim_scan(scan_id)), 200))


@app.route("/v1/worker/scans/<scan_id>/finish", methods=["POST"])
def worker_scan_finish(scan_id):
    body = json_body()
    findings = body.get("findings") or []
    if not isinstance(findings, list) or len(findings) > MAX_ALERTS:
        return jsonify({"error": "findings must be a list"}), 422
    if findings:
        batch_error = findings_batch_error({"findings": findings})
        if batch_error:
            return batch_error
    raw_outputs = body.get("raw_outputs") or []
    raw_error = scan_store.raw_outputs_error(raw_outputs)
    if raw_error:
        return jsonify({"error": raw_error}), 422

    def finish():
        stored = scan_store.complete_scan(
            scan_id, findings, body.get("error"), body.get("warning"), raw_outputs,
        )
        return jsonify({"stored": stored}), 200
    return worker_action(scan_id, finish)


def review_retry_batch():
    return max(1, min(int(os.getenv("REVIEW_RETRY_BATCH", "3")), 20))


@app.route("/v1/worker/reviews/retry", methods=["POST"])
def worker_review_retry():
    """Re-review alerts whose review didn't finish. Called on a schedule.

    Uses the scan worker's secret. Each call handles a small batch so it
    stays inside the host's request time limit.
    """
    if not worker_authorized():
        return jsonify({"error": "Unauthorized"}), 401
    try:
        due = alerts_due_for_review(review_retry_batch())
    except Exception:
        app.logger.exception("Could not list alerts due for review")
        return jsonify({"error": "Could not read from Supabase"}), 502

    outcomes = {}
    for row in due:
        try:
            _review, status = review_stored_alert(row["organization_id"], row["id"], row.get("source_payload") or {})
            if status == "unavailable":
                count_failed_review_attempt(row)
        except Exception:
            app.logger.exception("Retrying the review of alert %s failed", row["id"])
            status = "error"
        outcomes[status] = outcomes.get(status, 0) + 1
    return jsonify({"retried": len(due), "outcomes": outcomes}), 200

if __name__ == "__main__":
    app.run(
        debug=os.getenv("FLASK_DEBUG", "0") == "1",
        host="0.0.0.0",
        port=int(os.getenv("API_PORT", "8000")),
    )
