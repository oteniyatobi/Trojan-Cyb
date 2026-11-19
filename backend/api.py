import hmac
import json
import os
import uuid

from dotenv import load_dotenv
from flask import Flask, g, jsonify, request
from groq_review import check_review, get_review
from supabase_store import (
    SupabaseConfigurationError,
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


def review_alert(alert):
    """Ask Groq for a review. Returns (review, review_status)."""
    try:
        review = get_review(json.dumps(alert))
        problems = check_review(review)
    except Exception as error:
        app.logger.exception("Groq analysis failed")
        problems = [str(error)]
        review = {}
    if problems:
        return {"status": "unavailable", "problems": problems}, "unavailable"
    review["status"] = "done"
    return review, "done"


def review_stored_alert(organization_id, alert_id, alert):
    """Review a stored alert within the hourly limit and save the outcome."""
    limit = reviews_per_hour_limit()
    if reviews_in_last_hour(organization_id) >= limit:
        review = {"status": "rate_limited", "limit_per_hour": limit}
        review_status = "rate_limited"
    else:
        review, review_status = review_alert(alert)
    record_review(organization_id, alert_id, review, review_status)
    return review, review_status


@app.route("/v1/health", methods=["GET"])
def health():
    return jsonify({
        "status": "ok",
        "groq": "set" if os.getenv("GROQ_API_KEY") else "not set",
        "supabase": "configured" if (
            os.getenv("SUPABASE_URL")
            and os.getenv("SUPABASE_SERVICE_ROLE_KEY")
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

        if not inserted:
            # Already stored for this business: don't spend another review.
            results.append({"alert_id": alert_id, "review_status": "duplicate"})
            continue

        try:
            review, review_status = review_stored_alert(organization_id, alert_id, alert)
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


if __name__ == "__main__":
    app.run(
        debug=os.getenv("FLASK_DEBUG", "0") == "1",
        host="0.0.0.0",
        port=int(os.getenv("API_PORT", "8000")),
    )
