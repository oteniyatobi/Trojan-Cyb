import os
import json
import uuid
import logging
from sqlalchemy import create_engine, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import sessionmaker
from groq_review import get_review, check_review
from flask import Flask,  request, jsonify
from dotenv import load_dotenv
from models import Alert, Review
load_dotenv()

#Database
DATABASE_URL = os.getenv('DATABASE_URL')
if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL environment variable is not set.")
engine = create_engine(DATABASE_URL, connect_args={"connect_timeout": 5})
Session = sessionmaker(bind=engine)

# Single-tenant prototype: every row gets the same org UUID. When
# multi-tenancy is added, this comes from the authenticated user.
DEFAULT_ORG_ID = uuid.UUID(os.environ.get(
    "DEFAULT_ORG_ID", "00000000-0000-0000-0000-000000000001"
))


app = Flask(__name__)

logger = logging.getLogger(__name__)

@app.errorhandler(IntegrityError)
def handle_integrity_error(e):
    return jsonify({
        "error": "duplicate alert",
        "detail": "This wazuh_id is already stored.",
    }), 409

MAX_ALERTS = 1000

#HELPERS
def alert_to_dict(alert: Alert) -> dict:
    """Serialise an Alert and its optional Review for the dashboard."""
    d = {
        "id": alert.id,
        "wazuh_id": alert.wazuh_id,
        "received_at": alert.received_at.isoformat() if alert.received_at else None,
        "rule_id": alert.rule_id,
        "rule_level": alert.rule_level,
        "description": alert.description,
        "src_ip": alert.src_ip,
        "agent_name": alert.agent_name,
        "status": alert.status,
        "review_status": alert.review_status,
    }
    if alert.review:
        d["review"] = {
            "attack_type": alert.review.attack_type,
            "severity": alert.review.severity,
            "headline": alert.review.headline,
            "what_happened": alert.review.what_happened,
            "why_it_matters": alert.review.why_it_matters,
            "steps": alert.review.steps or [],
            "when_to_escalate": alert.review.when_to_escalate,
            "model": alert.review.model,
            "attempts": alert.review.attempts,
        }
    else:
        d["review"] = None
    return d

# ROUTES

@app.route('/v1/health', methods=['GET'])
def health():
    key = os.getenv('GROQ_API_KEY')
    db_ok = False
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
            db_ok = True
    except Exception as e:
        pass
    return jsonify({'status': 'ok', 'groq': 'set' if key is not None and key != '' else 'not set', 'database': 'ok' if db_ok else 'unavailable'}), 200


@app.route('/v1/analyze', methods=['POST'])
def analyze():
    data = request.get_json(silent=True)
      
    if data is None:
        return jsonify({'error': 'Invalid JSON'}), 400
    if not isinstance(data, dict) or 'alerts' not in data:
        return jsonify({'error': 'Missing "alerts" field in request body'}), 422
    if not isinstance(data['alerts'], list):
        return jsonify({'error': '"alerts" field must be a list'}), 422
    if not data['alerts'] or len(data['alerts']) == 0:
        return jsonify({'error': '"alerts" field must be a non-empty list'}), 422
    if len(data['alerts']) > MAX_ALERTS:
        return jsonify({'error': f'"alerts" field must contain no more than {MAX_ALERTS} items'}), 413
    else:
        session = Session()
        results = []
        try:
            for payload in data["alerts"]:
                if not isinstance(payload, dict):
                    return jsonify({"error": "Each alert must be a JSON object"}), 422

                # Unique Wazuh id: fall back to a generated one if the caller
                #  did not supply an id, so the unique constraint is satisfied.
                wazuh_id = (payload.get("id") or payload.get("wazuh_id")
                            or f"generated-{uuid.uuid4()}")

                alert = Alert(
                    org_id=DEFAULT_ORG_ID,
                    wazuh_id=wazuh_id,
                    rule_id=str(payload.get("rule", {}).get("id", "")) or None,
                    rule_level=payload.get("rule", {}).get("level"),
                    description=payload.get("rule", {}).get("description") or payload.get("description"),
                    src_ip=payload.get("src_ip") or payload.get("data", {}).get("srcip"),
                    agent_name=payload.get("agent", {}).get("name"),
                    raw=payload,
                    status="new",
                    review_status="pending",
                )
                session.add(alert)
                # Commit the alert before calling Groq, so the alert is stored even
                # # if the Groq call fails. The review is a second transaction below.
                session.commit()

                try:
                    review_data = get_review(json.dumps(payload))
                    problems = check_review(review_data)
                except Exception as e:
                    problems = [str(e)]
                    review_data = {}

                if problems:
                    alert.review_status = "unavailable"
                    session.commit()
                    results.append({
                        "id": alert.id,
                        "wazuh_id": alert.wazuh_id,
                        "review_status": "unavailable",
                        "problems": problems,
                    })
                    continue

                review = Review(
                    alert_id=alert.id,
                    attack_type=review_data.get("attack_type"),
                    severity=review_data.get("severity"),
                    headline=review_data.get("headline") or review_data.get("summary"),
                    what_happened=review_data.get("what_happened") or review_data.get("details"),
                    why_it_matters=review_data.get("why_it_matters"),
                    steps=review_data.get("steps") or review_data.get("recommendations"),
                    when_to_escalate=review_data.get("when_to_escalate"),
                    model=review_data.get("model"),
                    attempts=review_data.get("attempts", 1),
                )
                session.add(review)
                alert.review_status = "done"
                session.commit()


                results.append({
                    "id": alert.id,
                    "wazuh_id": alert.wazuh_id,
                    "review_status": "done",
                    "review": {
                        "attack_type": review.attack_type,
                        "severity": review.severity,
                        "headline": review.headline,
                    },
                })

            return jsonify({'results': results}), 200
        except IntegrityError:
            session.rollback()
            return jsonify({
                "error": "duplicate alert",
                "detail": "This wazuh_id is already stored.", 
            }), 409
        except Exception as e:
            session.rollback()
            logger.exception("analyze failed")
            return jsonify({"error": "internal error"}), 500
        finally:
            session.close()


@app.route('/v1/alerts', methods=['GET'])
def list_alerts():
    limit = min(int(request.args.get('limit', 100)), 500)
    offset = int(request.args.get('offset', 0))
    severity = request.args.get('severity')

    session = Session()
    try:
        query = session.query(Alert).order_by(Alert.id.desc())
        if severity: #filter by severity if provided
            query = query.join(Review, isouter=True).filter(Review.severity == severity)

        rows = query.offset(offset).limit(limit).all()
        total = session.query(Alert).count()
        return jsonify({
            'alerts': [alert_to_dict(alert) for alert in rows],
            'total': total,
            'limit': limit,
            'offset': offset,
        }), 200
    finally:
        session.close()


@app.route('/v1/alerts/<int:alert_id>', methods=['GET'])
def get_alert(alert_id):
    session = Session()
    try:
        alert = session.query(Alert).filter_by(id=alert_id).one_or_none()
        if alert is None:
            return jsonify({'error': 'Alert not found'}), 404
        return jsonify(alert_to_dict(alert)), 200
    finally:
        session.close()


if __name__ == '__main__':
    app.run(debug=False, host='127.0.0.1', port=8000)

