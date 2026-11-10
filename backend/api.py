import os
import json
import uuid
import logging
from datetime import datetime
from sqlalchemy import create_engine, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import sessionmaker, joinedload
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
def _obj(value) -> dict:
    """Return value if it is a dict, else {} (Wazuh fields may be null)."""
    return value if isinstance(value, dict) else {}


def _to_int(value):
    """Suricata sends numbers as strings ("80", "3"); return int or None."""
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _to_time(value):
    """Parse Wazuh's timestamp (e.g. 2026-11-03T09:55:15.767+0000)."""
    if not isinstance(value, str):
        return None
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        return None


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
        "event_time": alert.event_time.isoformat() if alert.event_time else None,
        "signature_id": alert.signature_id,
        "signature_name": alert.signature_name,
        "suricata_sev": alert.suricata_sev,
        "dest_ip": alert.dest_ip,
        "dest_port": alert.dest_port,
        "proto": alert.proto,
        "fired_times": alert.fired_times,
        "rule_groups": alert.rule_groups,
        "agent_id": alert.agent_id,
        "manager_name": alert.manager_name,
        "decoder_name": alert.decoder_name,
        "location": alert.location,
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

                # Wazuh nests the original event under "data"; for Suricata
                # alerts the signature lives in data.alert. Any block can be
                # missing or null depending on the decoder.
                rule = _obj(payload.get("rule"))
                data_block = _obj(payload.get("data"))
                agent = _obj(payload.get("agent"))
                manager = _obj(payload.get("manager"))
                decoder = _obj(payload.get("decoder"))
                suricata_alert = _obj(data_block.get("alert"))

                groups = rule.get("groups")
                rule_id = rule.get("id")
                signature_id = suricata_alert.get("signature_id")

                alert = Alert(
                    org_id=DEFAULT_ORG_ID,
                    wazuh_id=str(wazuh_id),
                    event_time=_to_time(payload.get("timestamp")),
                    rule_id=str(rule_id) if rule_id is not None else None,
                    rule_level=_to_int(rule.get("level")),
                    rule_groups=groups if isinstance(groups, list) else None,
                    # Suricata's own id (e.g. 1000002); Wazuh's rule_id is the
                    # generic 86601 "Suricata: Alert" for every signature.
                    signature_id=str(signature_id) if signature_id is not None else None,
                    signature_name=suricata_alert.get("signature"),
                    # Suricata severity: 1 = highest, 3 = lowest.
                    suricata_sev=_to_int(suricata_alert.get("severity")),
                    fired_times=_to_int(rule.get("firedtimes")) or 1,
                    description=rule.get("description") or payload.get("description"),
                    src_ip=(data_block.get("src_ip") or data_block.get("srcip")
                            or payload.get("src_ip")),
                    dest_ip=(data_block.get("dest_ip") or data_block.get("dstip")
                             or payload.get("dest_ip")),
                    dest_port=_to_int(data_block.get("dest_port") or data_block.get("dstport")),
                    proto=data_block.get("proto") or data_block.get("protocol"),
                    agent_id=agent.get("id"),
                    agent_name=agent.get("name"),
                    manager_name=manager.get("name"),
                    decoder_name=decoder.get("name"),
                    location=payload.get("location"),
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
    try:
        limit = min(max(int(request.args.get('limit', 100)), 1), 500)
        offset = max(int(request.args.get('offset', 0)), 0)
    except ValueError:
        return jsonify({"error": "limit and offset must be integers"}), 400
    severity = request.args.get('severity')

    session = Session()
    try:
        query = session.query(Alert).options(joinedload(Alert.review))
        if severity: #filter by severity if provided
            query = query.join(Review, isouter=True).filter(Review.severity == severity)

        total = query.count()
        rows = (query.order_by(Alert.id.desc()).offset(offset).limit(limit).all())
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

