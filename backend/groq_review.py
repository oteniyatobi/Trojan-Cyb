import os
import json
import logging
import requests
import uuid
from cryptography.fernet import Fernet, InvalidToken
from dotenv import load_dotenv
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from models import Setting
load_dotenv()

DEFAULT_ORG_ID = uuid.UUID(os.environ.get(
    "DEFAULT_ORG_ID", "00000000-0000-0000-0000-000000000001"
))

REQUIRED_KEYS = [
    "attack_type",
    "severity",
    "headline",
    "what_happened",
    "why_it_matters",
    "steps",
    "when_to_escalate",
]
SEVERITIES = ["low", "medium", "high", "critical"]
ATTACK_TYPES = [
    "Benign",
    "DoS",
    "DDoS",
    "Reconnaissance",
    "Brute force FTP",
    "Brute force SSH",
    "Web brute force",
    "Cross site scripting",
    "SQL injection",
    "Botnet",
    "Infiltration",
    "Heartbleed",
    "Exploits",
    "Fuzzers",
    "Generic",
    "Backdoor",
    "Shellcode",
    "Worms",
    "Analysis",
    "Other or unknown",
    "Other",
]
SYSTEM_PROMPT = f"""You are a security analyst helping a small business that has no security team. You will receive one alert from Wazuh or Suricata. Reply only with JSON, with exactly these keys:

attack_type: exactly one of these names: {", ".join(ATTACK_TYPES)}
severity: exactly one of: {", ".join(SEVERITIES)}
headline: one short sentence saying what this is
what_happened: two or three plain sentences about what the alert shows
why_it_matters: one or two plain sentences on the risk to the business
steps: a list of short steps the owner can take
when_to_escalate: one sentence on when to ask an expert for help

Rules:
Use plain language that a non technical person can understand.
You only advise. Never say you blocked, fixed or changed anything.
If the alert fits none of the attack types, use Other or unknown.
Do not invent details that are not in the alert."""
url = "https://api.groq.com/openai/v1/chat/completions"
logger = logging.getLogger(__name__)

# One database engine for the whole process, created on first use, so
# looking up the key does not open a new connection pool on every call.
_Session = None


def _db_session():
    global _Session
    if _Session is None:
        engine = create_engine(os.environ["DATABASE_URL"], pool_pre_ping=True,
                               connect_args={"connect_timeout": 5, "options": "-c app.org_id=00000000-0000-0000-0000-000000000001"})
        _Session = sessionmaker(bind=engine)
    return _Session()


def get_groq_key():
    """Return the Groq key: settings first (encrypted), env fallback.

    The key itself is never logged; warnings name only the error type.
    """
    secret = os.environ.get("TROJAN_SECRET_KEY", "").encode()
    if secret and os.environ.get("DATABASE_URL"):
        try:
            session = _db_session()
            try:
                setting = session.query(Setting).filter_by(org_id=DEFAULT_ORG_ID, key="groq_api_key").one_or_none()
            finally:
                session.close()
            if setting is not None:
                return Fernet(secret).decrypt(setting.value.encode()).decode()
        except InvalidToken:
            logger.warning("Stored Groq key cannot be decrypted (TROJAN_SECRET_KEY changed?); using GROQ_API_KEY")
        except Exception as e:
            logger.warning("Could not read Groq key from settings (%s); using GROQ_API_KEY", type(e).__name__)
    return os.environ.get("GROQ_API_KEY", "")


def get_review(alert):
    body = {
        "model": os.getenv('GROQ_MODEL'),
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": alert}
        ],
        "response_format": {"type": "json_object"}
    }
    # Read the key once per review (not once at import), so a key saved
    # through /v1/settings/groq-key takes effect without a restart.
    key = get_groq_key()
    if not key:
        raise Exception("No Groq API key configured")
    headers = {
        "Authorization": f"Bearer {key}",
        "Content-Type": "application/json"
    }
    for attempt in range(3):
        try:
            response = requests.post(url, headers=headers, json=body, timeout=15)
            if response.status_code == 200:
                text = response.json()['choices'][0]['message']['content']
                review = json.loads(text)
                return review
        except Exception as e:
            print(f"Attempt {attempt + 1} failed with error: {e}")
    raise Exception("Failed to get review after 3 attempts")


def check_groq_api_key():
    if not get_groq_key():
        print("Your Groq key is not set (neither in settings nor in GROQ_API_KEY).")
    else:
        print("Your Groq key is set.")

def check_review(review):
    problems = []
    missing = [key for key in REQUIRED_KEYS if key not in review]
    if missing:
        problems.append(f"Missing keys: {', '.join(missing)}")
        return problems
    if review['attack_type'] not in ATTACK_TYPES:
        problems.append(f"Invalid attack_type: {review['attack_type']}")
    if review['severity'] not in SEVERITIES:
        problems.append(f"Invalid severity: {review['severity']}")  
    return problems

if __name__ == "__main__":
    check_groq_api_key()
    review = get_review("Suricata alert: TROJAN test rule, source 10.0.0.5 to 10.0.0.9, http request containing trojan-test")
    print(check_review(review))
    print(review)
    # print(review['attack_type'])
    # print(review['severity'])