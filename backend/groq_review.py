import os
import json
import logging
import time
import requests
from dotenv import load_dotenv

load_dotenv()

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


def get_groq_key():
    return os.environ.get("GROQ_API_KEY", "")


def _retry_delay(status_code, headers, attempt):
    if status_code == 429:
        retry_after = headers.get("Retry-After")
        try:
            return min(int(retry_after), 60) if retry_after else 5
        except (TypeError, ValueError):
            return 5
    if 500 <= status_code < 600:
        return 2 ** attempt
    return None


def _positive_int_setting(name, default):
    value = int(os.environ.get(name, default))
    if value < 1:
        raise ValueError(f"{name} must be at least 1")
    return value


def get_review(alert):
    key = get_groq_key()
    if not key:
        raise RuntimeError("No Groq API key configured")

    body = {
        "model": os.getenv("GROQ_MODEL", "openai/gpt-oss-120b"),
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": alert}
        ],
        "response_format": {"type": "json_object"},
    }
    headers = {
        "Authorization": f"Bearer {key}",
        "Content-Type": "application/json",
    }
    timeout = _positive_int_setting("GROQ_TIMEOUT_SECONDS", "15")
    max_retries = _positive_int_setting("GROQ_MAX_RETRIES", "3")

    for attempt in range(max_retries):
        try:
            response = requests.post(url, headers=headers, json=body, timeout=timeout)
            if response.status_code == 200:
                content = response.json()["choices"][0]["message"]["content"]
                return json.loads(content)

            wait = _retry_delay(response.status_code, response.headers, attempt)
            if wait is None:
                logger.warning("Groq returned non-retryable HTTP %d", response.status_code)
                break
            logger.warning(
                "Groq returned HTTP %d; retrying after %d seconds",
                response.status_code,
                wait,
            )
            if attempt + 1 < max_retries:
                time.sleep(wait)
        except requests.RequestException as error:
            logger.warning(
                "Groq request failed on attempt %d/%d (%s)",
                attempt + 1,
                max_retries,
                type(error).__name__,
            )
            if attempt + 1 < max_retries:
                time.sleep(2 ** attempt)

    raise RuntimeError(f"Failed to get review after {max_retries} attempts")


def check_groq_api_key():
    if not get_groq_key():
        print("Your Groq key is not set (neither in settings nor in GROQ_API_KEY).")
    else:
        print("Your Groq key is set.")

def _normalize_choice(value, choices):
    """Return the entry of choices matching value ignoring case and spaces, else value."""
    if not isinstance(value, str):
        return value
    return {choice.lower(): choice for choice in choices}.get(value.strip().lower(), value)


def _steps_problem(review):
    steps = review["steps"]
    if isinstance(steps, str):
        steps = [steps]
    if not isinstance(steps, list) or not steps or not all(isinstance(step, str) and step.strip() for step in steps):
        return "steps must be a non-empty list of text"
    review["steps"] = steps
    return None


def check_review(review):
    """Return a list of problems with a review; empty means it can be saved.

    Fixes harmless variations in place first: severity or attack_type in
    another case ("High"), or steps sent as one string.
    """
    if not isinstance(review, dict):
        return ["Review is not a JSON object"]
    missing = [key for key in REQUIRED_KEYS if key not in review]
    if missing:
        return [f"Missing keys: {', '.join(missing)}"]

    review["severity"] = _normalize_choice(review["severity"], SEVERITIES)
    review["attack_type"] = _normalize_choice(review["attack_type"], ATTACK_TYPES)
    problems = []
    if review["severity"] not in SEVERITIES:
        problems.append(f"Invalid severity: {review['severity']}")
    if review["attack_type"] not in ATTACK_TYPES:
        problems.append(f"Invalid attack_type: {review['attack_type']}")
    for field in ("headline", "what_happened", "why_it_matters", "when_to_escalate"):
        if not isinstance(review[field], str) or not review[field].strip():
            problems.append(f"{field} must be non-empty text")
    steps_problem = _steps_problem(review)
    if steps_problem:
        problems.append(steps_problem)
    return problems


if __name__ == "__main__":
    check_groq_api_key()
    review = get_review("Suricata alert: TROJAN test rule, source 10.0.0.5 to 10.0.0.9, http request containing trojan-test")
    print(check_review(review))
    print(review)
    # print(review['attack_type'])
    # print(review['severity'])