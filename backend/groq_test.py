import os 
import json
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
key = os.getenv('GROQ_API_KEY')
url = "https://api.groq.com/openai/v1/chat/completions"
headers = {
    "Authorization": f"Bearer {key}",
    "Content-Type": "application/json"
}

def get_review(alert):
    body = {
        "model": os.getenv('GROQ_MODEL'),
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": alert}
        ],
        "response_format": {"type": "json_object"}
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
    raise Exception(f"Failed to get review after 3 attempts")
    
    

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
