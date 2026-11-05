import os 
import json
import requests
from dotenv import load_dotenv
load_dotenv()

key = os.getenv('GROQ_API_KEY')
url = "https://api.groq.com/openai/v1/chat/completions"
headers = {
    "Authorization": f"Bearer {key}",
    "Content-Type": "application/json"
}
body = {
    "model": os.getenv('GROQ_MODEL'),
    "messages": [
        {"role": "system", "content": "You are a security analyst. Reply only in JSON with the keys headline and severity."},
        {"role": "user", "content": "Suricata alert: TROJAN test rule, source 10.0.0.5 to 10.0.0.9, http request containing trojan-test"}
    ]
}
def check_groq_api_key():
    if not key:
       print("Your GROQ_API_KEY is not set in the environment variables. Please set it in your .env file.") 
    else:
        print("Your GROQ_API_KEY is set correctly.")


if __name__ == "__main__":
    check_groq_api_key()
    response = requests.post(url, headers=headers, json=body, timeout=15)
    print(response.status_code)
    print(response.json()['choices'][0]['message']['content'])