#THIS CODE IS WHAT SENDS AND RUNS THE MESSAGE FORM WAZUH LOGS TO BE SENT TO OUR API
import sys
import json 
import os
import requests
from dotenv import load_dotenv

load_dotenv()
PATH = sys.argv[1]
with open(PATH, 'r') as f:
    alert = json.load(f)
api_key = os.getenv('TROJAN_INGESTION_API_KEY')
if not api_key:
    raise SystemExit('TROJAN_INGESTION_API_KEY must be configured')

api_url = os.getenv('TROJAN_API_URL', 'http://localhost:8000').rstrip('/')
response = requests.post(
    f'{api_url}/v1/analyze',
    json={'alerts': [alert]},
    headers={'Authorization': f'Bearer {api_key}'},
    timeout=30,
)
response.raise_for_status()
print(response.json())