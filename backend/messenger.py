#THIS CODE IS WHAT SENDS AND RUNS THE MESSAGE FORM WAZUH LOGS TO BE SENT TO OUR API
import sys
import json 
import requests

PATH = sys.argv[1]
with open(PATH, 'r') as f:
    alert = json.load(f)
response = requests.post('http://localhost:8000/v1/analyze', json={'alerts': [alert]})
print(response.json())