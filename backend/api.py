import os
import json
from groq_review import get_review, check_review
from flask import Flask,  request, jsonify
from dotenv import load_dotenv
load_dotenv()

app = Flask(__name__)
MAX_ALERTS = 1000
@app.route('/v1/health', methods=['GET'])
def health():
    key = os.getenv('GROQ_API_KEY')
    return jsonify({'status': 'ok', 'groq': 'set' if key is not None and key != '' else 'not set'}), 200


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
        results = []
        for alert in data['alerts']:
            if not isinstance(alert, dict):
                return jsonify({'error': 'Each alert must be a JSON object'}), 422
            try:
                review = get_review(json.dumps(alert))
                problems = check_review(review)
                if not problems:
                    review['status'] = 'done'
                    results.append({'llm_review': review})
                else:
                    results.append({'llm_review': {'status': 'unavailable', 'problems': problems}})
            except Exception as e:
                print(f"Grok Call Failed: {e}")
                results.append({'llm_review': {'status': 'unavailable', 'problems': [str(e)]}})
        return jsonify({'results': results}), 200

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=8000)

