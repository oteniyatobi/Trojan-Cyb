FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1
WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY api.py groq_review.py messenger.py ./

RUN useradd --create-home appuser
USER appuser

EXPOSE 8000
# gunicorn instead of app.run(debug=True): no debugger exposed on the server
CMD ["gunicorn", "--bind", "0.0.0.0:8000", "--workers", "2", "--timeout", "120", "api:app"]
