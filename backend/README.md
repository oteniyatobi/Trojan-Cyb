# TROJAN backend

A Flask API that receives Wazuh and Suricata alerts, stores them in
Postgres, and asks Groq for a plain-language review of each one. The
dashboard reads alerts and reviews from it.

This README describes what the code does today. Planned work is listed
at the end.

## Files

| Path | What it is |
|---|---|
| `api.py` | Flask app: routes, API key check, alert ingest |
| `groq_review.py` | Groq call, retry and backoff, review validation, Groq key and model lookup |
| `models.py` | SQLAlchemy models for the tables in `db/schema.sql` |
| `db/schema.sql` | Postgres schema, `app_rls` role and row-level security policies |
| `scanners/` | Nmap, Wapiti, Nuclei and OSV-Scanner adapters (see [scanners/README.md](scanners/README.md)) |
| `messenger.py` | Sends a JSON alert file to `/v1/analyze` (manual test) |
| `test_alert.json` | A small sample alert for `messenger.py` |
| `groq_test.py` | Standalone script to try a Groq review |
| `Dockerfile` | API image: Python 3.12, gunicorn, 2 workers, 120 s timeout, non-root user |
| `requirements.txt` | API dependencies |
| `.flake8` | Per-file exemptions for existing style issues |

## How an alert flows

1. Wazuh's `custom-trojan` integration
   ([integrations/custom-trojan](../integrations/custom-trojan)) sends
   `POST /v1/analyze` with `{"alerts": [ ... ]}`.
2. The API saves each alert to `alerts` with `review_status = 'pending'`
   and commits, so the alert is kept even if the review fails.
3. It checks the business's Groq budget: if `reviews` already has
   `GROQ_REVIEWS_PER_HOUR` rows for that business in the last hour, the
   alert is marked `rate_limited` and Groq isn't called.
4. Otherwise it calls Groq. It retries up to `GROQ_MAX_RETRIES` times.
   On a 429 it waits as long as Groq's `Retry-After` header asks, up to
   60 s. On a 5xx it waits 1, 2, then 4 s.
5. The answer is checked by `check_review` (required keys, allowed
   severities and attack types). A valid answer is saved to `reviews` and
   the alert becomes `done`. Otherwise the alert becomes `unavailable`.

`review_status` values: `pending`, `done`, `unavailable`, `rate_limited`.

The Groq call happens inside the HTTP request, so a batch of alerts can
take a long time to answer. Moving it to a background worker is planned.

## Running it

With Docker, from the repo root:

```bash
cp .env.example .env      # then fill in the values, see below
docker compose up --build
curl http://localhost:8000/v1/health
```

Compose starts `db` (Postgres 16, which loads `db/schema.sql` the first
time its volume is created), `redis`, `backend` on port 8000 and
`dashboard` on port 3000. All ports are bound to 127.0.0.1.

`schema.sql` only runs on an empty database volume. To apply schema
changes locally, run `docker compose down -v` to delete the volume
(this deletes all local data), or run the new SQL by hand.

Without Docker, from `backend/`:

```bash
pip install -r requirements.txt
export DATABASE_URL=postgresql+psycopg://app_rls:<password>@localhost:5432/app_db
gunicorn --bind 127.0.0.1:8000 api:app
```

The URL must start with `postgresql+psycopg://`, the driver is psycopg 3.

## Configuration

Read from the environment or `.env`. Compose only passes the variables
listed in the backend service's `environment:` block, so a new variable
must be added there too, or the container never sees it.

| Variable | Default | Used for |
|---|---|---|
| `DATABASE_URL` | none (required) | Postgres connection. Compose sets it to the `app_rls` user |
| `DEFAULT_ORG_ID` | `00000000-0000-0000-0000-000000000001` | prototype business |
| `TROJAN_API_KEY` | empty | ingest key for `/v1/analyze`. If empty, ingest accepts anything |
| `TROJAN_ADMIN_KEY` | empty | bearer token for `/v1/settings/*`. If empty, those routes return 503 |
| `TROJAN_SECRET_KEY` | empty | Fernet key that encrypts the Groq key stored in `settings` |
| `GROQ_API_KEY` | empty | used when no key is stored in `settings` |
| `GROQ_MODEL` | `openai/gpt-oss-120b` | used when no model is stored in `settings` |
| `GROQ_TIMEOUT_SECONDS` | `15` | per-request timeout to Groq |
| `GROQ_MAX_RETRIES` | `3` | attempts per review |
| `GROQ_REVIEWS_PER_HOUR` | `100` | Groq reviews allowed per business per hour |
| `REDIS_URL` | set by compose | not used by the code yet |

Generate keys with:

```bash
python3 -c "import secrets; print(secrets.token_urlsafe(32))"                              # API and admin keys
python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"  # TROJAN_SECRET_KEY
```

Never commit `.env`.

## API

All routes are under `/v1`. Send keys as `Authorization: Bearer <key>`.

| Method and path | Auth | What it does |
|---|---|---|
| `GET /v1/health` | none | `{"status", "groq": "set"/"not set", "database": "ok"/"unavailable"}` |
| `POST /v1/analyze` | ingest key | stores and reviews up to 1000 alerts |
| `GET /v1/alerts` | API key (see note) | lists alerts with reviews. Query: `limit` (1-500, default 100), `offset`, `severity` |
| `GET /v1/alerts/<id>` | API key (see note) | one alert with its review, or 404 |
| `PUT /v1/settings/groq-key` | admin | body `{"key": "gsk_..."}`. Stored encrypted, returns `{"set": true, "last4"}` |
| `GET /v1/settings/groq-key` | admin | `{"set", "source": "database"/"env"/"none", "last4"}`. Never returns the full key |
| `DELETE /v1/settings/groq-key` | admin | removes the stored key and falls back to `GROQ_API_KEY` |
| `PUT /v1/settings/groq-model` | admin | body `{"model": "..."}`. Must be in `ALLOWED_MODELS` |
| `GET /v1/settings/groq-model` | admin | `{"model", "source": "database"/"env"}` |

`POST /v1/analyze` responses:

- 200 `{"results": [{"id", "wazuh_id", "review_status", "review"?, "limit"?}]}`
- 400 if the body isn't JSON. 422 if `alerts` is missing, not a list,
  empty, or holds a non-object. 413 if there are more than 1000 alerts.
- 409 if a `wazuh_id` is already stored. The batch stops there, but
  alerts earlier in the same batch are already saved.
- 401 if `TROJAN_API_KEY` is set and the key is neither that value nor a
  row in `api_keys`.

Alert objects returned by `/v1/alerts` have the alert columns (`id`,
`wazuh_id`, `received_at`, `rule_id`, `rule_level`, `description`,
`src_ip`, `dest_ip`, `dest_port`, `proto`, `signature_*`, `agent_*`,
`status`, `review_status`, ...) and `review`: `null`, or `{attack_type,
severity, headline, what_happened, why_it_matters, steps,
when_to_escalate, model, attempts}`.

Quick test with the sample alert:

```bash
python messenger.py test_alert.json
```

`messenger.py` sends no key, so it only works while `TROJAN_API_KEY` is
empty.

## Database and business isolation

Tables: `organizations`, `api_keys`, `alerts`, `reviews`, `settings`,
`audit_log`, `users`, `computers`, `incidents`, `incident_alerts`,
`scans`, `findings`.

Every business-owned table has an `org_id`. Row-level security is
switched on (`FORCE`) with the policy
`org_id = current_setting('app.org_id', true)::uuid`, so a connection
only sees rows for the business set in `app.org_id`. The API connects as
`app_rls`, which isn't a superuser, so the policies apply to it.
Superusers skip RLS, so `psql` as the `app` user sees everything.

`api_keys` stores a SHA-256 hash of each key, never the key itself. A
request's bearer token is hashed and looked up to find its business
(`g.org_id`).

## Known gaps

Read these before building on the API.

- **Only the prototype business works.** Every connection sets
  `app.org_id` to the prototype business when it opens. Because of RLS,
  that hides other businesses' `api_keys` rows, so their keys are never
  found. New alerts are also always saved with `DEFAULT_ORG_ID`.
- **Reads don't need a key.** `GET /v1/alerts` with no key, or a wrong
  one, returns the prototype business's alerts.
- **Placeholder secrets in `schema.sql`.** The `app_rls` password is
  `app_rls_password`, and a test key `changeme` is seeded for the
  prototype business. Both must be replaced before any real deployment.
- **No RLS** on `organizations` or `incident_alerts` yet.
- **Admin is one shared key.** There's no user login or role check, and
  nothing writes to `audit_log`.
- **Scanners aren't connected.** No route or worker runs them yet.
- **No tests.** CI skips pytest when no tests are found.

## Planned

- `/v1/analyze` saves alerts, returns 202 and leaves the review to a
  worker that uses `FOR UPDATE SKIP LOCKED`.
- Set `app.org_id` per transaction from the caller's key, with key
  lookup through a `SECURITY DEFINER` function.
- `PATCH /v1/alerts/<id>`, `POST /v1/alerts/<id>/review`.
- Login and roles, audit logging.
- Scan request and approval flow, approved targets, scan worker.
- Read endpoints for overview, findings, computers, settings, API keys
  and audit log.
- pytest suites and stricter CI.
