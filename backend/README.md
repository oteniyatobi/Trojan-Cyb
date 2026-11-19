# Flask backend

The Flask API receives alert and scanner-finding batches, stores them in the
shared Supabase project, and asks Groq for a plain-language review of each
alert. It does not run a local PostgreSQL database or scan targets itself.

## Endpoints

All endpoints are under `/v1`. Send the ingest key as
`Authorization: Bearer <key>`.

| Method and path | Authentication | Purpose |
|---|---|---|
| `GET /v1/health` | None | Reports API, Groq, and Supabase configuration status |
| `POST /v1/analyze` | Ingest key | Stores, then reviews, up to 1000 alerts |
| `POST /v1/findings` | Ingest key | Stores up to 1000 scanner findings |

## Which business a request belongs to

The caller never chooses the business. The backend works it out from the key:

- `TROJAN_INGESTION_API_KEY` maps to `TROJAN_ORGANIZATION_ID` (one install,
  one business).
- Any other key is hashed with SHA-256 and looked up in the Supabase
  `ingest_keys` table. A matching, unrevoked row gives the business. Only the
  hash is stored, and browsers can't read the table.
- Anything else gets 401.

To add a business key, generate one, then store its hash:

```bash
python3 -c "import secrets; print(secrets.token_urlsafe(32))"   # give this to the business
python3 -c "import hashlib,sys; print(hashlib.sha256(sys.argv[1].encode()).hexdigest())" '<the key>'
```

```sql
insert into public.ingest_keys (organization_id, key_hash, label)
values ('<organization uuid>', '<hash>', 'lab Wazuh manager');
```

Revoke a key with `update public.ingest_keys set revoked_at = now() where id = ...`.

## How an alert is processed

1. **Store first.** The alert is saved through the `ingest_alert` function
   with `review_status = 'pending'`, a severity from the Wazuh rule level, and
   a fixed set of fields in `source_payload`: rule id, level, groups and
   description; Suricata signature; source and destination IP and port;
   protocol; agent; manager; decoder; location. The raw event and `full_log`
   are not stored, because log lines can hold passwords or personal data.
2. **Duplicates are skipped.** If the business already has this event id,
   the result is `"review_status": "duplicate"` and Groq isn't called.
3. **Hourly limit.** If the business already has `GROQ_REVIEWS_PER_HOUR`
   done reviews in the last hour, the alert is marked `rate_limited` and
   Groq isn't called.
4. **Review.** Groq is called with retries: on a 429 it waits as long as
   `Retry-After` asks (up to 60 s), on a 5xx it backs off 1, 2, 4 s. A valid
   review is saved as `done`, and the alert's severity and title are updated
   from it. A failure is saved as `unavailable`. Either way the alert stays.

`review_status` values: `pending`, `done`, `unavailable`, `rate_limited`.

`POST /v1/analyze` returns 200 with
`{"results": [{"alert_id", "review_status", "llm_review"}]}`. If Supabase
fails, it returns 503 with `alert_index`, `stored_count` and the results
so far.

Groq is called inside the request, so a large batch can take a while.
`rate_limited` and `pending` alerts aren't retried yet; that needs a
background worker.

## Configuration and local run

Set backend variables in the repository-root `.env` using
[`.env.example`](../.env.example). Apply the migrations in
[`supabase/migrations/`](../supabase/migrations/) to the Supabase project,
including `20261118120000_ingest_keys_and_review_status.sql`. Then install
the dependencies and start Flask from this directory:

```bash
python -m pip install -r requirements.txt
python api.py
```

Run the tests with `python -m unittest discover -v`.

In production, Vercel routes `/v1/*` to this Flask service. See the root
[README](../README.md) for Supabase setup, deployment, and required Vercel
environment variables.

| Variable | Default | Used for |
|---|---|---|
| `SUPABASE_URL`, `SUPABASE_SERVICE_ROLE_KEY` | none | Supabase access. Server only, never in the frontend |
| `TROJAN_INGESTION_API_KEY`, `TROJAN_ORGANIZATION_ID` | none | single-install key and its business |
| `GROQ_API_KEY` | none | without it, alerts are stored as `unavailable` |
| `GROQ_MODEL` | `openai/gpt-oss-120b` | Groq model |
| `GROQ_TIMEOUT_SECONDS` | `15` | per-request timeout |
| `GROQ_MAX_RETRIES` | `3` | attempts per review |
| `GROQ_REVIEWS_PER_HOUR` | `100` | Groq reviews per business per hour |

Alert content is sent to Groq when the key is configured.

## Scanners

Scanner adapters are maintained in [`scanners/`](scanners/). Their findings
match what `POST /v1/findings` accepts (`target`, `title`, `severity`,
`cve_id`, plus `tool`, `evidence` and `found_at` kept in `details`). No API
route or worker runs them yet, and they are not deployed as Vercel services.
See the [scanner guide](scanners/README.md).
