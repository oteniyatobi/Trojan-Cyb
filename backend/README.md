# Flask backend

The Flask API receives alert and scanner-finding batches, requests optional
plain-language reviews from Groq, and stores records in the shared Supabase
project. It does not run a local PostgreSQL database or scan targets itself.

## Endpoints

All endpoints are under `/v1`.

| Method and path | Authentication | Purpose |
|---|---|---|
| `GET /v1/health` | None | Reports API, Groq, and Supabase configuration status |
| `POST /v1/analyze` | `TROJAN_INGESTION_API_KEY` | Reviews and stores alerts for the configured organization |
| `POST /v1/findings` | `TROJAN_INGESTION_API_KEY` | Stores scanner findings for the configured organization |

Both POST requests require a JSON batch. The caller cannot select an
organization: the backend uses `TROJAN_ORGANIZATION_ID`, and browser reads
are scoped by Supabase Auth and row-level security. Keep the Supabase
server-side key out of the frontend.

## Configuration and local run

Set backend variables in the repository-root `.env` using
[`.env.example`](../.env.example). Install dependencies and start Flask from
this directory:

```powershell
python -m pip install -r requirements.txt
python api.py
```

In production, Vercel routes `/v1/*` to this Flask service. See the root
[README](../README.md) for Supabase setup, deployment, and required Vercel
environment variables.

Groq is optional. Configure `GROQ_API_KEY` and, if needed,
`GROQ_MODEL`, `GROQ_TIMEOUT_SECONDS`, and `GROQ_MAX_RETRIES`. Alert content
is sent to Groq when the key is configured.

Scanner adapters are maintained in [`scanners/`](scanners/), but no API route
or worker invokes them yet. They are not deployed as Vercel services; see the
[scanner guide](scanners/README.md).
