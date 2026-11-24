# TROJAN API documentation

This is the developer guide to the TROJAN backend API (`backend/api.py`, a
Flask app). It covers every endpoint, how to sign in, errors and how to fix
them, rate limits, Python and JavaScript examples, and a Postman collection.

## What's in this folder

| File | What it's for |
| --- | --- |
| `API.md` | This guide |
| `openapi.yaml` | OpenAPI 3.1 spec of all 28 endpoints. Open it in [Swagger Editor](https://editor.swagger.io), import it into Postman, or generate a client from it |
| `examples/python/trojan_client.py` | Python client and runnable examples (`requests`) |
| `examples/javascript/trojan-client.mjs` | JavaScript client and runnable examples (`fetch`, `@supabase/supabase-js`) |
| `postman/TROJAN.postman_collection.json` | Postman collection: every endpoint plus error examples, with test scripts |
| `postman/TROJAN-production.postman_environment.json`, `postman/TROJAN-local.postman_environment.json` | Postman environments with the variables the collection uses |

Flask doesn't generate an OpenAPI spec by itself, so `openapi.yaml` is written
by hand. **When you add or change an endpoint, update `openapi.yaml` and this
guide in the same pull request**, then rebuild the Postman collection from it.

## Base URLs

| Environment | URL |
| --- | --- |
| Production | `https://trojan-cyb.vercel.app` |
| Admin site deployment | `https://trojan-cyb-admin.vercel.app` (same API; the scan worker uses it as a fallback) |
| Local | `http://localhost:8000` (`cd backend && python api.py`) |

All paths start with `/v1`. Send and expect JSON: requests with a body need
`Content-Type: application/json`.

## Quick start

```bash
# 1. Is the backend up and configured?
curl https://trojan-cyb.vercel.app/v1/health

# 2. Send an alert in, using your organization's ingest key
curl -X POST https://trojan-cyb.vercel.app/v1/analyze \
  -H "Authorization: Bearer $INGEST_KEY" -H "Content-Type: application/json" \
  -d '{"alerts":[{"id":"demo-1","rule":{"level":10,"description":"Test alert"}}]}'

# 3. Read it back as a signed-in user (token from Supabase Auth, see below)
curl "https://trojan-cyb.vercel.app/v1/alerts?organization_id=$ORG" \
  -H "Authorization: Bearer $USER_TOKEN"
```

## Authentication

Every endpoint except `GET /v1/health` needs an `Authorization: Bearer <token>`
header. There are three kinds of token:

| Caller | Token | Endpoints |
| --- | --- | --- |
| A person using the dashboard or admin site | Supabase Auth **access token** (a JWT) | Dashboard, Scans, Team, Admin |
| Wazuh or a scanner sending data in | **Ingest key** for one organization | `POST /v1/analyze`, `POST /v1/findings` |
| GitHub Actions (scan worker, review retry) | **Worker secret** (`SCAN_WORKER_SECRET`) | `/v1/worker/*` |

### Users: sign up, sign in and tokens

TROJAN has no login endpoint of its own. People sign in with **Supabase Auth**,
and TROJAN accepts the access token Supabase issues. The dashboard does this
with `@supabase/supabase-js`; any client can do the same.

1. **Sign up.** `supabase.auth.signUp({ email, password, options: { data: { organization_name } } })`.
   The organization name is kept on the account until the first sign in.
2. **Verify the email.** If email confirmation is turned on in the Supabase
   project (Authentication settings), Supabase emails a confirmation link and
   `signUp` returns no session. The person must click the link before signing
   in. With confirmation off, `signUp` returns a session straight away.
3. **Sign in.** `supabase.auth.signInWithPassword({ email, password })` returns a
   session with an `access_token` (the JWT to send to TROJAN), a
   `refresh_token` and `expires_in`. Without supabase-js, call Supabase's Auth
   REST API: `POST https://<project>.supabase.co/auth/v1/token?grant_type=password`
   with header `apikey: <publishable key>` and body `{"email": "...", "password": "..."}`.
4. **First sign in creates the organization.** If the person belongs to no
   organization yet, the dashboard calls the Supabase function
   `create_organization(p_name)` with the name from sign up. It creates the
   organization and makes the person its `org_admin`. People added by an admin
   skip this: they're already members.
5. **Find the organization ID.** Most TROJAN endpoints need `organization_id`.
   There is no TROJAN endpoint that lists "my organizations": read them from
   Supabase, where row-level security shows each person only their own:
   `supabase.from('organization_memberships').select('organization_id, role, organizations(name)')`.
6. **Call TROJAN** with `Authorization: Bearer <access_token>`.
7. **Refresh before the token expires.** Access tokens are short lived (one hour
   by default in Supabase; the project's JWT expiry setting decides). supabase-js
   refreshes them automatically: call `supabase.auth.getSession()` before each
   TROJAN request to get the current token, as the dashboard does. Without
   supabase-js: `POST /auth/v1/token?grant_type=refresh_token` with
   `{"refresh_token": "..."}`. Each refresh returns a new refresh token; use
   the newest one.
8. **Sign out.** `supabase.auth.signOut()` ends the session.

**Password reset, magic links and OAuth2/SSO (Google, Microsoft...)** aren't
part of TROJAN today. Supabase Auth supports them, so they can be switched on
in the Supabase project and the dashboard later without changing TROJAN's API:
the API only checks the access token, however it was obtained.

### Ingest keys: create, use, revoke

1. A TROJAN platform admin creates a key on the admin site
   (`POST /v1/admin/organizations/{organization_id}/keys`). **The raw key is
   shown once**, in that response. TROJAN stores only its SHA-256 hash.
2. The organization puts the key in its Wazuh integration config
   (`integrations/custom-trojan`, the `<api_key>` in `ossec.conf`), or in any
   tool that calls `/v1/analyze` or `/v1/findings`.
3. The key decides which organization data belongs to. Callers can't pick an
   `organization_id`.
4. Each use updates the key's `last_used_at` (at most every 5 minutes), visible
   on the admin site.
5. To rotate: create a new key, switch Wazuh to it, then revoke the old one
   (`POST /v1/admin/keys/{key_id}/revoke`). A revoked key stops working
   immediately with `401 Unauthorized`.

Single organization installs can instead set `TROJAN_INGESTION_API_KEY` and
`TROJAN_ORGANIZATION_ID` on the backend.

### Worker secret

`SCAN_WORKER_SECRET` is shared by the backend and GitHub Actions (repository
secret). It's compared in constant time. Rotate it by changing both at once.

### Expired, revoked and wrong tokens

| Situation | What the API returns | What to do |
| --- | --- | --- |
| No `Authorization` header (user endpoint) | `401 {"error": "Sign in required"}` | Sign in and send the token |
| Wrong or revoked ingest key | `401 {"error": "Unauthorized"}` | Check the key; ask an admin for a new one |
| Wrong worker secret | `401 {"error": "Unauthorized"}` | Check the GitHub secret matches the backend |
| **Expired or invalid user token** | **`502`** with `Could not read from Supabase`, `Scan request failed`, `Member request failed` or `Admin request failed` | Refresh the token and retry once. TROJAN passes the token to Supabase, which rejects it, and the API reports that as an upstream failure rather than a 401 |
| Valid token, wrong role | `403` | Ask an org admin (or TROJAN admin) for the role |
| Valid token, another organization's data | Empty lists, or `404` for a single item | Use one of your own organization IDs |

> **Known gap:** an expired user token gives 502, not 401. Clients should treat a
> 502 on a user endpoint as "refresh the token and retry once". Changing the
> API to return 401 for rejected tokens would make this clearer.

### Roles

| Role | Can |
| --- | --- |
| `viewer` | Read alerts, findings, scans and the member list |
| `analyst` | Same as viewer through the API today. The database rules also let analysts (and org admins) change an alert's or finding's `status`, and only that column, but no endpoint or screen uses it yet |
| `org_admin` | Also add members, add/confirm/remove websites and start scans |
| TROJAN platform admin | Use every `/v1/admin/*` endpoint, and confirm websites in any org |

## Errors and troubleshooting

Every error is a JSON object with one `error` message. `/v1/analyze` partial
failures add `alert_index`, `stored_count` and `results`.

```json
{ "error": "Confirm you own this website or have permission to scan it." }
```

| Status | Meaning |
| --- | --- |
| 400 | Invalid JSON (analyze), or input rejected by an admin/scan action |
| 401 | Missing or invalid token (`Unauthorized` / `Sign in required`) |
| 403 | Signed in but not allowed |
| 404 | Not found, or a path ID that isn't a UUID |
| 409 | Conflict: already exists, already running, wrong scan state |
| 413 | Batch over 1000 items (analyze, findings) |
| 422 | Missing or invalid field |
| 429 | 10 scans per organization per day reached |
| 502 | An upstream call failed (Supabase, GitHub, invite email), **or the user token expired** |
| 503 | Backend not configured, or storage failed |

### Common problems

| Symptom | Likely cause | Fix |
| --- | --- | --- |
| `401 Unauthorized` on `/v1/analyze` | Wrong, revoked or missing ingest key; or the header lacks `Bearer ` | Send `Authorization: Bearer <key>`; check the key on the admin site |
| `503 Ingestion API is not configured` | Backend has no Supabase settings | Set `SUPABASE_URL` and `SUPABASE_SERVICE_ROLE_KEY` on the backend |
| `422 Each finding must include a valid severity` | Severity `info` or a capital letter | Use `low`, `medium`, `high` or `critical`; send info-level items as `low` |
| `422 Request body must contain a findings list` on `/v1/findings` | Body isn't valid JSON, or the key isn't `findings` | Send `{"findings": [...]}` with `Content-Type: application/json` |
| `400 Invalid JSON` on `/v1/analyze` | Body isn't valid JSON | Check quoting; send `Content-Type: application/json` |
| Alerts stored but `review_status` stays `rate_limited` | Organization used its hourly AI reviews | Nothing: the review retries every 15 minutes. Raise `GROQ_REVIEWS_PER_HOUR` if this happens often |
| `review_status` is `unavailable` | Groq failed or returned an unusable answer | Retried automatically up to 5 times; check `GET /v1/health` shows `"groq": "set"` |
| `stored: 0` from `/v1/findings` | Every finding was already open for the same asset and title | Expected: duplicates are skipped |
| `502 Could not read from Supabase` on a dashboard call | User token expired, or Supabase is down | Refresh the token and retry once; if it persists, check Supabase status |
| `422 A valid organization_id is required` | Missing `organization_id`, or not a UUID | Read your organization ID from Supabase (see Authentication) |
| Empty `alerts` list but alerts exist | The user isn't a member of that organization | Check `organization_memberships` for the user |
| `400 That website isn't reachable on the public internet` | Hostname doesn't resolve, or resolves to a private address | Use the public domain name; internal sites can't be scanned |
| `409 A scan of this website is already running` | A scan is queued or running | Wait for it: poll `GET /v1/scans` |
| `409 This website's address isn't valid` | The stored address fails validation (e.g. added directly in Supabase) | Remove the website and add it again through the API |
| `429 Limit reached: 10 scans per day` | Ten scans started in the last 24 hours | Wait; the window is rolling |
| `503 Scanning isn't set up yet` | `GITHUB_DISPATCH_TOKEN` missing on the backend | Set it; `GET /v1/health` shows `"scanning": "configured"` when ready |
| Scan stuck in `queued`, then `failed` with "The scan timed out." | The GitHub Actions worker didn't start or crashed | Check the `scan.yml` workflow run in GitHub Actions |
| `403 TROJAN platform admin access required` | The user isn't in `platform_admins` | An existing platform admin adds them on the admin site |

## Rate limits and best practices

| Limit | Value | When exceeded |
| --- | --- | --- |
| Items per `analyze` / `findings` request | 1000 | `413` (`422` on the worker's finish endpoint) |
| AI reviews per organization per hour | `GROQ_REVIEWS_PER_HOUR`, default 100 | Alert is stored with `review_status: rate_limited` and reviewed later (no error) |
| Scans per organization per day | 10, rolling 24 hours | `429 Limit reached: 10 scans per day.` |
| Scans per website at once | 1 | `409 A scan of this website is already running.` |
| `limit` on list endpoints | 1-1000, default 200 | Clamped to the range (no error) |
| Raw output files per scan | 5, each up to 2,000,000 characters (gzipped, base64) | `422` |
| Review retries | Every 15 min, `REVIEW_RETRY_BATCH` alerts per run (default 3, max 20); an alert stops after 5 failed retries | - |
| Scan timeout | 45 minutes, then marked failed | - |
| Recent scans returned | 50 | - |
| Request body size (Vercel) | 4.5 MB | Vercel rejects the request before TROJAN sees it |

There are no per-endpoint request-per-second limits in TROJAN itself.

**Handling 429:** the only `429` is the daily scan limit. Don't retry it
quickly: it won't clear until the oldest of the last 10 scans is more than 24
hours old. Show the message to the user instead.

**Handling 503:** a `503` with `alert_index` from `/v1/analyze` means storage
failed part way. Wait a few seconds and resend only `alerts[alert_index:]`;
earlier alerts are already stored. Other `503`s mean the backend isn't
configured: retrying won't help.

**Best practices:**

- **Batch alerts and findings:** send up to a few hundred per request rather
  than one request per item, and stay under 1000 items and 4.5 MB.
- **Resending is safe:** alerts are de-duplicated by Wazuh `id` per
  organization, and findings by asset + title while open.
- **Give alerts their Wazuh `id`:** without it, duplicates can't be detected.
- **Poll gently:** when waiting for a scan, poll `GET /v1/scans` every 10-15
  seconds. Scans take several minutes.
- **Retry `502`/`503` with backoff** (e.g. 5 s, 10 s, 20 s), at most 3 times.
  On user endpoints, refresh the token before the first retry.
- **Keep keys server side:** ingest keys and the worker secret must never be
  shipped in a browser app or committed to a repository.

## Endpoint summary

| Method | Path | Auth | Purpose |
| --- | --- | --- | --- |
| GET | `/v1/health` | None | Configuration status |
| POST | `/v1/analyze` | Ingest key | Store and AI-review Wazuh/Suricata alerts |
| POST | `/v1/findings` | Ingest key | Store scanner findings |
| GET | `/v1/alerts` | User | List an organization's alerts |
| GET | `/v1/alerts/{alert_id}` | User | Get one alert |
| GET | `/v1/findings` | User | List an organization's findings |
| GET | `/v1/scans` | User | List websites and recent scans |
| POST | `/v1/scans` | User (org_admin) | Start a website scan |
| POST | `/v1/scan-targets` | User (org_admin) | Add a website |
| POST | `/v1/scan-targets/{target_id}/confirm` | User (org_admin) | Confirm permission to scan |
| DELETE | `/v1/scan-targets/{target_id}` | User (org_admin) | Remove a website |
| GET | `/v1/organizations/{organization_id}/members` | User (member) | List members |
| POST | `/v1/organizations/{organization_id}/members` | User (org_admin) | Add or invite a member |
| GET | `/v1/admin/overview` | Platform admin | Platform-wide counts |
| GET | `/v1/admin/organizations` | Platform admin | All organizations with members and keys |
| POST | `/v1/admin/organizations` | Platform admin | Create an organization |
| POST | `/v1/admin/organizations/{organization_id}/members` | Platform admin | Add a member to any org |
| PATCH | `/v1/admin/organizations/{organization_id}/members/{user_id}` | Platform admin | Change a member's role |
| POST | `/v1/admin/organizations/{organization_id}/keys` | Platform admin | Create an ingest key |
| POST | `/v1/admin/keys/{key_id}/revoke` | Platform admin | Revoke an ingest key |
| GET | `/v1/admin/users` | Platform admin | All user accounts |
| GET | `/v1/admin/platform-admins` | Platform admin | List platform admins |
| POST | `/v1/admin/platform-admins` | Platform admin | Add a platform admin |
| DELETE | `/v1/admin/platform-admins/{user_id}` | Platform admin | Remove a platform admin |
| GET | `/v1/admin/audit` | Platform admin | Audit log |
| POST | `/v1/worker/scans/{scan_id}/start` | Worker secret | Claim a queued scan |
| POST | `/v1/worker/scans/{scan_id}/finish` | Worker secret | Report scan results |
| POST | `/v1/worker/reviews/retry` | Worker secret | Retry AI reviews that didn't finish |

The examples below use these shell variables:

```bash
API=https://trojan-cyb.vercel.app
USER_TOKEN=...      # Supabase session access token
INGEST_KEY=...      # from the admin site
ORG=9a8b7c6d-5e4f-4a3b-8c2d-1e0f9a8b7c6d
```

---

## Health

### `GET /v1/health`

No auth. Reports whether settings are present. It doesn't contact Groq,
Supabase or GitHub.

```bash
curl $API/v1/health
```

```json
{ "status": "ok", "groq": "set", "supabase": "configured", "scanning": "configured" }
```

`scanning` is `configured` only when both `GITHUB_DISPATCH_TOKEN` and
`SCAN_WORKER_SECRET` are set.

---

## Ingestion (ingest key)

### `POST /v1/analyze`

Stores Wazuh/Suricata alerts and asks Groq for a plain-language review of each.
The Wazuh custom integration (`integrations/custom-trojan`) calls this for
every alert.

```bash
curl -X POST $API/v1/analyze \
  -H "Authorization: Bearer $INGEST_KEY" -H "Content-Type: application/json" \
  -d '{"alerts":[{"id":"1732441234.12345","rule":{"level":10,"description":"Suricata: Alert - ET SCAN Nmap Scripting Engine User-Agent Detected"},"data":{"src_ip":"203.0.113.50","dest_ip":"10.0.0.12","dest_port":"80"}}]}'
```

**Request:** `alerts` is a list of 1-1000 Wazuh alert objects. Any object is
accepted. TROJAN reads `id`, `timestamp`, `location`, `rule.*`, `agent.*`,
`manager.name`, `decoder.name` and the `data` IP, port, protocol and Suricata
`alert` fields, and drops everything else (full log lines can contain secrets
or personal data).

**What happens to each alert, in order:**

1. It's stored as `pending`. Severity starts from `rule.level`: 0-3 low,
   4-7 medium, 8-11 high, 12+ critical.
2. If this business already has an alert with the same Wazuh `id` **and its
   review finished**, the result is `duplicate` and no review is spent. If the
   earlier review didn't finish (`pending`, `unavailable` or `rate_limited`),
   resending the alert retries it.
3. If the business has used its hourly review limit, the result is
   `rate_limited`.
4. Otherwise Groq reviews it. Groq receives only the stored fields listed
   above, never the raw Wazuh event. On success (`done`) the alert's severity
   and title are replaced by the review's. If the review fails checks, the
   result is `unavailable`.

Reviews that don't finish are also retried automatically every 15 minutes
(see `POST /v1/worker/reviews/retry`).

**Response 200:**

```json
{
  "results": [
    {
      "alert_id": "6f1c1d2e-3b4a-4c5d-8e9f-0a1b2c3d4e5f",
      "review_status": "done",
      "llm_review": {
        "status": "done",
        "attack_type": "Reconnaissance",
        "severity": "medium",
        "headline": "Someone scanned your web server for weaknesses.",
        "what_happened": "A computer on the internet probed your shop server with the Nmap scanning tool.",
        "why_it_matters": "Scans often come before attempts to break in.",
        "steps": ["Check that only the services you need are open.", "Keep the web server software up to date."],
        "when_to_escalate": "Ask an expert if the scans continue or are followed by login attempts."
      }
    }
  ]
}
```

`review_status` is one of `done`, `unavailable`, `rate_limited`, `duplicate`.
`llm_review` is missing for duplicates. For `unavailable` it holds
`problems` (a list of strings); for `rate_limited`, `limit_per_hour`.

**Partial failure (503):** if storage fails part-way, the response says how
far it got, so the sender can resend from `alert_index`:

```json
{ "error": "Supabase storage failed", "alert_index": 2, "stored_count": 2, "results": [ ... ] }
```

Other errors: 400 invalid JSON, 401 bad key, 413 over 1000 alerts, 422 missing
or empty `alerts` or a non-object item, 503 ingestion not configured.

### `POST /v1/findings`

Stores vulnerability findings from any scanner, in TROJAN's unified finding
format (the format every adapter in `backend/scanners/` produces).

```bash
curl -X POST $API/v1/findings \
  -H "Authorization: Bearer $INGEST_KEY" -H "Content-Type: application/json" \
  -d '{"findings":[{"tool":"nuclei","target":"https://shop.example.com/.env","severity":"high","title":"Exposed .env file","description":"The site serves its environment file.","cve_id":null}]}'
```

| Field | Required | Notes |
| --- | --- | --- |
| `title` | Yes | Up to 500 characters are stored as the title |
| `severity` | Yes | `low`, `medium`, `high` or `critical` (`info` is rejected) |
| `target` or `asset` | One of them | URL, host or file the finding is about |
| `cve_id` | No | Stored in its own column |
| anything else | No | `tool`, `finding_type`, `description`, `evidence`, `found_at`... kept in `details` |

**Duplicates are skipped.** A finding with the same `target`/`asset` and
`title` as another in the batch, or as a finding already open or acknowledged
for this business, isn't stored again. Resolved findings don't block a new one.

**Response 201:** `{ "stored": 1 }`. `stored` counts only new findings, so it
can be lower than the number sent, or 0.

Errors: 401, 413 over 1000, 422 no `findings` list (also returned for invalid
JSON), empty list or an invalid finding, 503.

---

## Dashboard (user token)

### `GET /v1/alerts?organization_id={uuid}&limit={n}`

Newest first.

```bash
curl "$API/v1/alerts?organization_id=$ORG&limit=50" -H "Authorization: Bearer $USER_TOKEN"
```

```json
{
  "alerts": [
    {
      "id": "6f1c1d2e-3b4a-4c5d-8e9f-0a1b2c3d4e5f",
      "organization_id": "9a8b7c6d-5e4f-4a3b-8c2d-1e0f9a8b7c6d",
      "source_event_id": "1732441234.12345",
      "title": "Someone scanned your web server for weaknesses.",
      "severity": "medium",
      "status": "open",
      "source_payload": { "rule_id": "86601", "rule_level": 10, "src_ip": "203.0.113.50", "dest_port": "80" },
      "ai_review": { "status": "done", "attack_type": "Reconnaissance", "...": "..." },
      "review_status": "done",
      "reviewed_at": "2026-11-24T08:15:06.020Z",
      "created_at": "2026-11-24T08:15:03.412Z"
    }
  ]
}
```

`status` is `open`, `acknowledged` or `resolved`. `review_status` is `pending`,
`done`, `unavailable` or `rate_limited` (older alerts may only have
`ai_review.status`). Errors: 401, 422 bad `organization_id`, 502, 503.

### `GET /v1/alerts/{alert_id}`

One alert in the same shape. 404 if the ID isn't a UUID, doesn't exist or
belongs to another organization.

### `GET /v1/findings?organization_id={uuid}&limit={n}`

```json
{
  "findings": [
    {
      "id": "c4d5e6f7-0a1b-4c2d-9e3f-4a5b6c7d8e9f",
      "organization_id": "9a8b7c6d-5e4f-4a3b-8c2d-1e0f9a8b7c6d",
      "asset": "https://shop.example.com/.env",
      "title": "Exposed .env file",
      "cve_id": null,
      "severity": "high",
      "status": "open",
      "details": { "tool": "nuclei", "scan_id": "e1f2...", "...": "..." },
      "created_at": "2026-11-24T08:20:11.000Z"
    }
  ]
}
```

Findings from website scans have `details.scan_id`.

---

## Scans (user token)

How a scan runs: the dashboard calls `POST /v1/scans`, the backend queues it
and triggers the `scan.yml` GitHub Actions workflow, the worker claims it
(`/v1/worker/.../start`), runs Nuclei and Nmap, and reports back
(`/v1/worker/.../finish`).

### `GET /v1/scans?organization_id={uuid}`

```json
{
  "targets": [
    {
      "id": "0b6d3c1a-2f4e-4a8b-9c7d-1e2f3a4b5c6d",
      "organization_id": "9a8b7c6d-5e4f-4a3b-8c2d-1e0f9a8b7c6d",
      "url": "https://shop.example.com",
      "hostname": "shop.example.com",
      "verified_at": "2026-11-23T10:02:00Z",
      "created_at": "2026-11-23T10:02:00Z"
    }
  ],
  "scans": [
    {
      "id": "e1f2a3b4-c5d6-4e7f-8a9b-0c1d2e3f4a5b",
      "organization_id": "9a8b7c6d-5e4f-4a3b-8c2d-1e0f9a8b7c6d",
      "target_id": "0b6d3c1a-2f4e-4a8b-9c7d-1e2f3a4b5c6d",
      "status": "completed",
      "findings_count": 3,
      "error": "nmap did not finish.",
      "created_at": "2026-11-24T09:00:00Z",
      "started_at": "2026-11-24T09:00:40Z",
      "finished_at": "2026-11-24T09:06:12Z"
    }
  ]
}
```

Scan `status`: `queued` => `running` => `completed` or `failed`. On a completed
scan, `error` holds a warning if some tools didn't finish. Scans still queued
or running after 45 minutes are marked failed when this list is read.

### `POST /v1/scan-targets` (org_admin)

```bash
curl -X POST $API/v1/scan-targets -H "Authorization: Bearer $USER_TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"organization_id\":\"$ORG\",\"url\":\"shop.example.com\",\"confirmed\":true}"
```

- `confirmed` must be exactly `true`: the admin's statement that the
  organization owns the site or has permission to scan it.
- The URL is reduced to its origin; `https://` is assumed if missing.
- Refused (400): IP addresses, names without a dot, `.local`, `.internal`,
  `.localhost`, and any host that resolves to a non-public address.

**201:** the new website (`ScanTarget`, as above). Errors: 400, 401, 403 not
org_admin, 409 already added, 422 bad `organization_id`.

### `POST /v1/scan-targets/{target_id}/confirm` (org_admin)

Body `{ "confirmed": true }`. Confirms a website added before confirmation was
required. Platform admins can also confirm. **200:** the website. Already
confirmed websites are returned unchanged.

### `DELETE /v1/scan-targets/{target_id}` (org_admin)

**200:** `{ "removed": true }`. Errors: 401, 403, 404.

### `POST /v1/scans` (org_admin)

```bash
curl -X POST $API/v1/scans -H "Authorization: Bearer $USER_TOKEN" \
  -H "Content-Type: application/json" -d '{"target_id":"0b6d3c1a-2f4e-4a8b-9c7d-1e2f3a4b5c6d"}'
```

**201:** the new scan with `status: "queued"`.

| Status | When |
| --- | --- |
| 400 | Website not confirmed |
| 403 | Not org_admin |
| 404 | Website not found |
| 409 | This website already has a queued or running scan, or its stored address fails validation ("Remove it and add it again") |
| 422 | `target_id` missing or not a UUID |
| 429 | 10 scans started by the organization in the last 24 hours |
| 502 | GitHub refused to start the workflow (scan marked failed) |
| 503 | `GITHUB_DISPATCH_TOKEN` not set (scan marked failed) |

---

## Team (user token)

### `GET /v1/organizations/{organization_id}/members`

Any member can list.

```json
{
  "members": [
    { "user_id": "3c2b...", "email": "owner@example.com", "role": "org_admin", "joined_at": "2026-11-20T12:00:00Z" }
  ]
}
```

### `POST /v1/organizations/{organization_id}/members` (org_admin)

```json
{ "email": "thandi@example.com", "role": "analyst" }
```

`role` defaults to `viewer`. If no account uses the email, Supabase sends an
invitation and the new account is added right away.

**201:**

```json
{ "user_id": "3c2b1a09-...", "email": "thandi@example.com", "role": "analyst", "invited": true }
```

Errors: 400 invalid email or role, 403 not a member or not org_admin,
404 organization not found, 409 already a member, 502 invite failed.

---

## Admin (platform admin, user token)

All of these return 401 without a token and 403 for users who aren't TROJAN
platform admins. Changes are written to the audit log.

| Endpoint | Body | Success |
| --- | --- | --- |
| `GET /v1/admin/overview` | - | 200 `{organizations, users, alerts, open_critical_alerts, active_keys, by_organization[]}` |
| `GET /v1/admin/organizations` | - | 200 `{organizations[]}`, each with `members[]`, `alert_count` and `keys[]` (metadata only) |
| `POST /v1/admin/organizations` | `{name, admin_email?}` | 201 `{id, name, created_at}` |
| `POST /v1/admin/organizations/{id}/members` | `{email, role?}` | 201 same as the Team endpoint |
| `PATCH /v1/admin/organizations/{id}/members/{user_id}` | `{role}` | 200 `{role}` |
| `POST /v1/admin/organizations/{id}/keys` | `{label?}` | 201 `{id, label, created_at, key}` |
| `POST /v1/admin/keys/{key_id}/revoke` | - | 200 `{revoked: true}` |
| `GET /v1/admin/users` | - | 200 `{users[]}` with `platform_admin` and `organizations[]` |
| `GET /v1/admin/platform-admins` | - | 200 `{admins[]}` |
| `POST /v1/admin/platform-admins` | `{email}` | 201 `{user_id}` |
| `DELETE /v1/admin/platform-admins/{user_id}` | - | 200 `{removed: true}` |
| `GET /v1/admin/audit?limit=n` | - | 200 `{entries[]}` |

Notes:

- **Ingest keys:** the raw `key` is in the create response only. Only its hash
  is stored, so copy it straight into the Wazuh integration config.
- `admin_email` and platform admin emails must belong to an existing account
  (404 otherwise). Member emails don't: unknown emails get an invite.
- An admin can't remove their own platform-admin access (409).
- Audit `action` values: `organization.created`, `membership.added`,
  `membership.role_changed`, `ingest_key.created`, `ingest_key.revoked`,
  `platform_admin.added`, `platform_admin.removed`.

### Admin examples

The examples use `ADMIN_TOKEN`, a platform admin's access token.

**Onboard a new business:** create the organization, then a key for its Wazuh.

```bash
curl -X POST $API/v1/admin/organizations -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"Kigali Coffee Co","admin_email":"owner@kigalicoffee.example"}'
```

```json
{ "id": "5d1e7c0a-8b2f-4e6d-9a3c-2f1e0d9c8b7a", "name": "Kigali Coffee Co", "created_at": "2026-11-24T18:02:11.204Z" }
```

```bash
curl -X POST $API/v1/admin/organizations/5d1e7c0a-8b2f-4e6d-9a3c-2f1e0d9c8b7a/keys \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H "Content-Type: application/json" \
  -d '{"label":"Main office Wazuh"}'
```

```json
{
  "id": "a4b3c2d1-e0f9-4a8b-8c7d-6e5f4a3b2c1d",
  "label": "Main office Wazuh",
  "created_at": "2026-11-24T18:03:40.551Z",
  "key": "q3Vt9w0Lx...shown-once..."
}
```

**Revoke a key:** `POST /v1/admin/keys/a4b3c2d1-e0f9-4a8b-8c7d-6e5f4a3b2c1d/revoke`
=> `200 {"revoked": true}`. Revoking it again → `404 {"error": "Key not found or already revoked"}`.

**Add someone to any organization** (invites unknown emails):

```bash
curl -X POST $API/v1/admin/organizations/$ORG/members -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" -d '{"email":"it@kigalicoffee.example","role":"analyst"}'
```

```json
{ "user_id": "7f6e5d4c-3b2a-4190-8f7e-6d5c4b3a2918", "email": "it@kigalicoffee.example", "role": "analyst", "invited": true }
```

**Change their role:** `PATCH /v1/admin/organizations/$ORG/members/7f6e5d4c-...` with
`{"role": "org_admin"}` → `200 {"role": "org_admin"}`.

**Platform overview:** `GET /v1/admin/overview`

```json
{
  "organizations": 4,
  "users": 11,
  "alerts": 1287,
  "open_critical_alerts": 3,
  "active_keys": 4,
  "by_organization": [
    {
      "organization_id": "9a8b7c6d-5e4f-4a3b-8c2d-1e0f9a8b7c6d",
      "organization": "Demo Shop",
      "alerts": 412,
      "latest_alert": { "title": "Someone scanned your web server for weaknesses.", "severity": "medium", "created_at": "2026-11-24T08:15:03.412Z" }
    }
  ]
}
```

**All organizations:** `GET /v1/admin/organizations`

```json
{
  "organizations": [
    {
      "id": "9a8b7c6d-5e4f-4a3b-8c2d-1e0f9a8b7c6d",
      "name": "Demo Shop",
      "created_at": "2026-11-20T10:00:00Z",
      "members": [
        { "user_id": "1111...", "email": "owner@example.com", "display_name": "Amina", "role": "org_admin", "joined_at": "2026-11-20T10:00:00Z" }
      ],
      "alert_count": 412,
      "keys": [
        { "id": "a4b3...", "organization_id": "9a8b...", "label": "Main office Wazuh", "created_at": "2026-11-20T10:05:00Z", "revoked_at": null, "last_used_at": "2026-11-24T18:00:12Z" }
      ]
    }
  ]
}
```

**All users:** `GET /v1/admin/users`

```json
{
  "users": [
    {
      "id": "1111...", "email": "owner@example.com",
      "created_at": "2026-11-20 10:00:00+00:00", "last_sign_in_at": "2026-11-24 07:58:41+00:00",
      "platform_admin": false,
      "organizations": [ { "organization_id": "9a8b...", "organization": "Demo Shop", "role": "org_admin" } ]
    }
  ]
}
```

**Platform admins:** `GET /v1/admin/platform-admins` →
`{"admins": [{"user_id": "3333...", "email": "admin@trojan.example", "added_at": "...", "added_by": null, "added_by_email": null}]}`.
Add one with `POST /v1/admin/platform-admins` `{"email": "..."}` → `201 {"user_id": "..."}`;
remove with `DELETE /v1/admin/platform-admins/{user_id}` → `200 {"removed": true}`.

**Audit log:** `GET /v1/admin/audit?limit=50`

```json
{
  "entries": [
    {
      "id": "c0ffee00-...", "organization_id": "5d1e...", "organization": "Kigali Coffee Co",
      "actor_id": "3333...", "actor_email": "admin@trojan.example",
      "action": "ingest_key.created", "entity_type": "ingest_key", "entity_id": "a4b3...",
      "details": { "label": "Main office Wazuh" }, "created_at": "2026-11-24T18:03:40.560Z"
    }
  ]
}
```

---

## Worker (worker secret)

Called only by GitHub Actions: `backend/scanners/worker.py` (scans) and the
`review-retry.yml` schedule (reviews).

### `POST /v1/worker/scans/{scan_id}/start`

Moves a `queued` scan to `running` and returns the website:

```json
{ "url": "https://shop.example.com", "hostname": "shop.example.com" }
```

409 if the scan isn't queued, if its website was removed, or if the website's
stored address fails validation. In the last two cases the scan is marked
failed with that reason.

### `POST /v1/worker/scans/{scan_id}/finish`

```json
{
  "findings": [ { "tool": "nuclei", "target": "...", "severity": "high", "title": "..." } ],
  "error": null,
  "warning": "nmap did not finish.",
  "raw_outputs": [ { "tool": "nuclei", "name": "nuclei.jsonl", "content": "<gzip, base64>" } ]
}
```

- `findings` uses the same format as `POST /v1/findings` (0-1000 items; over
  1000 returns 422 here, not 413). Findings already open for the same asset and
  title aren't stored again.
- `error` set → scan marked `failed`. Otherwise `completed`, with any
  `warning` saved in the scan's `error` field.
- `raw_outputs` (optional, up to 5) is each tool's raw output, gzipped and
  base64-encoded. `name` must match `[a-z0-9][a-z0-9_.-]{0,39}`. Files go to
  the private `scan-raw-output` storage bucket at
  `<organization_id>/<scan_id>/<name>.gz`, and that tool's findings get a
  `raw_output_ref`. A failed upload is logged and skipped; it never fails the
  scan.

**200:** `{ "stored": 3 }`, the number of new findings. The scan's
`findings_count` is the number reported, which can be higher. 409 if the scan
isn't running; 422 for an invalid `findings` or `raw_outputs`.

### `POST /v1/worker/reviews/retry`

Called every 15 minutes by `.github/workflows/review-retry.yml`. No body.

It picks up to `REVIEW_RETRY_BATCH` alerts (default 3, max 20) across all
businesses, least recently updated first: `rate_limited` ones, `unavailable`
ones with fewer than 5 failed retries, and `pending` ones stuck for over 10
minutes. Alerts stored before 21 Nov 2026 without a description are skipped.

```bash
curl -X POST $API/v1/worker/reviews/retry -H "Authorization: Bearer $SCAN_WORKER_SECRET"
```

**200** (counts only, since the repository and its workflow logs are public):

```json
{ "retried": 3, "outcomes": { "done": 2, "rate_limited": 1 } }
```

401 without the worker secret; 502 if the alerts can't be listed.

---

## How TROJAN uses the Groq API

TROJAN doesn't expose Groq. The backend calls Groq itself, inside
`POST /v1/analyze` and `POST /v1/worker/reviews/retry`, to write the
plain-language alert reviews (`backend/groq_review.py`). Clients never need a
Groq key.

**The Groq key:** the team's Groq API key was created in the Groq console
(console.groq.com). It is set as `GROQ_API_KEY` in the backend's environment
(the Vercel project's environment variables in production, `backend/.env`
locally). Never commit the key or paste it into these docs; if it leaks,
revoke it in the Groq console and create a new one. `GET /v1/health` shows
`"groq": "set"` when the backend has a key.

```
Wazuh => TROJAN /v1/analyze => Groq chat completions => review saved on the alert => dashboard reads /v1/alerts
```

| Setting | Default | Meaning |
| --- | --- | --- |
| `GROQ_API_KEY` | (required) | Groq key, kept only on the backend |
| `GROQ_MODEL` | `openai/gpt-oss-120b` | Model used for reviews |
| `GROQ_TIMEOUT_SECONDS` | 15 | Timeout per Groq request |
| `GROQ_MAX_RETRIES` | 3 | Attempts per review |
| `GROQ_REVIEWS_PER_HOUR` | 100 | Reviews per business per hour (TROJAN's own limit) |

**The call:** `POST https://api.groq.com/openai/v1/chat/completions` with a
fixed system prompt, the stored alert fields as the user message, and
`response_format: {"type": "json_object"}`. Only the stored fields
(`AlertSourcePayload`) are sent, never the raw Wazuh event, so full log lines
that could hold passwords don't leave TROJAN.

**What Groq must return:** a JSON object with `attack_type`, `severity`,
`headline`, `what_happened`, `why_it_matters`, `steps` and
`when_to_escalate`. The prompt tells it to use plain language, only advise
(never claim it blocked or fixed anything), and not invent details.

**Checks before saving:** all keys present; `severity` one of low, medium,
high, critical; `attack_type` one of TROJAN's list; text fields non-empty;
`steps` a non-empty list. Harmless variations are fixed first ("High" →
`high`, a single string of steps → a list). A review that fails is saved as
`unavailable` with its `problems`, and retried later.

**Retries:** HTTP 429 waits for Groq's `Retry-After` (at most 60 s, else 5 s);
5xx and network errors back off 1 s, 2 s, 4 s... up to `GROQ_MAX_RETRIES`;
other errors aren't retried. Reviews that still don't finish are picked up by
the 15-minute retry schedule.

---

## AI analysis

TROJAN's AI threat analysis is made with the Groq API. Every alert sent to
`POST /v1/analyze` is classified (attack type and severity) and explained in
plain language by Groq, as described in "How TROJAN uses the Groq API" above.
There is no separate AI model endpoint: the reviews are stored on each alert
and read through `GET /v1/alerts` and `GET /v1/alerts/{alert_id}`.

---

## Real-time updates (WebSocket)

TROJAN has **no WebSocket or push API**, so there are no events such as
`scan_progress`, `scan_complete`, `threat_detected` or `alert_fired` to
subscribe to. Clients get updates by polling:

| To follow | Poll | Suggested interval |
| --- | --- | --- |
| A running scan | `GET /v1/scans?organization_id=...` until the scan's `status` is `completed` or `failed` | 10-15 s (the dashboard uses 10 s) |
| New alerts | `GET /v1/alerts?organization_id=...&limit=50`, comparing `created_at` with the last one seen | 30-60 s |
| An alert's AI review | `GET /v1/alerts/{alert_id}` until `review_status` is `done` | 30 s; retries run every 15 min |

If push updates are added later, Supabase Realtime (subscribing to inserts on
the `alerts` and `scans` tables) fits the current setup better than a
WebSocket server, which Vercel's serverless functions can't keep open.

---

## SDK examples

Full, runnable clients are in `examples/`. Each has retries for `429`/`503`,
partial-failure resending for `/v1/analyze`, and four example commands:
`send-alert`, `send-findings`, `list-alerts` and `scan <url>`.

### Python (`requests`)

```python
from trojan_client import SupabaseSession, TrojanClient

# Send alerts with an ingest key
ingest = TrojanClient("https://trojan-cyb.vercel.app", INGEST_KEY)
for result in ingest.send_alerts(wazuh_alerts):          # batches and resends partial failures
    print(result["review_status"], result["alert_id"])

# Sign in as a user and read alerts (token refreshes automatically)
session = SupabaseSession(SUPABASE_URL, SUPABASE_PUBLISHABLE_KEY)
session.sign_in("owner@example.com", PASSWORD)
org_id = session.my_organizations()[0]["organization_id"]
client = TrojanClient("https://trojan-cyb.vercel.app", session.token)
for alert in client.alerts(org_id, limit=20):
    print(alert["severity"], alert["title"])

# Scan a website your organization owns (org_admin only)
target = client.add_website(org_id, "https://shop.example.com")
scan = client.wait_for_scan(org_id, client.start_scan(target["id"])["id"])
print(scan["status"], scan["findings_count"])
```

Errors raise `TrojanError` with `.status`, `.message` and `.body`.

### JavaScript (`fetch` + `@supabase/supabase-js`)

```js
import { TrojanClient, signIn } from './trojan-client.mjs'

// Send alerts with an ingest key
const ingest = new TrojanClient('https://trojan-cyb.vercel.app', INGEST_KEY)
const results = await ingest.sendAlerts(wazuhAlerts)

// Sign in as a user; token() always returns a fresh access token
const { token, organizations } = await signIn(SUPABASE_URL, SUPABASE_PUBLISHABLE_KEY, email, password)
const client = new TrojanClient('https://trojan-cyb.vercel.app', token)
const orgId = organizations[0].organization_id
const alerts = await client.alerts(orgId, 20)

// Scan a website your organization owns (org_admin only)
const target = await client.addWebsite(orgId, 'https://shop.example.com')
const queued = await client.startScan(target.id)
const scan = await client.waitForScan(orgId, queued.id)
```

Errors throw `TrojanError` with `.status` and `.body`.

---

## Postman collection

`postman/TROJAN.postman_collection.json` has a request for every endpoint (28),
grouped as Health, Ingestion, Dashboard, Scans, Worker, Team and Admin, plus
**Error examples** (9 requests that should fail, such as a viewer starting a
scan or an empty alert list) and a **Clean up** step.

1. In Postman, **Import** the collection and both environment files.
2. Pick **TROJAN local** or **TROJAN production** and fill in:

   | Variable | Value |
   | --- | --- |
   | `baseUrl` | Already set per environment |
   | `userToken` | Access token of an `org_admin` (from Supabase sign-in) |
   | `viewerToken` | Access token of a `viewer` in the same organization (for the error examples) |
   | `adminToken` | Access token of a TROJAN platform admin |
   | `ingestKey` | An ingest key for that organization |
   | `workerSecret` | `SCAN_WORKER_SECRET` |
   | `organizationId` | The organization's UUID |
   | `scanUrl`, `scanHost` | A website **you own**, e.g. `https://your-site.example.com` and `your-site.example.com` |
   | `platformAdminCandidateEmail` | An existing account to add and then remove as platform admin |

3. Send requests one by one, or **Run collection** in order. Requests save the
   IDs they create (`alertId`, `targetId`, `scanId`, `newOrganizationId`,
   `memberUserId`, `keyId`, `platformAdminUserId`) for later ones, and each
   has tests checking the status code and response fields.

From the command line: `npx newman run postman/TROJAN.postman_collection.json -e postman/TROJAN-local.postman_environment.json --env-var userToken=...`.

> **Production warning:** a full run against production creates real data (an
> alert, a finding, a test organization, an invited member, a key) and queues a
> real scan of `scanUrl`. Use the local environment, or only a site you own.
