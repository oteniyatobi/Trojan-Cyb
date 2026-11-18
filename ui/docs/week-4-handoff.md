# Week 4 frontend handoff — 18 November 2026

## What we built and how it works

The frontend remains simple React functions, state, effects, hash navigation, local JSON, and plain CSS. No dependencies were added and backend files were not changed.

1. **API service:** `src/services/api.js` is the only place that sends Flask requests. It checks response status and shape and maps Flask's snake_case fields to display fields. It currently supports alert list, individual alert, and health reads.
2. **Alerts:** loading, empty results, filtering, explicit errors/retry, and manual refresh. A 15-second interval also reloads backend records without reloading the page. Errors hide stale results and never replace them with sample data. The next successful read recovers the list. Requests time out after ten seconds and are cancelled on navigation.
3. **Alert Detail:** original Wazuh evidence sits beside Groq's explanation. Pending reviews show Waiting; complete reviews show Done; failed/missing reviews show Not analyzed. Evidence stays visible in every review state. Only completed reviews show guidance. Waiting backend reviews are reread every 15 seconds; refresh does not run Groq again.
4. **Data source:** one Settings control applies to all pages. Demo reads JSON; Backend reads only available API resources. Missing resource endpoints have explicit messages instead of invented data. The selected source persists in local storage.
5. **Overview and Health:** backend overview is calculated from the latest 100 returned alerts, with the backend total shown separately. Unsupported historical/host metrics are omitted. Health displays the actual API's database check and Groq key presence; it never claims this tested Groq or Wazuh/Suricata services.
6. **Groq form:** admin-only UI preview with a password-type key field, model input, save-preview button, disabled Test connection action, and status. Backend key saving remains disabled because the requested login is demo-only. Model saving and real connection tests need backend work. Demo keys are cleared after saving; only their last four characters remain in memory.
7. **Admin preview:** optional member access and a demo admin credential check. Demo admin opens Organizations and can add sample organizations or pause/reactivate sample records. The role is held only in React state. Sign-out/reload removes it. This is a presentation prototype, not server-side security or a multi-tenant management system.
8. **Readability:** responsive grids, scrolling tables, readable labels, wrapping notices, square controls, light/dark tokens, and visible status/error messages.

## Files involved

All paths below are relative to `ui/`.

| File | Responsibility |
| --- | --- |
| `src/App.jsx` | Routes, global source/theme, demo session, shared sample state, mode boundaries |
| `src/services/api.js` | Flask requests, validation, alert mapping, health read |
| `src/pages/Alerts.jsx` | List, filters, error/empty/loading states, polling |
| `src/pages/AlertDetail.jsx` | Evidence/review panels, review states, detail read and waiting polling |
| `src/pages/BackendPage.jsx` | API overview and health; unsupported findings/scans messages |
| `src/pages/Settings.jsx` | Global data/theme controls, demo preferences, admin-only Groq preview |
| `src/components/GroqSettings.jsx` | Masked key/model preview, health-derived key presence, status |
| `src/pages/Login.jsx` | Optional workspace preview and demo admin credentials |
| `src/pages/Admin.jsx` | Sample organization management; backend limitation message |
| `src/data/demo.json` | Sample organizations, explicit review states, nested sample reviews |
| `src/components/Sidebar.jsx` | Conditional Organizations navigation |
| `src/components/Header.jsx` | Session label and sign-out wording |
| `src/components/Charts.jsx` | Case-insensitive severity comparison for API values |
| `src/components/Icon.jsx` | Review, clock, organization SVG paths |
| `src/styles/main.css` | Review states, notices, forms, readability and mobile adjustments |
| `vite.config.js` | Existing `/v1` proxy; removed an unused import in the first integration step |
| `README.md`, `docs/week-4-handoff.md` | Usage, setup, capabilities, and outstanding work |

## Backend in simple terms

The current API is **Flask**, not FastAPI. `backend/api.py` defines routes. `backend/models.py` describes PostgreSQL tables using SQLAlchemy. `backend/db/schema.sql` defines the database schema and row-level policies. The backend uses the psycopg driver to connect to PostgreSQL, including a suitable Supabase-hosted PostgreSQL database.

A typical alert travels through:

```text
Suricata network event → Wazuh agent/manager → custom-trojan integration
→ POST /v1/analyze → original alert stored → Groq review attempted
→ review stored or marked unavailable → React reads /v1/alerts
```

Wazuh can also provide host alerts. `integrations/custom-trojan` is the bridge script. `backend/groq_review.py` calls Groq, checks its JSON response, and provides review text. Groq advice is not an automatic blocking action. Original evidence survives a failed review. The current request processes the review synchronously; there is no implemented background retry queue for unavailable reviews.

Flask reads `DATABASE_URL` and stops at startup if it is empty. A Supabase project HTTPS URL and publishable key are not PostgreSQL connection credentials. Supabase's browser client exists in the frontend but is not used for the current API integration or user login.

The backend resolves an organization from known API keys, otherwise uses the prototype organization. Some settings and database session configuration still use a fixed default organization. A platform-wide organization portal requires further authorization and tenant-isolation work; adding a table alone does not provide it.

## Run Flask locally on your Mac

From the repository root, use a compatible Python environment. The Docker image uses Python 3.12; Python 3.13 is installed on this Mac. Do not change system Python for this project.

```bash
python3.13 -m venv .venv
source .venv/bin/activate
python -m pip install -r backend/requirements.txt
python backend/api.py
```

These commands are setup instructions; installing/running this environment against the team's Supabase database has not yet been verified. If dependency installation fails, capture the error before changing package versions.

Before starting, fill the ignored **root `.env`** privately:

```env
DATABASE_URL=postgresql+psycopg://USERNAME:PASSWORD@HOST:5432/postgres
GROQ_API_KEY=
GROQ_MODEL=openai/gpt-oss-120b
TROJAN_API_KEY=
TROJAN_ADMIN_KEY=
TROJAN_SECRET_KEY=
```

Use the exact team-approved database connection string and credentials, with the schema already installed. Do not run schema initialization against a shared database without coordinating with its owner. The SQLAlchemy connection currently sets a prototype organization through PostgreSQL connection options; the team must verify their chosen Supabase connection/role supports this setup.

- `GROQ_API_KEY`: backend-only AI credential. Missing credentials prevent AI reviews, not original evidence display.
- `GROQ_MODEL`: backend model name; use an explicit nonempty value. The listed model is the current Compose default, not a verified model recommendation.
- `TROJAN_API_KEY`: Wazuh ingest credential. Configure it before enabling external ingest.
- `TROJAN_ADMIN_KEY`: bearer credential for the real key-settings endpoints; the demo admin password is unrelated.
- `TROJAN_SECRET_KEY`: Fernet encryption key for saved Groq credentials. The team should supply a valid stable key; a random text password is not equivalent.

Flask binds to `127.0.0.1:8000`. In another terminal:

```bash
curl http://127.0.0.1:8000/v1/health
```

Check the JSON fields, not just HTTP 200: health can return `database: "unavailable"` while the API itself responds. `groq: "set"` means a key exists, not that a model call succeeded. A successful `SELECT 1` also does not prove all application tables and permissions are correct; read the alert list too.

Then start the frontend in a separate terminal:

```bash
cd ui
npm run dev
```

Choose Backend in Settings. Vite forwards `/v1` to Flask on port 8000, so the UI uses same-origin requests during development.

The repository's Docker Compose setup currently starts PostgreSQL, Redis, Flask/Gunicorn, and the nginx frontend. It **constructs a local PostgreSQL DATABASE_URL inside Compose**. Setting a Supabase URL in root `.env` does not replace that Compose value. Running Flask directly uses the root `.env` connection string. Redis being present does not mean frontend realtime transport is implemented; this frontend uses polling.

## Existing endpoints and remaining team work

| Capability | Current backend support |
| --- | --- |
| Alerts list/detail | `GET /v1/alerts`, `GET /v1/alerts/<integer id>` |
| Original alert ingest/review | `POST /v1/analyze` |
| Health | `GET /v1/health` |
| Groq key storage/status | `GET`, `PUT`, `DELETE /v1/settings/groq-key`; admin bearer required, saved keys encrypted |
| Save/read model setting | Missing; currently `GROQ_MODEL` environment variable |
| Test Groq connection | Missing |
| Findings and scans reads/actions | Models exist; API routes missing |
| Host list, trend history, monthly totals | Missing |
| Workspace/user profile and preferences | Missing |
| User authentication and real roles | Missing; Supabase Auth is not integrated with Flask |
| Organization list/create/update and platform-admin permissions | Missing |

Do not mark Week 4 fully integrated yet. The UI previews, read adapters, error handling, and polling are ready, but a real database test, real admin authorization, model saving, connection testing, and the team's review demo remain outstanding. Polling shows newly stored alerts but does not rerun unavailable AI analyses.

Suggested handoff to the team: provide a working database URL/schema/role; agree user authentication and organization boundaries; add the missing settings and resource endpoints. The frontend should then add those calls in `src/services/api.js` and replace the corresponding endpoint-needed panels.

## Verification performed

- `npm run lint` and `npm run build` passed; `git diff --check` passed.
- Browser checks used intercepted API fixtures, not the shared database: loading/empty/error/retry, API-only page data, missing endpoint messages, new alerts appearing by polling, and waiting reviews becoming complete.
- Demo admin checks covered invalid/valid credentials, guest access to admin routes, add/pause/reactivate sample organizations, Groq key masking/clearing, disabled backend writes, and role reset on sign-out/reload.
- The workspace and organization pages were checked at 320px and 390px in light and dark modes without horizontal page overflow. Tables scroll within their containers.
- No runtime browser exceptions were observed in the completed checks. Live Supabase connectivity, Wazuh ingest, Groq execution, and a group review demonstration are still unverified.

No commit, push, merge, or branch switch was performed. Only frontend source and frontend documentation were changed.
