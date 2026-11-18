# TROJAN UI

Student-level React + Vite frontend using JavaScript, plain CSS, and npm. Package name: `trojan-ui`. No router, icon, chart, or state-management library is required.

## Run the frontend

From the repository root:

```bash
cd ui
npm install
npm run dev
```

Use Node 22.12+ (this workspace uses Node 22.20.0). Open the URL printed by Vite. Verify changes with `npm run lint` and `npm run build` inside `ui/`.

## Demo and Backend modes

Go to **Settings → Application data**. The selection applies to every page and is remembered on this device as `trojan-data-source`. Backend is the initial default. Theme selection is stored separately as `trojan-theme`.

- **Demo:** reads `src/data/demo.json`; all pages show a sample-data notice. Demo scan requests, preferences, and organization changes only update React state and reset on reload.
- **Backend:** uses Flask for supported reads. Failed requests never silently fall back to sample records. Missing endpoints are explained on screen. The top bar uses generic workspace information because Flask has no profile endpoint.

| Page | Backend behavior |
| --- | --- |
| Overview | Reads `/v1/alerts?limit=100`; shows the backend total and clearly scoped counts from the latest loaded records. No sample history, host totals, or AI briefing. |
| Alerts | Same endpoint; loading, empty, filters, errors/retry, and refresh every 15 seconds. |
| Alert Detail | Reads `/v1/alerts/<id>`; original Wazuh evidence beside Groq review. Waiting reviews refresh every 15 seconds. |
| Health | Reads `/v1/health`; API response, database connectivity, and Groq key presence. Key presence is not a connection test. |
| Findings / Scans | Endpoint-needed message; Flask currently exposes neither resource. No demo records or pretend backend scan action. |
| Settings | Global mode/theme controls. Workspace settings need an endpoint. Admin preview can read Groq key presence from `/v1/health`; backend saves remain disabled. |
| Organizations | Admin preview only. In Backend mode, explains that organization endpoints and authorization are missing. |

Overview counts other than the backend total cover at most 100 loaded alerts. The severity chart excludes unrated alerts. Wazuh rule level and Groq severity are distinct values.

## Login and administration preview

**Workspace preview** requires no credentials. To open the admin preview, select **Demo admin**:

```text
Username: admin
Password: trojan-demo
```

This is a public demo credential check in JavaScript, not secure authentication. Admin login opens Organizations in Demo mode. Add sample organizations and pause/reactivate them. These actions change no real access or database records.

Only the demo admin sees the Organizations navigation and Groq configuration fields. Direct organization routes also check the current React role. Sign-out and reload remove the admin session; no credentials or admin role are stored in local storage. Real Flask admin-key login and Supabase user authentication are intentionally not implemented in this phase.

## Groq form

The demo admin sees a masked key field, model-name draft, save-preview button, disabled Test connection button, and status line. Demo saving clears the entered key and keeps only its final four characters in state. Use an example key beginning with `gsk_` and at least 50 characters.

In Backend mode, key presence is read from health. Key entry/saving is disabled because the demo login does not authorize real backend changes. Flask's existing encrypted key endpoint requires `TROJAN_ADMIN_KEY` and `TROJAN_SECRET_KEY`. Model changes still use backend `GROQ_MODEL`; model-saving and test-connection endpoints do not exist. The model input is explicitly an unsaved draft in Backend mode.

## Alert review states

In Demo mode, open:

| Route | State |
| --- | --- |
| `#/alerts/ALT-001` | Done: original evidence and example review |
| `#/alerts/ALT-002` | Waiting: evidence retained, no AI guidance |
| `#/alerts/ALT-003` | Not analyzed: evidence retained, no AI guidance |

`pending`, `done`, and `unavailable` come from Flask's `review_status`. Demo JSON uses `reviewStatus` after the same display mapping. Completed reviews have a nested `review` object; other examples have `review: null`. A missing completed review is treated as unavailable. A refresh reads the stored result, never requests a new analysis. Backend analysis retries are not provided by the frontend.

Backend detail URLs use numeric IDs such as `#/alerts/123`. Opening an alert from the other source asks you to change modes; it never mixes demo details into a live list.

## Frontend files

```text
ui/
├── public/                 # Favicon
├── screenshots/            # Figma references only
├── docs/week-4-handoff.md   # Work summary, backend setup, remaining contracts
├── src/
│   ├── assets/             # Original TROJAN logos
│   ├── components/         # Sidebar, Header, icons, charts, theme, Groq form
│   ├── data/demo.json      # Explicit sample records and organizations
│   ├── lib/supabase.js     # Existing unused client; no Supabase login wired yet
│   ├── pages/              # Demo pages, alerts, settings, BackendPage, Admin
│   ├── services/api.js     # All Flask requests and alert field mapping
│   ├── styles/main.css     # Tokens, light/dark colors, responsive styles
│   ├── App.jsx             # Hash routes, source, session, shared demo state
│   └── main.jsx
├── .env.local              # Ignored browser-safe configuration, if needed
├── index.html
├── package.json
├── package-lock.json
└── vite.config.js
```

Vite forwards `/v1` to `http://localhost:8000` in development. Production hosting also needs this proxy; the repository's nginx dashboard configuration provides it. Vite reads frontend values from `ui/.env.local`. Flask reads the root `.env`. Never place database credentials or private Groq/admin/service-role keys in a `VITE_` variable. The current Flask integration does not require Supabase browser keys.

Hash routes also include `#/login`, `#/overview`, `#/findings`, `#/scans`, `#/health`, `#/settings`, and `#/organizations`. They work with browser navigation and reload without a router package. Admin access must be re-entered after reload.

## Appearance and references

Plain CSS variables in `src/styles/main.css` control fonts, colors, and spacing. Light/dark mode works in Settings and the profile menu. Sora headings and Plus Jakarta Sans interface text load through Google Fonts with fallbacks. Corners are square; the sidebar collapses using one boolean and a fixed menu icon.

The [TROJAN Figma designs](https://www.figma.com/design/BodyaUM2wEUjrzZpivC7ys/Trojan?node-id=9-3) guide the interface. These images are design references, not implementation screenshots:

<img src="screenshots/trojan-1.png" alt="TROJAN overview design reference" width="600" />
<img src="screenshots/trojan-login.png" alt="TROJAN login design reference" width="600" />

See [the Week 4 handoff](docs/week-4-handoff.md) for backend startup and the work still requiring your team.
