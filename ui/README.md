# TROJAN UI

The frontend for TROJAN, a university project helping SMEs in developing countries understand and monitor cybersecurity risks. The package name is `trojan-ui`. The interface includes six working demo pages using local JSON data, ready for a later Flask API connection.

## Technology stack

- React and React DOM for the interface.
- Vite for local development and production builds.
- JavaScript with JSX and plain CSS.
- npm for dependencies and scripts.
- Oxlint for lint checks, as supplied by the official Vite React JavaScript template.

The project was created with `create-vite@9.3.3 --template react`. Its standard Vite configuration is retained. React type definitions supplied by the template support editor hints; the application uses JavaScript, not TypeScript.

## Requirements

Use Node.js 20.19+ within Node 20, or Node 22.12 and newer, and npm. Setup was verified with Node.js 22.20.0 and npm 10.9.3.

```bash
node --version
npm --version
```

## Install and start

From the repository root:

```bash
cd ui
npm install
npm run dev
```

Open the local URL printed by Vite, normally `http://localhost:5173`. Press Ctrl+C to stop the development server.

## Check and build

Run these commands from `ui/`:

```bash
npm run lint
npm run build
```

The build is written to `dist/`. To preview that build locally:

```bash
npm run preview
```

## Folder structure

```text
ui/
├── public/                 # Files served directly by Vite
├── screenshots/            # Figma screenshots for documentation only
├── src/
│   ├── assets/
│   │   ├── trojan-logo.png
│   │   └── trojan-logo-white.png
│   ├── components/
│   │   ├── Sidebar.jsx
│   │   ├── Header.jsx
│   │   ├── Icon.jsx
│   │   ├── Badge.jsx
│   │   └── Charts.jsx
│   ├── data/
│   │   └── demo.json         # All starting demo records
│   ├── pages/               # One component per page, plus alert details
│   ├── styles/
│   │   └── main.css
│   ├── App.jsx
│   └── main.jsx
├── .gitignore
├── .oxlintrc.json
├── index.html
├── package.json
├── package-lock.json
├── vite.config.js
└── README.md
```

`main.jsx` mounts React. `App.jsx` imports the demo JSON, switches the visible page, and holds the local scan queue and workspace preferences. Each page is a functional component in `src/pages/`. Shared colors, fonts, spacing, and responsive rules live in `src/styles/main.css`. Sidebar icons are small inline SVGs in `Icon.jsx`; no icon or chart packages are installed.

## Branding and design references

The [TROJAN Figma designs](https://www.figma.com/design/BodyaUM2wEUjrzZpivC7ys/Trojan?node-id=9-3) guide the layout. Both official logos were copied unchanged from the project's supplied assets:

- `src/assets/trojan-logo.png`: regular logo used in the light top bar and demo login.
- `src/assets/trojan-logo-white.png`: white-text version used in the dark top bar and login branding panel.

The logo uses its original 3:1 aspect ratio, with CSS controlling the display width and automatic height. Sora is used for major headings and Plus Jakarta Sans for interface text. Both load through Google Fonts, with local sans-serif fallbacks when internet access is unavailable.

### Screenshot previews

These are **Figma design references**, not screenshots of the implemented application. The dashboard pages use local demo values and simple charts inspired by these designs. A demo login accepts an empty submission; real authentication is not implemented.

<img src="screenshots/trojan-1.png" alt="TROJAN Overview design reference" width="600" />

<img src="screenshots/trojan-login.png" alt="TROJAN login design reference" width="600" />

| File in `screenshots/` | Design |
| --- | --- |
| `trojan-login.png` | Login |
| `trojan-1.png` | Overview |
| `trojan-2.png` | Alerts |
| `trojan-3.png` | Alert detail |
| `trojan-4.png` | Scans |

Screenshots are kept outside `src/` and are not imported into React components. Other numbered images in the supplied assets show third-party interfaces and were not copied into the TROJAN screenshot collection.

## Currently implemented

- **Overview:** KPI cards, severity breakdown, activity chart, detection categories, and a sample briefing.
- **Alerts:** title/host search, severity and status filters, and clickable alert details with evidence and example guidance.
- **Findings:** vulnerability table, search, severity filter, and suggested next steps.
- **Scans:** sample requests, status counts, and a form that adds a request to a local demo queue. It never contacts the target or runs a scanner.
- **Health:** service status cards and a searchable host list.
- **Settings:** demo account details and editable workspace/notification preferences. Saving does not send emails or contact a service.

Navigation uses hash routes and one React state value, without a routing library. Scans and saved settings remain available while switching pages; a browser reload resets them to the JSON defaults. Search filters reset when leaving their page. All security records are demo data.

## Demo data and the future Flask API

`src/data/demo.json` contains the workspace, overview history, alerts, findings, scans, hosts, and services. Edit that file to change the starting data. The snapshot date is stored there too; the charts are a fixed example week, not a live feed.

Overview alert counts and host totals are calculated from the records. Monthly resolved incidents and weekly activity are separate sample history. The AI text is written example guidance, not output from a running model. All addresses and organizations are illustrative.

`App.jsx` is the entry point for the data. When the Flask endpoints are available, replace the JSON import with API loading there and pass the returned data to the same page components. Keep the same field names where practical, and add loading/error messages at that stage. Queue creation and settings saving will also need real API endpoints; currently they only update React state. No backend files or API calls were added in this phase.

## Planned next steps

1. Agree the response fields with the Flask API team.
2. Replace local JSON reads and demo changes with API requests.
3. Add real authentication and service status reporting when those endpoints are ready.

See the [project README](../README.md) for the planned platform capabilities and architecture.

## Light and dark mode

Use the Dark mode switch in the profile dropdown or in Settings → Appearance. Both switches update the same theme immediately, without saving the demo preferences form. The theme is stored in browser local storage as `trojan-theme` and survives a reload; other demo settings still reset. If storage is unavailable, switching works for the current visit. Theme colors are defined in `src/styles/main.css`.

## Demo login and sidebar

Click **Sign in to demo** without entering an email or password. No credentials are checked or stored. The logout button to the right of the profile returns to the login screen. Reloading keeps the current route; this demo does not enforce authentication.

The top bar spans the full page. Its three-line button expands or collapses the sidebar using one boolean state; the icon stays the same in both states. Collapsed navigation keeps the page icons and accessible labels. On small screens the expanded sidebar overlays the content and closes after selecting a page. All interface corners are square. The favicon in `public/favicon.png` is the icon extracted from the official logo.

The top-bar profile opens a dropdown with Alerts, Settings, and the theme switch. Its arrow points up while open. Settings also appears at the bottom of the sidebar with a sliders icon. Overview and Findings use compact KPI cards with icons.

## Page routes

The URL changes when you navigate, using the part after `#`:

- `#/login`
- `#/overview`
- `#/alerts` and `#/alerts/ALT-001`
- `#/findings`
- `#/scans`
- `#/health`
- `#/settings`

`App.jsx` reads the hash and listens for `hashchange`. Browser Back/Forward, direct links, and reloads work without a router package or server rewrite rules. Unknown routes show a small page-not-found message. Routes are public in this demo; real login checks will be added with the API.
