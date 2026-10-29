# TROJAN UI

Week 3 frontend foundation for TROJAN, an AI-powered cybersecurity platform for SMEs. The npm package is `trojan-ui`.

## Requirements and setup

Use Node.js 20.19+ or 22.12+ (the supported Node ranges for this Vite version) and npm. This project was set up with Node.js 22.20.0 and npm 10.9.3.

From the repository root:

```sh
cd ui
npm install
npm run dev
```

Open the local URL printed by Vite (normally http://localhost:5173). Press Ctrl+C to stop the server.

```sh
npm run lint
npm run build
npm run preview
```

The production build is written to `dist/`. `npm run preview` serves that build locally.

## Structure

```text
ui/
├── public/
│   └── .gitkeep
├── src/
│   ├── assets/
│   │   └── trojan-logo.png
│   ├── components/
│   │   ├── Sidebar.jsx
│   │   └── Header.jsx
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

## Implementation

Created from the official Vite React JavaScript template (`create-vite@9.3.3`, `--template react`). The standard Vite configuration and template lint tooling (Oxlint) are retained. React and React DOM are the only application dependencies; Vite, its React plugin, Oxlint, and React type definitions are development dependencies supplied by the template. The type definitions support editor hints; application code uses JavaScript and JSX.

`App.jsx` composes the sidebar, header, welcome heading, and four KPI placeholders. Navigation labels, search text, and the profile are static placeholders. Monitoring displays “Not connected”; KPI values display “—”. There is no routing, authentication, API integration, or security data yet.

The layout is inspired by the [TROJAN Overview design](https://www.figma.com/design/BodyaUM2wEUjrzZpivC7ys/Trojan?node-id=24-25). The TROJAN logo is stored locally from that design. Colors, fonts, and spacing can be changed in `src/styles/main.css`. Sora and Plus Jakarta Sans load from Google Fonts, so they require internet access; local sans-serif fonts are used as fallbacks. On smaller screens, the sidebar sits above the content and cards reduce to two columns, then one.
