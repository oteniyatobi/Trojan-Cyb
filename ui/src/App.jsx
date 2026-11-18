import { useEffect, useState } from 'react'
import demoData from './data/demo.json'
import Sidebar from './components/Sidebar.jsx'
import Header from './components/Header.jsx'
import Overview from './pages/Overview.jsx'
import Alerts from './pages/Alerts.jsx'
import AlertDetail from './pages/AlertDetail.jsx'
import Findings from './pages/Findings.jsx'
import Scans from './pages/Scans.jsx'
import Health from './pages/Health.jsx'
import Settings from './pages/Settings.jsx'
import Login from './pages/Login.jsx'
import BackendPage from './pages/BackendPage.jsx'
import Admin from './pages/Admin.jsx'

const pages = {
  overview: 'Overview',
  alerts: 'Alerts',
  findings: 'Findings',
  scans: 'Scans',
  health: 'Health',
  settings: 'Settings',
  organizations: 'Organizations',
}

function App() {
  const [theme, setTheme] = useState(() => {
    try {
      return localStorage.getItem('trojan-theme') === 'dark' ? 'dark' : 'light'
    } catch {
      return 'light'
    }
  })
  const [source, setSource] = useState(() => {
    try {
      return localStorage.getItem('trojan-data-source') === 'Demo'
        ? 'Demo'
        : 'Backend'
    } catch {
      return 'Backend'
    }
  })
  const [session, setSession] = useState({
    name: 'Workspace viewer',
    role: 'member',
    kind: 'preview',
  })
  const [collapsed, setCollapsed] = useState(window.innerWidth <= 700)
  const [route, setRoute] = useState(window.location.hash.slice(1) || '/login')
  const [scans, setScans] = useState(demoData.scans)
  const [workspace, setWorkspace] = useState(demoData.workspace)
  const [organizations, setOrganizations] = useState(demoData.organizations)

  const [page, alertId] = route.slice(1).split('/')
  const activePage = Object.hasOwn(pages, page) ? pages[page] : null
  const selectedAlert =
    page === 'alerts'
      ? demoData.alerts.find((alert) => alert.id === alertId)
      : null
  const isBackendAlert = page === 'alerts' && /^[1-9]\d*$/.test(alertId || '')
  const pageNotFound =
    !activePage ||
    (alertId && !selectedAlert && !isBackendAlert) ||
    route.split('/').length > 3
  const wrongSource =
    alertId &&
    ((selectedAlert && source !== 'Demo') ||
      (isBackendAlert && source !== 'Backend'))
  const isAdmin = session.role === 'admin'
  const headerWorkspace = {
    name: source === 'Demo' ? workspace.name : 'TROJAN',
    organization:
      source === 'Demo' ? workspace.organization : 'Backend workspace',
    user: session.name,
    role: isAdmin ? 'Demo administrator' : 'Workspace preview',
  }

  useEffect(() => {
    const previousScrollRestoration = window.history.scrollRestoration
    window.history.scrollRestoration = 'manual'
    function updateRoute() {
      setRoute(window.location.hash.slice(1) || '/login')
      if (window.innerWidth <= 700) setCollapsed(true)
    }
    if (!window.location.hash) window.location.replace('#/login')
    window.addEventListener('hashchange', updateRoute)
    return () => {
      window.removeEventListener('hashchange', updateRoute)
      window.history.scrollRestoration = previousScrollRestoration
    }
  }, [])

  useEffect(() => {
    window.scrollTo(0, 0)
  }, [route])

  useEffect(() => {
    document.documentElement.dataset.theme = theme
    try {
      localStorage.setItem('trojan-theme', theme)
    } catch {
      /* The theme still works when browser storage is unavailable. */
    }
  }, [theme])

  useEffect(() => {
    try {
      localStorage.setItem('trojan-data-source', source)
    } catch {
      /* The selected source still applies for the current visit. */
    }
  }, [source])

  function toggleTheme() {
    setTheme(theme === 'light' ? 'dark' : 'light')
  }
  function navigate(page) {
    window.location.hash = '/' + page.toLowerCase()
    if (window.innerWidth <= 700) setCollapsed(true)
  }
  function signOut() {
    setSession({ name: 'Workspace viewer', role: 'member', kind: 'preview' })
    navigate('Login')
  }
  function addScan(scan) {
    setScans([
      {
        ...scan,
        id: `SCN-${String(scans.length + 1).padStart(3, '0')}`,
        status: 'Queued',
        requested: new Date().toLocaleString('en-GB', {
          timeZone: workspace.timezone,
        }),
        findings: null,
      },
      ...scans,
    ])
  }

  if (route === '/login')
    return (
      <Login
        theme={theme}
        onToggleTheme={toggleTheme}
        onLogin={(user) => {
          setSession(user)
          if (user.role === 'admin') setSource('Demo')
          navigate(user.role === 'admin' ? 'Organizations' : 'Overview')
        }}
      />
    )

  return (
    <div className="app-shell">
      <a
        className="skip-link"
        href="#main-content"
        onClick={(event) => {
          event.preventDefault()
          document.getElementById('main-content').focus()
        }}
      >
        Skip to content
      </a>
      <Header
        workspace={headerWorkspace}
        theme={theme}
        onToggleTheme={toggleTheme}
        onNavigate={navigate}
        collapsed={collapsed}
        onToggleSidebar={() => setCollapsed(!collapsed)}
        onSignOut={signOut}
      />
      <div className={`app-body${collapsed ? ' sidebar-collapsed' : ''}`}>
        <Sidebar
          activePage={activePage}
          onNavigate={navigate}
          isAdmin={isAdmin}
        />
        <main className="main-content" id="main-content" tabIndex={-1}>
          <div className="page-heading">
            <h1>
              {pageNotFound
                ? 'Page not found'
                : alertId
                  ? 'Alert Detail'
                  : activePage}
            </h1>
          </div>
          <div className="demo-notice">
            <span className="demo-label">
              {source === 'Demo' ? 'Demo mode' : 'Backend mode'}
            </span>
            <p>
              {source === 'Demo'
                ? 'Sample records only. Changes stay in this session.'
                : 'API data only. Missing endpoints and connection errors are shown explicitly.'}
            </p>
            <button
              className="text-button"
              onClick={() => navigate('Settings')}
            >
              Data settings
            </button>
          </div>
          {pageNotFound ? (
            <section className="panel">
              <p>This page does not exist.</p>
              <button
                className="text-button"
                onClick={() => navigate('Overview')}
              >
                Go to Overview
              </button>
            </section>
          ) : wrongSource ? (
            <section className="panel detail-panel">
              <h2>This alert belongs to the other data source</h2>
              <p>
                Choose {selectedAlert ? 'Demo' : 'Backend'} in Settings to open
                this alert.
              </p>
              <button
                className="text-button"
                onClick={() => navigate('Settings')}
              >
                Open data settings
              </button>
            </section>
          ) : (
            <>
              {activePage === 'Organizations' &&
                (isAdmin ? (
                  <Admin
                    source={source}
                    organizations={organizations}
                    onChange={setOrganizations}
                  />
                ) : (
                  <section className="panel detail-panel">
                    <h2>Administrator access required</h2>
                    <p>
                      Sign in with the demo admin account to preview
                      organization management.
                    </p>
                    <button
                      className="text-button"
                      onClick={() => navigate('Login')}
                    >
                      Open login
                    </button>
                  </section>
                ))}
              {['Overview', 'Findings', 'Scans', 'Health'].includes(
                activePage,
              ) &&
                (source === 'Backend' ? (
                  <BackendPage
                    key={activePage}
                    page={activePage}
                    onNavigate={navigate}
                  />
                ) : (
                  <>
                    {activePage === 'Overview' && (
                      <Overview data={demoData} onNavigate={navigate} />
                    )}
                    {activePage === 'Findings' && (
                      <Findings findings={demoData.findings} />
                    )}
                    {activePage === 'Scans' && (
                      <Scans scans={scans} onAddScan={addScan} />
                    )}
                    {activePage === 'Health' && (
                      <Health
                        services={demoData.services}
                        hosts={demoData.hosts}
                        snapshotDate={demoData.snapshotDate}
                      />
                    )}
                  </>
                ))}
              {activePage === 'Alerts' &&
                (alertId ? (
                  <AlertDetail
                    key={alertId}
                    demoAlert={source === 'Demo' ? selectedAlert : null}
                    alertId={alertId}
                    onBack={() => navigate('Alerts')}
                  />
                ) : (
                  <Alerts
                    key={source}
                    data={demoData}
                    source={source}
                    onSelect={(alert) => {
                      window.location.hash = '/alerts/' + alert.id
                    }}
                  />
                ))}
              {activePage === 'Settings' && (
                <Settings
                  key={source}
                  workspace={workspace}
                  onSave={setWorkspace}
                  theme={theme}
                  onToggleTheme={toggleTheme}
                  source={source}
                  onSourceChange={setSource}
                  session={session}
                />
              )}
            </>
          )}
        </main>
      </div>
    </div>
  )
}
export default App
