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

const pages = {
  overview: 'Overview',
  alerts: 'Alerts',
  findings: 'Findings',
  scans: 'Scans',
  health: 'Health',
  settings: 'Settings',
}

function App() {
  const [theme, setTheme] = useState(() => {
    try {
      return localStorage.getItem('trojan-theme') === 'dark' ? 'dark' : 'light'
    } catch {
      return 'light'
    }
  })
  const [collapsed, setCollapsed] = useState(window.innerWidth <= 700)
  const [route, setRoute] = useState(window.location.hash.slice(1) || '/login')
  const [scans, setScans] = useState(demoData.scans)
  const [workspace, setWorkspace] = useState(demoData.workspace)

  const [page, alertId] = route.slice(1).split('/')
  const activePage = Object.hasOwn(pages, page) ? pages[page] : null
  const selectedAlert =
    page === 'alerts'
      ? demoData.alerts.find((alert) => alert.id === alertId)
      : null
  const pageNotFound =
    !activePage || (alertId && !selectedAlert) || route.split('/').length > 3

  useEffect(() => {
    function updateRoute() {
      setRoute(window.location.hash.slice(1) || '/login')
      if (window.innerWidth <= 700) setCollapsed(true)
    }
    if (!window.location.hash) window.location.replace('#/login')
    window.addEventListener('hashchange', updateRoute)
    return () => window.removeEventListener('hashchange', updateRoute)
  }, [])

  useEffect(() => {
    document.documentElement.dataset.theme = theme
    try {
      localStorage.setItem('trojan-theme', theme)
    } catch {
      // Theme switching still works when browser storage is unavailable.
    }
  }, [theme])

  function toggleTheme() {
    setTheme(theme === 'light' ? 'dark' : 'light')
  }

  function navigate(page) {
    window.location.hash = '/' + page.toLowerCase()
    if (window.innerWidth <= 700) setCollapsed(true)
  }

  function addScan(scan) {
    const now = new Date()
    setScans([
      {
        ...scan,
        id: `SCN-${String(scans.length + 1).padStart(3, '0')}`,
        status: 'Queued',
        requested: now.toLocaleString('en-GB', {
          timeZone: workspace.timezone,
        }),
        findings: null,
      },
      ...scans,
    ])
  }

  if (route === '/login') {
    return (
      <Login
        theme={theme}
        onToggleTheme={toggleTheme}
        onLogin={() => navigate('Overview')}
      />
    )
  }

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
        workspace={workspace}
        theme={theme}
        onToggleTheme={toggleTheme}
        onNavigate={navigate}
        collapsed={collapsed}
        onToggleSidebar={() => setCollapsed(!collapsed)}
        onSignOut={() => navigate('Login')}
      />
      <div className={`app-body${collapsed ? ' sidebar-collapsed' : ''}`}>
        <Sidebar activePage={activePage} onNavigate={navigate} />
        <main className="main-content" id="main-content" tabIndex={-1}>
          <div className="page-heading">
            <h1>
              {pageNotFound
                ? 'Page not found'
                : selectedAlert
                  ? 'Alert Detail'
                  : activePage}
            </h1>
          </div>
          <div className="demo-notice hidden">
            <span className="demo-label">Demo mode</span>
            <p>
              Sample data only. No live monitoring, scans, or API connection.
            </p>
          </div>
          {pageNotFound ? (
            <section className="panel">
              <p>This demo page does not exist.</p>
              <button
                type="button"
                className="text-button"
                onClick={() => navigate('Overview')}
              >
                Go to Overview
              </button>
            </section>
          ) : (
            <>
              {activePage === 'Overview' && (
                <Overview data={demoData} onNavigate={navigate} />
              )}
              {activePage === 'Alerts' &&
                (selectedAlert ? (
                  <AlertDetail
                    alert={selectedAlert}
                    onBack={() => navigate('Alerts')}
                  />
                ) : (
                  <Alerts
                    data={demoData}
                    onSelect={(alert) => {
                      window.location.hash = '/alerts/' + alert.id
                    }}
                  />
                ))}
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
              {activePage === 'Settings' && (
                <Settings
                  workspace={workspace}
                  onSave={setWorkspace}
                  theme={theme}
                  onToggleTheme={toggleTheme}
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
