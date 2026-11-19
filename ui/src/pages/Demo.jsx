import { useState } from 'react'
import Sidebar from '../components/Sidebar.jsx'
import Header from '../components/Header.jsx'
import Overview from './Overview.jsx'
import Alerts from './Alerts.jsx'
import AlertDetail from './AlertDetail.jsx'
import Findings from './Findings.jsx'
import DemoScans from './DemoScans.jsx'
import Health from './Health.jsx'
import Settings from './Settings.jsx'
import Admin from './Admin.jsx'
import demo from '../data/demo.json'

const pages = {
  overview: 'Overview',
  alerts: 'Alerts',
  findings: 'Findings',
  scans: 'Scans',
  health: 'Health',
  settings: 'Settings',
  organizations: 'Organizations',
}

function Demo({ route, theme, onToggleTheme }) {
  const [collapsed, setCollapsed] = useState(window.innerWidth <= 700)
  const [workspace, setWorkspace] = useState(demo.workspace)
  const [scans, setScans] = useState(demo.scans)
  const [organizations, setOrganizations] = useState(demo.organizations)

  const [, , page = 'overview', alertId] = route.split('/')
  const activePage = pages[page] ?? 'Overview'
  const selectedAlert = activePage === 'Alerts' && alertId
    ? demo.alerts.find((alert) => alert.id === alertId)
    : null

  function navigate(destination) {
    window.location.hash = `/demo/${destination.toLowerCase()}`
    if (window.innerWidth <= 700) setCollapsed(true)
  }

  function addScan(scan) {
    setScans((current) => [
      {
        ...scan,
        id: `DEMO-${String(current.length + 1).padStart(3, '0')}`,
        status: 'Queued',
        requested: new Date().toLocaleString(),
        findings: null,
      },
      ...current,
    ])
  }

  return (
    <div className="app-shell">
      <Header
        workspace={workspace}
        theme={theme}
        onToggleTheme={onToggleTheme}
        onNavigate={navigate}
        collapsed={collapsed}
        onToggleSidebar={() => setCollapsed(!collapsed)}
        onSignOut={() => {
          window.location.hash = '/login'
        }}
      />
      <div className={`app-body${collapsed ? ' sidebar-collapsed' : ''}`}>
        <Sidebar activePage={activePage} onNavigate={navigate} isAdmin />
        <main className="main-content" id="main-content" tabIndex={-1}>
          <div className="page-heading">
            <h1>{selectedAlert ? 'Alert Detail' : activePage}</h1>
          </div>
          <div className="demo-notice">
            <span className="demo-label">Demo</span>
            <p>
              Sample data for a fictional workspace. Nothing here is live or saved.{' '}
              <a href="#/login">Sign in</a> to see your organization.
            </p>
          </div>
          {activePage === 'Overview' && <Overview data={demo} onNavigate={navigate} />}
          {activePage === 'Alerts' && (
            selectedAlert ? (
              <AlertDetail alert={selectedAlert} onBack={() => navigate('Alerts')} demo />
            ) : (
              <Alerts
                data={demo}
                onSelect={(alert) => {
                  window.location.hash = `/demo/alerts/${alert.id}`
                }}
              />
            )
          )}
          {activePage === 'Organizations' && (
            <Admin organizations={organizations} onChange={setOrganizations} />
          )}
          {activePage === 'Findings' && <Findings findings={demo.findings} />}
          {activePage === 'Scans' && <DemoScans scans={scans} onAddScan={addScan} />}
          {activePage === 'Health' && (
            <Health services={demo.services} hosts={demo.hosts} snapshotDate={demo.snapshotDate} />
          )}
          {activePage === 'Settings' && (
            <Settings
              workspace={workspace}
              onSave={setWorkspace}
              theme={theme}
              onToggleTheme={onToggleTheme}
            />
          )}
        </main>
      </div>
    </div>
  )
}

export default Demo
