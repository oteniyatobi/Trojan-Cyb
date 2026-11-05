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

const descriptions = {
  Overview: '',
  Alerts: '',
  Findings: '',
  Scans: '',
  Health: '',
  Settings: '',
}

function App() {
  const [theme, setTheme] = useState(() => {
    try {
      return localStorage.getItem('trojan-theme') === 'dark' ? 'dark' : 'light'
    } catch {
      return 'light'
    }
  })
  const [activePage, setActivePage] = useState('Overview')
  const [selectedAlert, setSelectedAlert] = useState(null)
  const [scans, setScans] = useState(demoData.scans)
  const [workspace, setWorkspace] = useState(demoData.workspace)

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
    setActivePage(page)
    setSelectedAlert(null)
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

  return (
    <div className="app-shell">
      <a className="skip-link" href="#main-content">
        Skip to content
      </a>
      <Sidebar activePage={activePage} onNavigate={navigate} theme={theme} />
      <div className="workspace">
        <Header workspace={workspace} theme={theme} onToggleTheme={toggleTheme} />
        <main className="main-content" id="main-content" tabIndex={-1}>
          <div className="page-heading">
            <h1>{selectedAlert ? 'Alert Detail' : activePage}</h1>
            <p>
              {selectedAlert
                ? ''
                : descriptions[activePage]}
            </p>
          </div>
          <div className="demo-notice hidden">
            <span className="demo-label">Demo mode</span>
            <p>
              Sample data only. No live monitoring, scans, or API connection.
            </p>
          </div>
          {activePage === 'Overview' && (
            <Overview data={demoData} onNavigate={navigate} />
          )}
          {activePage === 'Alerts' &&
            (selectedAlert ? (
              <AlertDetail
                alert={selectedAlert}
                onBack={() => setSelectedAlert(null)}
              />
            ) : (
              <Alerts data={demoData} onSelect={setSelectedAlert} />
            ))}
          {activePage === 'Findings' && (
            <Findings findings={demoData.findings} />
          )}
          {activePage === 'Scans' && (
            <Scans scans={scans} onAddScan={addScan} />
          )}
          {activePage === 'Health' && (
            <Health services={demoData.services} hosts={demoData.hosts} snapshotDate={demoData.snapshotDate} />
          )}
          {activePage === 'Settings' && (
            <Settings workspace={workspace} onSave={setWorkspace} theme={theme} onToggleTheme={toggleTheme} />
          )}
        </main>
      </div>
    </div>
  )
}

export default App
