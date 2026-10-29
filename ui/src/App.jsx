import Sidebar from './components/Sidebar.jsx'
import Header from './components/Header.jsx'

const kpiLabels = [
  'Active Alerts',
  'Critical Threats',
  'Monitored Hosts',
  'Resolved Incidents',
]

function App() {
  return (
    <div className="app-shell">
      <a className="skip-link" href="#main-content">Skip to content</a>
      <Sidebar />

      <div className="workspace">
        <Header />
        <main className="main-content" id="main-content" tabIndex={-1}>
          <div className="page-heading">
            <h1>Overview</h1>
            <p>Welcome to TROJAN, your organization’s security workspace.</p>
          </div>

          <section className="kpi-grid" aria-label="Security overview placeholders">
            {kpiLabels.map((label) => (
              <article className="kpi-card" key={label}>
                <h2>{label}</h2>
                <p className="kpi-value" aria-label="Not available">—</p>
                <p className="kpi-description">Awaiting security data</p>
              </article>
            ))}
          </section>
        </main>
      </div>
    </div>
  )
}

export default App
