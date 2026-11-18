import { useEffect, useState } from 'react'
import { getAlerts } from '../services/api.js'
import Badge from '../components/Badge.jsx'
import Icon from '../components/Icon.jsx'
import { ActivityChart, SeverityChart } from '../components/Charts.jsx'

function Alerts({ data, onSelect }) {
  const [search, setSearch] = useState('')
  const [severity, setSeverity] = useState('All')
  const [status, setStatus] = useState('All')
  const [source, setSource] = useState('Backend')
  const [result, setResult] = useState({ alerts: [], total: 0 })
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [attempt, setAttempt] = useState(0)

  useEffect(() => {
    if (source !== 'Backend') return
    let active = true
    const controller = new AbortController()
    const timeout = setTimeout(() => controller.abort(), 10000)

    getAlerts(controller.signal)
      .then((response) => {
        if (active) setResult(response)
      })
      .catch((error) => {
        if (active) {
          setError(error.name === 'AbortError'
            ? 'The backend took too long to respond. Try again.'
            : error instanceof TypeError
              ? 'Cannot reach the backend. Check that Flask is running on port 8000.'
              : error instanceof SyntaxError
                ? 'The backend did not return a valid JSON response.'
                : error.message)
        }
      })
      .finally(() => {
        clearTimeout(timeout)
        if (active) setLoading(false)
      })

    return () => {
      active = false
      clearTimeout(timeout)
      controller.abort()
    }
  }, [source, attempt])

  function refreshAlerts() {
    setLoading(true)
    setError('')
    setAttempt(attempt + 1)
  }

  const records = source === 'Demo' ? data.alerts : result.alerts
  const alerts = records.filter(
    (alert) =>
      (severity === 'All' || alert.severity === severity) &&
      (status === 'All' || alert.status === status) &&
      `${alert.id} ${alert.title} ${alert.host}`
        .toLowerCase()
        .includes(search.toLowerCase()),
  )

  return (
    <>
      <div className="filters">
        <label>
          Alert data
          <select value={source} onChange={(event) => {
            setSource(event.target.value)
            setSearch('')
            setSeverity('All')
            setStatus('All')
            setLoading(true)
            setError('')
          }}>
            <option>Backend</option>
            <option>Demo</option>
          </select>
        </label>
        <p className="panel-caption">
          {source === 'Demo'
            ? 'Sample records only. These are not live security events.'
            : 'Flask alerts · latest 100 records. Refresh to check for new alerts.'}
        </p>
        {source === 'Backend' && (
          <button type="button" className="text-button" disabled={loading}
            onClick={refreshAlerts}>Refresh alerts</button>
        )}
      </div>
      {source === 'Backend' && loading ? (
        <section className="panel" role="status">Loading alerts from the backend…</section>
      ) : source === 'Backend' && error ? (
        <section className="panel connection-error" role="alert">
          <h2>Alerts unavailable</h2>
          <p>{error}</p>
          <p>Check the Flask terminal and database configuration, then try again. Demo records are available from the Alert data menu.</p>
          <button type="button" className="text-button"
            onClick={refreshAlerts}>Try again</button>
        </section>
      ) : <>
        <div className="filters">
          <label className="search-field">
            <span className="sr-only">Search alerts</span>
            <Icon name="search" />
            <input
              type="search"
              value={search}
              onChange={(event) => setSearch(event.target.value)}
              placeholder="Search alerts or hosts…"
            />
          </label>
          <label>
            Status
            <select
              value={status}
              onChange={(event) => setStatus(event.target.value)}
            >
              {['All', ...new Set(records.map((alert) => alert.status))].map((value) => (
                <option key={value}>{value}</option>
              ))}
            </select>
          </label>
          <label>
            Severity
            <select
              value={severity}
              onChange={(event) => setSeverity(event.target.value)}
            >
              {['All', ...new Set(records.map((alert) => alert.severity))].map((value) => (
                <option key={value}>{value}</option>
              ))}
            </select>
          </label>
        </div>
        {source === 'Demo' && <div className="two-column">
          <SeverityChart
            alerts={data.alerts.filter((alert) => alert.status !== 'Resolved')}
          />
          <ActivityChart
            activity={data.overview.activity}
            period={data.overview.period}
          />
        </div>}
        <section className="panel">
          <div className="section-heading">
            <h2>Recent alerts</h2>
            <span className="panel-caption">
              {source === 'Demo'
                ? `${alerts.length} demo results · ${data.snapshotDate}`
                : `${alerts.length} matching · ${records.length} loaded of ${result.total} total`}
            </span>
          </div>
          <div className="table-scroll">
            <table>
              <thead>
                <tr>
                  <th>Time</th>
                  <th>Rule / finding</th>
                  <th>Source host</th>
                  <th>{source === 'Backend' ? 'Groq severity' : 'Severity'}</th>
                  <th>Status</th>
                  {source === 'Demo' && <th>
                    <span className="sr-only">Details</span>
                  </th>}
                </tr>
              </thead>
              <tbody>
                {alerts.map((alert) => (
                  <tr key={alert.id}>
                    <td>{alert.time}</td>
                    <td>
                      {source === 'Demo' ? <button
                        type="button"
                        className="table-link"
                        onClick={() => onSelect(alert)}
                      >
                        {alert.title}
                      </button> : <strong>{alert.title}</strong>}
                      <span className="cell-note">
                        {alert.id} · {alert.source}
                      </span>
                    </td>
                    <td>{alert.host}</td>
                    <td>
                      <Badge>{alert.severity}</Badge>
                    </td>
                    <td>
                      <Badge>{alert.status}</Badge>
                    </td>
                    {source === 'Demo' && <td>
                      <button
                        type="button"
                        className="icon-button"
                        aria-label={`View ${alert.id}`}
                        onClick={() => onSelect(alert)}
                      >
                        <Icon name="arrow" />
                      </button>
                    </td>}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {alerts.length === 0 && (
            <p className="empty-state">{records.length === 0
              ? 'No alerts have been received yet.'
              : 'No alerts match your filters.'}</p>
          )}
        </section>
      </>}
    </>
  )
}

export default Alerts
