import { useEffect, useState } from 'react'
import { getAlerts, getHealth } from '../services/api.js'
import Icon from '../components/Icon.jsx'
import { SeverityChart } from '../components/Charts.jsx'

function BackendPage({ page, onNavigate }) {
  const [data, setData] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [attempt, setAttempt] = useState(0)
  const supported = page === 'Overview' || page === 'Health'

  useEffect(() => {
    if (!supported) return
    let active = true
    const controller = new AbortController()
    const timeout = setTimeout(() => controller.abort(), 10000)
    const request = page === 'Overview' ? getAlerts : getHealth
    request(controller.signal)
      .then((result) => {
        if (active) setData(result)
      })
      .catch((error) => {
        if (active)
          setError(
            error.name === 'AbortError'
              ? 'The backend took too long to respond.'
              : 'Could not load this page from Flask. ' + error.message,
          )
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
  }, [page, supported, attempt])

  if (!supported)
    return (
      <section className="panel detail-panel">
        <h2>{page} API not available yet</h2>
        <p>
          Flask has no {page.toLowerCase()} endpoint in this repository. No
          sample records are shown in Backend mode.
        </p>
        <p className="panel-caption">
          You can preview this page by choosing Demo in Settings. The backend
          team needs to add the endpoint before live records and actions can
          work.
        </p>
        <button className="text-button" onClick={() => onNavigate('Settings')}>
          Open data settings
        </button>
      </section>
    )
  if (loading)
    return (
      <section className="panel" role="status">
        Loading {page.toLowerCase()} from Flask…
      </section>
    )
  if (error)
    return (
      <section className="panel connection-error" role="alert">
        <h2>{page} unavailable</h2>
        <p>{error}</p>
        <button
          className="text-button"
          onClick={() => {
            setLoading(true)
            setError('')
            setAttempt(attempt + 1)
          }}
        >
          Try again
        </button>
      </section>
    )
  if (page === 'Health')
    return (
      <>
        <div className="kpi-grid compact-grid">
          {[
            [
              'Flask API',
              data.status === 'ok' ? 'Responding' : 'Unknown',
              'Received from /v1/health',
            ],
            [
              'Database',
              data.database === 'ok' ? 'Connected' : 'Unavailable',
              'Flask runs SELECT 1 to check connectivity.',
            ],
            [
              'Groq key',
              data.groq === 'set' ? 'Configured' : 'Not configured',
              'Key presence only; this is not a Groq connection test.',
            ],
          ].map(([title, value, detail]) => (
            <section className="panel detail-panel" key={title}>
              <h2>{title}</h2>
              <strong>{value}</strong>
              <p>{detail}</p>
            </section>
          ))}
        </div>
        <section className="panel">
          <h2>Host monitoring</h2>
          <p className="panel-caption">
            The API does not yet return host, Wazuh, or Suricata service health.
            Their status cannot be inferred from this check.
          </p>
        </section>
      </>
    )
  const active = data.alerts.filter(
    (alert) => alert.status.toLowerCase() !== 'resolved',
  )
  const cards = [
    ['Stored alerts', data.total, 'Backend total', 'alerts'],
    [
      'Active in loaded records',
      active.length,
      `${data.alerts.length} latest records loaded`,
      'findings',
    ],
    [
      'Critical in loaded records',
      active.filter((alert) => alert.severity.toLowerCase() === 'critical')
        .length,
      'Groq severity only',
      'warning',
    ],
    [
      'Waiting for review',
      data.alerts.filter((alert) => alert.reviewStatus === 'pending').length,
      'Within the loaded records',
      'clock',
    ],
  ]
  return (
    <>
      <section className="kpi-grid">
        {cards.map(([label, value, detail, icon]) => (
          <article className="kpi-card metric-card" key={label}>
            <h2>{label}</h2>
            <p className="kpi-value">{value}</p>
            <p className="kpi-description">{detail}</p>
            <span className="metric-icon">
              <Icon name={icon} />
            </span>
          </article>
        ))}
      </section>
      <SeverityChart
        alerts={active.filter((alert) => alert.severity !== 'Not rated')}
      />
      <section className="panel detail-panel backend-summary">
        <h2>Overview coverage</h2>
        <p>
          Counts and severity come from the alerts API. The severity chart
          excludes alerts without a completed Groq rating.
        </p>
        <p className="panel-caption">
          Historical charts, monitored host totals, and monthly incident totals
          need additional backend endpoints.
        </p>
        <button className="text-button" onClick={() => onNavigate('Alerts')}>
          View alerts
        </button>
      </section>
    </>
  )
}
export default BackendPage
