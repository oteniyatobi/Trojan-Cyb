import { useEffect, useState } from 'react'
import { getAlert } from '../services/api.js'
import Badge from '../components/Badge.jsx'
import Icon from '../components/Icon.jsx'

function AlertDetail({ demoAlert, alertId, onBack }) {
  const [alert, setAlert] = useState(demoAlert)
  const [loading, setLoading] = useState(!demoAlert)
  const [error, setError] = useState('')
  const [attempt, setAttempt] = useState(0)

  useEffect(() => {
    if (demoAlert) return
    let active = true
    const controller = new AbortController()
    const timeout = setTimeout(() => controller.abort(), 10000)

    getAlert(alertId, controller.signal)
      .then((result) => {
        if (active) { setAlert(result); setError('') }
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
  }, [demoAlert, alertId, attempt])

  useEffect(() => {
    if (demoAlert || alert?.reviewStatus !== 'pending') return
    const interval = setInterval(() => setAttempt(value => value + 1), 15000)
    return () => clearInterval(interval)
  }, [demoAlert, alert?.reviewStatus])

  function refreshAlert() {
    setLoading(true)
    setError('')
    setAttempt(attempt + 1)
  }

  const review = alert?.review
  const reviewState = alert?.reviewStatus === 'done' && !review
    ? 'unavailable'
    : alert?.reviewStatus
  const reviewLabel = { pending: 'Waiting', done: 'Done', unavailable: 'Not analyzed' }[reviewState] || 'Not analyzed'

  return (
    <>
      <div className="detail-toolbar">
        <button type="button" className="text-button" onClick={onBack}>
          <Icon name="back" /> Back to alerts
        </button>
        {!demoAlert && <button type="button" className="text-button"
          disabled={loading} onClick={refreshAlert}>Refresh alert</button>}
      </div>
      {demoAlert && (
        <div className="demo-notice">
          <span className="demo-label">Demo alert</span>
          <p>Sample evidence and example Groq guidance. No live analysis was performed.</p>
        </div>
      )}
      {loading ? (
        <section className="panel" role="status">Loading alert details…</section>
      ) : error ? (
        <section className="panel connection-error" role="alert">
          <h2>Alert unavailable</h2>
          <p>{error}</p>
          <p>Check the backend connection. HTTP 404 means this alert could not be found.</p>
          <button type="button" className="text-button" onClick={refreshAlert}>Try again</button>
        </section>
      ) : alert && <>
        <div className="detail-badges">
          <Badge>{alert.status}</Badge>
          <span className="panel-caption">
            {alert.id} · {alert.date ? alert.date + ' at ' : ''}{alert.time}
          </span>
        </div>
        <div className="two-column alert-detail-grid">
          <section className="panel detail-panel">
            <div className="section-heading">
              <h2><Icon name="findings" /> Wazuh evidence</h2>
              <Badge>Original detection</Badge>
            </div>
            <h3>{alert.title}</h3>
            <dl className="detail-list">
              <div><dt>Source</dt><dd>{alert.source}</dd></div>
              <div><dt>Rule ID</dt><dd>{alert.rule}</dd></div>
              <div><dt>Wazuh level</dt><dd>{alert.ruleLevel == null ? 'Not recorded' : alert.ruleLevel + ' / 15'}</dd></div>
              <div><dt>Host</dt><dd>{alert.host}</dd></div>
              <div><dt>Source IP</dt><dd>{alert.sourceIp}</dd></div>
              {alert.signature && <div><dt>Signature</dt><dd>{alert.signature}</dd></div>}
              {alert.destinationIp && <div><dt>Destination</dt><dd>{alert.destinationIp}{alert.destinationPort != null ? ':' + alert.destinationPort : ''}</dd></div>}
              {alert.protocol && <div><dt>Protocol</dt><dd>{alert.protocol}</dd></div>}
            </dl>
            <div className="evidence-summary">
              <h3>Recorded evidence</h3>
              <p>{alert.evidence}</p>
            </div>
            <p className="panel-caption">Original evidence remains available even when the Groq review is waiting or unavailable.</p>
          </section>
          <section className="panel detail-panel" aria-label="Groq review">
            <div className="section-heading">
              <h2><Icon name="review" /> Groq review</h2>
              <span role="status"><Badge>{reviewLabel}</Badge></span>
            </div>
            {reviewState === 'done' && review ? <>
              <div className="detail-badges">
                <Badge>{review.severity || 'Not rated'}</Badge>
                {review.attack_type && <span className="panel-caption">{review.attack_type}</span>}
              </div>
              <h3>{review.headline || 'Review completed'}</h3>
              <h3>What happened</h3>
              <p>{review.what_happened || 'No summary was provided.'}</p>
              <h3>Why it matters</h3>
              <p>{review.why_it_matters || 'No explanation was provided.'}</p>
              <h3>Suggested steps</h3>
              {review.steps?.length ? <ol className="guidance-list">
                {review.steps.map((step, index) => <li key={index}>{step}</li>)}
              </ol> : <p>No steps were provided.</p>}
              {review.when_to_escalate && <>
                <h3>When to escalate</h3>
                <p>{review.when_to_escalate}</p>
              </>}
              {review.model && <p className="panel-caption">Model: {review.model}</p>}
            </> : <div className={`review-message review-${reviewState === 'pending' ? 'waiting' : 'unavailable'}`}>
              <Icon name={reviewState === 'pending' ? 'clock' : 'warning'} />
              <h3>{reviewState === 'pending' ? 'Waiting for Groq’s review' : 'This alert has not been analyzed'}</h3>
              <p>{reviewState === 'pending'
                ? 'The alert has been saved. Groq’s review is not ready yet.'
                : 'A Groq review is unavailable. You can still investigate the original Wazuh evidence.'}</p>
              <p>{demoAlert
                ? 'This is a fixed demo example; its review state will not change.'
                : 'Checks every 15 seconds while waiting. Refresh reads the result; it does not request a new analysis.'}</p>
            </div>}
          </section>
        </div>
        <section className="panel response-note">
          <h2>Guidance for your review</h2>
          <p>Groq’s suggestions do not block threats or change devices. Check the original evidence and confirm any response with your administrator.</p>
        </section>
      </>}
    </>
  )
}

export default AlertDetail
