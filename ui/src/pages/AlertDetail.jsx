import Badge from '../components/Badge.jsx'
import Icon from '../components/Icon.jsx'

function AlertDetail({ alert, onBack }) {
  return (
    <>
      <button
        type="button"
        className="text-button back-button"
        onClick={onBack}
      >
        <Icon name="back" /> Back to alerts
      </button>
      <div className="detail-badges">
        <Badge>{alert.severity}</Badge>
        <Badge>{alert.status}</Badge>
        <span className="panel-caption">
          {alert.id} · {alert.date} at {alert.time}
        </span>
      </div>
      <div className="two-column">
        <section className="panel detail-panel">
          <h2>{alert.source} detection</h2>
          <h3>{alert.title}</h3>
          <dl className="detail-list">
            <div>
              <dt>Rule</dt>
              <dd>{alert.rule}</dd>
            </div>
            <div>
              <dt>Host</dt>
              <dd>{alert.host}</dd>
            </div>
            <div>
              <dt>Source IP</dt>
              <dd>{alert.sourceIp}</dd>
            </div>
          </dl>
          <p>{alert.evidence}</p>
        </section>
        <section className="panel detail-panel">
          <div className="section-heading">
            <h2>AI review</h2>
            <Badge>Demo guidance</Badge>
          </div>
          <h3>Why it matters</h3>
          <p>{alert.explanation}</p>
          <h3>Suggested steps</h3>
          <ol className="guidance-list">
            {alert.steps.map((step) => (
              <li key={step}>{step}</li>
            ))}
          </ol>
        </section>
      </div>
      <section className="panel response-note">
        <h2>Response guidance</h2>
        <p>
          These are example suggestions. TROJAN has not blocked traffic or
          changed any devices. Confirm the evidence with your administrator
          before taking action.
        </p>
      </section>
    </>
  )
}

export default AlertDetail
