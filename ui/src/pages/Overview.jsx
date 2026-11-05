import { ActivityChart, SeverityChart } from '../components/Charts.jsx'
import Badge from '../components/Badge.jsx'
import Icon from '../components/Icon.jsx'

function Overview({ data, onNavigate }) {
  const activeAlerts = data.alerts.filter(
    (alert) => alert.status !== 'Resolved',
  )
  const onlineHosts = data.hosts.filter((host) => host.status === 'Online')
  const criticalAlerts = activeAlerts.filter(
    (alert) => alert.severity === 'Critical',
  )
  const categories = data.overview.categories
  const maximum = Math.max(...categories.map((category) => category.count), 1)
  const cards = [
    {
      label: 'Active Alerts',
      value: activeAlerts.length,
      detail: `${activeAlerts.filter((alert) => alert.status === 'In review').length} in review`,
      tone: 'violet',
      icon: 'alerts',
    },
    {
      label: 'Critical Threats',
      value: criticalAlerts.length,
      detail: 'Attention required',
      tone: 'red',
      icon: 'warning',
    },
    {
      label: 'Monitored Hosts',
      value: `${onlineHosts.length} / ${data.hosts.length}`,
      detail: `${data.hosts.length - onlineHosts.length} disconnected`,
      tone: 'blue',
      icon: 'hosts',
    },
    {
      label: 'Resolved Incidents',
      value: data.overview.resolvedThisMonth,
      detail: 'This month · demo history',
      tone: 'green',
      icon: 'check',
    },
  ]

  return (
    <>
      <section className="kpi-grid" aria-label="Security overview">
        {cards.map((card) => (
          <article
            className={`kpi-card metric-card tone-${card.tone}`}
            key={card.label}
          >
            <h2>{card.label}</h2>
            <p className="kpi-value">{card.value}</p>
            <p className="kpi-description">{card.detail}</p>
            <span className="metric-icon">
              <Icon name={card.icon} />
            </span>
          </article>
        ))}
      </section>
      <div className="two-column">
        <SeverityChart alerts={activeAlerts} />
        <ActivityChart
          activity={data.overview.activity}
          period={data.overview.period}
        />
        <section className="panel">
          <h2>Weekly Detections by Category</h2>
          <p className="panel-caption">{data.overview.period}</p>
          <div className="bar-chart">
            {categories.map((category) => (
              <div className="bar-column" key={category.name}>
                <strong>{category.count}</strong>
                <div className="bar-track">
                  <div
                    className="bar-fill"
                    style={{ height: `${(category.count / maximum) * 100}%` }}
                  />
                </div>
                <span>{category.name}</span>
              </div>
            ))}
          </div>
        </section>
        <section className="panel briefing-panel">
          <h2>AI-Assisted Security Briefing</h2>
          <div>
            <Badge>Demo guidance</Badge>
          </div>
          <h3>{criticalAlerts.length} critical alerts need review</h3>
          <p>{data.overview.briefing}</p>
          <button
            type="button"
            className="text-button"
            onClick={() => onNavigate('Alerts')}
          >
            View security alerts <Icon name="arrow" />
          </button>
        </section>
      </div>
    </>
  )
}

export default Overview
