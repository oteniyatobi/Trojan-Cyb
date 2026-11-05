import { useState } from 'react'
import Badge from '../components/Badge.jsx'
import Icon from '../components/Icon.jsx'
import { ActivityChart, SeverityChart } from '../components/Charts.jsx'

function Alerts({ data, onSelect }) {
  const [search, setSearch] = useState('')
  const [severity, setSeverity] = useState('All')
  const [status, setStatus] = useState('All')
  const alerts = data.alerts.filter(
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
            {['All', 'Open', 'In review', 'Resolved'].map((value) => (
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
            {['All', 'Critical', 'High', 'Medium', 'Low'].map((value) => (
              <option key={value}>{value}</option>
            ))}
          </select>
        </label>
      </div>
      <div className="two-column">
        <SeverityChart
          alerts={data.alerts.filter((alert) => alert.status !== 'Resolved')}
        />
        <ActivityChart
          activity={data.overview.activity}
          period={data.overview.period}
        />
      </div>
      <section className="panel">
        <div className="section-heading">
          <h2>Recent alerts</h2>
          <span className="panel-caption">
            {alerts.length} results · {data.snapshotDate}
          </span>
        </div>
        <div className="table-scroll">
          <table>
            <thead>
              <tr>
                <th>Time</th>
                <th>Rule / finding</th>
                <th>Source host</th>
                <th>Severity</th>
                <th>Status</th>
                <th>
                  <span className="sr-only">Details</span>
                </th>
              </tr>
            </thead>
            <tbody>
              {alerts.map((alert) => (
                <tr key={alert.id}>
                  <td>{alert.time}</td>
                  <td>
                    <button
                      type="button"
                      className="table-link"
                      onClick={() => onSelect(alert)}
                    >
                      {alert.title}
                    </button>
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
                  <td>
                    <button
                      type="button"
                      className="icon-button"
                      aria-label={`View ${alert.id}`}
                      onClick={() => onSelect(alert)}
                    >
                      <Icon name="arrow" />
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        {alerts.length === 0 && (
          <p className="empty-state">No alerts match your filters.</p>
        )}
      </section>
    </>
  )
}

export default Alerts
