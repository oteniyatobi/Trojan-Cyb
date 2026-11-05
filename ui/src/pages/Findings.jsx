import { useState } from 'react'
import Badge from '../components/Badge.jsx'
import Icon from '../components/Icon.jsx'

function Findings({ findings }) {
  const [severity, setSeverity] = useState('All')
  const [search, setSearch] = useState('')
  const filtered = findings.filter(
    (finding) =>
      (severity === 'All' || finding.severity === severity) &&
      `${finding.title} ${finding.host}`
        .toLowerCase()
        .includes(search.toLowerCase()),
  )

  return (
    <>
      <div className="kpi-grid compact-grid">
        <article className="kpi-card metric-card">
          <h2>Total Findings</h2>
          <p className="kpi-value">{findings.length}</p>
          <p className="kpi-description">Latest demo scan results</p>
          <span className="metric-icon">
            <Icon name="findings" />
          </span>
        </article>
        <article className="kpi-card metric-card tone-red">
          <h2>Need Attention</h2>
          <p className="kpi-value">
            {findings.filter((finding) => finding.status !== 'Resolved').length}
          </p>
          <p className="kpi-description">Open or in review</p>
          <span className="metric-icon">
            <Icon name="warning" />
          </span>
        </article>
        <article className="kpi-card metric-card tone-green">
          <h2>Resolved</h2>
          <p className="kpi-value">
            {findings.filter((finding) => finding.status === 'Resolved').length}
          </p>
          <p className="kpi-description">Reviewed by the demo team</p>
          <span className="metric-icon">
            <Icon name="check" />
          </span>
        </article>
      </div>
      <div className="filters">
        <label className="grow">
          Search findings
          <input
            type="search"
            value={search}
            onChange={(event) => setSearch(event.target.value)}
            placeholder="Search a finding or host…"
          />
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
      <section className="panel">
        <div className="section-heading">
          <h2>Vulnerability findings</h2>
          <span className="panel-caption">{filtered.length} results</span>
        </div>
        <div className="table-scroll">
          <table>
            <thead>
              <tr>
                <th>Finding</th>
                <th>Host / target</th>
                <th>Severity</th>
                <th>Status</th>
                <th>Suggested next step</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map((finding) => (
                <tr key={finding.id}>
                  <td>
                    <strong>{finding.title}</strong>
                    <span className="cell-note">
                      {finding.id} · {finding.tool}
                    </span>
                  </td>
                  <td>{finding.host}</td>
                  <td>
                    <Badge>{finding.severity}</Badge>
                  </td>
                  <td>
                    <Badge>{finding.status}</Badge>
                  </td>
                  <td className="guidance-cell">{finding.guidance}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        {filtered.length === 0 && (
          <p className="empty-state">No findings match your filters.</p>
        )}
      </section>
    </>
  )
}

export default Findings
