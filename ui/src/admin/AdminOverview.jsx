import Badge from '../components/Badge.jsx'
import { admin } from '../lib/api.js'
import useAdminData from './useAdminData.js'

function titleCase(value) {
  return value ? value[0].toUpperCase() + value.slice(1) : ''
}

function AdminOverview({ getToken }) {
  const { data, error } = useAdminData(getToken, admin.overview)

  if (error) return <p className="error-message" role="alert">{error}</p>
  if (!data) return <p className="empty-state" role="status">Loading overview…</p>

  return (
    <>
      <div className="kpi-grid compact-grid">
        {[
          ['Organizations', data.organizations],
          ['Users', data.users],
          ['Alerts', data.alerts],
          ['Open critical alerts', data.open_critical_alerts],
          ['Active ingest keys', data.active_keys],
        ].map(([label, count]) => (
          <section className="panel" key={label}>
            <h2>{label}</h2>
            <p className="kpi-value">{count}</p>
          </section>
        ))}
      </div>
      <section className="panel">
        <h2>Organizations</h2>
        <div className="table-scroll">
          <table>
            <thead>
              <tr>
                <th>Organization</th>
                <th>Alerts</th>
                <th>Latest alert</th>
              </tr>
            </thead>
            <tbody>
              {data.by_organization.map((row) => (
                <tr key={row.organization_id}>
                  <td>
                    <strong>{row.organization}</strong>
                    <span className="cell-note">{row.organization_id}</span>
                  </td>
                  <td>{row.alerts}</td>
                  <td>
                    {row.latest_alert ? (
                      <>
                        <Badge>{titleCase(row.latest_alert.severity)}</Badge>{' '}
                        {row.latest_alert.title}
                        <span className="cell-note">
                          {new Date(row.latest_alert.created_at).toLocaleString()}
                        </span>
                      </>
                    ) : (
                      <span className="cell-note">No alerts yet</span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>
    </>
  )
}

export default AdminOverview
