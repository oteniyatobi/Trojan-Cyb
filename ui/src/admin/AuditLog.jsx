import { admin } from '../lib/api.js'
import useAdminData from './useAdminData.js'

const actions = {
  'organization.created': 'Created organization',
  'membership.role_changed': 'Changed member role',
  'ingest_key.created': 'Created ingest key',
  'ingest_key.revoked': 'Revoked ingest key',
  'platform_admin.added': 'Added TROJAN admin',
  'platform_admin.removed': 'Removed TROJAN admin',
}

function describe(entry) {
  const details = entry.details ?? {}
  if (details.role) return `New role: ${details.role}`
  if (details.label) return `Label: ${details.label}`
  if (details.email) return details.email
  if (details.name) return details.name
  return entry.entity_id ?? ''
}

function AuditLog({ getToken }) {
  const { data, error } = useAdminData(getToken, admin.audit)

  if (error) return <p className="error-message" role="alert">{error}</p>
  if (!data) return <p className="empty-state" role="status">Loading audit log…</p>

  return (
    <section className="panel">
      <div className="section-heading">
        <h2>Recent admin actions</h2>
        <span className="panel-caption">Latest {data.entries.length}</span>
      </div>
      <div className="table-scroll">
        <table>
          <thead>
            <tr>
              <th>When</th>
              <th>Who</th>
              <th>Action</th>
              <th>Organization</th>
              <th>Details</th>
            </tr>
          </thead>
          <tbody>
            {data.entries.map((entry) => (
              <tr key={entry.id}>
                <td>{new Date(entry.created_at).toLocaleString()}</td>
                <td>{entry.actor_email ?? 'System'}</td>
                <td>{actions[entry.action] ?? entry.action}</td>
                <td>{entry.organization ?? '—'}</td>
                <td>{describe(entry)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {data.entries.length === 0 && <p className="empty-state">No admin actions recorded yet.</p>}
    </section>
  )
}

export default AuditLog
