import { useState } from 'react'
import Badge from '../components/Badge.jsx'
import { admin } from '../lib/api.js'
import useAdminData from './useAdminData.js'

const roles = { org_admin: 'Admin', analyst: 'Analyst', viewer: 'Viewer' }

function formatDate(value) {
  return value ? new Date(value).toLocaleString() : 'Never'
}

function AdminUsers({ getToken }) {
  const { data, error } = useAdminData(getToken, admin.users)
  const [search, setSearch] = useState('')

  if (error) return <p className="error-message" role="alert">{error}</p>
  if (!data) return <p className="empty-state" role="status">Loading users…</p>

  const users = data.users.filter((user) => (
    `${user.email} ${user.organizations.map((membership) => membership.organization).join(' ')}`
      .toLowerCase()
      .includes(search.toLowerCase())
  ))

  return (
    <section className="panel">
      <div className="section-heading">
        <h2>All accounts</h2>
        <span className="panel-caption">{users.length} of {data.users.length}</span>
      </div>
      <label className="host-search">
        Search users
        <input
          onChange={(event) => setSearch(event.target.value)}
          placeholder="Email or organization"
          type="search"
          value={search}
        />
      </label>
      <div className="table-scroll">
        <table>
          <thead>
            <tr>
              <th>Account</th>
              <th>Organizations</th>
              <th>Signed up</th>
              <th>Last sign-in</th>
            </tr>
          </thead>
          <tbody>
            {users.map((user) => (
              <tr key={user.id}>
                <td>
                  <strong>{user.email}</strong>
                  {user.platform_admin && <> <Badge>TROJAN admin</Badge></>}
                </td>
                <td>
                  {user.organizations.length
                    ? user.organizations.map((membership) => (
                      <span className="cell-note" key={membership.organization_id}>
                        {membership.organization} · {roles[membership.role] ?? membership.role}
                      </span>
                    ))
                    : <span className="cell-note">None</span>}
                </td>
                <td>{formatDate(user.created_at)}</td>
                <td>{formatDate(user.last_sign_in_at)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {users.length === 0 && <p className="empty-state">No users match your search.</p>}
    </section>
  )
}

export default AdminUsers
