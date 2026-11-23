import { useCallback, useState } from 'react'
import useAdminData from '../admin/useAdminData.js'
import AddMemberForm from '../components/AddMemberForm.jsx'
import { roleNames } from '../lib/roles.js'
import { members as memberApi } from '../lib/api.js'

function Team({ getToken, organizationId, canManage }) {
  const [reload, setReload] = useState(0)
  const fetcher = useCallback((token) => memberApi.list(token, organizationId), [organizationId])
  const { data, error } = useAdminData(getToken, fetcher, reload)
  const [busy, setBusy] = useState(false)
  const [actionError, setActionError] = useState('')

  async function add(email, role) {
    setBusy(true)
    setActionError('')
    try {
      const added = await memberApi.add(await getToken(), organizationId, email, role)
      setReload((value) => value + 1)
      return added
    } catch (addError) {
      setActionError(addError.message)
      return null
    } finally {
      setBusy(false)
    }
  }

  if (error) return <p className="error-message" role="alert">{error}</p>
  if (!data) return <p className="empty-state" role="status">Loading team…</p>

  return (
    <>
      {canManage && (
        <section className="panel">
          <h2>Add a person</h2>
          <p className="panel-caption">
            If they don't have a TROJAN account yet, they'll get an email invite to set one up.
          </p>
          {actionError && <p className="error-message" role="alert">{actionError}</p>}
          <AddMemberForm busy={busy} onAdd={add} />
        </section>
      )}
      <section className="panel">
        <h2>People in this organization</h2>
        <div className="table-scroll">
          <table>
            <thead>
              <tr>
                <th>Email</th>
                <th>Role</th>
                <th>Joined</th>
              </tr>
            </thead>
            <tbody>
              {data.members.map((member) => (
                <tr key={member.user_id}>
                  <td>{member.email ?? 'Unknown user'}</td>
                  <td>{roleNames[member.role] ?? member.role}</td>
                  <td>{new Date(member.joined_at).toLocaleDateString()}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>
    </>
  )
}

export default Team
