import { useState } from 'react'
import { admin } from '../lib/api.js'
import useAdminData from './useAdminData.js'

function PlatformAdmins({ getToken, currentUserId }) {
  const [reload, setReload] = useState(0)
  const { data, error } = useAdminData(getToken, admin.platformAdmins, reload)
  const [email, setEmail] = useState('')
  const [busy, setBusy] = useState(false)
  const [message, setMessage] = useState('')
  const [actionError, setActionError] = useState('')

  async function run(action, success) {
    setBusy(true)
    setActionError('')
    setMessage('')
    try {
      await action(await getToken())
      setMessage(success)
      setReload((value) => value + 1)
      return true
    } catch (runError) {
      setActionError(runError.message)
      return false
    } finally {
      setBusy(false)
    }
  }

  async function addAdmin(event) {
    event.preventDefault()
    const added = await run((token) => admin.addPlatformAdmin(token, email), `${email} is now a TROJAN admin.`)
    if (added) setEmail('')
  }

  if (error) return <p className="error-message" role="alert">{error}</p>
  if (!data) return <p className="empty-state" role="status">Loading admins…</p>

  return (
    <>
      {actionError && <p className="error-message" role="alert">{actionError}</p>}
      {message && <p className="form-message" role="status">{message}</p>}
      <section className="panel">
        <h2>Add a TROJAN admin</h2>
        <p className="panel-caption">
          TROJAN admins can see and manage every organization. The person must already have an account.
        </p>
        <form className="inline-form" onSubmit={addAdmin}>
          <label>
            Email
            <input onChange={(event) => setEmail(event.target.value)} required type="email" value={email} />
          </label>
          <button className="primary-button" disabled={busy} type="submit">Add admin</button>
        </form>
      </section>
      <section className="panel">
        <h2>Current TROJAN admins</h2>
        <div className="table-scroll">
          <table>
            <thead>
              <tr>
                <th>Account</th>
                <th>Added</th>
                <th>Added by</th>
                <th><span className="sr-only">Actions</span></th>
              </tr>
            </thead>
            <tbody>
              {data.admins.map((row) => (
                <tr key={row.user_id}>
                  <td><strong>{row.email ?? row.user_id}</strong></td>
                  <td>{new Date(row.added_at).toLocaleString()}</td>
                  <td>{row.added_by_email ?? '—'}</td>
                  <td>
                    {row.user_id === currentUserId ? (
                      <span className="cell-note">You</span>
                    ) : (
                      <button
                        className="text-button"
                        disabled={busy}
                        type="button"
                        onClick={() => run(
                          (token) => admin.removePlatformAdmin(token, row.user_id),
                          `${row.email} is no longer a TROJAN admin.`,
                        )}
                      >
                        Remove
                      </button>
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

export default PlatformAdmins
