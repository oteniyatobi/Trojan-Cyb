import { useState } from 'react'
import Badge from '../components/Badge.jsx'

function Admin({ organizations, onChange }) {
  const [name, setName] = useState('')
  const [email, setEmail] = useState('')
  const [message, setMessage] = useState('')

  function addOrganization(event) {
    event.preventDefault()
    if (!name.trim()) return
    onChange([
      ...organizations,
      {
        id: 'DEMO-ORG-' + Date.now(),
        name: name.trim(),
        email: email.trim(),
        status: 'Active',
      },
    ])
    setName('')
    setEmail('')
    setMessage('Sample organization added for this session only.')
  }

  return (
    <>
      <div className="kpi-grid compact-grid">
        {[
          ['Organizations', organizations.length],
          [
            'Active',
            organizations.filter((org) => org.status === 'Active').length,
          ],
          [
            'Paused',
            organizations.filter((org) => org.status === 'Paused').length,
          ],
        ].map(([label, count]) => (
          <section className="panel" key={label}>
            <h2>{label}</h2>
            <p className="kpi-value">{count}</p>
          </section>
        ))}
      </div>
      <div className="two-column">
        <section className="panel">
          <h2>Add a demo organization</h2>
          <p className="panel-caption">
            Changes affect sample records in this browser session only.
          </p>
          <form className="form-stack" onSubmit={addOrganization}>
            <label>
              Organization name
              <input
                value={name}
                onChange={(event) => setName(event.target.value)}
                maxLength={80}
                required
              />
            </label>
            <label>
              Contact email
              <input
                type="email"
                value={email}
                onChange={(event) => setEmail(event.target.value)}
                required
              />
            </label>
            <button className="primary-button">Add demo organization</button>
            <p role="status" className="form-message">
              {message}
            </p>
          </form>
        </section>
        <section className="panel detail-panel">
          <h2>Administration preview</h2>
          <p>Add organizations and pause or reactivate their sample records.</p>
          <p>
            No real organization, account, subscription, or monitoring access is
            changed.
          </p>
        </section>
      </div>
      <section className="panel">
        <h2>Demo organizations</h2>
        <div className="table-scroll">
          <table>
            <thead>
              <tr>
                <th>Organization</th>
                <th>Contact</th>
                <th>Status</th>
                <th>Action</th>
              </tr>
            </thead>
            <tbody>
              {organizations.map((org) => (
                <tr key={org.id}>
                  <td>
                    <strong>{org.name}</strong>
                    <span className="cell-note">{org.id}</span>
                  </td>
                  <td>{org.email}</td>
                  <td>
                    <Badge>{org.status}</Badge>
                  </td>
                  <td>
                    <button
                      className="text-button"
                      aria-label={`${org.status === 'Active' ? 'Pause' : 'Activate'} ${org.name}`}
                      onClick={() => {
                        onChange(
                          organizations.map((item) =>
                            item.id === org.id
                              ? {
                                  ...item,
                                  status:
                                    item.status === 'Active'
                                      ? 'Paused'
                                      : 'Active',
                                }
                              : item,
                          ),
                        )
                        setMessage(
                          'Sample organization status updated. No real access was changed.',
                        )
                      }}
                    >
                      {org.status === 'Active' ? 'Pause demo' : 'Activate demo'}
                    </button>
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
export default Admin
