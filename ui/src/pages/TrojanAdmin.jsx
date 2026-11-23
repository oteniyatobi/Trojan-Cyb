import { useCallback, useEffect, useState } from 'react'
import Badge from '../components/Badge.jsx'
import { admin } from '../lib/api.js'
import ConnectWazuh from './ConnectWazuh.jsx'
import AddMemberForm from '../components/AddMemberForm.jsx'

const roles = { org_admin: 'Admin', analyst: 'Analyst', viewer: 'Viewer' }

function NewKey({ created, onDone }) {
  const [copied, setCopied] = useState(false)

  async function copy() {
    try {
      await navigator.clipboard.writeText(created.key)
      setCopied(true)
    } catch {
      setCopied(false)
    }
  }

  return (
    <div className="key-reveal" role="status">
      <p>
        <strong>Copy this key now.</strong> It won’t be shown again. It goes in the
        <code>&lt;api_key&gt;</code> line of the Wazuh config below.
      </p>
      <code className="key-value">{created.key}</code>
      <div className="key-actions">
        <button type="button" className="text-button" onClick={copy}>
          {copied ? 'Copied' : 'Copy key'}
        </button>
        <button type="button" className="text-button" onClick={onDone}>Done</button>
      </div>
      <h4>Connect Wazuh</h4>
      <ConnectWazuh apiKey={created.key} />
    </div>
  )
}

function OrganizationPanel({ organization, run, busy }) {
  const [label, setLabel] = useState('')
  const [created, setCreated] = useState(null)
  const activeKeys = organization.keys.filter((key) => !key.revoked_at)

  async function createKey(event) {
    event.preventDefault()
    const result = await run((token) => admin.createKey(token, organization.id, label))
    if (result) {
      setCreated(result)
      setLabel('')
    }
  }

  return (
    <section className="panel">
      <div className="section-heading">
        <h2>{organization.name}</h2>
        <span className="panel-caption">
          {organization.members.length} members · {organization.alert_count} alerts ·{' '}
          {activeKeys.length} active keys
        </span>
      </div>
      <p className="cell-note">{organization.id}</p>

      <h3>Members</h3>
      <div className="table-scroll">
        <table>
          <thead>
            <tr>
              <th>Member</th>
              <th>Role</th>
            </tr>
          </thead>
          <tbody>
            {organization.members.map((member) => (
              <tr key={member.user_id}>
                <td>
                  <strong>{member.display_name || member.email || 'Unknown user'}</strong>
                  {member.display_name && <span className="cell-note">{member.email}</span>}
                </td>
                <td>
                  <select
                    aria-label={`Role for ${member.email ?? member.user_id}`}
                    disabled={busy}
                    value={member.role}
                    onChange={(event) => run((token) => (
                      admin.setRole(token, organization.id, member.user_id, event.target.value)
                    ))}
                  >
                    {Object.entries(roles).map(([value, name]) => (
                      <option key={value} value={value}>{name}</option>
                    ))}
                  </select>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {organization.members.length === 0 && <p className="empty-state">No members yet.</p>}
      <AddMemberForm
        busy={busy}
        onAdd={(email, role) => run((token) => admin.addMember(token, organization.id, email, role))}
      />

      <h3>Wazuh ingest keys</h3>
      {organization.keys.length > 0 && (
        <div className="table-scroll">
          <table>
            <thead>
              <tr>
                <th>Label</th>
                <th>Created</th>
                <th>Last used</th>
                <th>Status</th>
                <th><span className="sr-only">Actions</span></th>
              </tr>
            </thead>
            <tbody>
              {organization.keys.map((key) => (
                <tr key={key.id}>
                  <td>{key.label || 'Unlabelled'}</td>
                  <td>{new Date(key.created_at).toLocaleString()}</td>
                  <td>{key.last_used_at ? new Date(key.last_used_at).toLocaleString() : 'Never'}</td>
                  <td><Badge>{key.revoked_at ? 'Revoked' : 'Active'}</Badge></td>
                  <td>
                    {!key.revoked_at && (
                      <button
                        type="button"
                        className="text-button"
                        disabled={busy}
                        onClick={() => run((token) => admin.revokeKey(token, key.id))}
                      >
                        Revoke
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {created ? (
        <NewKey created={created} onDone={() => setCreated(null)} />
      ) : (
        <>
          {activeKeys.length > 0 && (
            <details className="setup-details">
              <summary>How to connect Wazuh</summary>
              <ConnectWazuh />
            </details>
          )}
          <form className="inline-form" onSubmit={createKey}>
          <label>
            Key label
            <input
              maxLength={120}
              onChange={(event) => setLabel(event.target.value)}
              placeholder="e.g. Office Wazuh manager"
              value={label}
            />
          </label>
          <button className="primary-button" disabled={busy} type="submit">Create key</button>
          </form>
        </>
      )}
    </section>
  )
}

function TrojanAdmin({ getToken }) {
  const [organizations, setOrganizations] = useState(null)
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  const [name, setName] = useState('')
  const [adminEmail, setAdminEmail] = useState('')
  const [search, setSearch] = useState('')

  const load = useCallback(async () => {
    const token = await getToken()
    const body = await admin.organizations(token)
    setOrganizations(body.organizations)
  }, [getToken])

  useEffect(() => {
    let active = true
    getToken()
      .then((token) => admin.organizations(token))
      .then((result) => {
        if (active) setOrganizations(result.organizations)
      })
      .catch((loadError) => {
        if (active) setError(loadError.message)
      })
    return () => {
      active = false
    }
  }, [getToken])

  async function run(action) {
    setBusy(true)
    setError('')
    try {
      const result = await action(await getToken())
      await load()
      return result
    } catch (actionError) {
      setError(actionError.message)
      return null
    } finally {
      setBusy(false)
    }
  }

  async function createOrganization(event) {
    event.preventDefault()
    const result = await run((token) => admin.createOrganization(token, name, adminEmail))
    if (result) {
      setName('')
      setAdminEmail('')
    }
  }

  if (!organizations) {
    return error
      ? <p className="error-message" role="alert">{error}</p>
      : <p className="empty-state" role="status">Loading organizations…</p>
  }

  const members = organizations.flatMap((organization) => organization.members)
  const activeKeys = organizations.flatMap((organization) => organization.keys)
    .filter((key) => !key.revoked_at)
  const shown = organizations.filter((organization) => (
    `${organization.name} ${organization.id} ${organization.members.map((member) => member.email).join(' ')}`
      .toLowerCase()
      .includes(search.toLowerCase())
  ))

  return (
    <>
      {error && <p className="error-message" role="alert">{error}</p>}
      <div className="kpi-grid compact-grid">
        {[
          ['Organizations', organizations.length],
          ['Organization admins', members.filter((member) => member.role === 'org_admin').length],
          ['Members', members.length],
          ['Active ingest keys', activeKeys.length],
        ].map(([label, count]) => (
          <section className="panel" key={label}>
            <h2>{label}</h2>
            <p className="kpi-value">{count}</p>
          </section>
        ))}
      </div>
      <section className="panel">
        <h2>Create an organization</h2>
        <p className="panel-caption">
          The admin must already have a TROJAN account. Leave the email empty to add one later.
        </p>
        <form className="form-stack" onSubmit={createOrganization}>
          <label>
            Organization name
            <input
              maxLength={120}
              onChange={(event) => setName(event.target.value)}
              required
              value={name}
            />
          </label>
          <label>
            Admin email
            <input
              onChange={(event) => setAdminEmail(event.target.value)}
              type="email"
              value={adminEmail}
            />
          </label>
          <button className="primary-button" disabled={busy} type="submit">
            Create organization
          </button>
        </form>
      </section>
      <label className="host-search">
        Search organizations
        <input
          onChange={(event) => setSearch(event.target.value)}
          placeholder="Name, ID or member email"
          type="search"
          value={search}
        />
      </label>
      {shown.map((organization) => (
        <OrganizationPanel
          busy={busy}
          key={organization.id}
          organization={organization}
          run={run}
        />
      ))}
      {shown.length === 0 && <p className="empty-state">No organizations match your search.</p>}
    </>
  )
}

export default TrojanAdmin
