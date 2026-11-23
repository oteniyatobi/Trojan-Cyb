import { useState } from 'react'
import { roleNames } from '../lib/roles.js'

function AddMemberForm({ busy, onAdd }) {
  const [email, setEmail] = useState('')
  const [role, setRole] = useState('viewer')
  const [message, setMessage] = useState('')

  async function submit(event) {
    event.preventDefault()
    setMessage('')
    const added = await onAdd(email, role)
    if (added) {
      setMessage(added.invited
        ? `Invite sent to ${added.email}. They'll join once they accept it.`
        : `${added.email} was added.`)
      setEmail('')
      setRole('viewer')
    }
  }

  return (
    <>
      <form className="inline-form" onSubmit={submit}>
        <label>
          Email
          <input
            autoComplete="off"
            onChange={(event) => setEmail(event.target.value)}
            placeholder="person@example.com"
            required
            type="email"
            value={email}
          />
        </label>
        <label>
          Role
          <select onChange={(event) => setRole(event.target.value)} value={role}>
            {Object.entries(roleNames).map(([value, name]) => (
              <option key={value} value={value}>{name}</option>
            ))}
          </select>
        </label>
        <button className="primary-button" disabled={busy} type="submit">Add person</button>
      </form>
      {message && <p className="form-message" role="status">{message}</p>}
    </>
  )
}

export default AddMemberForm
