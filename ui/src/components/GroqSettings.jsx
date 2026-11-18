import { useEffect, useState } from 'react'
import { getHealth } from '../services/api.js'
import Badge from './Badge.jsx'

function GroqSettings({ source }) {
  const [key, setKey] = useState('')
  const [model, setModel] = useState('')
  const [status, setStatus] = useState(
    source === 'Demo'
      ? 'Demo key not configured.'
      : 'Loading backend key presence…',
  )
  const [message, setMessage] = useState('')

  useEffect(() => {
    if (source !== 'Backend') return
    let active = true
    const controller = new AbortController()
    const timeout = setTimeout(() => controller.abort(), 10000)
    getHealth(controller.signal)
      .then((result) => {
        if (active)
          setStatus(
            `Backend key ${result.groq === 'set' ? 'configured' : 'not configured'}. Database ${result.database}. Connection to Groq not tested.`,
          )
      })
      .catch(() => {
        if (active) setStatus('Backend unavailable. Key status is unknown.')
      })
      .finally(() => clearTimeout(timeout))
    return () => {
      active = false
      clearTimeout(timeout)
      controller.abort()
    }
  }, [source])

  function handleSave(event) {
    event.preventDefault()
    if (source !== 'Demo') return
    setStatus(
      'Demo key configured · ends in ' +
        key.slice(-4) +
        '. Connection not tested.',
    )
    setKey('')
    setMessage(
      'Demo settings updated in memory only. No key or model was sent to Flask.',
    )
  }

  return (
    <section className="panel">
      <div className="section-heading">
        <h2>Groq configuration</h2>
        <Badge>Admin preview</Badge>
      </div>
      <p className="panel-caption">
        {source === 'Demo'
          ? 'Use an example key. This is a form preview; changes stay in memory.'
          : 'Key presence is read from /v1/health. The demo admin login does not authorize real configuration changes.'}
      </p>
      <form className="form-stack" onSubmit={handleSave}>
        <label>
          Groq API key
          <input
            type="password"
            value={key}
            onChange={(event) => setKey(event.target.value)}
            placeholder="gsk_…"
            autoComplete="off"
            spellCheck={false}
            minLength={50}
            pattern="gsk_.*"
            required
            disabled={source === 'Backend'}
          />
        </label>
        <label>
          Model name{source === 'Backend' ? ' (unsaved draft)' : ' (demo only)'}
          <input
            value={model}
            onChange={(event) => setModel(event.target.value)}
            placeholder="Configured with GROQ_MODEL on Flask"
            maxLength={100}
          />
        </label>
        <p className="panel-caption">
          Flask supports encrypted key storage, but saving requires real admin
          verification. Model saving and connection testing need new backend
          endpoints.
        </p>
        <div className="button-row">
          <button className="primary-button" disabled={source === 'Backend'}>
            {source === 'Demo'
              ? 'Save demo settings'
              : 'Save key — unavailable'}
          </button>
          <button type="button" className="sign-out-button" disabled>
            Test connection — unavailable
          </button>
        </div>
      </form>
      <div className="settings-status" role="status">
        {status}
      </div>
      {message && (
        <p className="form-message" role="status">
          {message}
        </p>
      )}
    </section>
  )
}
export default GroqSettings
