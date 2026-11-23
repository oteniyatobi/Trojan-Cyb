import { useCallback, useEffect, useRef, useState } from 'react'
import useAdminData from '../admin/useAdminData.js'
import Badge from '../components/Badge.jsx'
import { scans as scanApi } from '../lib/api.js'

const statusNames = { queued: 'Queued', running: 'Running', completed: 'Completed', failed: 'Failed' }
const active = (scan) => scan.status === 'queued' || scan.status === 'running'

function formatDate(value) {
  return value ? new Date(value).toLocaleString() : '—'
}

function Scans({ getToken, organizationId, canScan, onFindingsChanged }) {
  const [reload, setReload] = useState(0)
  const fetcher = useCallback((token) => scanApi.list(token, organizationId), [organizationId])
  const { data, error } = useAdminData(getToken, fetcher, reload)
  const [url, setUrl] = useState('')
  const [confirmed, setConfirmed] = useState(false)
  const [busy, setBusy] = useState(false)
  const [message, setMessage] = useState('')
  const [actionError, setActionError] = useState('')
  const finished = useRef(null)

  const scanList = data?.scans ?? []
  const running = scanList.some(active)

  useEffect(() => {
    if (!running) return undefined
    const timer = setInterval(() => setReload((value) => value + 1), 10000)
    return () => clearInterval(timer)
  }, [running])

  useEffect(() => {
    if (!data) return
    const done = new Set(data.scans.filter((scan) => scan.status === 'completed').map((scan) => scan.id))
    if (finished.current && [...done].some((id) => !finished.current.has(id))) onFindingsChanged?.()
    finished.current = done
  }, [data, onFindingsChanged])

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

  async function addTarget(event) {
    event.preventDefault()
    const added = await run(
      (token) => scanApi.addTarget(token, organizationId, url, confirmed),
      'Website added. You can scan it now.',
    )
    if (added) {
      setUrl('')
      setConfirmed(false)
    }
  }

  if (error) return <p className="error-message" role="alert">{error}</p>
  if (!data) return <p className="empty-state" role="status">Loading scans…</p>

  const hostnames = Object.fromEntries(data.targets.map((target) => [target.id, target.hostname]))

  return (
    <>
      {actionError && <p className="error-message" role="alert">{actionError}</p>}
      {message && <p className="form-message" role="status">{message}</p>}
      {canScan && (
        <section className="panel">
          <h2>Add a website</h2>
          <p className="panel-caption">
            Only add websites your organization owns or has written permission to test.
          </p>
          <form className="inline-form" onSubmit={addTarget}>
            <label>
              Website address
              <input
                onChange={(event) => setUrl(event.target.value)}
                placeholder="https://example.com"
                required
                value={url}
              />
            </label>
            <label className="checkbox-label">
              <input
                checked={confirmed}
                onChange={(event) => setConfirmed(event.target.checked)}
                required
                type="checkbox"
              />
              I own this website or have permission to scan it
            </label>
            <button className="primary-button" disabled={busy} type="submit">Add website</button>
          </form>
        </section>
      )}

      <section className="panel">
        <h2>Websites</h2>
        <p className="panel-caption">
          A scan checks the website with Nuclei (known vulnerabilities and misconfigurations) and Nmap
          (open ports). It usually takes 5–15 minutes. Results appear on the Findings page.
        </p>
        {data.targets.length === 0 && <p className="empty-state">No websites added yet.</p>}
        {data.targets.map((target) => {
          const scanning = scanList.some((scan) => scan.target_id === target.id && active(scan))
          return (
            <div className="scan-target" key={target.id}>
              <div className="section-heading">
                <h3>{target.hostname}</h3>
                {!target.verified_at && <Badge>Not confirmed</Badge>}
              </div>
              {!target.verified_at && (
                <p className="panel-caption">Remove this website and add it again to confirm you may scan it.</p>
              )}
              {canScan && (
                <div className="key-actions">
                  {target.verified_at && (
                    <button
                      className="primary-button"
                      disabled={busy || scanning}
                      type="button"
                      onClick={() => run((token) => scanApi.start(token, target.id), 'Scan started.')}
                    >
                      {scanning ? 'Scanning…' : 'Scan now'}
                    </button>
                  )}
                  <button
                    className="text-button"
                    disabled={busy || scanning}
                    type="button"
                    onClick={() => run((token) => scanApi.removeTarget(token, target.id), 'Website removed.')}
                  >
                    Remove
                  </button>
                </div>
              )}
            </div>
          )
        })}
      </section>

      <section className="panel">
        <h2>Scan history</h2>
        <div className="table-scroll">
          <table>
            <thead>
              <tr>
                <th>Website</th>
                <th>Status</th>
                <th>Requested</th>
                <th>Finished</th>
                <th>Findings</th>
              </tr>
            </thead>
            <tbody>
              {scanList.map((scan) => (
                <tr key={scan.id}>
                  <td>{hostnames[scan.target_id] ?? 'Removed website'}</td>
                  <td>
                    <Badge>{statusNames[scan.status] ?? scan.status}</Badge>
                    {scan.error && <span className="cell-note">{scan.error}</span>}
                  </td>
                  <td>{formatDate(scan.created_at)}</td>
                  <td>{formatDate(scan.finished_at)}</td>
                  <td>{scan.findings_count ?? '—'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        {scanList.length === 0 && <p className="empty-state">No scans yet.</p>}
      </section>
    </>
  )
}

export default Scans
