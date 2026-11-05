import { useState } from 'react'
import Badge from '../components/Badge.jsx'

function Scans({ scans, onAddScan }) {
  const [target, setTarget] = useState('')
  const [tool, setTool] = useState('Nuclei')
  const [authorized, setAuthorized] = useState(false)
  const [message, setMessage] = useState('')

  function handleSubmit(event) {
    event.preventDefault()
    if (!target.trim() || !authorized) return
    onAddScan({ target: target.trim(), tool })
    setMessage(
      'Demo request added to the queue. No scan will run or contact this target.',
    )
    setTarget('')
    setAuthorized(false)
  }

  return (
    <>
      <div className="scan-layout">
        <section className="panel">
          <h2>Request a demo scan</h2>
          <p className="panel-caption">
            Practice the request flow. This form does not run scanning tools.
          </p>
          <form className="form-stack" onSubmit={handleSubmit}>
            <label>
              Target website or network range
              <input
                value={target}
                onChange={(event) => setTarget(event.target.value)}
                placeholder="demo.example.test or 192.0.2.0/24"
                required
              />
            </label>
            <label>
              Scanning tool
              <select
                value={tool}
                onChange={(event) => setTool(event.target.value)}
              >
                <option>Nuclei</option>
                <option>Wapiti</option>
              </select>
            </label>
            <label className="checkbox-label">
              <input
                type="checkbox"
                checked={authorized}
                onChange={(event) => setAuthorized(event.target.checked)}
                required
              />
              I confirm ownership or authorization for this target.
            </label>
            <button type="submit" className="primary-button">
              Add demo scan to queue
            </button>
            <p role="status" className="form-message">
              {message}
            </p>
          </form>
        </section>
        <section className="panel">
          <h2>Scan status</h2>
          <p className="panel-caption">Current demo queue</p>
          <div className="status-list">
            {['Queued', 'Running', 'Completed', 'Failed'].map((status) => (
              <div key={status}>
                <Badge>{status}</Badge>
                <strong>
                  {scans.filter((scan) => scan.status === status).length}
                </strong>
              </div>
            ))}
          </div>
        </section>
      </div>
      <section className="panel">
        <h2>Recent scan requests</h2>
        <div className="table-scroll">
          <table>
            <thead>
              <tr>
                <th>Request</th>
                <th>Target</th>
                <th>Tool</th>
                <th>Status</th>
                <th>Findings</th>
              </tr>
            </thead>
            <tbody>
              {scans.map((scan) => (
                <tr key={scan.id}>
                  <td>
                    <strong>{scan.id}</strong>
                    <span className="cell-note">{scan.requested}</span>
                  </td>
                  <td>{scan.target}</td>
                  <td>{scan.tool}</td>
                  <td>
                    <Badge>{scan.status}</Badge>
                  </td>
                  <td>{scan.findings ?? '—'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>
    </>
  )
}

export default Scans
