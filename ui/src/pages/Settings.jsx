import { useState } from 'react'
import ThemeToggle from '../components/ThemeToggle.jsx'
import GroqSettings from '../components/GroqSettings.jsx'

function Settings({
  workspace,
  onSave,
  theme,
  onToggleTheme,
  source,
  onSourceChange,
  session,
}) {
  const [name, setName] = useState(workspace.name)
  const [notifications, setNotifications] = useState(workspace.notifications)
  const [weeklyReport, setWeeklyReport] = useState(workspace.weeklyReport)
  const [message, setMessage] = useState('')

  function handleSubmit(event) {
    event.preventDefault()
    if (!name.trim()) return
    onSave({ ...workspace, name: name.trim(), notifications, weeklyReport })
    setMessage(
      'Demo preferences saved for this session. No emails will be sent.',
    )
  }

  return (
    <div className="two-column settings-layout">
      <section className="panel appearance-panel">
        <div>
          <h2>Data source</h2>
          <p className="panel-caption">
            Applies to every page. Backend mode never falls back to sample
            records.
          </p>
        </div>
        <label>
          Application data
          <select
            value={source}
            onChange={(event) => onSourceChange(event.target.value)}
          >
            <option>Backend</option>
            <option>Demo</option>
          </select>
        </label>
      </section>
      <section className="panel appearance-panel">
        <div>
          <h2>Appearance</h2>
          <p className="panel-caption">
            Choose light or dark mode. Saved on this device.
          </p>
        </div>
        <ThemeToggle theme={theme} onToggle={onToggleTheme} />
      </section>
      {source === 'Demo' ? (
        <section className="panel">
          <h2>Demo workspace preferences</h2>
          <p className="panel-caption">
            Changes are kept until you reload the page.
          </p>
          <form className="form-stack" onSubmit={handleSubmit}>
            <label>
              Workspace name
              <input
                value={name}
                onChange={(event) => setName(event.target.value)}
                maxLength={60}
                required
              />
            </label>
            <label className="checkbox-label">
              <input
                type="checkbox"
                checked={notifications}
                onChange={(event) => setNotifications(event.target.checked)}
              />
              Critical alert notifications
            </label>
            <label className="checkbox-label">
              <input
                type="checkbox"
                checked={weeklyReport}
                onChange={(event) => setWeeklyReport(event.target.checked)}
              />
              Weekly security summary
            </label>
            <button className="primary-button">Save demo preferences</button>
            <p role="status" className="form-message">
              {message}
            </p>
          </form>
        </section>
      ) : (
        <section className="panel detail-panel">
          <h2>Workspace settings</h2>
          <p>
            Workspace profile, notification preferences, and user accounts need
            backend endpoints. No demo account details are shown in Backend
            mode.
          </p>
          <dl className="detail-list">
            <div>
              <dt>Access</dt>
              <dd>
                {session.role === 'admin'
                  ? 'Administrator'
                  : 'Workspace preview'}
              </dd>
            </div>
            <div>
              <dt>Verification</dt>
              <dd>{'No backend authentication — demo access only'}</dd>
            </div>
          </dl>
        </section>
      )}
      {session.role === 'admin' ? (
        <GroqSettings key={source} source={source} />
      ) : (
        <section className="panel">
          <h2>Administrator settings</h2>
          <p className="panel-caption">
            Sign in as an administrator to view Groq configuration.
          </p>
        </section>
      )}
    </div>
  )
}
export default Settings
