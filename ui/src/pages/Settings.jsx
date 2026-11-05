import { useState } from 'react'
import Badge from '../components/Badge.jsx'
import ThemeToggle from '../components/ThemeToggle.jsx'

function Settings({ workspace, onSave, theme, onToggleTheme }) {
  const [name, setName] = useState(workspace.name)
  const [notifications, setNotifications] = useState(workspace.notifications)
  const [weeklyReport, setWeeklyReport] = useState(workspace.weeklyReport)
  const [message, setMessage] = useState('')

  function handleSubmit(event) {
    event.preventDefault()
    if (!name.trim()) return
    onSave({ ...workspace, name: name.trim(), notifications, weeklyReport })
    setMessage('Demo settings saved for this session. No emails will be sent.')
  }

  return (
    <div className="two-column settings-layout">
      <section className="panel appearance-panel">
        <div>
          <h2>Appearance</h2>
          <p className="panel-caption">Choose light or dark mode. Saved on this device.</p>
        </div>
        <ThemeToggle theme={theme} onToggle={onToggleTheme} />
      </section>
      <section className="panel">
        <h2>Workspace preferences</h2>
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
          <button className="primary-button" type="submit">
            Save demo settings
          </button>
          <p role="status" className="form-message">
            {message}
          </p>
        </form>
      </section>
      <section className="panel detail-panel">
        <h2>Demo account</h2>
        <dl className="detail-list">
          <div>
            <dt>Name</dt>
            <dd>{workspace.user}</dd>
          </div>
          <div>
            <dt>Email</dt>
            <dd>{workspace.email}</dd>
          </div>
          <div>
            <dt>Role</dt>
            <dd>{workspace.role}</dd>
          </div>
          <div>
            <dt>Time zone</dt>
            <dd>{workspace.timezone}</dd>
          </div>
        </dl>
        <h3>External AI advice</h3>
        <div>
          <Badge>Not connected</Badge>
        </div>
        <p>
          Groq integration is not configured. The demo uses example guidance
          from the local JSON file.
        </p>
        <p className="panel-caption">
          No passwords or API keys are collected in this demo.
        </p>
      </section>
    </div>
  )
}

export default Settings
