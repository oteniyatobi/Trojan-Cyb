import ThemeToggle from './ThemeToggle.jsx'

function Header({ workspace, theme, onToggleTheme }) {
  return (
    <header className="header">
      <div>
        <p className="workspace-name">{workspace.name}</p>
        <p className="search-placeholder">{workspace.organization}</p>
      </div>
      <div className="header-details">
        <ThemeToggle theme={theme} onToggle={onToggleTheme} />
        <p className="monitoring-status hidden">
          <span className="status-dot" aria-hidden="true" /> Demo monitoring
        </p>
        <div className="user-profile">
          <div className="profile-placeholder" aria-hidden="true">
            AM
          </div>
          <div className="profile-text">
            <p>{workspace.user}</p>
            <span>{workspace.role}</span>
          </div>
        </div>
      </div>
    </header>
  )
}

export default Header
