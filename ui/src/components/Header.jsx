import trojanLogo from '../assets/trojan-logo.png'
import trojanLogoWhite from '../assets/trojan-logo-white.png'
import ThemeToggle from './ThemeToggle.jsx'
import Icon from './Icon.jsx'

function Header({
  workspace,
  theme,
  onToggleTheme,
  collapsed,
  onToggleSidebar,
  onSignOut,
  onNavigate,
}) {
  function openPage(event, page) {
    onNavigate(page)
    event.currentTarget.closest('details').open = false
  }

  const initials = workspace.user
    .split(' ')
    .map((name) => name[0])
    .slice(0, 2)
    .join('')

  return (
    <header className="header">
      <div className="header-brand">
        <button
          type="button"
          className="icon-button"
          onClick={onToggleSidebar}
          aria-label={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
          aria-expanded={!collapsed}
          aria-controls="sidebar"
        >
          <Icon name="menu" />
        </button>
        <img
          className="logo"
          src={theme === 'dark' ? trojanLogoWhite : trojanLogo}
          alt="TROJAN"
          width="2172"
          height="724"
        />
      </div>
      <div className="header-workspace">
        <p className="workspace-name">{workspace.name}</p>
        <p className="search-placeholder">{workspace.organization}</p>
      </div>
      <div className="header-details">
        <details
          className="profile-dropdown"
          onBlur={(event) => {
            if (!event.currentTarget.contains(event.relatedTarget))
              event.currentTarget.open = false
          }}
          onKeyDown={(event) => {
            if (event.key === 'Escape') {
              event.currentTarget.open = false
              event.currentTarget.querySelector('summary').focus()
            }
          }}
        >
          <summary className="user-profile" aria-label="Profile options">
            <span className="profile-placeholder" aria-hidden="true">
              {initials}
            </span>
            <span className="profile-text">
              <strong>{workspace.user}</strong>
              <span>{workspace.role}</span>
            </span>
            <Icon name="chevron" />
          </summary>
          <div className="profile-menu">
            <button
              type="button"
              onClick={(event) => openPage(event, 'Alerts')}
            >
              <Icon name="alerts" />
              Alerts
            </button>
            <button
              type="button"
              onClick={(event) => openPage(event, 'Settings')}
            >
              <Icon name="settings" />
              Settings
            </button>
            <div className="profile-theme">
              <span>Dark mode</span>
              <ThemeToggle theme={theme} onToggle={onToggleTheme} />
            </div>
          </div>
        </details>
        <button
          type="button"
          className="icon-button"
          aria-label="Sign out of demo"
          title="Sign out of demo"
          onClick={onSignOut}
        >
          <Icon name="logout" />
        </button>
      </div>
    </header>
  )
}

export default Header
