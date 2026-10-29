import trojanLogo from '../assets/trojan-logo.png'

const navigationItems = ['Overview', 'Alerts', 'Findings', 'Scans', 'Health', 'Settings']

function Sidebar() {
  return (
    <aside className="sidebar">
      <div className="logo-area">
        <img className="logo" src={trojanLogo} alt="TROJAN" width="172" height="57" />
      </div>

      <nav aria-label="Workspace">
        <p className="navigation-label">Workspace</p>
        <ul className="navigation-list">
          {navigationItems.map((item) => (
            <li key={item}>
              <span
                className={`navigation-item${item === 'Overview' ? ' active' : ''}`}
                aria-current={item === 'Overview' ? 'page' : undefined}
              >
                <span aria-hidden="true">◈</span>
                {item}
              </span>
            </li>
          ))}
        </ul>
      </nav>

      <p className="sidebar-note">Your security workspace</p>
    </aside>
  )
}

export default Sidebar
