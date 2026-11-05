import Icon from './Icon.jsx'

const navigationItems = ['Overview', 'Alerts', 'Findings', 'Scans', 'Health']

function Sidebar({ activePage, onNavigate }) {
  return (
    <aside className="sidebar" id="sidebar">
      <nav aria-label="Workspace">
        <p className="navigation-label"></p>
        <ul className="navigation-list">
          {navigationItems.map((item) => (
            <li key={item}>
              <button
                type="button"
                className={`navigation-item${item === activePage ? ' active' : ''}`}
                aria-current={item === activePage ? 'page' : undefined}
                onClick={() => onNavigate(item)}
                aria-label={item}
                title={item}
              >
                <Icon name={item.toLowerCase()} />
                <span className="navigation-text">{item}</span>
              </button>
            </li>
          ))}
        </ul>
      </nav>
      <footer className="sidebar-footer">
        <button
          type="button"
          className={`navigation-item${activePage === 'Settings' ? ' active' : ''}`}
          aria-current={activePage === 'Settings' ? 'page' : undefined}
          aria-label="Settings"
          title="Settings"
          onClick={() => onNavigate('Settings')}
        >
          <Icon name="settings" />
          <span className="navigation-text">Settings</span>
        </button>
      </footer>
      <p className="sidebar-note hidden">
        <span className="status-dot" /> Demo workspace
      </p>
    </aside>
  )
}

export default Sidebar
