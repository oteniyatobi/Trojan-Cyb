import trojanLogo from '../assets/trojan-logo.png'
import trojanLogoWhite from '../assets/trojan-logo-white.png'
import Icon from './Icon.jsx'

const navigationItems = [
  'Overview',
  'Alerts',
  'Findings',
  'Scans',
  'Health',
  'Settings',
]

function Sidebar({ activePage, onNavigate, theme }) {
  return (
    <aside className="sidebar">
      <div className="logo-area">
        <img
          className="logo"
          src={theme === 'dark' ? trojanLogoWhite : trojanLogo}
          alt="TROJAN"
          width="2172"
          height="724"
        />
      </div>
      <nav aria-label="Workspace">
        <p className="navigation-label">Workspace</p>
        <ul className="navigation-list">
          {navigationItems.map((item) => (
            <li key={item}>
              <button
                type="button"
                className={`navigation-item${item === activePage ? ' active' : ''}`}
                aria-current={item === activePage ? 'page' : undefined}
                onClick={() => onNavigate(item)}
              >
                <Icon name={item.toLowerCase()} />
                {item}
              </button>
            </li>
          ))}
        </ul>
      </nav>
      <p className="sidebar-note hidden">
        <span className="status-dot" /> Demo workspace
      </p>
    </aside>
  )
}

export default Sidebar
