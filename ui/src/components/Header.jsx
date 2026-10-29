function Header() {
  return (
    <header className="header">
      <p className="search-placeholder">Search alerts, hosts, vulnerabilities…</p>

      <div className="header-details">
        <p className="monitoring-status">
          <span className="status-dot" aria-hidden="true" />
          Local monitoring · Not connected
        </p>
        <div className="profile-placeholder" aria-label="User profile placeholder">
          U
        </div>
      </div>
    </header>
  )
}

export default Header
