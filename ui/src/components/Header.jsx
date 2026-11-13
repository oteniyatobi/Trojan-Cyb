function Header({ user, onSignOut }) {
  return (
    <header className="header">
      <p className="search-placeholder">Supabase · Monitoring not connected</p>

      <div className="header-details">
        <p className="user-email">{user.email}</p>
        <div className="profile-placeholder" aria-hidden="true">
          {user.email?.charAt(0).toUpperCase() ?? 'U'}
        </div>
        <button className="sign-out-button" onClick={onSignOut} type="button">Sign out</button>
      </div>
    </header>
  )
}

export default Header
