import { useCallback, useEffect, useState } from 'react'
import trojanLogo from '../assets/trojan-logo.png'
import trojanLogoWhite from '../assets/trojan-logo-white.png'
import Icon from '../components/Icon.jsx'
import ThemeToggle from '../components/ThemeToggle.jsx'
import Login from '../pages/Login.jsx'
import TrojanAdmin from '../pages/TrojanAdmin.jsx'
import AdminOverview from './AdminOverview.jsx'
import AdminUsers from './AdminUsers.jsx'
import PlatformAdmins from './PlatformAdmins.jsx'
import AuditLog from './AuditLog.jsx'
import { supabase, supabaseConfigured } from '../lib/supabase.js'

const sections = [
  ['overview', 'Overview', 'overview'],
  ['organizations', 'Organizations', 'organizations'],
  ['users', 'Users', 'hosts'],
  ['admins', 'TROJAN admins', 'review'],
  ['audit', 'Audit log', 'findings'],
]

function AdminApp() {
  const [theme, setTheme] = useState(() => {
    try {
      return localStorage.getItem('trojan-theme') === 'dark' ? 'dark' : 'light'
    } catch {
      return 'light'
    }
  })
  const [session, setSession] = useState(null)
  const [loading, setLoading] = useState(supabaseConfigured)
  const [allowed, setAllowed] = useState(null)
  const [error, setError] = useState('')
  const [section, setSection] = useState(() => window.location.hash.slice(2) || 'overview')
  const [collapsed, setCollapsed] = useState(window.innerWidth <= 700)
  const userId = session?.user?.id ?? ''

  useEffect(() => {
    document.documentElement.dataset.theme = theme
    try {
      localStorage.setItem('trojan-theme', theme)
    } catch {
      return
    }
  }, [theme])

  useEffect(() => {
    function updateSection() {
      setSection(window.location.hash.slice(2) || 'overview')
    }
    window.addEventListener('hashchange', updateSection)
    return () => window.removeEventListener('hashchange', updateSection)
  }, [])

  useEffect(() => {
    if (!supabase) return undefined
    let active = true
    const { data: { subscription } } = supabase.auth.onAuthStateChange((_event, nextSession) => {
      if (active) setSession(nextSession)
    })
    supabase.auth.getSession().then(({ data }) => {
      if (!active) return
      setSession(data.session)
      setLoading(false)
    })
    return () => {
      active = false
      subscription.unsubscribe()
    }
  }, [])

  useEffect(() => {
    if (!userId) return undefined
    let active = true
    supabase.rpc('current_user_is_platform_admin').then(({ data, error: roleError }) => {
      if (!active) return
      if (roleError) setError(roleError.message)
      setAllowed({ userId, value: data === true })
    })
    return () => {
      active = false
    }
  }, [userId])

  const getToken = useCallback(async () => {
    const { data } = await supabase.auth.getSession()
    return data.session?.access_token
  }, [])

  function toggleTheme() {
    setTheme(theme === 'light' ? 'dark' : 'light')
  }

  function signOut() {
    supabase.auth.signOut()
  }

  if (!supabaseConfigured) {
    return <main className="auth-screen"><p>Supabase is not configured.</p></main>
  }
  if (loading) {
    return <main className="auth-screen"><p>Checking your session…</p></main>
  }
  if (!session) {
    return <Login adminMode theme={theme} onToggleTheme={toggleTheme} onLogin={() => setError('')} error={error} />
  }
  if (allowed?.userId !== userId) {
    return <main className="auth-screen"><p>Checking admin access…</p></main>
  }
  if (!allowed.value) {
    return (
      <main className="auth-screen">
        <section className="auth-card">
          <h1>TROJAN admin access required</h1>
          <p>{session.user.email} is not a TROJAN platform admin.</p>
          {error && <p className="error-message" role="alert">{error}</p>}
          <button type="button" className="primary-button" onClick={signOut}>Sign out</button>
        </section>
      </main>
    )
  }

  const active = sections.find(([key]) => key === section) ?? sections[0]

  return (
    <div className="app-shell">
      <header className="header">
        <div className="header-brand">
          <button
            type="button"
            className="icon-button"
            onClick={() => setCollapsed(!collapsed)}
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
          <p className="workspace-name">TROJAN Admin</p>
          <p className="search-placeholder">Platform administration</p>
        </div>
        <div className="header-details">
          <span className="admin-user">{session.user.email}</span>
          <ThemeToggle theme={theme} onToggle={toggleTheme} />
          <button type="button" className="icon-button" aria-label="Sign out" title="Sign out" onClick={signOut}>
            <Icon name="logout" />
          </button>
        </div>
      </header>
      <div className={`app-body${collapsed ? ' sidebar-collapsed' : ''}`}>
        <aside className="sidebar" id="sidebar">
          <nav aria-label="Admin">
            <ul className="navigation-list">
              {sections.map(([key, label, icon]) => (
                <li key={key}>
                  <a
                    className={`navigation-item${key === active[0] ? ' active' : ''}`}
                    aria-current={key === active[0] ? 'page' : undefined}
                    href={`#/${key}`}
                    aria-label={label}
                    title={label}
                  >
                    <Icon name={icon} />
                    <span className="navigation-text">{label}</span>
                  </a>
                </li>
              ))}
            </ul>
          </nav>
        </aside>
        <main className="main-content" id="main-content" tabIndex={-1}>
          <div className="page-heading">
            <h1>{active[1]}</h1>
          </div>
          {active[0] === 'overview' && <AdminOverview getToken={getToken} />}
          {active[0] === 'organizations' && <TrojanAdmin getToken={getToken} />}
          {active[0] === 'users' && <AdminUsers getToken={getToken} />}
          {active[0] === 'admins' && <PlatformAdmins getToken={getToken} currentUserId={userId} />}
          {active[0] === 'audit' && <AuditLog getToken={getToken} />}
        </main>
      </div>
    </div>
  )
}

export default AdminApp
