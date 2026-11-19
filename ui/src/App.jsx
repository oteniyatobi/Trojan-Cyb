import { useEffect, useMemo, useState } from 'react'
import Sidebar from './components/Sidebar.jsx'
import Header from './components/Header.jsx'
import Overview from './pages/Overview.jsx'
import Alerts from './pages/Alerts.jsx'
import AlertDetail from './pages/AlertDetail.jsx'
import Findings from './pages/Findings.jsx'
import Scans from './pages/Scans.jsx'
import Health from './pages/Health.jsx'
import Settings from './pages/Settings.jsx'
import Login from './pages/Login.jsx'
import Demo from './pages/Demo.jsx'
import { supabase, supabaseConfigured } from './lib/supabase.js'
import { fetchAlerts, fetchFindings, fetchHealth } from './lib/api.js'

const pages = {
  overview: 'Overview',
  alerts: 'Alerts',
  findings: 'Findings',
  scans: 'Scans',
  health: 'Health',
  settings: 'Settings',
}

function titleCase(value) {
  return value ? value[0].toUpperCase() + value.slice(1) : ''
}

function mapAlert(row) {
  const payload = row.source_payload ?? {}
  const review = row.ai_review ?? {}
  const createdAt = new Date(row.created_at)
  const status = {
    open: 'Open',
    acknowledged: 'In review',
    resolved: 'Resolved',
  }[row.status] ?? 'Open'

  return {
    id: row.id,
    time: createdAt.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
    date: createdAt.toLocaleDateString(),
    title: row.title,
    host: payload.agent_name ?? payload.host ?? 'Unknown host',
    severity: titleCase(row.severity),
    status,
    source: 'Wazuh',
    rule: payload.rule_id ?? payload.event_id ?? row.source_event_id ?? '—',
    ruleLevel: payload.rule_level ?? null,
    sourceIp: payload.src_ip ?? '—',
    evidence: payload.description ?? row.title,
    explanation: review.what_happened ?? review.explanation ?? 'No AI review is available.',
    steps: Array.isArray(review.steps) ? review.steps : [],
    review: review.status === 'done' ? review : null,
    reviewStatus: review.status === 'done' ? 'done' : 'unavailable',
  }
}

function mapFinding(row) {
  const details = row.details ?? {}
  const status = {
    open: 'Open',
    acknowledged: 'In review',
    resolved: 'Resolved',
  }[row.status] ?? 'Open'

  return {
    id: row.id,
    title: row.title,
    host: row.asset,
    severity: titleCase(row.severity),
    status,
    tool: details.tool ?? 'Scanner',
    guidance: details.description ?? 'Review this finding with your security administrator.',
  }
}

function makeActivity(alerts) {
  if (!alerts.length) return []
  const latestTimestamp = Math.max(...alerts.map((alert) => Date.parse(alert.created_at)))
  if (!Number.isFinite(latestTimestamp)) return []
  const latest = new Date(latestTimestamp)
  return Array.from({ length: 7 }, (_, index) => {
    const date = new Date(latest)
    date.setDate(latest.getDate() - (6 - index))
    const dateKey = date.toLocaleDateString()
    return {
      day: date.toLocaleDateString(undefined, { weekday: 'short' }),
      events: alerts.filter(
        (alert) => new Date(alert.created_at).toLocaleDateString() === dateKey,
      ).length,
    }
  })
}

function mapHealth(health) {
  return [
    {
      name: 'Backend API',
      status: health.status === 'ok' ? 'Online' : 'Offline',
      description: 'Flask service that reviews alerts and serves dashboard data.',
      detail: '/v1/health',
    },
    {
      name: 'Supabase storage',
      status: health.supabase === 'configured' ? 'Healthy' : 'Not connected',
      description: 'Stores alerts and findings sent by Wazuh and the scanners.',
      detail: health.supabase === 'configured' ? 'Ingestion configured' : 'Ingestion not configured',
    },
    {
      name: 'Groq AI review',
      status: health.groq === 'set' ? 'Healthy' : 'Not connected',
      description: 'Writes plain-language explanations for new alerts.',
      detail: health.groq === 'set' ? 'API key set' : 'API key missing',
    },
  ]
}

function App() {
  const [theme, setTheme] = useState(() => {
    try {
      return localStorage.getItem('trojan-theme') === 'dark' ? 'dark' : 'light'
    } catch {
      return 'light'
    }
  })
  const [collapsed, setCollapsed] = useState(window.innerWidth <= 700)
  const [route, setRoute] = useState(window.location.hash.slice(1) || '/login')
  const [session, setSession] = useState(null)
  const [authLoading, setAuthLoading] = useState(supabaseConfigured)
  const [authError, setAuthError] = useState('')
  const [organizations, setOrganizations] = useState([])
  const [selectedOrganizationId, setSelectedOrganizationId] = useState('')
  const [isPlatformAdmin, setIsPlatformAdmin] = useState(false)
  const [workspaceLoadedForUser, setWorkspaceLoadedForUser] = useState('')
  const [workspaceError, setWorkspaceError] = useState(null)
  const [workspaceReload, setWorkspaceReload] = useState(0)
  const [organizationName, setOrganizationName] = useState('')
  const [organizationError, setOrganizationError] = useState('')
  const [creatingOrganization, setCreatingOrganization] = useState(false)
  const [alerts, setAlerts] = useState([])
  const [findings, setFindings] = useState([])
  const [dataLoadedForOrganization, setDataLoadedForOrganization] = useState('')
  const [dataLoadedForUser, setDataLoadedForUser] = useState('')
  const [dataError, setDataError] = useState(null)
  const [scans, setScans] = useState([])
  const [workspaceOverrides, setWorkspaceOverrides] = useState(null)
  const [services, setServices] = useState([])
  const [healthError, setHealthError] = useState('')

  const user = session?.user
  const userId = user?.id ?? ''
  const signupOrganizationName = typeof user?.user_metadata?.organization_name === 'string'
    ? user.user_metadata.organization_name.trim()
    : ''
  const workspaceReady = Boolean(userId && workspaceLoadedForUser === userId)
  const selectedOrganization = organizations.find(
    (organization) => organization.id === selectedOrganizationId,
  )
  const userName = user?.user_metadata?.display_name
    || user?.email?.split('@')[0]
    || 'User'
  const membershipRole = organizations.find(
    (organization) => organization.id === selectedOrganizationId,
  )?.role
  const workspace = workspaceOverrides ?? {
    name: selectedOrganization?.name ?? 'TROJAN',
    organization: isPlatformAdmin ? 'Platform administrator' : 'Security workspace',
    user: userName,
    role: isPlatformAdmin ? 'Platform admin' : membershipRole ?? 'Member',
    email: user?.email ?? '',
    timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
    notifications: true,
    weeklyReport: false,
  }

  const [page, alertId] = route.slice(1).split('/')
  const activePage = Object.hasOwn(pages, page) ? pages[page] : null
  const visibleWorkspaceError = workspaceError?.userId === userId
    ? workspaceError.message
    : ''
  const organizationDataReady = Boolean(
    workspaceReady
    && selectedOrganizationId
    && dataLoadedForUser === userId
    && dataLoadedForOrganization === selectedOrganizationId,
  )
  const visibleDataError = dataError?.userId === userId
    && dataError?.organizationId === selectedOrganizationId
    ? dataError.message
    : ''
  const organizationDataLoading = Boolean(
    selectedOrganizationId
    && !visibleDataError
    && !organizationDataReady,
  )
  const organizationAlerts = useMemo(
    () => organizationDataReady ? alerts : [],
    [alerts, organizationDataReady],
  )
  const organizationFindings = useMemo(
    () => organizationDataReady ? findings : [],
    [findings, organizationDataReady],
  )
  const mappedAlerts = useMemo(() => organizationAlerts.map(mapAlert), [organizationAlerts])
  const mappedFindings = useMemo(() => organizationFindings.map(mapFinding), [organizationFindings])
  const selectedAlert = page === 'alerts'
    ? mappedAlerts.find((alert) => alert.id === alertId)
    : null
  const pageNotFound = !activePage
    || (alertId && !selectedAlert && !organizationDataLoading)
    || route.split('/').length > 3
  const dashboardData = {
    snapshotDate: organizationAlerts[0]?.created_at
      ? new Date(organizationAlerts[0].created_at).toLocaleDateString()
      : 'No activity yet',
    alerts: mappedAlerts,
    findings: mappedFindings,
    hosts: [],
    services,
    overview: {
      period: 'Recent activity',
      resolvedThisMonth: organizationAlerts.filter((alert) => alert.status === 'resolved').length,
      briefing: mappedAlerts.length
        ? `${mappedAlerts.length} alerts are recorded for this organization. Review critical and high-severity alerts first.`
        : 'No alerts have been recorded for this organization.',
      activity: makeActivity(organizationAlerts),
      categories: [],
    },
  }

  useEffect(() => {
    function updateRoute() {
      setRoute(window.location.hash.slice(1) || '/login')
      if (window.innerWidth <= 700) setCollapsed(true)
    }
    if (!window.location.hash) window.location.replace('#/login')
    window.addEventListener('hashchange', updateRoute)
    return () => window.removeEventListener('hashchange', updateRoute)
  }, [])

  useEffect(() => {
    if (!supabase) return undefined

    let active = true
    const { data: { subscription } } = supabase.auth.onAuthStateChange((_event, nextSession) => {
      if (!active) return
      setSession(nextSession)
      setAuthError('')
    })

    supabase.auth.getSession().then(({ data, error }) => {
      if (!active) return
      if (error) setAuthError(error.message)
      else setSession(data.session)
      setAuthLoading(false)
    }).catch((error) => {
      if (!active) return
      setAuthError(error.message)
      setAuthLoading(false)
    })

    return () => {
      active = false
      subscription.unsubscribe()
    }
  }, [])

  useEffect(() => {
    document.documentElement.dataset.theme = theme
    try {
      localStorage.setItem('trojan-theme', theme)
    } catch {
      return
    }
  }, [theme])

  useEffect(() => {
    if (authLoading || route.startsWith('/demo')) return
    if (session && route === '/login') window.location.hash = '/overview'
    if (!session && route !== '/login') window.location.hash = '/login'
  }, [authLoading, route, session])

  useEffect(() => {
    if (!userId) return undefined

    let active = true
    async function loadOrganizations() {
      const { data: platformAdmin, error: roleError } = await supabase.rpc(
        'current_user_is_platform_admin',
      )
      if (roleError) throw roleError

      let availableOrganizations
      if (platformAdmin) {
        const { data, error } = await supabase
          .from('organizations')
          .select('id, name')
          .order('name')
        if (error) throw error
        availableOrganizations = data.map((organization) => ({
          ...organization,
          role: 'platform_admin',
        }))
      } else {
        let { data, error } = await supabase
          .from('organization_memberships')
          .select('organization_id, role, created_at, organizations(id, name)')
          .eq('user_id', userId)
          .order('created_at')
        if (error) throw error

        if (!data.length && signupOrganizationName) {
          const { error: createError } = await supabase.rpc('create_organization', {
            p_name: signupOrganizationName,
          })
          if (createError) throw createError

          const result = await supabase
            .from('organization_memberships')
            .select('organization_id, role, created_at, organizations(id, name)')
            .eq('user_id', userId)
            .order('created_at')
          if (result.error) throw result.error
          data = result.data
        }

        availableOrganizations = data
          .map((membership) => ({
            ...membership.organizations,
            role: membership.role,
          }))
          .filter((organization) => organization.id)
      }

      if (!active) return
      setIsPlatformAdmin(Boolean(platformAdmin))
      setOrganizations(availableOrganizations)
      setSelectedOrganizationId((current) => (
        availableOrganizations.some((organization) => organization.id === current)
          ? current
          : availableOrganizations[0]?.id ?? ''
      ))
      setWorkspaceError(null)
      setWorkspaceLoadedForUser(userId)
      setWorkspaceOverrides(null)
    }

    loadOrganizations().catch((error) => {
      if (active) setWorkspaceError({ userId, message: error.message })
    })

    return () => {
      active = false
    }
  }, [userId, signupOrganizationName, workspaceReload])

  useEffect(() => {
    if (!selectedOrganizationId || !workspaceReady) return undefined

    let active = true
    async function loadOrganizationData() {
      const { data: { session: current } } = await supabase.auth.getSession()
      const token = current?.access_token
      const [alertRows, findingRows] = await Promise.all([
        fetchAlerts(token, selectedOrganizationId),
        fetchFindings(token, selectedOrganizationId),
      ])
      if (!active) return
      setAlerts(alertRows)
      setFindings(findingRows)
      setDataLoadedForOrganization(selectedOrganizationId)
      setDataLoadedForUser(userId)
      setDataError(null)
    }

    loadOrganizationData().catch((error) => {
      if (!active) return
      setDataError({ userId, organizationId: selectedOrganizationId, message: error.message })
    })

    return () => {
      active = false
    }
  }, [selectedOrganizationId, userId, workspaceReady])

  useEffect(() => {
    if (page !== 'health' || !userId) return undefined

    let active = true
    fetchHealth()
      .then((health) => {
        if (!active) return
        setServices(mapHealth(health))
        setHealthError('')
      })
      .catch((error) => {
        if (!active) return
        setServices(mapHealth({}))
        setHealthError(error.message)
      })

    return () => {
      active = false
    }
  }, [page, userId])

  function navigate(destination) {
    window.location.hash = `/${destination.toLowerCase()}`
    if (window.innerWidth <= 700) setCollapsed(true)
  }

  function toggleTheme() {
    setTheme(theme === 'light' ? 'dark' : 'light')
  }

  function addScan(scan) {
    const requested = new Date().toLocaleString(undefined, {
      timeZone: workspace.timezone,
    })
    setScans((current) => [
      {
        ...scan,
        id: `DEMO-${String(current.length + 1).padStart(3, '0')}`,
        status: 'Queued',
        requested,
        findings: null,
      },
      ...current,
    ])
  }

  async function handleSignOut() {
    const { error } = await supabase.auth.signOut()
    if (error) setAuthError(error.message)
  }

  async function handleCreateOrganization(event) {
    event.preventDefault()
    setCreatingOrganization(true)
    setOrganizationError('')
    try {
      const { error } = await supabase.rpc('create_organization', {
        p_name: organizationName.trim(),
      })
      if (error) throw error
      setOrganizationName('')
      setWorkspaceLoadedForUser('')
      setWorkspaceReload((current) => current + 1)
    } catch (error) {
      setOrganizationError(error.message)
    } finally {
      setCreatingOrganization(false)
    }
  }

  if (route.startsWith('/demo')) {
    return <Demo route={route} theme={theme} onToggleTheme={toggleTheme} />
  }

  if (!supabaseConfigured) {
    return (
      <main className="auth-screen">
        <section className="auth-card" aria-labelledby="setup-title">
          <h1 id="setup-title">Supabase configuration required</h1>
          <p>Set VITE_SUPABASE_URL and VITE_SUPABASE_PUBLISHABLE_KEY in the root environment.</p>
        </section>
      </main>
    )
  }

  if (authLoading) {
    return <main className="auth-screen"><p>Checking your session…</p></main>
  }

  if (!session) {
    return (
      <Login
        theme={theme}
        onToggleTheme={toggleTheme}
        onLogin={() => setAuthError('')}
        error={authError}
      />
    )
  }

  if (!workspaceReady && !visibleWorkspaceError) {
    return <main className="auth-screen"><p>Loading your organization…</p></main>
  }

  if (visibleWorkspaceError) {
    return (
      <main className="auth-screen">
        <section className="auth-card">
          <h1>Could not load your organization</h1>
          <p className="error-message" role="alert">{visibleWorkspaceError}</p>
          <button type="button" className="primary-button" onClick={handleSignOut}>
            Sign out
          </button>
        </section>
      </main>
    )
  }

  if (!organizations.length) {
    return (
      <main className="auth-screen">
        <section className="auth-card" aria-labelledby="create-org-title">
          <h1 id="create-org-title">Set up your organization</h1>
          <p>Your account will become its organization administrator.</p>
          {organizationError && <p className="error-message" role="alert">{organizationError}</p>}
          <form className="form-stack" onSubmit={handleCreateOrganization}>
            <label>
              Organization name
              <input
                autoComplete="organization"
                maxLength={120}
                onChange={(event) => setOrganizationName(event.target.value)}
                required
                value={organizationName}
              />
            </label>
            <button className="primary-button" disabled={creatingOrganization} type="submit">
              {creatingOrganization ? 'Creating organization…' : 'Create organization'}
            </button>
          </form>
        </section>
      </main>
    )
  }

  const alertRouteLoading = page === 'alerts' && alertId && organizationDataLoading
  const demoNotice = {
    scans: 'Scan requests are demonstrations only; no scanner runs or contacts a target.',
    health: 'Service status is live from the backend. Host monitoring is not connected yet.',
    settings: 'Workspace preferences are local demo settings and are not saved to Supabase.',
  }[page]

  return (
    <div className="app-shell">
      <a
        className="skip-link"
        href="#main-content"
        onClick={(event) => {
          event.preventDefault()
          document.getElementById('main-content').focus()
        }}
      >
        Skip to content
      </a>
      <Header
        workspace={workspace}
        theme={theme}
        onToggleTheme={toggleTheme}
        onNavigate={navigate}
        collapsed={collapsed}
        onToggleSidebar={() => setCollapsed(!collapsed)}
        onSignOut={handleSignOut}
      />
      <div className={`app-body${collapsed ? ' sidebar-collapsed' : ''}`}>
        <Sidebar activePage={activePage} onNavigate={navigate} />
        <main className="main-content" id="main-content" tabIndex={-1}>
          <div className="page-heading">
            <h1>{pageNotFound ? 'Page not found' : selectedAlert ? 'Alert Detail' : activePage}</h1>
          </div>
          {organizations.length > 1 && (
            <label className="organization-picker">
              Organization
              <select
                onChange={(event) => setSelectedOrganizationId(event.target.value)}
                value={selectedOrganizationId}
              >
                {organizations.map((organization) => (
                  <option key={organization.id} value={organization.id}>
                    {organization.name}
                  </option>
                ))}
              </select>
            </label>
          )}
          {demoNotice && (
            <div className="demo-notice">
              <span className="demo-label">Not connected</span>
              <p>{demoNotice}</p>
            </div>
          )}
          {visibleDataError && <p className="error-message" role="alert">{visibleDataError}</p>}
          {page === 'health' && healthError && (
            <p className="error-message" role="alert">{healthError}</p>
          )}
          {organizationDataLoading && (
            <p className="empty-state" role="status">Loading organization data…</p>
          )}
          {pageNotFound && !alertRouteLoading ? (
            <section className="panel">
              <p>This page or alert does not exist.</p>
              <button type="button" className="text-button" onClick={() => navigate('Overview')}>
                Go to Overview
              </button>
            </section>
          ) : alertRouteLoading ? (
            <p className="empty-state">Loading alert…</p>
          ) : (
            <>
              {activePage === 'Overview' && (
                <Overview data={dashboardData} onNavigate={navigate} />
              )}
              {activePage === 'Alerts' && (
                selectedAlert ? (
                  <AlertDetail alert={selectedAlert} onBack={() => navigate('Alerts')} />
                ) : (
                  <Alerts
                    data={dashboardData}
                    onSelect={(alert) => {
                      window.location.hash = '/alerts/' + alert.id
                    }}
                  />
                )
              )}
              {activePage === 'Findings' && <Findings findings={mappedFindings} />}
              {activePage === 'Scans' && <Scans scans={scans} onAddScan={addScan} />}
              {activePage === 'Health' && (
                <Health
                  services={dashboardData.services}
                  hosts={dashboardData.hosts}
                  snapshotDate={dashboardData.snapshotDate}
                />
              )}
              {activePage === 'Settings' && (
                <Settings
                  workspace={workspace}
                  onSave={setWorkspaceOverrides}
                  theme={theme}
                  onToggleTheme={toggleTheme}
                />
              )}
            </>
          )}
        </main>
      </div>
    </div>
  )
}

export default App
