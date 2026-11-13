import { useEffect, useState } from 'react'
import Header from './components/Header.jsx'
import Sidebar from './components/Sidebar.jsx'
import { supabase, supabaseConfigured } from './lib/supabase.js'

function SignIn({ onSignedIn, error }) {
  const [mode, setMode] = useState('sign-in')
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [organizationName, setOrganizationName] = useState('')
  const [submitting, setSubmitting] = useState(false)
  const [formError, setFormError] = useState('')
  const [message, setMessage] = useState('')

  async function handleSubmit(event) {
    event.preventDefault()
    setSubmitting(true)
    setFormError('')
    setMessage('')

    try {
      if (mode === 'sign-in') {
        const { error: signInError } = await supabase.auth.signInWithPassword({
          email,
          password,
        })

        if (signInError) throw signInError
        onSignedIn()
      } else {
        const { data, error: signUpError } = await supabase.auth.signUp({
          email,
          password,
          options: {
            data: { organization_name: organizationName.trim() },
          },
        })

        if (signUpError) throw signUpError
        if (data.session) {
          onSignedIn()
        } else {
          setMode('sign-in')
          setPassword('')
          setMessage('Check your email to confirm your account, then sign in. Your organization will be set up automatically.')
        }
      }
    } catch (error) {
      setFormError(error.message)
      setSubmitting(false)
      return
    }

    setSubmitting(false)
  }

  return (
    <main className="auth-screen">
      <section className="auth-card" aria-labelledby="sign-in-title">
        <p className="auth-eyebrow">TROJAN security workspace</p>
        <h1 id="sign-in-title">{mode === 'sign-in' ? 'Sign in' : 'Create your organization'}</h1>
        <p className="auth-description">
          {mode === 'sign-in'
            ? 'Sign in to your organization’s security workspace.'
            : 'Create your account. Your organization and admin access will be set up automatically.'}
        </p>
        {(error || formError) && <p className="error-message" role="alert">{error || formError}</p>}
        {message && <p className="success-message" role="status">{message}</p>}
        <form className="auth-form" onSubmit={handleSubmit}>
          {mode === 'sign-up' && (
            <>
              <label className="field-label" htmlFor="organization-name">Organization name</label>
              <input
                autoComplete="organization"
                id="organization-name"
                maxLength={120}
                onChange={(event) => setOrganizationName(event.target.value)}
                required
                value={organizationName}
              />
            </>
          )}
          <label className="field-label" htmlFor="email">Email</label>
          <input
            autoComplete="email"
            id="email"
            onChange={(event) => setEmail(event.target.value)}
            required
            type="email"
            value={email}
          />
          <label className="field-label" htmlFor="password">Password</label>
          <input
            autoComplete="current-password"
            id="password"
            onChange={(event) => setPassword(event.target.value)}
            minLength={8}
            required
            type="password"
            value={password}
          />
          <button className="primary-button" disabled={submitting} type="submit">
            {submitting
              ? (mode === 'sign-in' ? 'Signing in…' : 'Creating account…')
              : (mode === 'sign-in' ? 'Sign in' : 'Create account')}
          </button>
        </form>
        <button
          className="auth-mode-button"
          onClick={() => {
            setMode(mode === 'sign-in' ? 'sign-up' : 'sign-in')
            setFormError('')
            setMessage('')
          }}
          type="button"
        >
          {mode === 'sign-in' ? 'New organization? Create an account' : 'Already have an account? Sign in'}
        </button>
      </section>
    </main>
  )
}

function App() {
  const [session, setSession] = useState(null)
  const [authLoading, setAuthLoading] = useState(true)
  const [authError, setAuthError] = useState('')
  const [organizations, setOrganizations] = useState([])
  const [selectedOrganizationId, setSelectedOrganizationId] = useState('')
  const [isPlatformAdmin, setIsPlatformAdmin] = useState(false)
  const [workspaceError, setWorkspaceError] = useState('')
  const [workspaceLoadedForUser, setWorkspaceLoadedForUser] = useState('')
  const [workspaceReload, setWorkspaceReload] = useState(0)
  const [newOrganizationName, setNewOrganizationName] = useState('')
  const [creatingOrganization, setCreatingOrganization] = useState(false)
  const [createOrganizationError, setCreateOrganizationError] = useState('')
  const [alerts, setAlerts] = useState([])
  const [alertsLoadedForOrganization, setAlertsLoadedForOrganization] = useState('')
  const [alertsError, setAlertsError] = useState('')
  const [findings, setFindings] = useState([])
  const [findingsLoadedForOrganization, setFindingsLoadedForOrganization] = useState('')
  const [findingsError, setFindingsError] = useState('')
  const userId = session?.user?.id ?? ''
  const signupOrganizationName = typeof session?.user?.user_metadata?.organization_name === 'string'
    ? session.user.user_metadata.organization_name.trim()
    : ''
  const workspaceReady = Boolean(userId && workspaceLoadedForUser === userId)

  useEffect(() => {
    if (!supabase) return undefined

    let active = true
    const { data: { subscription } } = supabase.auth.onAuthStateChange((_event, nextSession) => {
      if (active) {
        setSession(nextSession)
        setAuthError('')
      }
    })

    supabase.auth.getSession().then(({ data, error }) => {
      if (!active) return
      if (error) {
        setAuthError(error.message)
      } else {
        setSession(data.session)
      }
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
        availableOrganizations = data
      } else {
        let { data, error } = await supabase
          .from('organization_memberships')
          .select('organization_id, role, organizations(id, name)')
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
            .select('organization_id, role, organizations(id, name)')
            .eq('user_id', userId)
            .order('created_at')
          if (result.error) throw result.error
          data = result.data
        }

        availableOrganizations = data
          .map((membership) => membership.organizations)
          .filter(Boolean)
      }

      if (!active) return
      setIsPlatformAdmin(platformAdmin)
      setOrganizations(availableOrganizations)
      setSelectedOrganizationId(availableOrganizations[0]?.id ?? '')
      setWorkspaceError('')
      setWorkspaceLoadedForUser(userId)
    }

    loadOrganizations().catch((error) => {
      if (!active) return
      setWorkspaceError({ userId, message: error.message })
    })

    return () => {
      active = false
    }
  }, [userId, signupOrganizationName, workspaceReload])

  useEffect(() => {
    if (!selectedOrganizationId || !workspaceReady) return undefined

    let active = true
    async function loadAlerts() {
      const { data, error } = await supabase
        .from('alerts')
        .select('id, title, severity, status, created_at')
        .eq('organization_id', selectedOrganizationId)
        .order('created_at', { ascending: false })
        .limit(20)

      if (error) throw error
      if (!active) return
      setAlerts(data)
      setAlertsLoadedForOrganization(selectedOrganizationId)
      setAlertsError('')
    }

    loadAlerts().catch((error) => {
      if (!active) return
      setAlertsError({ organizationId: selectedOrganizationId, message: error.message })
    })

    return () => {
      active = false
    }
  }, [selectedOrganizationId, workspaceReady])

  useEffect(() => {
    if (!selectedOrganizationId || !workspaceReady) return undefined

    let active = true
    async function loadFindings() {
      const { data, error } = await supabase
        .from('vulnerability_findings')
        .select('id, title, asset, cve_id, severity, status, created_at')
        .eq('organization_id', selectedOrganizationId)
        .order('created_at', { ascending: false })
        .limit(20)

      if (error) throw error
      if (!active) return
      setFindings(data)
      setFindingsLoadedForOrganization(selectedOrganizationId)
      setFindingsError('')
    }

    loadFindings().catch((error) => {
      if (!active) return
      setFindingsError({ organizationId: selectedOrganizationId, message: error.message })
    })

    return () => {
      active = false
    }
  }, [selectedOrganizationId, workspaceReady])

  async function handleSignOut() {
    const { error } = await supabase.auth.signOut()
    if (error) setAuthError(error.message)
  }

  async function handleCreateOrganization(event) {
    event.preventDefault()
    setCreatingOrganization(true)
    setCreateOrganizationError('')

    try {
      const { error } = await supabase.rpc('create_organization', {
        p_name: newOrganizationName.trim(),
      })
      if (error) throw error

      setNewOrganizationName('')
      setWorkspaceLoadedForUser('')
      setWorkspaceReload((reload) => reload + 1)
    } catch (error) {
      setCreateOrganizationError(error.message)
    } finally {
      setCreatingOrganization(false)
    }
  }

  if (!supabaseConfigured) {
    return (
      <main className="auth-screen">
        <section className="auth-card" aria-labelledby="setup-title">
          <p className="auth-eyebrow">TROJAN setup</p>
          <h1 id="setup-title">Supabase configuration required</h1>
          <p className="auth-description">
            Set VITE_SUPABASE_URL and VITE_SUPABASE_PUBLISHABLE_KEY in ui/.env, then restart Vite.
          </p>
        </section>
      </main>
    )
  }

  if (authLoading) {
    return <main className="auth-screen"><p>Checking your session…</p></main>
  }

  if (!session) {
    return <SignIn error={authError} onSignedIn={() => setAuthError('')} />
  }

  const visibleWorkspaceError = workspaceError?.userId === userId
    ? workspaceError.message
    : ''
  const selectedOrganization = workspaceReady ? organizations.find(
    (organization) => organization.id === selectedOrganizationId,
  ) : null
  const visibleAlerts = alertsLoadedForOrganization === selectedOrganizationId ? alerts : []
  const visibleAlertsError = alertsError?.organizationId === selectedOrganizationId
    ? alertsError.message
    : ''
  const visibleFindings = findingsLoadedForOrganization === selectedOrganizationId
    ? findings
    : []
  const visibleFindingsError = findingsError?.organizationId === selectedOrganizationId
    ? findingsError.message
    : ''
  const alertsLoading = Boolean(
    selectedOrganizationId
    && workspaceReady
    && alertsLoadedForOrganization !== selectedOrganizationId
    && !visibleAlertsError,
  )
  const findingsLoading = Boolean(
    selectedOrganizationId
    && workspaceReady
    && findingsLoadedForOrganization !== selectedOrganizationId
    && !visibleFindingsError,
  )

  return (
    <div className="app-shell">
      <a className="skip-link" href="#main-content">Skip to content</a>
      <Sidebar />

      <div className="workspace">
        <Header onSignOut={handleSignOut} user={session.user} />
        <main className="main-content" id="main-content" tabIndex={-1}>
          <div className="page-heading">
            <h1>Overview</h1>
            <p>
              {selectedOrganization
                ? `Security alerts for ${selectedOrganization.name}.`
                : 'Your organization’s security workspace.'}
            </p>
            {workspaceReady && isPlatformAdmin && (
              <p className="admin-note">TROJAN platform administrator access</p>
            )}
          </div>

          {authError && <p className="error-message" role="alert">{authError}</p>}

          {workspaceReady && organizations.length > 1 && (
            <label className="organization-picker">
              Organization
              <select
                onChange={(event) => setSelectedOrganizationId(event.target.value)}
                value={selectedOrganizationId}
              >
                {organizations.map((organization) => (
                  <option key={organization.id} value={organization.id}>{organization.name}</option>
                ))}
              </select>
            </label>
          )}

          {!workspaceReady && !visibleWorkspaceError && (
            <p className="empty-state">Loading your organizations…</p>
          )}
          {visibleWorkspaceError && (
            <p className="error-message" role="alert">{visibleWorkspaceError}</p>
          )}
          {workspaceReady && !visibleWorkspaceError && !organizations.length && (
            <section className="auth-card org-setup-card" aria-labelledby="create-org-title">
              <h2 id="create-org-title">Set up your organization</h2>
              <p className="auth-description">
                Create an organization to get started. Your account will become its administrator.
              </p>
              {createOrganizationError && (
                <p className="error-message" role="alert">{createOrganizationError}</p>
              )}
              <form className="auth-form" onSubmit={handleCreateOrganization}>
                <label className="field-label" htmlFor="new-organization-name">Organization name</label>
                <input
                  autoComplete="organization"
                  id="new-organization-name"
                  maxLength={120}
                  onChange={(event) => setNewOrganizationName(event.target.value)}
                  required
                  value={newOrganizationName}
                />
                <button className="primary-button" disabled={creatingOrganization} type="submit">
                  {creatingOrganization ? 'Creating organization…' : 'Create organization'}
                </button>
              </form>
            </section>
          )}

          {selectedOrganization && (
            <>
            <section className="alerts-section" aria-labelledby="alerts-title">
              <div className="section-heading">
                <h2 id="alerts-title">Recent alerts</h2>
                <span>Latest 20</span>
              </div>
              {alertsLoading && <p className="empty-state">Loading organization alerts…</p>}
              {visibleAlertsError && (
                <p className="error-message" role="alert">{visibleAlertsError}</p>
              )}
              {!alertsLoading && !visibleAlertsError && visibleAlerts.length === 0 && (
                <p className="empty-state">No alerts have been recorded for this organization.</p>
              )}
              {visibleAlerts.length > 0 && (
                <ul className="alert-list">
                  {visibleAlerts.map((alert) => (
                    <li className="alert-row" key={alert.id}>
                      <div>
                        <h3>{alert.title}</h3>
                        <p>{new Date(alert.created_at).toLocaleString()}</p>
                      </div>
                      <div className="alert-badges">
                        <span className={`severity-badge severity-${alert.severity}`}>
                          {alert.severity}
                        </span>
                        <span className="status-badge">{alert.status}</span>
                      </div>
                    </li>
                  ))}
                </ul>
              )}
            </section>
            <section className="alerts-section findings-section" aria-labelledby="findings-title">
              <div className="section-heading">
                <h2 id="findings-title">Recent findings</h2>
                <span>Latest 20</span>
              </div>
              {findingsLoading && <p className="empty-state">Loading organization findings…</p>}
              {visibleFindingsError && (
                <p className="error-message" role="alert">{visibleFindingsError}</p>
              )}
              {!findingsLoading && !visibleFindingsError && visibleFindings.length === 0 && (
                <p className="empty-state">No vulnerability findings have been recorded for this organization.</p>
              )}
              {visibleFindings.length > 0 && (
                <ul className="alert-list">
                  {visibleFindings.map((finding) => (
                    <li className="alert-row" key={finding.id}>
                      <div>
                        <h3>{finding.title}</h3>
                        <p>
                          {finding.asset}
                          {finding.cve_id ? ` · ${finding.cve_id}` : ''}
                          {` · ${new Date(finding.created_at).toLocaleString()}`}
                        </p>
                      </div>
                      <div className="alert-badges">
                        <span className={`severity-badge severity-${finding.severity}`}>
                          {finding.severity}
                        </span>
                        <span className="status-badge">{finding.status}</span>
                      </div>
                    </li>
                  ))}
                </ul>
              )}
            </section>
            </>
          )}
        </main>
      </div>
    </div>
  )
}

export default App
