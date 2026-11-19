import { useState } from 'react'
import trojanLogo from '../assets/trojan-logo.png'
import trojanLogoWhite from '../assets/trojan-logo-white.png'
import ThemeToggle from '../components/ThemeToggle.jsx'
import { supabase } from '../lib/supabase.js'

function Login({ theme, onToggleTheme, onLogin, error }) {
  const [mode, setMode] = useState('sign-in')
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [organizationName, setOrganizationName] = useState('')
  const [loading, setLoading] = useState(false)
  const [formError, setFormError] = useState('')
  const [message, setMessage] = useState('')

  async function handleSubmit(event) {
    event.preventDefault()
    setLoading(true)
    setFormError('')
    setMessage('')

    try {
      if (mode === 'sign-in') {
        const { error: signInError } = await supabase.auth.signInWithPassword({
          email,
          password,
        })
        if (signInError) throw signInError
        onLogin()
        return
      }

      const { data, error: signUpError } = await supabase.auth.signUp({
        email,
        password,
        options: {
          data: { organization_name: organizationName.trim() },
        },
      })
      if (signUpError) throw signUpError
      if (data.session) {
        onLogin()
      } else {
        setMode('sign-in')
        setPassword('')
        setMessage('Check your email to confirm your account, then sign in. Your organization will be set up automatically.')
      }
    } catch (submitError) {
      setFormError(submitError.message)
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="login-layout">
      <section className="login-form-panel">
        <div className="login-brand">
          <img
            className="logo"
            src={theme === 'dark' ? trojanLogoWhite : trojanLogo}
            alt="TROJAN"
            width="2172"
            height="724"
          />
          <ThemeToggle theme={theme} onToggle={onToggleTheme} />
        </div>
        <div className="login-content">
          <h1>{mode === 'sign-in' ? 'Welcome Back' : 'Create your organization'}</h1>
          <p>
            {mode === 'sign-in'
              ? 'Sign in to your organization’s security workspace.'
              : 'Create an account. Your organization and admin access will be set up automatically.'}
          </p>
          {(error || formError) && (
            <p className="form-message" role="alert">{formError || error}</p>
          )}
          {message && <p className="form-message" role="status">{message}</p>}
          <form className="form-stack" onSubmit={handleSubmit}>
            {mode === 'sign-up' && (
              <label>
                Organization name
                <input
                  type="text"
                  name="organization"
                  autoComplete="organization"
                  maxLength={120}
                  required
                  value={organizationName}
                  onChange={(event) => setOrganizationName(event.target.value)}
                />
              </label>
            )}
            <label>
              Work email
              <input
                type="email"
                name="email"
                placeholder="user@company.com"
                autoComplete="username"
                required
                value={email}
                onChange={(event) => setEmail(event.target.value)}
              />
            </label>
            <label>
              Password
              <input
                type="password"
                name="password"
                placeholder="Enter your password"
                autoComplete="current-password"
                minLength={8}
                required
                value={password}
                onChange={(event) => setPassword(event.target.value)}
              />
            </label>
            <button type="submit" className="primary-button" disabled={loading}>
              {loading
                ? (mode === 'sign-in' ? 'Signing in…' : 'Creating account…')
                : (mode === 'sign-in' ? 'Sign In' : 'Create account')}
            </button>
          </form>
          <button
            className="text-button"
            type="button"
            onClick={() => {
              setMode(mode === 'sign-in' ? 'sign-up' : 'sign-in')
              setFormError('')
              setMessage('')
            }}
          >
            {mode === 'sign-in'
              ? 'New organization? Create an account'
              : 'Already registered? Sign in'}
          </button>
          <a className="text-button" href="#/demo/overview">View the demo workspace</a>
        </div>
      </section>
      <section className="login-brand-panel">
        <img src={trojanLogoWhite} alt="" width="2172" height="724" />
        <h2>Protection you can understand.</h2>
        <p>Local monitoring · Intelligent alerts · Guided response</p>
        <div className="login-feature">
          <strong>Monitor</strong>
          <span>A clear view of your security workspace.</span>
        </div>
        <div className="login-feature">
          <strong>Understand</strong>
          <span>Simple guidance for your next steps.</span>
        </div>
      </section>
    </div>
  )
}

export default Login
