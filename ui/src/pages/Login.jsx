import { useState } from 'react'
import trojanLogo from '../assets/trojan-logo.png'
import trojanLogoWhite from '../assets/trojan-logo-white.png'
import ThemeToggle from '../components/ThemeToggle.jsx'

function Login({ theme, onToggleTheme, onLogin }) {
  const [access, setAccess] = useState('Workspace preview')
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')

  function handleSubmit(event) {
    event.preventDefault()
    setError('')
    if (access === 'Workspace preview') {
      onLogin({ name: 'Workspace viewer', role: 'member', kind: 'preview' })
      return
    }
    if (access === 'Demo admin') {
      if (username !== 'admin' || password !== 'trojan-demo') {
        setError('Use admin and trojan-demo for this demo account.')
        return
      }
      setPassword('')
      onLogin({ name: 'Demo administrator', role: 'admin', kind: 'demo' })
      return
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
          <h1>Welcome back</h1>
          <p>Explore your workspace or open the administration portal.</p>
          <form className="form-stack" onSubmit={handleSubmit}>
            <label>
              Access
              <select
                value={access}
                onChange={(event) => {
                  setAccess(event.target.value)
                  setUsername('')
                  setPassword('')
                  setError('')
                }}
              >
                <option>Workspace preview</option>
                <option>Demo admin</option>
              </select>
            </label>
            {access === 'Demo admin' && (
              <label>
                Username
                <input
                  value={username}
                  onChange={(event) => setUsername(event.target.value)}
                  autoComplete="username"
                  required
                />
              </label>
            )}
            {access !== 'Workspace preview' && (
              <label>
                Demo password
                <input
                  type="password"
                  value={password}
                  onChange={(event) => setPassword(event.target.value)}
                  autoComplete="current-password"
                  required
                />
              </label>
            )}
            <p className="panel-caption">
              {access === 'Workspace preview'
                ? 'Continue without credentials. This does not authenticate a real user.'
                : 'Demo only: username admin · password trojan-demo. This is a UI preview, not secure authentication.'}
            </p>
            {error && (
              <p className="error-message" role="alert">
                {error}
              </p>
            )}
            <button type="submit" className="primary-button">
              {access === 'Workspace preview'
                ? 'Continue to workspace'
                : 'Open admin portal'}
            </button>
          </form>
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
