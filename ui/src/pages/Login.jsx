import trojanLogo from '../assets/trojan-logo.png'
import trojanLogoWhite from '../assets/trojan-logo-white.png'
import ThemeToggle from '../components/ThemeToggle.jsx'

function Login({ theme, onToggleTheme, onLogin }) {
  function handleSubmit(event) {
    event.preventDefault()
    onLogin()
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
          <h1>Welcome Back</h1>
          <p>Explore your organization’s security workspace.</p>
          <form className="form-stack" onSubmit={handleSubmit}>
            <label>
              Work email
              <input
                type="email"
                name="email"
                placeholder="user@company.com"
                autoComplete="username"
              />
            </label>
            <label>
              Password
              <input
                type="password"
                name="password"
                placeholder="Enter your password"
                autoComplete="current-password"
              />
            </label>
            <p className="panel-caption"></p>
            <button type="submit" className="primary-button">
              Sign In
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
