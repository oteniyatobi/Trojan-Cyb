import Icon from './Icon.jsx'

function ThemeToggle({ theme, onToggle }) {
  return (
    <button
      type="button"
      className="theme-toggle"
      role="switch"
      aria-label="Dark mode"
      aria-checked={theme === 'dark'}
      onClick={onToggle}
    >
      <Icon name={theme === 'dark' ? 'moon' : 'sun'} />
      <span className="theme-label"></span>
      <span className="switch-track" aria-hidden="true"><span className="switch-thumb" /></span>
    </button>
  )
}

export default ThemeToggle
