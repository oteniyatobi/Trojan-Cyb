const severityColors = ['var(--color-danger)', 'var(--color-warning)', 'var(--color-primary)', 'var(--color-success)']

export function SeverityChart({ alerts }) {
  const levels = ['Critical', 'High', 'Medium', 'Low']
  const counts = levels.map(
    (level) => alerts.filter((alert) => alert.severity === level).length,
  )
  const total = alerts.length
  let offset = 0

  return (
    <section className="panel">
      <h2>Threat severity</h2>
      <p className="panel-caption">Active alerts by priority</p>
      <div className="severity-chart">
        <div className="donut">
          <svg viewBox="0 0 120 120" aria-hidden="true">
            <circle
              cx="60"
              cy="60"
              r="44"
              fill="none"
              stroke="var(--color-border)"
              strokeWidth="14"
            />
            {counts.map((count, index) => {
              const percentage = total === 0 ? 0 : (count / total) * 100
              const start = offset
              offset += percentage
              return (
                <circle
                  key={levels[index]}
                  cx="60"
                  cy="60"
                  r="44"
                  fill="none"
                  stroke={severityColors[index]}
                  strokeWidth="14"
                  pathLength="100"
                  strokeDasharray={`${percentage} ${100 - percentage}`}
                  strokeDashoffset={-start}
                  transform="rotate(-90 60 60)"
                />
              )
            })}
          </svg>
          <div className="donut-label">
            <strong>{total}</strong>
            <span>active</span>
          </div>
        </div>
        <ul className="chart-legend">
          {levels.map((level, index) => (
            <li key={level}>
              <span className={`legend-dot severity-${level.toLowerCase()}`} />
              {level}
              <strong>{counts[index]}</strong>
            </li>
          ))}
        </ul>
      </div>
    </section>
  )
}

export function ActivityChart({ activity, period }) {
  const maximum = Math.max(...activity.map((day) => day.events), 1)
  const points = activity
    .map(
      (day, index) =>
        `${10 + index * 60},${130 - (day.events / maximum) * 110}`,
    )
    .join(' ')

  return (
    <section className="panel">
      <h2>Threat activity</h2>
      <p className="panel-caption">Security events · {period}</p>
      <div className="activity-chart">
        <svg
          viewBox="0 0 380 150"
          role="img"
          aria-label={`Demo security events: ${activity.map((day) => `${day.day} ${day.events}`).join(', ')}`}
        >
          {[30, 65, 100, 135].map((y) => (
            <line key={y} x1="0" y1={y} x2="380" y2={y} stroke="var(--color-border)" />
          ))}
          <polyline
            points={points}
            fill="none"
            stroke="var(--color-primary)"
            strokeWidth="2.5"
            strokeLinejoin="round"
          />
        </svg>
        <div className="chart-days">
          {activity.map((day) => (
            <span key={day.day}>{day.day}</span>
          ))}
        </div>
      </div>
    </section>
  )
}
