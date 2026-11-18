// Vite forwards /v1 requests to Flask on localhost:8000.
export async function getAlerts(signal) {
  const response = await fetch('/v1/alerts?limit=100', { signal })
  if (!response.ok) {
    throw new Error(`The backend could not load alerts (HTTP ${response.status}).`)
  }

  const data = await response.json()
  if (!Array.isArray(data?.alerts) || !Number.isInteger(data.total) || data.total < 0
    || data.alerts.some((alert) => !alert || !Number.isInteger(alert.id))) {
    throw new Error('The backend returned an unexpected alerts response.')
  }

  return {
    total: data.total,
    alerts: data.alerts.map((alert) => ({
      id: alert.id,
      title: alert.description || 'Untitled alert',
      host: alert.agent_name || 'Unknown host',
      time: alert.event_time || alert.received_at || 'Not recorded',
      source: 'Wazuh',
      // Groq severity is separate from Wazuh's numeric rule level.
      severity: alert.review?.severity || 'Not rated',
      status: alert.status || 'Unknown',
    })),
  }
}
