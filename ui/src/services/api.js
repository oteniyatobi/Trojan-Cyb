// Vite forwards /v1 requests to Flask on localhost:8000.
async function getJson(path, signal) {
  const response = await fetch('/v1' + path, { signal })
  if (!response.ok) {
    throw new Error(`The backend request failed (HTTP ${response.status}).`)
  }
  return response.json()
}

// Both endpoints use the same Flask alert fields.
function formatAlert(alert) {
  return {
    id: alert.id,
    title: alert.description || 'Untitled alert',
    host: alert.agent_name || 'Unknown host',
    time: alert.event_time || alert.received_at || 'Not recorded',
    source: 'Wazuh',
    rule: alert.rule_id || 'Not recorded',
    ruleLevel: alert.rule_level,
    sourceIp: alert.src_ip || 'Not recorded',
    evidence: alert.description || 'No description was recorded.',
    signature: alert.signature_name,
    destinationIp: alert.dest_ip,
    destinationPort: alert.dest_port,
    protocol: alert.proto,
    // Review progress and incident status are separate fields.
    reviewStatus: alert.review_status === 'done' && !alert.review ? 'unavailable' : alert.review_status,
    review: alert.review,
    // Groq severity is separate from Wazuh's numeric rule level.
    severity: alert.review_status === 'done' ? alert.review?.severity || 'Not rated' : 'Not rated',
    status: alert.status || 'Unknown',
  }
}

export async function getAlerts(signal) {
  const data = await getJson('/alerts?limit=100', signal)
  if (!Array.isArray(data?.alerts) || !Number.isInteger(data.total) || data.total < 0
    || data.alerts.some((alert) => !alert || !Number.isInteger(alert.id))) {
    throw new Error('The backend returned an unexpected alerts response.')
  }
  return { total: data.total, alerts: data.alerts.map(formatAlert) }
}

export async function getAlert(id, signal) {
  const data = await getJson('/alerts/' + encodeURIComponent(id), signal)
  if (!data || !Number.isInteger(data.id)) {
    throw new Error('The backend returned an unexpected alert response.')
  }
  return formatAlert(data)
}
