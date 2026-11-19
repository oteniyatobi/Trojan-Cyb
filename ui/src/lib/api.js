async function request(path, accessToken) {
  const headers = accessToken ? { Authorization: `Bearer ${accessToken}` } : {}
  let response
  try {
    response = await fetch(`/v1${path}`, { headers })
  } catch {
    throw new Error('Could not reach the TROJAN backend.')
  }
  const body = await response.json().catch(() => null)
  if (!response.ok) {
    throw new Error(body?.error ?? `Backend request failed (HTTP ${response.status}).`)
  }
  return body
}

export async function fetchAlerts(accessToken, organizationId) {
  const query = new URLSearchParams({ organization_id: organizationId, limit: '200' })
  const body = await request(`/alerts?${query}`, accessToken)
  return body.alerts
}

export async function fetchFindings(accessToken, organizationId) {
  const query = new URLSearchParams({ organization_id: organizationId, limit: '200' })
  const body = await request(`/findings?${query}`, accessToken)
  return body.findings
}

export function fetchHealth() {
  return request('/health')
}
