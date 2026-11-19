async function request(path, accessToken, { method = 'GET', body } = {}) {
  const headers = accessToken ? { Authorization: `Bearer ${accessToken}` } : {}
  if (body) headers['Content-Type'] = 'application/json'
  let response
  try {
    response = await fetch(`/v1${path}`, {
      method,
      headers,
      body: body ? JSON.stringify(body) : undefined,
    })
  } catch {
    throw new Error('Could not reach the TROJAN backend.')
  }
  const result = await response.json().catch(() => null)
  if (!response.ok) {
    throw new Error(result?.error ?? `Backend request failed (HTTP ${response.status}).`)
  }
  return result
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

export const admin = {
  organizations: (token) => request('/admin/organizations', token),
  createOrganization: (token, name, adminEmail) => request('/admin/organizations', token, {
    method: 'POST',
    body: { name, admin_email: adminEmail },
  }),
  setRole: (token, organizationId, userId, role) => request(
    `/admin/organizations/${organizationId}/members/${userId}`,
    token,
    { method: 'PATCH', body: { role } },
  ),
  createKey: (token, organizationId, label) => request(
    `/admin/organizations/${organizationId}/keys`,
    token,
    { method: 'POST', body: { label } },
  ),
  revokeKey: (token, keyId) => request(`/admin/keys/${keyId}/revoke`, token, { method: 'POST' }),
}
