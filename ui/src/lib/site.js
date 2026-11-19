export const adminUrl = import.meta.env.VITE_ADMIN_URL || 'https://trojan-cyb-admin.vercel.app'

export function isAdminSite() {
  const { hostname, search } = window.location
  return hostname === new URL(adminUrl).hostname
    || hostname.startsWith('admin.')
    || new URLSearchParams(search).has('admin')
}
