import react from '@vitejs/plugin-react'
import { defineConfig } from 'vite'
import { createHash } from 'node:crypto'
import { existsSync, readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'

const integrationPath = new URL('../integrations/custom-trojan', import.meta.url)
const integration = existsSync(integrationPath) ? readFileSync(integrationPath) : null

function wazuhIntegration() {
  return {
    name: 'wazuh-integration',
    generateBundle() {
      if (!integration) return
      this.emitFile({ type: 'asset', fileName: 'integrations/custom-trojan', source: integration })
    },
  }
}

export default defineConfig({
  plugins: [react(), wazuhIntegration()],
  define: {
    __INTEGRATION_SHA256__: JSON.stringify(
      integration ? createHash('sha256').update(integration).digest('hex') : '',
    ),
  },
  envDir: fileURLToPath(new URL('../', import.meta.url)),
  server: {
    proxy: {
      '/v1': {
        target: 'http://localhost:8000',
        changeOrigin: true,
      },
    },
  },
})
