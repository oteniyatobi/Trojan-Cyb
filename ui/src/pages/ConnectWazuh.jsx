import CodeBlock from '../components/CodeBlock.jsx'
import { appUrl } from '../lib/site.js'

const scriptUrl = `${appUrl}/integrations/custom-trojan`
const checksum = __INTEGRATION_SHA256__

function ConnectWazuh({ apiKey }) {
  const install = [
    `curl -fsSL -o /tmp/custom-trojan ${scriptUrl}`,
    checksum && `echo "${checksum}  /tmp/custom-trojan" | sha256sum -c`,
    'sudo install -o root -g wazuh -m 750 /tmp/custom-trojan /var/ossec/integrations/custom-trojan',
  ].filter(Boolean).join('\n')

  const config = `<integration>
  <name>custom-trojan</name>
  <hook_url>${appUrl}/v1/analyze</hook_url>
  <api_key>${apiKey || 'YOUR_KEY'}</api_key>
  <level>10</level>
  <alert_format>json</alert_format>
</integration>`

  return (
    <div className="setup-steps">
      <p className="panel-caption">
        Run these on the business’s Wazuh manager. If Wazuh runs in Docker, run them inside the
        manager container.
      </p>
      <ol>
        <li>
          Download the TROJAN integration{checksum ? ', check it and install it' : ' and install it'}:
          <CodeBlock label="Install commands" text={install} />
        </li>
        <li>
          Add this inside <code>&lt;ossec_config&gt;</code> in <code>/var/ossec/etc/ossec.conf</code>:
          <CodeBlock label="ossec.conf integration" text={config} />
          Level 10 sends serious alerts only. Add <code>&lt;group&gt;suricata&lt;/group&gt;</code> to
          send only Suricata alerts.
        </li>
        <li>
          Restart Wazuh:
          <CodeBlock label="Restart command" text="sudo systemctl restart wazuh-manager" />
        </li>
        <li>
          Check it works:
          <CodeBlock label="Log command" text="sudo tail -f /var/ossec/logs/integrations.log" />
          <code>HTTP 200</code> means alerts are arriving. <code>HTTP 401</code> means the key is
          wrong or revoked. <code>FAILED</code> means TROJAN can’t be reached. Alerts that fail
          aren’t sent again.
        </li>
      </ol>
      {!apiKey && (
        <p className="cell-note">
          Keys are only shown once. If a key is lost, create a new one and revoke the old one.
        </p>
      )}
    </div>
  )
}

export default ConnectWazuh
