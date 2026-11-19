import { useState } from 'react'

function CodeBlock({ label, text }) {
  const [copied, setCopied] = useState(false)

  async function copy() {
    try {
      await navigator.clipboard.writeText(text)
      setCopied(true)
    } catch {
      setCopied(false)
    }
  }

  return (
    <div className="code-block">
      <pre aria-label={label}><code>{text}</code></pre>
      <button type="button" className="text-button" onClick={copy}>
        {copied ? 'Copied' : 'Copy'}
      </button>
    </div>
  )
}

export default CodeBlock
