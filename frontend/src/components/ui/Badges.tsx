import type { ReactNode } from 'react'
import { Link } from 'react-router'

/** Always visible: this project simulates QKD and never claims physical security. */
export function SimBadge() {
  return (
    <Link to="/security" className="badge badge-sim" title="What 'simulated' means for security">
      Simulated QKD · not physically secure
    </Link>
  )
}

export function StatusDot({ tone }: { tone: 'key' | 'eve' | 'danger' | 'idle' }) {
  return <span className={`dot ${tone === 'idle' ? '' : `dot-${tone}`}`} aria-hidden="true" />
}

export function Badge({ tone, children }: { tone?: 'key' | 'eve'; children: ReactNode }) {
  return <span className={`badge ${tone ? `badge-${tone}` : ''}`}>{children}</span>
}
