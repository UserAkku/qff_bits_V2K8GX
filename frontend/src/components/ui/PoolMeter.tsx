import { formatBits } from '@/lib/format'
import { useLink } from '@/state/link'

const CAP_BITS = 16_000

/** The one place the key pool is shown. Two separate streams so a pad is never issued twice. */
export function PoolMeter() {
  const snapshot = useLink((s) => s.snapshot)
  if (!snapshot) return <span className="meta">Connecting…</span>
  const rows = [
    { label: 'Alice → Bob', bits: snapshot.kme.alice.outgoing_bits },
    { label: 'Bob → Alice', bits: snapshot.kme.bob.outgoing_bits },
  ]
  return (
    <div className="row" style={{ gap: 16 }} aria-label="Key pool">
      {rows.map((row) => (
        <div key={row.label} style={{ minWidth: 112 }}>
          <div className="row" style={{ justifyContent: 'space-between', gap: 8 }}>
            <span className="meta">{row.label}</span>
            <span className="mono" style={{ fontSize: 12 }}>
              {formatBits(row.bits)}
            </span>
          </div>
          <div className="bar" role="meter" aria-valuemin={0} aria-valuemax={CAP_BITS} aria-valuenow={row.bits} aria-label={`${row.label} key pool`}>
            <span style={{ width: `${Math.min(100, (row.bits / CAP_BITS) * 100)}%` }} />
          </div>
        </div>
      ))}
    </div>
  )
}
