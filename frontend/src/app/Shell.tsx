import { FlaskConical, LineChart, MessageSquare, ShieldCheck } from 'lucide-react'
import { useEffect } from 'react'
import { NavLink, Outlet } from 'react-router'
import { PoolMeter } from '@/components/ui/PoolMeter'
import { SimBadge } from '@/components/ui/Badges'
import { useLink } from '@/state/link'

const NAV = [
  { to: '/chat', label: 'Chat', icon: MessageSquare },
  { to: '/lab', label: 'Key lab', icon: FlaskConical },
  { to: '/experiments', label: 'Experiments', icon: LineChart },
  { to: '/security', label: 'Security model', icon: ShieldCheck },
]

export function Shell() {
  const refresh = useLink((s) => s.refresh)
  useEffect(() => {
    void refresh()
    const timer = setInterval(() => void refresh(), 2000)
    return () => clearInterval(timer)
  }, [refresh])

  return (
    <div className="shell">
      <aside className="rail">
        <div className="brand">
          <svg width="22" height="22" viewBox="0 0 32 32" aria-hidden="true">
            <path d="M8 20 L16 8 L24 20" fill="none" stroke="var(--key)" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round" />
            <circle cx="16" cy="23" r="2.6" fill="var(--eve)" />
          </svg>
          Quantum Whisper
        </div>
        <nav className="nav" aria-label="Main">
          {NAV.map(({ to, label, icon: Icon }) => (
            <NavLink key={to} to={to}>
              <Icon size={16} strokeWidth={1.75} aria-hidden="true" />
              {label}
            </NavLink>
          ))}
        </nav>
      </aside>
      <header className="header">
        <SimBadge />
        <span className="grow" />
        <PoolMeter />
      </header>
      <main className="main">
        <Outlet />
      </main>
    </div>
  )
}
