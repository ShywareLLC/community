import { useState } from 'react'
import Overview from './pages/Overview.jsx'
import Billing from './pages/Billing.jsx'
import Posture from './pages/Posture.jsx'

const PURPLE = '#A78BFA'
const BG = '#09090B'
const SURFACE = '#18181B'
const BORDER = '#27272A'
const TEXT = '#FAFAFA'
const MUTED = '#71717A'

const NAV = [
  { id: 'overview', label: 'Overview' },
  { id: 'billing', label: 'Billing' },
  { id: 'posture', label: 'Posture Control' },
]

export default function App() {
  const [page, setPage] = useState('overview')

  return (
    <div style={{ minHeight: '100vh', background: BG, color: TEXT, fontFamily: 'Inter, system-ui, sans-serif' }}>
      {/* Topbar */}
      <div style={{
        borderBottom: `1px solid ${BORDER}`,
        display: 'flex',
        alignItems: 'center',
        padding: '0 24px',
        height: 52,
        gap: 32,
        position: 'sticky',
        top: 0,
        background: BG,
        zIndex: 10,
      }}>
        <span style={{ fontSize: 13, fontWeight: 700, letterSpacing: '0.08em', color: PURPLE, textTransform: 'uppercase' }}>
          shyware
        </span>
        <span style={{ fontSize: 12, color: MUTED }}>console</span>
        <div style={{ display: 'flex', gap: 4, marginLeft: 'auto' }}>
          {NAV.map(n => (
            <button
              key={n.id}
              onClick={() => setPage(n.id)}
              style={{
                background: page === n.id ? SURFACE : 'none',
                border: page === n.id ? `1px solid ${BORDER}` : '1px solid transparent',
                borderRadius: 6,
                color: page === n.id ? TEXT : MUTED,
                cursor: 'pointer',
                fontSize: 13,
                fontWeight: page === n.id ? 600 : 400,
                padding: '5px 14px',
                fontFamily: 'Inter, system-ui, sans-serif',
                transition: 'color 0.12s',
              }}
            >
              {n.label}
            </button>
          ))}
        </div>
      </div>

      {/* Page content */}
      <div style={{ maxWidth: 780, margin: '0 auto', padding: '36px 24px 64px' }}>
        {page === 'overview' && <Overview setPage={setPage} />}
        {page === 'billing'  && <Billing />}
        {page === 'posture'  && <Posture />}
      </div>
    </div>
  )
}
