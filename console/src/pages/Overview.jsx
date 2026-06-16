import { useState, useEffect } from 'react'
import deployments from '../deployments.json'
import { PURPLE, SURFACE, BORDER, TEXT, MUTED, GREEN, GREEN_BG, GREEN_BORDER, postureBadge } from '../components/tokens.js'

const PRICE_PER_PATIENT = 5

function fmt(n) {
  return n.toLocaleString('en-US', { style: 'currency', currency: 'USD', maximumFractionDigits: 0 })
}

function DeploymentRow({ d, setPage }) {
  const [posture, setPosture] = useState(null)
  const [patients, setPatients] = useState(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    let cancelled = false
    Promise.allSettled([
      fetch(d.postureUrl).then(r => r.ok ? r.json() : null),
      fetch(d.billingUrl).then(r => r.ok ? r.json() : null),
    ]).then(([p, b]) => {
      if (cancelled) return
      if (p.status === 'fulfilled') setPosture(p.value)
      if (b.status === 'fulfilled') setPatients(b.value?.active_patients ?? null)
      setLoading(false)
    })
    return () => { cancelled = true }
  }, [d.postureUrl, d.billingUrl])

  const eff = posture?.posture ?? posture?.effective_posture ?? null
  const badge = postureBadge(eff)
  const annualFee = patients !== null ? fmt(Math.round(patients * PRICE_PER_PATIENT)) : '—'
  const raMap = { operator: 'you', shyware: 'Shyware', independent_third_party: 'third party' }

  return (
    <div style={{
      background: SURFACE,
      border: `1px solid ${BORDER}`,
      borderRadius: 10,
      padding: '18px 20px',
      display: 'flex',
      flexDirection: 'column',
      gap: 12,
    }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: 12 }}>
        <div>
          <div style={{ fontWeight: 600, fontSize: 15, color: TEXT }}>{d.name}</div>
          <div style={{ fontSize: 12, color: MUTED, marginTop: 3 }}>{d.domain}</div>
        </div>
        {loading ? (
          <span style={{ fontSize: 12, color: MUTED }}>loading…</span>
        ) : (
          <span style={{
            display: 'inline-block',
            padding: '2px 10px',
            borderRadius: 99,
            fontSize: 11,
            fontWeight: 700,
            letterSpacing: '0.04em',
            background: badge.bg,
            color: badge.color,
            border: `1px solid ${badge.border}`,
          }}>{badge.label}</span>
        )}
      </div>

      <div style={{ display: 'flex', gap: 24, flexWrap: 'wrap' }}>
        <Stat label="Contract" value={d.contract} mono />
        <Stat label="Tier" value={d.deploymentTier} mono />
        <Stat label="RA operator" value={raMap[d.raOperator] ?? d.raOperator} />
        <Stat label="Active patients (180d)" value={loading ? '…' : patients !== null ? patients.toLocaleString() : '—'} />
        <Stat label="Est. annual fee" value={loading ? '…' : annualFee} highlight />
      </div>

      <div style={{ display: 'flex', gap: 8 }}>
        <button onClick={() => setPage('billing')} style={linkBtn}>Billing →</button>
        <button onClick={() => setPage('posture')} style={linkBtn}>Posture control →</button>
      </div>
    </div>
  )
}

function Stat({ label, value, mono, highlight }) {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
      <span style={{ fontSize: 11, fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.06em', color: MUTED }}>
        {label}
      </span>
      <span style={{
        fontSize: 13,
        fontFamily: mono ? 'JetBrains Mono, monospace' : 'Inter, sans-serif',
        color: highlight ? '#A78BFA' : '#D4D4D8',
        fontWeight: highlight ? 600 : 400,
      }}>
        {value}
      </span>
    </div>
  )
}

const linkBtn = {
  background: 'none',
  border: 'none',
  color: PURPLE,
  fontSize: 12,
  fontWeight: 600,
  cursor: 'pointer',
  fontFamily: 'Inter, sans-serif',
  padding: 0,
  letterSpacing: '0.01em',
}

export default function Overview({ setPage }) {
  return (
    <div>
      <PageHeader
        title="Overview"
        sub="All deployments. Active patient counts are fetched live from the deployment API and are derived from HSM-signed period-close attestations."
      />
      <div style={{ display: 'flex', flexDirection: 'column', gap: 12, marginTop: 24 }}>
        {deployments.map(d => (
          <DeploymentRow key={d.id} d={d} setPage={setPage} />
        ))}
      </div>
      <div style={{ marginTop: 28, fontSize: 12, color: MUTED, lineHeight: 1.6, padding: '12px 16px', background: SURFACE, borderRadius: 8, border: `1px solid ${BORDER}` }}>
        <strong style={{ color: '#D4D4D8' }}>Billing unit:</strong> any participant with a List 2 identity hash written to canonical state within the preceding 180-day billing period, verified from the signed period-close attestation.
        Active patient counts shown here are sourced from <code style={{ color: '#D4D4D8', fontFamily: 'JetBrains Mono, monospace' }}>GET /api/v1/billing/active-patients</code> on each deployment.
      </div>
    </div>
  )
}

export function PageHeader({ title, sub }) {
  return (
    <div style={{ marginBottom: 4 }}>
      <div style={{ fontSize: 11, fontWeight: 700, letterSpacing: '0.12em', color: PURPLE, textTransform: 'uppercase', marginBottom: 6 }}>
        shyware console
      </div>
      <h1 style={{ margin: 0, fontSize: 20, fontWeight: 600, color: '#FAFAFA' }}>{title}</h1>
      {sub && <p style={{ margin: '6px 0 0', fontSize: 13, color: MUTED, lineHeight: 1.55, maxWidth: 600 }}>{sub}</p>}
    </div>
  )
}
