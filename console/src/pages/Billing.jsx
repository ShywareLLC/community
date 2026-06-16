import { useState, useEffect } from 'react'
import deployments from '../deployments.json'
import { PURPLE, SURFACE, BORDER, TEXT, MUTED, RED, RED_BG, RED_BORDER, GREEN, GREEN_BG, GREEN_BORDER } from '../components/tokens.js'
import { PageHeader } from './Overview.jsx'

const PRICE_PER_PATIENT_RECOVERABLE = 5
const PRICE_PER_PATIENT_COERCION_RESISTANT = 7  // 5 × 1.4, rounded

function fmt(n) {
  return n.toLocaleString('en-US', { style: 'currency', currency: 'USD', maximumFractionDigits: 0 })
}

function BillingCard({ d }) {
  const [billing, setBilling] = useState(null)
  const [posture, setPosture] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)

  useEffect(() => {
    let cancelled = false
    Promise.allSettled([
      fetch(d.billingUrl).then(r => r.ok ? r.json() : Promise.reject(r.status)),
      fetch(d.postureUrl).then(r => r.ok ? r.json() : null),
    ]).then(([b, p]) => {
      if (cancelled) return
      if (b.status === 'fulfilled') setBilling(b.value)
      else setError(`billing API: HTTP ${b.reason}`)
      if (p.status === 'fulfilled') setPosture(p.value)
      setLoading(false)
    })
    return () => { cancelled = true }
  }, [d.billingUrl, d.postureUrl])

  const eff = posture?.posture ?? posture?.effective_posture ?? 'recoverable'
  const isCoercionResistant = eff === 'write_only' || eff === 'coercion_resistant'
  const rate = isCoercionResistant ? PRICE_PER_PATIENT_COERCION_RESISTANT : PRICE_PER_PATIENT_RECOVERABLE
  const patients = billing?.active_patients ?? null
  const periodStart = billing?.period_start ?? null
  const periodEnd = billing?.period_end ?? null
  const attestationId = billing?.attestation_id ?? null
  const annual = patients !== null ? Math.round(patients * rate) : null

  const hasStripe = Boolean(d.stripeSubscriptionId)

  return (
    <div style={{ background: SURFACE, border: `1px solid ${BORDER}`, borderRadius: 10, padding: '20px 22px', display: 'flex', flexDirection: 'column', gap: 16 }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
        <div>
          <div style={{ fontWeight: 600, fontSize: 15, color: TEXT }}>{d.name}</div>
          <div style={{ fontSize: 12, color: MUTED, marginTop: 2 }}>{d.domain} · <span style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 11 }}>{d.contract}</span></div>
        </div>
        {!loading && (
          <SubscriptionBadge hasStripe={hasStripe} />
        )}
      </div>

      {loading && <div style={{ fontSize: 13, color: MUTED }}>Loading billing data…</div>}

      {error && (
        <div style={{ fontSize: 13, color: RED, background: RED_BG, border: `1px solid ${RED_BORDER}`, borderRadius: 6, padding: '8px 12px' }}>
          {error}
        </div>
      )}

      {!loading && !error && (
        <>
          {/* Period */}
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(140px, 1fr))', gap: 12 }}>
            <BillingStat label="Billing period" value="180-day rolling" />
            <BillingStat label="Period start" value={periodStart ? new Date(periodStart).toLocaleDateString() : '—'} />
            <BillingStat label="Period end" value={periodEnd ? new Date(periodEnd).toLocaleDateString() : '—'} />
            <BillingStat label="Active patients" value={patients !== null ? patients.toLocaleString() : '—'} highlight />
          </div>

          {/* Attestation */}
          {attestationId && (
            <div style={{ fontSize: 12, color: MUTED, fontFamily: 'JetBrains Mono, monospace', background: '#0c0c10', borderRadius: 6, padding: '6px 10px', wordBreak: 'break-all' }}>
              attestation: <span style={{ color: '#D4D4D8' }}>{attestationId}</span>
            </div>
          )}

          {/* Fee estimate */}
          <div style={{ background: '#0c0c10', borderRadius: 8, padding: '14px 16px', display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 12 }}>
            <div>
              <div style={{ fontSize: 11, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.07em', color: MUTED, marginBottom: 4 }}>
                Estimated annual fee
              </div>
              <div style={{ fontSize: 22, fontWeight: 700, color: PURPLE }}>
                {annual !== null ? fmt(annual) : '—'}
              </div>
              <div style={{ fontSize: 11, color: MUTED, marginTop: 3 }}>
                {patients?.toLocaleString() ?? '—'} patients × ${rate}/yr
                {isCoercionResistant && ' (coercion-resistant posture)'}
              </div>
            </div>
            <div>
              {hasStripe ? (
                <a
                  href={`https://billing.stripe.com/p/login/PLACEHOLDER?customer=${d.stripeCustomerId}`}
                  target="_blank"
                  rel="noreferrer"
                  style={stripeBtn}
                >
                  Manage subscription →
                </a>
              ) : (
                <a
                  href="https://shyware.fyi/pricing"
                  target="_blank"
                  rel="noreferrer"
                  style={stripeBtn}
                >
                  Set up billing →
                </a>
              )}
            </div>
          </div>

          {/* Posture note */}
          {isCoercionResistant && (
            <div style={{ fontSize: 12, color: '#fde68a', background: '#422006', border: '1px solid #92400e', borderRadius: 6, padding: '8px 12px', lineHeight: 1.5 }}>
              <strong>Coercion-resistant posture active.</strong> Write-only mode is enforced at the attested execution environment. Rate is ${PRICE_PER_PATIENT_COERCION_RESISTANT}/patient/year (+40% vs recoverable).
            </div>
          )}
        </>
      )}
    </div>
  )
}

function BillingStat({ label, value, highlight }) {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 3 }}>
      <span style={{ fontSize: 10, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.07em', color: MUTED }}>{label}</span>
      <span style={{ fontSize: 14, fontWeight: highlight ? 700 : 400, color: highlight ? PURPLE : '#D4D4D8' }}>{value}</span>
    </div>
  )
}

function SubscriptionBadge({ hasStripe }) {
  return (
    <span style={{
      display: 'inline-block',
      padding: '2px 10px',
      borderRadius: 99,
      fontSize: 11,
      fontWeight: 700,
      letterSpacing: '0.04em',
      background: hasStripe ? GREEN_BG : '#0c0c10',
      color: hasStripe ? GREEN : MUTED,
      border: `1px solid ${hasStripe ? GREEN_BORDER : BORDER}`,
    }}>
      {hasStripe ? 'subscription active' : 'no subscription'}
    </span>
  )
}

const stripeBtn = {
  display: 'inline-block',
  background: PURPLE,
  color: '#fff',
  padding: '8px 18px',
  borderRadius: 6,
  fontSize: 13,
  fontWeight: 600,
  textDecoration: 'none',
  whiteSpace: 'nowrap',
}

export default function Billing() {
  return (
    <div>
      <PageHeader
        title="Billing"
        sub="Active patient counts from HSM-signed period-close attestations. No operator self-reporting. Stripe self-serve checkout for US operators."
      />

      <div style={{ marginTop: 20, padding: '10px 14px', background: SURFACE, border: `1px solid ${BORDER}`, borderRadius: 8, fontSize: 12, color: MUTED, lineHeight: 1.6 }}>
        <strong style={{ color: '#D4D4D8' }}>Billing unit:</strong>{' '}
        any participant with a List 2 identity hash written to canonical state within the preceding 180-day period, verified from <code style={{ fontFamily: 'JetBrains Mono, monospace', color: '#D4D4D8' }}>|L2(S)|</code> in the signed attestation.
        {' '}<strong style={{ color: '#D4D4D8' }}>Base rate:</strong> $5/patient/year (recoverable) · $7/patient/year (coercion-resistant).
      </div>

      <div style={{ display: 'flex', flexDirection: 'column', gap: 14, marginTop: 18 }}>
        {deployments.map(d => <BillingCard key={d.id} d={d} />)}
      </div>

      <div style={{ marginTop: 28, fontSize: 12, color: MUTED, lineHeight: 1.6 }}>
        International billing available on request. Contact{' '}
        <a href="mailto:nicholas@shyware.fyi" style={{ color: PURPLE }}>nicholas@shyware.fyi</a>.
      </div>
    </div>
  )
}
