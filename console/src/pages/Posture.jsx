// Posture Control — operator override of deployment posture (write-only vs recoverable).
// Migrated from ShywareLLC/community/documentation/POSTURE_DASH/src/PostureDash.jsx
// and extended with deployment metadata from deployments.json.

import { useState, useEffect, useCallback } from 'react'
import deployments from '../deployments.json'
import { PURPLE, SURFACE, BORDER, TEXT, MUTED, btn, postureBadge } from '../components/tokens.js'
import { PageHeader } from './Overview.jsx'

function DeploymentCard({ d }) {
  const [status, setStatus] = useState(null)
  const [loading, setLoading] = useState(true)
  const [submitting, setSubmitting] = useState(false)
  const [reason, setReason] = useState('')
  const [error, setError] = useState(null)
  const [lastAction, setLastAction] = useState(null)

  const fetchStatus = useCallback(async () => {
    try {
      const res = await fetch(d.postureUrl)
      if (!res.ok) throw new Error(`HTTP ${res.status}`)
      setStatus(await res.json())
      setError(null)
    } catch (e) {
      setError(e.message)
    } finally {
      setLoading(false)
    }
  }, [d.postureUrl])

  useEffect(() => {
    fetchStatus()
    const id = setInterval(fetchStatus, 30_000)
    return () => clearInterval(id)
  }, [fetchStatus])

  const override = async (posture) => {
    setSubmitting(true)
    setError(null)
    try {
      const res = await fetch(d.adminUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ posture, reason: reason.trim() || null }),
      })
      if (!res.ok) throw new Error(`HTTP ${res.status}`)
      setLastAction({ posture, at: new Date().toISOString() })
      setReason('')
      await fetchStatus()
    } catch (e) {
      setError(e.message)
    } finally {
      setSubmitting(false)
    }
  }

  const eff = status?.posture ?? status?.effective_posture ?? null
  const source = status?.source ?? 'manifest'
  const badge = postureBadge(eff)
  const raMap = { operator: 'you', shyware: 'Shyware', independent_third_party: 'third party' }

  return (
    <div style={{ background: SURFACE, border: `1px solid ${BORDER}`, borderRadius: 10, padding: '20px 22px', display: 'flex', flexDirection: 'column', gap: 14 }}>
      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: 12 }}>
        <div>
          <div style={{ fontWeight: 600, fontSize: 15, color: TEXT }}>{d.name}</div>
          <div style={{ fontSize: 12, color: MUTED, marginTop: 2 }}>
            {d.domain} ·{' '}
            <span style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 11 }}>{d.contract}</span>
            {' '}· RA: {raMap[d.raOperator] ?? d.raOperator}
          </div>
        </div>
        {loading
          ? <span style={{ fontSize: 12, color: MUTED }}>loading…</span>
          : error
            ? <span style={{ fontSize: 12, color: '#fca5a5' }}>{error}</span>
            : eff
              ? <span style={{ display: 'inline-block', padding: '2px 10px', borderRadius: 99, fontSize: 11, fontWeight: 700, letterSpacing: '0.04em', background: badge.bg, color: badge.color, border: `1px solid ${badge.border}` }}>{badge.label}</span>
              : <span style={{ fontSize: 12, color: MUTED }}>manifest default</span>
        }
      </div>

      {/* Source + timestamp */}
      {!loading && !error && (
        <div style={{ fontSize: 12, color: MUTED }}>
          source:{' '}
          <span style={{ color: source === 'operator' ? PURPLE : TEXT }}>{source}</span>
          {status?.updated_at && (
            <span style={{ marginLeft: 8 }}>
              · {new Date(status.updated_at).toLocaleString()}
            </span>
          )}
        </div>
      )}

      {/* Security note for voting deployments */}
      {d.contract === 'shyvoting-v1' && (
        <div style={{ fontSize: 12, color: '#fde68a', background: '#422006', border: '1px solid #92400e', borderRadius: 6, padding: '8px 12px', lineHeight: 1.5 }}>
          <strong>shyvoting-v1:</strong> Coercion-resistant posture requires an attested mobile device (Play Integrity / App Attest). Forcing write-only in a browser-only deployment does not provide structural coercion resistance.
        </div>
      )}

      {/* Reason */}
      <textarea
        value={reason}
        onChange={e => setReason(e.target.value)}
        placeholder="Reason for override (logged to audit surface)"
        rows={2}
        style={{
          background: '#0c0c10',
          border: `1px solid ${BORDER}`,
          borderRadius: 6,
          color: TEXT,
          fontSize: 13,
          padding: '8px 12px',
          resize: 'vertical',
          fontFamily: 'Inter, sans-serif',
          outline: 'none',
          width: '100%',
        }}
      />

      {/* Controls */}
      <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
        <button onClick={() => override('write_only')} disabled={submitting} style={btn('#7f1d1d', '#fca5a5', submitting)}>
          Force write-only
        </button>
        <button onClick={() => override('recoverable')} disabled={submitting} style={btn('#14532d', '#86efac', submitting)}>
          Force recoverable
        </button>
        <button onClick={() => override(null)} disabled={submitting} style={btn(BORDER, MUTED, submitting)}>
          Clear override
        </button>
        <button onClick={fetchStatus} disabled={submitting || loading} style={{ ...btn('#1c1c20', MUTED, submitting || loading), marginLeft: 'auto' }}>
          Refresh
        </button>
      </div>

      {/* Last action */}
      {lastAction && (
        <div style={{ fontSize: 12, color: MUTED }}>
          Set to{' '}
          <strong style={{ color: TEXT }}>{lastAction.posture ?? 'cleared'}</strong>
          {' '}at {new Date(lastAction.at).toLocaleTimeString()}
        </div>
      )}
    </div>
  )
}

export default function Posture() {
  return (
    <div>
      <PageHeader
        title="Posture Control"
        sub="Force write-only or recoverable posture across deployments. Overrides the manifest default and all user preferences. Clients pick up changes on next initialization."
      />

      <div style={{ marginTop: 20, padding: '10px 14px', background: SURFACE, border: `1px solid ${BORDER}`, borderRadius: 8, fontSize: 12, color: MUTED, lineHeight: 1.6 }}>
        This page is gated by Cloudflare Access.{' '}
        <code style={{ color: '#D4D4D8', fontFamily: 'JetBrains Mono, monospace' }}>GET /api/v1/posture</code> is publicly readable (clients poll it).{' '}
        <code style={{ color: '#D4D4D8', fontFamily: 'JetBrains Mono, monospace' }}>POST /api/v1/posture/admin</code> requires operator authentication. All overrides are logged to the authority-action audit surface (Claim 60).
      </div>

      <div style={{ display: 'flex', flexDirection: 'column', gap: 14, marginTop: 18 }}>
        {deployments.map(d => <DeploymentCard key={d.id} d={d} />)}
      </div>
    </div>
  )
}
