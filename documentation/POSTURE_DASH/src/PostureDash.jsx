import { useState, useEffect, useCallback } from 'react'
import deployments from './deployments.json'

const PURPLE = '#A78BFA'
const PURPLE_DARK = '#7C3AED'
const BG = '#09090B'
const SURFACE = '#18181B'
const BORDER = '#27272A'
const TEXT = '#FAFAFA'
const MUTED = '#71717A'

const badge = (posture) => ({
  display: 'inline-block',
  padding: '2px 10px',
  borderRadius: 99,
  fontSize: 12,
  fontWeight: 600,
  letterSpacing: '0.04em',
  background: posture === 'write_only' ? '#450a0a' : '#052e16',
  color: posture === 'write_only' ? '#fca5a5' : '#86efac',
  border: `1px solid ${posture === 'write_only' ? '#7f1d1d' : '#14532d'}`,
})

function DeploymentCard({ deployment }) {
  const [status, setStatus] = useState(null)
  const [loading, setLoading] = useState(true)
  const [submitting, setSubmitting] = useState(false)
  const [reason, setReason] = useState('')
  const [error, setError] = useState(null)
  const [lastAction, setLastAction] = useState(null)

  const fetchStatus = useCallback(async () => {
    try {
      const res = await fetch(deployment.postureUrl)
      if (!res.ok) throw new Error(`HTTP ${res.status}`)
      setStatus(await res.json())
      setError(null)
    } catch (e) {
      setError(e.message)
    } finally {
      setLoading(false)
    }
  }, [deployment.postureUrl])

  useEffect(() => {
    fetchStatus()
    const interval = setInterval(fetchStatus, 30_000)
    return () => clearInterval(interval)
  }, [fetchStatus])

  const override = async (posture) => {
    setSubmitting(true)
    setError(null)
    try {
      const res = await fetch(deployment.adminUrl, {
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

  const clearOverride = () => override(null)

  const effectivePosture = status?.posture ?? status?.effective_posture ?? null
  const source = status?.source ?? 'manifest'

  return (
    <div style={{
      background: SURFACE,
      border: `1px solid ${BORDER}`,
      borderRadius: 12,
      padding: '20px 24px',
      display: 'flex',
      flexDirection: 'column',
      gap: 16,
    }}>
      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 12, justifyContent: 'space-between' }}>
        <div>
          <div style={{ fontWeight: 600, fontSize: 15, color: TEXT }}>{deployment.name}</div>
          <div style={{ fontSize: 12, color: MUTED, marginTop: 2 }}>{deployment.domain}</div>
        </div>
        {loading
          ? <span style={{ fontSize: 12, color: MUTED }}>loading…</span>
          : error
            ? <span style={{ fontSize: 12, color: '#fca5a5' }}>{error}</span>
            : effectivePosture
              ? <span style={badge(effectivePosture)}>{effectivePosture}</span>
              : <span style={{ fontSize: 12, color: MUTED }}>no override</span>
        }
      </div>

      {/* Source */}
      {!loading && !error && (
        <div style={{ fontSize: 12, color: MUTED }}>
          source: <span style={{ color: source === 'operator' ? PURPLE : TEXT }}>{source}</span>
          {status?.updated_at && (
            <span style={{ marginLeft: 8 }}>
              · {new Date(status.updated_at).toLocaleString()}
            </span>
          )}
        </div>
      )}

      {/* Reason field */}
      <textarea
        value={reason}
        onChange={e => setReason(e.target.value)}
        placeholder="Reason for override (optional)"
        rows={2}
        style={{
          background: BG,
          border: `1px solid ${BORDER}`,
          borderRadius: 6,
          color: TEXT,
          fontSize: 13,
          padding: '8px 12px',
          resize: 'vertical',
          fontFamily: 'Inter, sans-serif',
          outline: 'none',
        }}
      />

      {/* Controls */}
      <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
        <button
          onClick={() => override('write_only')}
          disabled={submitting}
          style={btnStyle('#7f1d1d', '#fca5a5', submitting)}
        >
          Force write-only
        </button>
        <button
          onClick={() => override('recoverable')}
          disabled={submitting}
          style={btnStyle('#14532d', '#86efac', submitting)}
        >
          Force recoverable
        </button>
        <button
          onClick={clearOverride}
          disabled={submitting}
          style={btnStyle(BORDER, MUTED, submitting)}
        >
          Clear override
        </button>
      </div>

      {/* Last action */}
      {lastAction && (
        <div style={{ fontSize: 12, color: MUTED }}>
          Set to <strong style={{ color: TEXT }}>{lastAction.posture ?? 'cleared'}</strong>
          {' '}at {new Date(lastAction.at).toLocaleTimeString()}
        </div>
      )}
    </div>
  )
}

function btnStyle(bg, color, disabled) {
  return {
    background: disabled ? BORDER : bg,
    color: disabled ? MUTED : color,
    border: `1px solid ${bg}`,
    borderRadius: 6,
    padding: '6px 14px',
    fontSize: 13,
    fontWeight: 500,
    cursor: disabled ? 'not-allowed' : 'pointer',
    fontFamily: 'Inter, sans-serif',
    transition: 'opacity 0.15s',
  }
}

export default function PostureDash() {
  return (
    <div style={{
      minHeight: '100vh',
      background: BG,
      color: TEXT,
      fontFamily: 'Inter, sans-serif',
      padding: '40px 24px',
      maxWidth: 680,
      margin: '0 auto',
    }}>
      <div style={{ marginBottom: 32 }}>
        <div style={{ fontSize: 11, fontWeight: 600, letterSpacing: '0.12em', color: PURPLE, textTransform: 'uppercase', marginBottom: 8 }}>
          shyware
        </div>
        <h1 style={{ margin: 0, fontSize: 22, fontWeight: 600 }}>Posture Control</h1>
        <p style={{ margin: '8px 0 0', fontSize: 14, color: MUTED, lineHeight: 1.5 }}>
          Force write-only or recoverable posture across deployments.
          Overrides the manifest default and all user preferences.
          Clients pick up changes on next initialization.
        </p>
      </div>

      <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
        {deployments.map(d => (
          <DeploymentCard key={d.id} deployment={d} />
        ))}
      </div>

      <div style={{ marginTop: 40, fontSize: 12, color: MUTED, lineHeight: 1.6 }}>
        This page is gated by Cloudflare Access. The API endpoints it controls
        are publicly readable (<code style={{ color: TEXT }}>GET /api/v1/posture</code>)
        and operator-gated for writes
        (<code style={{ color: TEXT }}>POST /api/v1/posture/admin</code>).
      </div>
    </div>
  )
}
