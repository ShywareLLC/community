export const PURPLE       = '#A78BFA'
export const PURPLE_DARK  = '#7C3AED'
export const BG           = '#09090B'
export const SURFACE      = '#18181B'
export const BORDER       = '#27272A'
export const TEXT         = '#FAFAFA'
export const MUTED        = '#71717A'
export const GREEN        = '#86efac'
export const GREEN_BG     = '#052e16'
export const GREEN_BORDER = '#14532d'
export const RED          = '#fca5a5'
export const RED_BG       = '#450a0a'
export const RED_BORDER   = '#7f1d1d'
export const YELLOW       = '#fde68a'
export const YELLOW_BG    = '#422006'
export const YELLOW_BORDER = '#92400e'

export function postureBadge(posture) {
  if (posture === 'write_only' || posture === 'coercion_resistant') {
    return { bg: RED_BG, color: RED, border: RED_BORDER, label: 'write-only' }
  }
  if (posture === 'recoverable') {
    return { bg: GREEN_BG, color: GREEN, border: GREEN_BORDER, label: 'recoverable' }
  }
  return { bg: SURFACE, color: MUTED, border: BORDER, label: posture ?? 'unknown' }
}

export const btn = (bg, color, disabled) => ({
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
})
