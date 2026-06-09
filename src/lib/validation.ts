import type { Algorithm } from './jwt'

export type ExpDuration = '1h' | '6h' | '1d' | '7d' | '30d' | '90d' | 'custom'

export const EXP_DURATION_OPTIONS: { value: ExpDuration; label: string }[] = [
  { value: '1h', label: '1 hour' },
  { value: '6h', label: '6 hours' },
  { value: '1d', label: '1 day' },
  { value: '7d', label: '7 days' },
  { value: '30d', label: '30 days' },
  { value: '90d', label: '90 days' },
  { value: 'custom', label: 'Custom date & time' },
]

const DURATION_SECONDS: Record<Exclude<ExpDuration, 'custom'>, number> = {
  '1h': 3600,
  '6h': 6 * 3600,
  '1d': 24 * 3600,
  '7d': 7 * 24 * 3600,
  '30d': 30 * 24 * 3600,
  '90d': 90 * 24 * 3600,
}

export interface StandardClaims {
  iss: string
  aud: string
  expDuration: ExpDuration
  expCustom: string
  nbf: string
}

export interface CustomClaim {
  id: string
  key: string
  value: string
}

const RESERVED_CLAIMS = new Set(['iss', 'aud', 'exp', 'iat', 'nbf', 'alg', 'typ'])

export function datetimeToUnix(value: string): number | null {
  if (!value.trim()) return null
  const ms = new Date(value).getTime()
  if (Number.isNaN(ms)) return null
  return Math.floor(ms / 1000)
}

export function unixToDatetimeLocal(unix: number): string {
  const date = new Date(unix * 1000)
  const offset = date.getTimezoneOffset()
  const local = new Date(date.getTime() - offset * 60_000)
  return local.toISOString().slice(0, 16)
}

export function resolveExp(claims: StandardClaims, now = Math.floor(Date.now() / 1000)): number | null {
  if (claims.expDuration === 'custom') {
    return datetimeToUnix(claims.expCustom)
  }
  return now + DURATION_SECONDS[claims.expDuration]
}

export function formatReadableDate(unix: number): string {
  return new Intl.DateTimeFormat(undefined, {
    weekday: 'short',
    year: 'numeric',
    month: 'short',
    day: 'numeric',
    hour: 'numeric',
    minute: '2-digit',
  }).format(new Date(unix * 1000))
}

export function formatExpirySummary(unix: number, now = Math.floor(Date.now() / 1000)): string {
  const diff = unix - now
  if (diff <= 0) return 'already expired'

  const minutes = Math.round(diff / 60)
  const hours = Math.round(diff / 3600)
  const days = Math.round(diff / 86_400)

  if (minutes < 90) return `in ${minutes} minute${minutes === 1 ? '' : 's'}`
  if (hours < 48) return `in ${hours} hour${hours === 1 ? '' : 's'}`
  return `in ${days} day${days === 1 ? '' : 's'}`
}

export interface ValidationResult {
  valid: boolean
  errors: string[]
}

export function validateForm(
  secret: string,
  claims: StandardClaims,
  customClaims: CustomClaim[],
  algorithm: Algorithm,
): ValidationResult {
  const errors: string[] = []

  if (!secret.trim()) {
    errors.push('Secret key is required.')
  }

  if (!algorithm) {
    errors.push('Signing algorithm is required.')
  }

  const now = Math.floor(Date.now() / 1000)
  const exp = resolveExp(claims, now)
  const nbf = datetimeToUnix(claims.nbf)

  if (claims.expDuration === 'custom' && !claims.expCustom.trim()) {
    errors.push('Expiration (exp) is required.')
  }

  if (claims.expDuration === 'custom' && claims.expCustom.trim() && exp === null) {
    errors.push('Expiration (exp) is not a valid date.')
  }

  if (claims.nbf.trim() && nbf === null) {
    errors.push('Not before (nbf) is not a valid date.')
  }

  if (exp !== null && exp <= now) {
    errors.push('Expiration (exp) must be in the future.')
  }

  if (exp !== null && nbf !== null && nbf >= exp) {
    errors.push('Not before (nbf) must be before expiration (exp).')
  }

  const seenKeys = new Set<string>()

  for (const claim of customClaims) {
    const key = claim.key.trim()
    if (!key) {
      errors.push('Custom claim keys cannot be empty.')
      continue
    }

    if (RESERVED_CLAIMS.has(key)) {
      errors.push(`"${key}" is a reserved claim name.`)
    }

    if (seenKeys.has(key)) {
      errors.push(`Duplicate custom claim key: "${key}".`)
    }
    seenKeys.add(key)
  }

  return { valid: errors.length === 0, errors }
}

export function buildPayload(
  claims: StandardClaims,
  customClaims: CustomClaim[],
  parseValue: (value: string) => unknown,
): Record<string, unknown> {
  const payload: Record<string, unknown> = {}
  const now = Math.floor(Date.now() / 1000)

  if (claims.iss.trim()) payload.iss = claims.iss.trim()
  if (claims.aud.trim()) payload.aud = claims.aud.trim()

  payload.iat = now

  const exp = resolveExp(claims, now)
  const nbf = datetimeToUnix(claims.nbf)

  if (exp !== null) payload.exp = exp
  if (nbf !== null) payload.nbf = nbf

  for (const claim of customClaims) {
    const key = claim.key.trim()
    if (key) {
      payload[key] = parseValue(claim.value)
    }
  }

  return payload
}
