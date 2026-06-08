import type { Algorithm } from './jwt'

export interface StandardClaims {
  sub: string
  iss: string
  aud: string
  exp: string
  iat: string
  nbf: string
}

export interface CustomClaim {
  id: string
  key: string
  value: string
}

const RESERVED_CLAIMS = new Set(['sub', 'iss', 'aud', 'exp', 'iat', 'nbf', 'alg', 'typ'])

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

export function defaultIat(): string {
  return unixToDatetimeLocal(Math.floor(Date.now() / 1000))
}

export function defaultExp(): string {
  return unixToDatetimeLocal(Math.floor(Date.now() / 1000) + 3600)
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

  if (!claims.exp.trim()) {
    errors.push('Expiration (exp) is required.')
  }

  const exp = datetimeToUnix(claims.exp)
  const iat = datetimeToUnix(claims.iat)
  const nbf = datetimeToUnix(claims.nbf)

  if (claims.exp.trim() && exp === null) {
    errors.push('Expiration (exp) is not a valid date.')
  }

  if (claims.iat.trim() && iat === null) {
    errors.push('Issued at (iat) is not a valid date.')
  }

  if (claims.nbf.trim() && nbf === null) {
    errors.push('Not before (nbf) is not a valid date.')
  }

  if (exp !== null && iat !== null && exp <= iat) {
    errors.push('Expiration (exp) must be after issued at (iat).')
  }

  if (exp !== null && nbf !== null && nbf >= exp) {
    errors.push('Not before (nbf) must be before expiration (exp).')
  }

  if (exp !== null && exp < Math.floor(Date.now() / 1000)) {
    errors.push('Expiration (exp) is in the past.')
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

  if (claims.sub.trim()) payload.sub = claims.sub.trim()
  if (claims.iss.trim()) payload.iss = claims.iss.trim()
  if (claims.aud.trim()) payload.aud = claims.aud.trim()

  const exp = datetimeToUnix(claims.exp)
  const iat = datetimeToUnix(claims.iat)
  const nbf = datetimeToUnix(claims.nbf)

  if (exp !== null) payload.exp = exp
  if (iat !== null) payload.iat = iat
  if (nbf !== null) payload.nbf = nbf

  for (const claim of customClaims) {
    const key = claim.key.trim()
    if (key) {
      payload[key] = parseValue(claim.value)
    }
  }

  return payload
}
