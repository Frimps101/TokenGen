export type Algorithm = 'HS256' | 'HS384' | 'HS512'

const ALG_CONFIG: Record<
  Algorithm,
  { name: 'HMAC'; hash: 'SHA-256' | 'SHA-384' | 'SHA-512' }
> = {
  HS256: { name: 'HMAC', hash: 'SHA-256' },
  HS384: { name: 'HMAC', hash: 'SHA-384' },
  HS512: { name: 'HMAC', hash: 'SHA-512' },
}

function base64UrlEncode(data: ArrayBuffer | Uint8Array | string): string {
  const bytes =
    typeof data === 'string'
      ? new TextEncoder().encode(data)
      : data instanceof Uint8Array
        ? data
        : new Uint8Array(data)

  let binary = ''
  for (const byte of bytes) {
    binary += String.fromCharCode(byte)
  }

  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

async function importKey(secret: string, algorithm: Algorithm): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(secret),
    ALG_CONFIG[algorithm],
    false,
    ['sign'],
  )
}

export async function signJwt(
  payload: Record<string, unknown>,
  secret: string,
  algorithm: Algorithm,
): Promise<string> {
  const header = { alg: algorithm, typ: 'JWT' }
  const encodedHeader = base64UrlEncode(JSON.stringify(header))
  const encodedPayload = base64UrlEncode(JSON.stringify(payload))
  const signingInput = `${encodedHeader}.${encodedPayload}`

  const key = await importKey(secret, algorithm)
  const signature = await crypto.subtle.sign(
    ALG_CONFIG[algorithm],
    key,
    new TextEncoder().encode(signingInput),
  )

  return `${signingInput}.${base64UrlEncode(signature)}`
}

export function parseClaimValue(value: string): unknown {
  const trimmed = value.trim()
  if (trimmed === '') return ''

  if (trimmed === 'true') return true
  if (trimmed === 'false') return false
  if (trimmed === 'null') return null

  if (/^-?\d+(\.\d+)?$/.test(trimmed)) {
    const num = Number(trimmed)
    if (!Number.isNaN(num)) return num
  }

  if (
    (trimmed.startsWith('{') && trimmed.endsWith('}')) ||
    (trimmed.startsWith('[') && trimmed.endsWith(']'))
  ) {
    try {
      return JSON.parse(trimmed)
    } catch {
      return trimmed
    }
  }

  return trimmed
}

export function splitToken(token: string): [string, string, string] | null {
  const parts = token.split('.')
  if (parts.length !== 3) return null
  return [parts[0], parts[1], parts[2]]
}

export function decodePayload(token: string): Record<string, unknown> | null {
  const parts = splitToken(token)
  if (!parts) return null

  try {
    const padded = parts[1].replace(/-/g, '+').replace(/_/g, '/')
    const json = atob(padded.padEnd(padded.length + ((4 - (padded.length % 4)) % 4), '='))
    return JSON.parse(json) as Record<string, unknown>
  } catch {
    return null
  }
}
