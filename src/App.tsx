import { useCallback, useEffect, useMemo, useState } from 'react'
import {
  buildPayload,
  EXP_DURATION_OPTIONS,
  formatExpirySummary,
  formatReadableDate,
  resolveExp,
  validateForm,
  type CustomClaim,
  type ExpDuration,
  type StandardClaims,
} from './lib/validation'
import {
  decodePayload,
  parseClaimValue,
  signJwt,
  splitToken,
  type Algorithm,
} from './lib/jwt'

const ALGORITHMS: Algorithm[] = ['HS256', 'HS384', 'HS512']

const STANDARD_FIELDS: { key: 'iss' | 'aud'; label: string }[] = [
  { key: 'iss', label: 'Issuer (iss)' },
  { key: 'aud', label: 'Audience (aud)' },
]

const DEFAULT_CLAIMS: StandardClaims = {
  iss: '',
  aud: '',
  expDuration: '7d',
  expCustom: '',
  nbf: '',
}

function newClaimId() {
  return crypto.randomUUID()
}

const datetimeInputClassName =
  'field-datetime w-full rounded-lg border border-cursor-border-strong bg-cursor-elevated px-3 py-2.5 pr-10 text-cursor-text outline-none focus:border-orange-500 focus:ring-1 focus:ring-orange-500'

function DatetimeInput({
  id,
  value,
  onChange,
  className = '',
}: {
  id: string
  value: string
  onChange: (value: string) => void
  className?: string
}) {
  return (
    <div className={`field-datetime-wrap relative ${className}`}>
      <input
        id={id}
        type="datetime-local"
        value={value}
        onChange={(e) => onChange(e.target.value)}
        className={datetimeInputClassName}
      />
      <svg
        className="field-datetime-icon pointer-events-none absolute top-1/2 right-3 h-4 w-4 -translate-y-1/2 text-cursor-text"
        viewBox="0 0 24 24"
        fill="none"
        stroke="currentColor"
        strokeWidth="2"
        strokeLinecap="round"
        strokeLinejoin="round"
        aria-hidden="true"
      >
        <path d="M8 2v4M16 2v4M3 10h18M5 4h14a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2z" />
      </svg>
    </div>
  )
}

function CopyIconButton({
  copied,
  onClick,
  label,
}: {
  copied: boolean
  onClick: () => void
  label: string
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      aria-label={copied ? 'Copied' : label}
      title={copied ? 'Copied!' : label}
      className="rounded-lg border border-cursor-border-strong p-2 text-cursor-text hover:border-orange-500 hover:text-cursor-text"
    >
      {copied ? (
        <svg
          className="h-4 w-4"
          viewBox="0 0 24 24"
          fill="none"
          stroke="currentColor"
          strokeWidth="2"
          strokeLinecap="round"
          strokeLinejoin="round"
          aria-hidden="true"
        >
          <path d="M20 6 9 17l-5-5" />
        </svg>
      ) : (
        <svg
          className="h-4 w-4"
          viewBox="0 0 24 24"
          fill="none"
          stroke="currentColor"
          strokeWidth="2"
          strokeLinecap="round"
          strokeLinejoin="round"
          aria-hidden="true"
        >
          <rect x="9" y="9" width="13" height="13" rx="2" ry="2" />
          <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1" />
        </svg>
      )}
    </button>
  )
}

function App() {
  const [claims, setClaims] = useState<StandardClaims>(DEFAULT_CLAIMS)
  const [customClaims, setCustomClaims] = useState<CustomClaim[]>([])
  const [algorithm, setAlgorithm] = useState<Algorithm>('HS256')
  const [secret, setSecret] = useState('')
  const [showSecret, setShowSecret] = useState(false)
  const [token, setToken] = useState('')
  const [errors, setErrors] = useState<string[]>([])
  const [copied, setCopied] = useState(false)
  const [payloadCopied, setPayloadCopied] = useState(false)
  const [claimsJsonCopied, setClaimsJsonCopied] = useState(false)
  const [generating, setGenerating] = useState(false)
  const [currentIat, setCurrentIat] = useState(() => Math.floor(Date.now() / 1000))
  const [customClaimsOpen, setCustomClaimsOpen] = useState(false)
  const [customClaimsView, setCustomClaimsView] = useState<'list' | 'json'>('list')

  const customClaimsJson = useMemo(() => {
    const obj: Record<string, unknown> = {}
    for (const claim of customClaims) {
      const key = claim.key.trim()
      if (key) obj[key] = parseClaimValue(claim.value)
    }
    return obj
  }, [customClaims])

  const customClaimsJsonText = useMemo(
    () => JSON.stringify(customClaimsJson, null, 2),
    [customClaimsJson],
  )

  useEffect(() => {
    const tick = () => setCurrentIat(Math.floor(Date.now() / 1000))
    tick()
    const id = setInterval(tick, 30_000)
    return () => clearInterval(id)
  }, [])

  useEffect(() => {
    if (!customClaimsOpen) return

    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') setCustomClaimsOpen(false)
    }

    document.addEventListener('keydown', onKeyDown)
    return () => document.removeEventListener('keydown', onKeyDown)
  }, [customClaimsOpen])

  const updateClaim = (key: keyof StandardClaims, value: string) => {
    setClaims((prev) => ({ ...prev, [key]: value }))
  }

  const addCustomClaim = () => {
    setCustomClaims((prev) => [...prev, { id: newClaimId(), key: '', value: '' }])
  }

  const updateCustomClaim = (id: string, field: 'key' | 'value', value: string) => {
    setCustomClaims((prev) =>
      prev.map((c) => (c.id === id ? { ...c, [field]: value } : c)),
    )
  }

  const removeCustomClaim = (id: string) => {
    setCustomClaims((prev) => prev.filter((c) => c.id !== id))
  }

  const handleGenerate = useCallback(async () => {
    const result = validateForm(secret, claims, customClaims, algorithm)
    setErrors(result.errors)

    if (!result.valid) {
      setToken('')
      return
    }

    setGenerating(true)
    try {
      const payload = buildPayload(claims, customClaims, parseClaimValue)
      const signed = await signJwt(payload, secret, algorithm)
      setToken(signed)
      const stampedIat = decodePayload(signed)?.iat
      if (typeof stampedIat === 'number') setCurrentIat(stampedIat)
    } catch {
      setErrors(['Failed to sign token. Check your secret key and try again.'])
      setToken('')
    } finally {
      setGenerating(false)
    }
  }, [secret, claims, customClaims, algorithm])

  const handleCopy = async () => {
    if (!token) return
    try {
      await navigator.clipboard.writeText(token)
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
    } catch {
      setErrors(['Could not copy to clipboard.'])
    }
  }

  const handleCopyClaimsJson = async () => {
    try {
      await navigator.clipboard.writeText(customClaimsJsonText)
      setClaimsJsonCopied(true)
      setTimeout(() => setClaimsJsonCopied(false), 2000)
    } catch {
      setErrors(['Could not copy to clipboard.'])
    }
  }

  const handleCopyPayload = async () => {
    if (!decoded) return
    try {
      await navigator.clipboard.writeText(JSON.stringify(decoded, null, 2))
      setPayloadCopied(true)
      setTimeout(() => setPayloadCopied(false), 2000)
    } catch {
      setErrors(['Could not copy to clipboard.'])
    }
  }

  const handleReset = () => {
    const hasData =
      secret ||
      token ||
      customClaims.length > 0 ||
      claims.iss ||
      claims.aud ||
      claims.nbf ||
      claims.expDuration !== '7d' ||
      claims.expCustom

    if (hasData && !window.confirm('Reset all fields and clear the generated token?')) {
      return
    }

    setClaims(DEFAULT_CLAIMS)
    setCustomClaims([])
    setAlgorithm('HS256')
    setSecret('')
    setShowSecret(false)
    setToken('')
    setErrors([])
    setCopied(false)
    setPayloadCopied(false)
    setClaimsJsonCopied(false)
    setCurrentIat(Math.floor(Date.now() / 1000))
    setCustomClaimsOpen(false)
    setCustomClaimsView('list')
  }

  const tokenParts = token ? splitToken(token) : null
  const decoded = token ? decodePayload(token) : null
  const resolvedExp = resolveExp(claims)

  const generateButton = (
    <button
      type="button"
      onClick={handleGenerate}
      disabled={generating}
      className="w-full rounded-xl bg-orange-600 px-6 py-3 text-base font-semibold text-cursor-text shadow-lg shadow-orange-600/25 transition hover:bg-orange-500 disabled:cursor-not-allowed disabled:opacity-60 sm:w-auto sm:min-w-48"
    >
      {generating ? 'Signing…' : 'Generate token'}
    </button>
  )

  return (
    <div className="min-h-svh bg-cursor-bg">
      <header className="border-b border-cursor-divider px-4 py-5 text-center sm:px-6">
        <h1 className="text-xl font-bold tracking-tight text-cursor-text sm:text-2xl">
          JWT Token Generator
        </h1>
        <p className="mt-1 text-xs text-cursor-muted sm:text-sm">
          Fill in your claims, sign with a secret, copy the token
        </p>
      </header>

      <main>
        <div className="mx-auto grid w-full max-w-6xl items-start gap-6 px-4 py-6 sm:px-6 lg:grid-cols-2 lg:px-8">
          <section className="space-y-5 lg:pr-2">
            <div className="rounded-xl border border-cursor-border bg-cursor-surface p-5 sm:p-6">
              <h2 className="mb-4 text-lg font-semibold text-cursor-text">Signing</h2>
              <div className="grid gap-4 sm:grid-cols-[10rem_1fr]">
                <div>
                  <label htmlFor="algorithm" className="mb-1.5 block text-sm font-medium text-cursor-text">
                    Algorithm
                  </label>
                  <select
                    id="algorithm"
                    value={algorithm}
                    onChange={(e) => setAlgorithm(e.target.value as Algorithm)}
                    className="field-select w-full rounded-lg border border-cursor-border-strong bg-cursor-elevated px-3 py-2.5 text-cursor-text outline-none focus:border-orange-500 focus:ring-1 focus:ring-orange-500"
                  >
                    {ALGORITHMS.map((alg) => (
                      <option key={alg} value={alg}>
                        {alg}
                      </option>
                    ))}
                  </select>
                </div>

                <div>
                  <label htmlFor="secret" className="mb-1.5 block text-sm font-medium text-cursor-text">
                    Secret key <span className="text-cursor-error">*</span>
                  </label>
                  <div className="relative">
                    <input
                      id="secret"
                      type={showSecret ? 'text' : 'password'}
                      value={secret}
                      onChange={(e) => setSecret(e.target.value)}
                      placeholder="Enter your HMAC secret"
                      className="w-full rounded-lg border border-cursor-border-strong bg-cursor-elevated px-3 py-2.5 pr-20 font-mono text-sm text-cursor-text outline-none focus:border-orange-500 focus:ring-1 focus:ring-orange-500"
                    />
                    <button
                      type="button"
                      onClick={() => setShowSecret((s) => !s)}
                      className="absolute right-2 top-1/2 -translate-y-1/2 rounded-md px-2 py-1 text-xs text-cursor-muted hover:bg-cursor-elevated hover:text-cursor-text"
                    >
                      {showSecret ? 'Hide' : 'Show'}
                    </button>
                  </div>
                </div>
              </div>
            </div>

            <div className="rounded-xl border border-cursor-border bg-cursor-surface p-5 sm:p-6">
              <h2 className="mb-4 text-lg font-semibold text-cursor-text">Standard claims</h2>
              <div className="grid gap-4 sm:grid-cols-2">
                {STANDARD_FIELDS.map(({ key, label }) => (
                  <div key={key}>
                    <label htmlFor={key} className="mb-1.5 block text-sm font-medium text-cursor-text">
                      {label}
                    </label>
                    <input
                      id={key}
                      type="text"
                      value={claims[key]}
                      onChange={(e) => updateClaim(key, e.target.value)}
                      placeholder={`Enter ${key}`}
                      className="w-full rounded-lg border border-cursor-border-strong bg-cursor-elevated px-3 py-2.5 text-cursor-text outline-none focus:border-orange-500 focus:ring-1 focus:ring-orange-500"
                    />
                  </div>
                ))}

                <div className="sm:col-span-2">
                  <label htmlFor="iat" className="mb-1.5 block text-sm font-medium text-cursor-text">
                    Issued at (iat)
                  </label>
                  <input
                    id="iat"
                    readOnly
                    value={formatReadableDate(currentIat)}
                    className="w-full cursor-default rounded-lg border border-cursor-border bg-cursor-bg px-3 py-2.5 text-cursor-text outline-none"
                  />
                </div>

                <div className="sm:col-span-2">
                  <label htmlFor="expDuration" className="mb-1.5 block text-sm font-medium text-cursor-text">
                    Expiration (exp) <span className="text-cursor-error">*</span>
                  </label>
                  <select
                    id="expDuration"
                    value={claims.expDuration}
                    onChange={(e) =>
                      setClaims((prev) => ({ ...prev, expDuration: e.target.value as ExpDuration }))
                    }
                    className="field-select w-full rounded-lg border border-cursor-border-strong bg-cursor-elevated px-3 py-2.5 text-cursor-text outline-none focus:border-orange-500 focus:ring-1 focus:ring-orange-500"
                  >
                    {EXP_DURATION_OPTIONS.map((option) => (
                      <option key={option.value} value={option.value}>
                        {option.label}
                      </option>
                    ))}
                  </select>
                  {claims.expDuration === 'custom' && (
                    <DatetimeInput
                      id="expCustom"
                      className="mt-3"
                      value={claims.expCustom}
                      onChange={(value) =>
                        setClaims((prev) => ({ ...prev, expCustom: value }))
                      }
                    />
                  )}
                  {resolvedExp !== null && (
                    <p className="mt-2 text-sm text-orange-300/90">
                      Expires {formatReadableDate(resolvedExp)} ({formatExpirySummary(resolvedExp)})
                    </p>
                  )}
                </div>

                <div className="sm:col-span-2">
                  <label htmlFor="nbf" className="mb-1.5 block text-sm font-medium text-cursor-text">
                    Not before (nbf)
                  </label>
                  <DatetimeInput
                    id="nbf"
                    value={claims.nbf}
                    onChange={(value) => updateClaim('nbf', value)}
                  />
                </div>
              </div>
            </div>

            <div className="rounded-xl border border-cursor-border bg-cursor-surface p-5 sm:p-6">
              <div className="mb-4 flex items-center justify-between">
                <h2 className="text-lg font-semibold text-cursor-text">Custom claims</h2>
                <div className="flex items-center gap-2">
                  {customClaims.length > 0 && customClaimsView === 'json' && (
                    <CopyIconButton
                      copied={claimsJsonCopied}
                      onClick={handleCopyClaimsJson}
                      label="Copy JSON"
                    />
                  )}
                  <button
                    type="button"
                    onClick={() => setCustomClaimsOpen(true)}
                    className="rounded-lg border border-cursor-border-strong px-3 py-1.5 text-sm text-orange-400 hover:border-orange-500 hover:text-cursor-text"
                  >
                    {customClaims.length === 0 ? '+ Add' : 'Edit'}
                  </button>
                </div>
              </div>

              {customClaims.length === 0 ? (
                <p className="text-sm text-cursor-subtle">
                  No custom claims yet. Add key-value pairs like userId, role, staffId…
                </p>
              ) : (
                <>
                  <div className="mb-4 flex gap-1 rounded-lg border border-cursor-border bg-cursor-bg/60 p-1">
                    <button
                      type="button"
                      onClick={() => setCustomClaimsView('list')}
                      className={`flex-1 rounded-md px-3 py-1.5 text-sm font-medium transition ${
                        customClaimsView === 'list'
                          ? 'bg-cursor-elevated text-cursor-text'
                          : 'text-cursor-muted hover:text-cursor-text'
                      }`}
                    >
                      List
                    </button>
                    <button
                      type="button"
                      onClick={() => setCustomClaimsView('json')}
                      className={`flex-1 rounded-md px-3 py-1.5 text-sm font-medium transition ${
                        customClaimsView === 'json'
                          ? 'bg-cursor-elevated text-cursor-text'
                          : 'text-cursor-muted hover:text-cursor-text'
                      }`}
                    >
                      JSON
                    </button>
                  </div>

                  {customClaimsView === 'list' ? (
                    <ul className="space-y-2">
                      {customClaims.map((claim) => (
                        <li
                          key={claim.id}
                          className="flex items-baseline gap-2 rounded-lg bg-cursor-bg/60 px-3 py-2 font-mono text-sm"
                        >
                          <span className="shrink-0 text-orange-400">
                            {claim.key.trim() || '(empty key)'}
                          </span>
                          <span className="text-cursor-subtle">:</span>
                          <span className="min-w-0 truncate text-cursor-text">
                            {claim.value.trim() || '(empty)'}
                          </span>
                        </li>
                      ))}
                    </ul>
                  ) : (
                    <pre className="overflow-x-auto rounded-lg bg-cursor-bg p-4 font-mono text-sm leading-relaxed text-emerald-300">
                      {customClaimsJsonText}
                    </pre>
                  )}
                </>
              )}
            </div>

          </section>

          <section className="space-y-5 lg:pl-2">
            <div className="rounded-xl border border-cursor-border bg-cursor-surface p-5 sm:p-6">
              <div className="mb-4 flex items-center justify-between">
                <h2 className="text-lg font-semibold text-cursor-text">Generated token</h2>
                {token && (
                  <CopyIconButton copied={copied} onClick={handleCopy} label="Copy token" />
                )}
              </div>

              {tokenParts ? (
                <div className="overflow-x-auto rounded-lg bg-cursor-bg p-4 font-mono text-sm leading-relaxed break-all">
                  <span className="text-rose-400">{tokenParts[0]}</span>
                  <span className="text-cursor-subtle">.</span>
                  <span className="text-orange-400">{tokenParts[1]}</span>
                  <span className="text-cursor-subtle">.</span>
                  <span className="text-amber-400">{tokenParts[2]}</span>
                </div>
              ) : (
                <div className="rounded-lg border border-dashed border-cursor-border bg-cursor-bg/50 p-8 text-center text-sm text-cursor-subtle">
                  Your signed JWT will appear here
                </div>
              )}

              {tokenParts && (
                <div className="mt-3 flex flex-wrap gap-3 text-xs text-cursor-muted">
                  <span className="flex items-center gap-1.5">
                    <span className="h-2.5 w-2.5 rounded-full bg-rose-400" />
                    Header
                  </span>
                  <span className="flex items-center gap-1.5">
                    <span className="h-2.5 w-2.5 rounded-full bg-orange-400" />
                    Payload
                  </span>
                  <span className="flex items-center gap-1.5">
                    <span className="h-2.5 w-2.5 rounded-full bg-amber-400" />
                    Signature
                  </span>
                </div>
              )}
            </div>

            <div className="rounded-xl border border-cursor-border bg-cursor-surface p-5 sm:p-6">
              <div className="mb-4 flex items-center justify-between">
                <h2 className="text-lg font-semibold text-cursor-text">Decoded payload</h2>
                {decoded && (
                  <CopyIconButton
                    copied={payloadCopied}
                    onClick={handleCopyPayload}
                    label="Copy payload"
                  />
                )}
              </div>
              {decoded ? (
                <pre className="overflow-x-auto rounded-lg bg-cursor-bg p-4 font-mono text-sm leading-relaxed text-emerald-300">
                  {JSON.stringify(decoded, null, 2)}
                </pre>
              ) : (
                <div className="rounded-lg border border-dashed border-cursor-border bg-cursor-bg/50 p-8 text-center text-sm text-cursor-subtle">
                  Decoded JSON will appear here
                </div>
              )}
            </div>

          </section>
        </div>
      </main>

      {/* In-flow spacer so fixed buttons never cover scrollable content */}
      <div className="h-24 shrink-0" aria-hidden="true" />

      <div className="pointer-events-none fixed inset-x-0 bottom-0 z-10">
        <div className="pointer-events-auto mx-auto flex max-w-6xl flex-col gap-3 bg-cursor-bg px-4 py-4 sm:flex-row sm:items-center sm:px-6 lg:px-8">
          {errors.length > 0 && (
            <p className="min-w-0 flex-1 truncate text-sm text-cursor-error">
              {errors.join(' · ')}
            </p>
          )}
          <div className={`flex gap-3 ${errors.length > 0 ? '' : 'sm:ml-auto'}`}>
            <button
              type="button"
              onClick={handleReset}
              className="rounded-xl border border-cursor-border-strong px-5 py-3 text-sm font-medium text-cursor-text transition hover:border-cursor-muted hover:text-cursor-text"
            >
              Reset
            </button>
            {generateButton}
          </div>
        </div>
      </div>

      {customClaimsOpen && (
        <div
          className="fixed inset-0 z-[60] flex items-end justify-center bg-black/60 p-4 sm:items-center"
          onClick={() => setCustomClaimsOpen(false)}
          role="presentation"
        >
          <div
            className="flex max-h-[85vh] w-full max-w-lg flex-col rounded-xl border border-cursor-border bg-cursor-surface shadow-2xl"
            onClick={(e) => e.stopPropagation()}
            role="dialog"
            aria-modal="true"
            aria-labelledby="custom-claims-title"
          >
            <div className="flex items-center justify-between border-b border-cursor-border px-5 py-4">
              <h2 id="custom-claims-title" className="text-lg font-semibold text-cursor-text">
                Custom claims
              </h2>
              <button
                type="button"
                onClick={() => setCustomClaimsOpen(false)}
                className="rounded-lg px-2 py-1 text-cursor-muted hover:bg-cursor-elevated hover:text-cursor-text"
                aria-label="Close"
              >
                ✕
              </button>
            </div>

            <div className="flex-1 overflow-y-auto px-5 py-4">
              {customClaims.length === 0 ? (
                <p className="text-sm text-cursor-subtle">No custom claims yet. Add one below.</p>
              ) : (
                <div className="space-y-3">
                  {customClaims.map((claim) => (
                    <div key={claim.id} className="flex gap-2">
                      <input
                        type="text"
                        value={claim.key}
                        onChange={(e) => updateCustomClaim(claim.id, 'key', e.target.value)}
                        placeholder="Key"
                        className="w-1/3 rounded-lg border border-cursor-border-strong bg-cursor-elevated px-3 py-2 font-mono text-sm text-cursor-text outline-none focus:border-orange-500"
                      />
                      <input
                        type="text"
                        value={claim.value}
                        onChange={(e) => updateCustomClaim(claim.id, 'value', e.target.value)}
                        placeholder="Value"
                        className="flex-1 rounded-lg border border-cursor-border-strong bg-cursor-elevated px-3 py-2 font-mono text-sm text-cursor-text outline-none focus:border-orange-500"
                      />
                      <button
                        type="button"
                        onClick={() => removeCustomClaim(claim.id)}
                        className="rounded-lg px-3 py-2 text-cursor-muted hover:bg-rose-500/20 hover:text-rose-400"
                        aria-label="Remove claim"
                      >
                        ✕
                      </button>
                    </div>
                  ))}
                </div>
              )}
            </div>

            <div className="flex gap-3 border-t border-cursor-border px-5 py-4">
              <button
                type="button"
                onClick={addCustomClaim}
                className="rounded-lg border border-cursor-border-strong px-4 py-2 text-sm text-cursor-text hover:border-orange-500 hover:text-cursor-text"
              >
                + Add claim
              </button>
              <button
                type="button"
                onClick={() => setCustomClaimsOpen(false)}
                className="ml-auto rounded-lg bg-orange-600 px-4 py-2 text-sm font-medium text-cursor-text hover:bg-orange-500"
              >
                Done
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

export default App
