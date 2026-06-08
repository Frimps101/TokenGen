import { useCallback, useState } from 'react'
import {
  buildPayload,
  defaultExp,
  defaultIat,
  validateForm,
  type CustomClaim,
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

const STANDARD_FIELDS: { key: keyof StandardClaims; label: string; required?: boolean }[] = [
  { key: 'sub', label: 'Subject (sub)' },
  { key: 'iss', label: 'Issuer (iss)' },
  { key: 'aud', label: 'Audience (aud)' },
  { key: 'iat', label: 'Issued at (iat)' },
  { key: 'exp', label: 'Expiration (exp)', required: true },
  { key: 'nbf', label: 'Not before (nbf)' },
]

function newClaimId() {
  return crypto.randomUUID()
}

function App() {
  const [claims, setClaims] = useState<StandardClaims>({
    sub: '',
    iss: '',
    aud: '',
    exp: defaultExp(),
    iat: defaultIat(),
    nbf: '',
  })
  const [customClaims, setCustomClaims] = useState<CustomClaim[]>([])
  const [algorithm, setAlgorithm] = useState<Algorithm>('HS256')
  const [secret, setSecret] = useState('')
  const [showSecret, setShowSecret] = useState(false)
  const [token, setToken] = useState('')
  const [errors, setErrors] = useState<string[]>([])
  const [copied, setCopied] = useState(false)
  const [generating, setGenerating] = useState(false)

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

  const tokenParts = token ? splitToken(token) : null
  const decoded = token ? decodePayload(token) : null

  return (
    <div className="min-h-svh bg-gradient-to-b from-slate-950 via-slate-900 to-slate-950">
      <div className="mx-auto max-w-6xl px-4 py-8 sm:px-6 lg:px-8">
        <header className="mb-8 text-center">
          <div className="mb-3 inline-flex items-center gap-2 rounded-full border border-emerald-500/30 bg-emerald-500/10 px-4 py-1.5 text-sm text-emerald-300">
            <span className="h-2 w-2 rounded-full bg-emerald-400" />
            100% client-side — your secret never leaves this device
          </div>
          <h1 className="text-3xl font-bold tracking-tight text-white sm:text-4xl">
            JWT Token Generator
          </h1>
          <p className="mt-2 text-slate-400">
            Build and sign JSON Web Tokens locally using the Web Crypto API
          </p>
        </header>

        <div className="grid gap-6 lg:grid-cols-2">
          <section className="space-y-6">
            <div className="rounded-xl border border-slate-700/60 bg-slate-900/60 p-5 backdrop-blur sm:p-6">
              <h2 className="mb-4 text-lg font-semibold text-white">Signing</h2>
              <div className="space-y-4">
                <div>
                  <label htmlFor="algorithm" className="mb-1.5 block text-sm font-medium text-slate-300">
                    Algorithm
                  </label>
                  <select
                    id="algorithm"
                    value={algorithm}
                    onChange={(e) => setAlgorithm(e.target.value as Algorithm)}
                    className="w-full rounded-lg border border-slate-600 bg-slate-800 px-3 py-2.5 text-white outline-none focus:border-violet-500 focus:ring-1 focus:ring-violet-500"
                  >
                    {ALGORITHMS.map((alg) => (
                      <option key={alg} value={alg}>
                        {alg}
                      </option>
                    ))}
                  </select>
                </div>

                <div>
                  <label htmlFor="secret" className="mb-1.5 block text-sm font-medium text-slate-300">
                    Secret key <span className="text-rose-400">*</span>
                  </label>
                  <div className="relative">
                    <input
                      id="secret"
                      type={showSecret ? 'text' : 'password'}
                      value={secret}
                      onChange={(e) => setSecret(e.target.value)}
                      placeholder="Enter your HMAC secret"
                      className="w-full rounded-lg border border-slate-600 bg-slate-800 px-3 py-2.5 pr-20 font-mono text-sm text-white outline-none focus:border-violet-500 focus:ring-1 focus:ring-violet-500"
                    />
                    <button
                      type="button"
                      onClick={() => setShowSecret((s) => !s)}
                      className="absolute right-2 top-1/2 -translate-y-1/2 rounded-md px-2 py-1 text-xs text-slate-400 hover:bg-slate-700 hover:text-white"
                    >
                      {showSecret ? 'Hide' : 'Show'}
                    </button>
                  </div>
                </div>
              </div>
            </div>

            <div className="rounded-xl border border-slate-700/60 bg-slate-900/60 p-5 backdrop-blur sm:p-6">
              <h2 className="mb-4 text-lg font-semibold text-white">Standard claims</h2>
              <div className="grid gap-4 sm:grid-cols-2">
                {STANDARD_FIELDS.map(({ key, label, required }) => (
                  <div key={key} className={key === 'exp' || key === 'iat' || key === 'nbf' ? 'sm:col-span-2' : ''}>
                    <label htmlFor={key} className="mb-1.5 block text-sm font-medium text-slate-300">
                      {label}
                      {required && <span className="text-rose-400"> *</span>}
                    </label>
                    {key === 'exp' || key === 'iat' || key === 'nbf' ? (
                      <input
                        id={key}
                        type="datetime-local"
                        value={claims[key]}
                        onChange={(e) => updateClaim(key, e.target.value)}
                        className="w-full rounded-lg border border-slate-600 bg-slate-800 px-3 py-2.5 text-white outline-none focus:border-violet-500 focus:ring-1 focus:ring-violet-500"
                      />
                    ) : (
                      <input
                        id={key}
                        type="text"
                        value={claims[key]}
                        onChange={(e) => updateClaim(key, e.target.value)}
                        placeholder={`Enter ${key}`}
                        className="w-full rounded-lg border border-slate-600 bg-slate-800 px-3 py-2.5 text-white outline-none focus:border-violet-500 focus:ring-1 focus:ring-violet-500"
                      />
                    )}
                  </div>
                ))}
              </div>
            </div>

            <div className="rounded-xl border border-slate-700/60 bg-slate-900/60 p-5 backdrop-blur sm:p-6">
              <div className="mb-4 flex items-center justify-between">
                <h2 className="text-lg font-semibold text-white">Custom claims</h2>
                <button
                  type="button"
                  onClick={addCustomClaim}
                  className="rounded-lg border border-slate-600 px-3 py-1.5 text-sm text-slate-300 hover:border-violet-500 hover:text-white"
                >
                  + Add claim
                </button>
              </div>

              {customClaims.length === 0 ? (
                <p className="text-sm text-slate-500">No custom claims yet.</p>
              ) : (
                <div className="space-y-3">
                  {customClaims.map((claim) => (
                    <div key={claim.id} className="flex gap-2">
                      <input
                        type="text"
                        value={claim.key}
                        onChange={(e) => updateCustomClaim(claim.id, 'key', e.target.value)}
                        placeholder="Key"
                        className="w-1/3 rounded-lg border border-slate-600 bg-slate-800 px-3 py-2 font-mono text-sm text-white outline-none focus:border-violet-500"
                      />
                      <input
                        type="text"
                        value={claim.value}
                        onChange={(e) => updateCustomClaim(claim.id, 'value', e.target.value)}
                        placeholder="Value"
                        className="flex-1 rounded-lg border border-slate-600 bg-slate-800 px-3 py-2 font-mono text-sm text-white outline-none focus:border-violet-500"
                      />
                      <button
                        type="button"
                        onClick={() => removeCustomClaim(claim.id)}
                        className="rounded-lg px-3 py-2 text-slate-400 hover:bg-rose-500/20 hover:text-rose-400"
                        aria-label="Remove claim"
                      >
                        ✕
                      </button>
                    </div>
                  ))}
                </div>
              )}
            </div>

            {errors.length > 0 && (
              <div className="rounded-xl border border-rose-500/40 bg-rose-500/10 p-4">
                <ul className="space-y-1 text-sm text-rose-300">
                  {errors.map((err) => (
                    <li key={err}>• {err}</li>
                  ))}
                </ul>
              </div>
            )}

            <button
              type="button"
              onClick={handleGenerate}
              disabled={generating}
              className="w-full rounded-xl bg-violet-600 px-6 py-3.5 text-base font-semibold text-white shadow-lg shadow-violet-600/25 transition hover:bg-violet-500 disabled:cursor-not-allowed disabled:opacity-60"
            >
              {generating ? 'Signing…' : 'Generate token'}
            </button>
          </section>

          <section className="space-y-6">
            <div className="rounded-xl border border-slate-700/60 bg-slate-900/60 p-5 backdrop-blur sm:p-6">
              <div className="mb-4 flex items-center justify-between">
                <h2 className="text-lg font-semibold text-white">Generated token</h2>
                {token && (
                  <button
                    type="button"
                    onClick={handleCopy}
                    className="rounded-lg border border-slate-600 px-3 py-1.5 text-sm text-slate-300 hover:border-violet-500 hover:text-white"
                  >
                    {copied ? 'Copied!' : 'Copy'}
                  </button>
                )}
              </div>

              {tokenParts ? (
                <div className="overflow-x-auto rounded-lg bg-slate-950 p-4 font-mono text-sm leading-relaxed break-all">
                  <span className="text-rose-400">{tokenParts[0]}</span>
                  <span className="text-slate-500">.</span>
                  <span className="text-violet-400">{tokenParts[1]}</span>
                  <span className="text-slate-500">.</span>
                  <span className="text-amber-400">{tokenParts[2]}</span>
                </div>
              ) : (
                <div className="rounded-lg border border-dashed border-slate-700 bg-slate-950/50 p-8 text-center text-sm text-slate-500">
                  Your signed JWT will appear here
                </div>
              )}

              {tokenParts && (
                <div className="mt-3 flex flex-wrap gap-3 text-xs text-slate-400">
                  <span className="flex items-center gap-1.5">
                    <span className="h-2.5 w-2.5 rounded-full bg-rose-400" />
                    Header
                  </span>
                  <span className="flex items-center gap-1.5">
                    <span className="h-2.5 w-2.5 rounded-full bg-violet-400" />
                    Payload
                  </span>
                  <span className="flex items-center gap-1.5">
                    <span className="h-2.5 w-2.5 rounded-full bg-amber-400" />
                    Signature
                  </span>
                </div>
              )}
            </div>

            <div className="rounded-xl border border-slate-700/60 bg-slate-900/60 p-5 backdrop-blur sm:p-6">
              <h2 className="mb-4 text-lg font-semibold text-white">Decoded payload</h2>
              {decoded ? (
                <pre className="overflow-x-auto rounded-lg bg-slate-950 p-4 font-mono text-sm leading-relaxed text-emerald-300">
                  {JSON.stringify(decoded, null, 2)}
                </pre>
              ) : (
                <div className="rounded-lg border border-dashed border-slate-700 bg-slate-950/50 p-8 text-center text-sm text-slate-500">
                  Decoded JSON will appear here
                </div>
              )}
            </div>

            <div className="rounded-xl border border-slate-700/40 bg-slate-800/30 p-4 text-sm text-slate-400">
              <p>
                <strong className="text-slate-300">Privacy:</strong> All signing happens in your
                browser via the Web Crypto API. No data is sent to any server. Close this tab and
                everything is gone.
              </p>
            </div>
          </section>
        </div>
      </div>
    </div>
  )
}

export default App
