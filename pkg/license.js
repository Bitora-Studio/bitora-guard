// The licence of @bitora/guard. The package works only for a site of a Bitora Security subscriber: it asks Bitora for a licence with the
// API key of the site, checks its signature here (Ed25519, the public key is below) and keeps working until it expires, renewing it in
// the background every few hours. Without an active subscription, a key, or a licence that verifies, the package does nothing: every call
// lets the traffic through and nothing is reported, so it can never take a site down.
//
// The licence is bound to the API key it was issued for (a hash of the key, never the key), lasts seven days, and travels in the clear:
// it is a signed statement, not a secret. If Bitora cannot be reached the last good licence keeps working until it expires.

// Verifies licences issued by Bitora Security.
export const LICENSE_PUBLIC_KEY = 'ZRVGbHOMbj6koUtmNsD4ha0kc1qXGX4nvasCkhdM/eY='

const b64 = (s) => {
  const t = String(s).replace(/-/g, '+').replace(/_/g, '/')
  const bin = atob(t + '='.repeat((4 - (t.length % 4)) % 4))
  return Uint8Array.from(bin, (c) => c.charCodeAt(0))
}

async function importKey(subtle, rawB64) {
  const raw = b64(rawB64)
  for (const alg of [{ name: 'Ed25519' }, { name: 'NODE-ED25519', namedCurve: 'Ed25519' }]) {
    try {
      return { key: await subtle.importKey('raw', raw, alg, false, ['verify']), name: alg.name }
    } catch {
      /* this runtime names the algorithm differently: try the next */
    }
  }
  return null
}

async function keyHash(subtle, secret) {
  const d = new Uint8Array(await subtle.digest('SHA-256', new TextEncoder().encode(secret)))
  return [...d].map((x) => x.toString(16).padStart(2, '0')).join('').slice(0, 16)
}

// createLicense({ secret, apiUrl, fetch, now, token, publicKey, timeoutMs }) -> { usable, ready, status, reason, token }
//   usable()  synchronous: is there a valid licence right now (and start a renewal in the background when it is due)
//   ready()   asynchronous: like usable() but waits (up to timeoutMs) for the first answer, which is what a cold start needs
export function createLicense({ secret, apiUrl = 'https://security.bitora.es', fetch: doFetch = globalThis.fetch, now = () => Date.now(), token, publicKey = LICENSE_PUBLIC_KEY, timeoutMs = 1500 } = {}) {
  const subtle = globalThis.crypto?.subtle
  let st = { status: 'checking', reason: '', exp: 0, renewAt: 0, token: '' }
  let inflight = null
  let keyP = null
  let warned = false
  const warn = (msg) => {
    if (warned) return
    warned = true
    try {
      console.warn('[bitora/guard] ' + msg)
    } catch {
      /* no console in this runtime */
    }
  }
  const off = (reason, retryMs = 5 * 60 * 1000) => {
    st = { status: 'inactive', reason, exp: 0, renewAt: now() + retryMs, token: '' }
  }

  // Is this licence signed by Bitora, for this key, and still valid? Sets the state when it is.
  async function accept(lic) {
    try {
      if (!subtle || typeof lic !== 'string' || lic.length > 2048) return false
      const [body, sig] = lic.split('.')
      if (!body || !sig) return false
      keyP ||= importKey(subtle, publicKey)
      const k = await keyP
      if (!k) return false
      if (!(await subtle.verify(k.name, k.key, b64(sig), new TextEncoder().encode(body)))) return false
      const c = JSON.parse(new TextDecoder().decode(b64(body)))
      if (c.v !== 1 || !(c.exp * 1000 > now()) || c.kh !== (await keyHash(subtle, String(secret)))) return false
      st = { status: 'active', reason: '', exp: c.exp * 1000, renewAt: now() + 6 * 3600 * 1000, token: lic }
      return true
    } catch {
      return false
    }
  }

  async function fetchLicense() {
    const ctl = typeof AbortController === 'function' ? new AbortController() : null
    const timer = ctl ? setTimeout(() => ctl.abort(), 5000) : null
    try {
      const res = await doFetch(apiUrl + '/api/v1/guard/license', { method: 'POST', headers: { authorization: 'Bearer ' + secret, 'content-type': 'application/json' }, body: '{}', signal: ctl?.signal })
      if (res.status === 402) {
        off('subscription_required', 30 * 60 * 1000)
        return warn('inactive: @bitora/guard needs an active Bitora Security subscription (https://security.bitora.es). Your traffic is not affected.')
      }
      if (res.status === 401 || res.status === 403) {
        off('bad_key', 30 * 60 * 1000)
        return warn('inactive: Bitora did not accept this API key (BITORA_SECRET). Your traffic is not affected.')
      }
      if (!res.ok) throw new Error('status ' + res.status)
      const d = await res.json()
      const renew = Math.max(60, Number(d.renew_after_s) || 6 * 3600) * 1000
      if (await accept(d.license)) st.renewAt = now() + renew
      else off('invalid_license')
    } catch {
      // Bitora cannot be reached: a licence that is still valid keeps working; otherwise try again soon.
      if (st.status === 'active' && now() < st.exp) st.renewAt = now() + 10 * 60 * 1000
      else off('unreachable', 30 * 1000)
    } finally {
      if (timer) clearTimeout(timer)
    }
  }

  function refresh() {
    inflight ||= fetchLicense().finally(() => {
      inflight = null
    })
    return inflight
  }

  if (!secret) {
    off('no_key', 24 * 3600 * 1000)
    warn('inactive: set the API key of your site (BITORA_SECRET) to use @bitora/guard, which needs a Bitora Security subscription.')
  } else if (token) {
    inflight = accept(token).then((ok) => {
      if (!ok) st = { ...st, status: 'checking' }
    }).finally(() => {
      inflight = null
    })
  }

  const valid = () => st.status === 'active' && now() < st.exp
  function usable() {
    if (valid()) {
      if (now() >= st.renewAt) refresh()
      return true
    }
    if (secret && !inflight && (st.status === 'checking' || now() >= st.renewAt)) refresh()
    return false
  }
  async function ready() {
    if (valid()) {
      usable()
      return true
    }
    if (!secret) return false
    if (inflight || st.status === 'checking' || now() >= st.renewAt) {
      const p = inflight || refresh()
      let t
      await Promise.race([p, new Promise((r) => { t = setTimeout(r, timeoutMs); t.unref?.() })])
      clearTimeout(t)
    }
    return valid()
  }
  return { usable, ready, status: () => (valid() ? 'active' : st.status === 'active' ? 'inactive' : st.status), reason: () => st.reason, token: () => st.token }
}
