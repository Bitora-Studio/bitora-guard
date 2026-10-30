// Shared stores for the counters that must add up across every instance of your server (a serverless platform starts as many as it
// needs, and each one counts on its own). The guard keeps its fast limits in memory; this is for the few budgets where that is not
// enough: SMS, coupons, the spend of an AI endpoint, sign-ups. A store has one method:
//
//   hit(name, key, { windowSec, amount, max }) -> Promise<{ count, retryAfter }>
//
// count is the total of the window after adding amount (a fixed window that starts with its first hit), retryAfter the seconds until
// it resets. max is only used by the Bitora store, which decides on its side; the others return the count and the guard compares.
//
//   memoryStore()                          this instance only (the default: no network, nothing to set up)
//   bitoraStore({ apiUrl, secret })        counters kept by Bitora (POST /api/v1/guard/decide, kind meter): nothing to install
//   upstashStore({ url, token })           Upstash Redis through its REST API: works on the edge and on Cloudflare
//   redisStore(client)                     any Redis client with incrby / expire / ttl (ioredis, node-redis)
//
// Every store throws if it cannot answer; the guard catches it and lets the request through (fail-open).

export function memoryStore({ now = () => Date.now() } = {}) {
  const map = new Map()
  return {
    async hit(name, key, { windowSec, amount = 1 }) {
      const t = now()
      const k = name + '|' + key
      let w = map.get(k)
      if (!w || t - w.start >= windowSec * 1000) {
        w = { start: t, count: 0 }
        map.set(k, w)
        if (map.size > 50000) for (const [kk, v] of map) if (t - v.start >= windowSec * 1000) map.delete(kk)
      }
      w.count += amount
      return { count: w.count, retryAfter: Math.max(1, Math.ceil((w.start + windowSec * 1000 - t) / 1000)) }
    },
  }
}

const withTimeout = (ms) => {
  const ctl = typeof AbortController === 'function' ? new AbortController() : null
  const timer = ctl ? setTimeout(() => ctl.abort(), ms) : null
  return { signal: ctl?.signal, done: () => timer && clearTimeout(timer) }
}

export function bitoraStore({ apiUrl = 'https://security.bitora.es', secret, fetch: f = globalThis.fetch, timeoutMs = 300 } = {}) {
  return {
    async hit(name, key, { windowSec, amount = 1, max }) {
      if (!secret) throw new Error('no secret')
      const t = withTimeout(timeoutMs)
      try {
        const res = await f(apiUrl + '/api/v1/guard/decide', {
          method: 'POST',
          headers: { authorization: 'Bearer ' + secret, 'content-type': 'application/json' },
          body: JSON.stringify({ kind: 'meter', name, key, amount, max, window_s: windowSec }),
          signal: t.signal,
        })
        if (!res.ok) throw new Error('status ' + res.status)
        const d = await res.json()
        // Bitora already compared with max; when it says block, make the count exceed it so the guard agrees.
        return { count: d.action === 'block' ? Math.max(d.count || 0, max + 1) : d.count || 0, retryAfter: d.retry_after || windowSec }
      } finally {
        t.done()
      }
    },
  }
}

export function upstashStore({ url, token, fetch: f = globalThis.fetch, timeoutMs = 300 } = {}) {
  return {
    async hit(name, key, { windowSec, amount = 1 }) {
      if (!url || !token) throw new Error('no url or token')
      const k = 'bsg:' + name + ':' + key
      const t = withTimeout(timeoutMs)
      try {
        const res = await f(url.replace(/\/$/, '') + '/pipeline', {
          method: 'POST',
          headers: { authorization: 'Bearer ' + token, 'content-type': 'application/json' },
          body: JSON.stringify([['INCRBY', k, amount], ['EXPIRE', k, windowSec, 'NX'], ['TTL', k]]),
          signal: t.signal,
        })
        if (!res.ok) throw new Error('status ' + res.status)
        const r = await res.json()
        const count = Number(r[0]?.result)
        const ttl = Number(r[2]?.result)
        if (!Number.isFinite(count)) throw new Error('bad answer')
        return { count, retryAfter: ttl > 0 ? ttl : windowSec }
      } finally {
        t.done()
      }
    },
  }
}

export function redisStore(client) {
  const incr = client.incrby?.bind(client) ?? client.incrBy?.bind(client)
  if (!incr || !client.expire || !client.ttl) throw new TypeError('redisStore needs a client with incrby, expire and ttl')
  return {
    async hit(name, key, { windowSec, amount = 1 }) {
      const k = 'bsg:' + name + ':' + key
      const count = Number(await incr(k, amount))
      if (count === amount) await client.expire(k, windowSec) // the first hit of the window starts it
      let ttl = Number(await client.ttl(k))
      if (ttl < 0) {
        await client.expire(k, windowSec) // a key that lost its expiry would count forever
        ttl = windowSec
      }
      return { count, retryAfter: ttl }
    },
  }
}
