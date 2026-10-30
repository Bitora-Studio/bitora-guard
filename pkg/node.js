// guardFetch: a fetch that cannot be aimed at the inside of your network. Node only (it needs DNS and sockets), so it lives
// in its own entry point and the rest of the package stays usable on the edge.
//
//   import { createGuard } from '@bitora/guard'
//   import { guardFetch } from '@bitora/guard/node'
//   const guard = createGuard({ secret: process.env.BITORA_SECRET })
//   const safeFetch = guardFetch(guard)
//   const res = await safeFetch(userSuppliedUrl)          // throws BlockedUrlError instead of calling 169.254.169.254
//
// What it does for every address it is asked to reach, and for every redirect it follows:
//   1. only http and https, only ports 80 and 443 (change them with ports), no user:password@ in the address;
//   2. it resolves the name itself, and EVERY address the name resolves to must be public;
//   3. it connects to the address it just checked (not to the name again), so a DNS answer that changes between the check
//      and the connection (rebinding) gets nothing;
//   4. redirects are followed by hand, up to maxRedirects, and each hop goes through 1-3 again;
//   5. a timeout and a ceiling for the size of the answer.
// allow: ['api.stripe.com', '.example.com'] restricts it further to those hosts (a leading dot means any subdomain).
// What it does not do: it does not look at what the other server answers, and it does not protect other ways your code
// can reach the network (a database driver, an SDK with its own HTTP client).

import dns from 'node:dns/promises'
import http from 'node:http'
import https from 'node:https'
import net from 'node:net'

export class BlockedUrlError extends Error {
  constructor(reason, detail) {
    super('Blocked request (' + reason + ')' + (detail ? ': ' + detail : ''))
    this.name = 'BlockedUrlError'
    this.reason = reason
  }
}

// Expands an IPv6 address into its eight 16-bit groups (an embedded IPv4 tail counts as two groups). null if malformed.
function groups(ip) {
  let s = ip.toLowerCase().replace(/^\[|\]$/g, '').split('%')[0]
  const v4 = /(\d+)\.(\d+)\.(\d+)\.(\d+)$/.exec(s)
  if (v4) {
    const n = v4.slice(1).map(Number)
    if (n.some((x) => x > 255)) return null
    s = s.slice(0, v4.index) + ((n[0] << 8) | n[1]).toString(16) + ':' + ((n[2] << 8) | n[3]).toString(16)
  }
  const halves = s.split('::')
  if (halves.length > 2) return null
  const head = halves[0] ? halves[0].split(':') : []
  const tail = halves.length === 2 && halves[1] ? halves[1].split(':') : []
  const fill = halves.length === 2 ? 8 - head.length - tail.length : 0
  if (fill < 0 || (halves.length === 1 && head.length !== 8)) return null
  const all = [...head, ...Array(fill).fill('0'), ...tail].map((h) => parseInt(h || '0', 16))
  return all.length === 8 && all.every((x) => x >= 0 && x <= 0xffff) ? all : null
}

function publicV4(a, b, c, d) {
  if (a === 0 || a === 10 || a === 127 || a >= 224) return false // this network, private, loopback, multicast and reserved
  if (a === 100 && b >= 64 && b <= 127) return false // carrier-grade NAT
  if (a === 169 && b === 254) return false // link-local, where the cloud metadata service lives
  if (a === 172 && b >= 16 && b <= 31) return false
  if (a === 192 && b === 168) return false
  if (a === 192 && b === 0 && c === 0) return false // IETF protocol assignments
  if (a === 192 && b === 0 && c === 2) return false // documentation
  if (a === 198 && (b === 18 || b === 19)) return false // benchmarking
  if (a === 198 && b === 51 && c === 100) return false
  if (a === 203 && b === 0 && c === 113) return false
  return true
}

// isPublicIp says whether an address is one a visitor on the internet could be sending you to on purpose without it being
// your own network: not private, loopback, link-local, carrier-grade NAT, multicast, documentation or reserved. IPv6
// addresses that carry an IPv4 address (mapped, NAT64, 6to4) are judged by the IPv4 address inside.
export function isPublicIp(ip) {
  const kind = net.isIP(String(ip).replace(/^\[|\]$/g, ''))
  if (kind === 4) {
    const [a, b, c, d] = ip.split('.').map(Number)
    return publicV4(a, b, c, d)
  }
  if (kind !== 6) return false
  const g = groups(ip)
  if (!g) return false
  const [g0, g1, g2, g3, g4, g5, g6, g7] = g
  const embedded = (hi, lo) => publicV4(hi >> 8, hi & 255, lo >> 8, lo & 255)
  if (g.every((x) => x === 0) || (g.slice(0, 7).every((x) => x === 0) && g7 === 1)) return false // :: and ::1
  if (g0 === 0 && g1 === 0 && g2 === 0 && g3 === 0 && g4 === 0 && g5 === 0xffff) return embedded(g6, g7) // ::ffff:a.b.c.d
  if (g0 === 0 && g1 === 0 && g2 === 0 && g3 === 0 && g4 === 0 && g5 === 0) return embedded(g6, g7) // ::a.b.c.d (deprecated)
  if (g0 === 0x64 && g1 === 0xff9b && g2 === 0 && g3 === 0 && g4 === 0 && g5 === 0) return embedded(g6, g7) // NAT64
  if (g0 === 0x2002) return embedded(g1, g2) // 6to4
  if ((g0 & 0xfe00) === 0xfc00) return false // unique local
  if ((g0 & 0xffc0) === 0xfe80) return false // link-local
  if ((g0 & 0xff00) === 0xff00) return false // multicast
  if (g0 === 0x2001 && g1 === 0x0db8) return false // documentation
  if (g0 === 0x0100 && g1 === 0 && g2 === 0 && g3 === 0) return false // discard
  return true
}

const hostAllowed = (host, allow) => !allow || allow.some((a) => (a.startsWith('.') ? host === a.slice(1) || host.endsWith(a) : host === a))

// Resolves a host and checks EVERY address it has. Returns the one to connect to.
async function pin(host, o) {
  const bare = host.replace(/^\[|\]$/g, '')
  if (net.isIP(bare)) {
    if (!o.allowPrivate && !isPublicIp(bare)) throw new BlockedUrlError('private_address')
    return { address: bare, family: net.isIP(bare) }
  }
  let list
  try {
    list = await o.resolve(bare)
  } catch {
    throw new BlockedUrlError('dns_failed')
  }
  if (!list.length) throw new BlockedUrlError('dns_failed')
  if (!o.allowPrivate && list.some((a) => !isPublicIp(a.address))) throw new BlockedUrlError('private_address') // one bad answer spoils the lot
  return list[0]
}

function validate(u, o) {
  if (u.protocol !== 'http:' && u.protocol !== 'https:') throw new BlockedUrlError('scheme')
  if (u.username || u.password) throw new BlockedUrlError('credentials')
  const port = Number(u.port || (u.protocol === 'https:' ? 443 : 80))
  if (!o.ports.includes(port)) throw new BlockedUrlError('port')
  if (!hostAllowed(u.hostname.toLowerCase(), o.allow)) throw new BlockedUrlError('not_allowed')
}

// The real connection: to the address already checked, with the name only used for TLS and the Host header.
function dispatch(u, target, init, o) {
  return new Promise((resolve, reject) => {
    const lib = u.protocol === 'https:' ? https : http
    const host = u.hostname.replace(/^\[|\]$/g, '')
    const req = lib.request(
      {
        host,
        port: u.port || undefined,
        path: u.pathname + u.search,
        method: init.method,
        headers: init.headers,
        servername: net.isIP(host) ? undefined : host,
        lookup: (h, opts, cb) => (opts && opts.all ? cb(null, [{ address: target.address, family: target.family }]) : cb(null, target.address, target.family)),
        timeout: o.timeoutMs,
      },
      (res) => {
        const chunks = []
        let size = 0
        res.on('data', (c) => {
          size += c.length
          if (size > o.maxBytes) {
            req.destroy()
            reject(new BlockedUrlError('too_large'))
            return
          }
          chunks.push(c)
        })
        res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks) }))
        res.on('error', reject)
      },
    )
    req.on('timeout', () => req.destroy(new BlockedUrlError('timeout')))
    req.on('error', reject)
    if (init.body !== undefined && init.body !== null) req.write(init.body)
    req.end()
  })
}

const NO_BODY = new Set([101, 204, 205, 304])

export function guardFetch(guard, options = {}) {
  const o = {
    ports: [80, 443],
    maxRedirects: 5,
    maxBytes: 5 * 1024 * 1024,
    timeoutMs: 10000,
    allow: null,
    allowPrivate: false, // only for local development: it turns the main protection off
    resolve: (h) => dns.lookup(h, { all: true, verbatim: true }),
    dispatch,
    ...options,
  }
  const report = (reason, extra) => {
    try {
      guard?.note?.('ssrf_blocked', { param: reason, ip: extra?.ip })
    } catch {
      /* reporting never changes the outcome */
    }
  }
  return async function safeFetch(input, init = {}) {
    let method = (init.method || 'GET').toUpperCase()
    let body = init.body === undefined ? undefined : typeof init.body === 'string' || Buffer.isBuffer(init.body) || init.body instanceof Uint8Array ? init.body : String(init.body)
    const headers = {}
    for (const [k, v] of init.headers instanceof Headers ? init.headers.entries() : Object.entries(init.headers || {})) headers[k.toLowerCase()] = String(v)
    let u
    try {
      u = new URL(typeof input === 'string' ? input : input.url || String(input))
    } catch {
      report('invalid_url', init)
      throw new BlockedUrlError('invalid_url')
    }
    try {
      for (let hop = 0; ; hop++) {
        validate(u, o)
        const target = await pin(u.hostname, o)
        const r = await o.dispatch(u, target, { method, headers, body }, o)
        const loc = r.headers?.location
        if (r.status >= 300 && r.status < 400 && loc && init.redirect !== 'manual') {
          if (hop >= o.maxRedirects) throw new BlockedUrlError('too_many_redirects')
          u = new URL(Array.isArray(loc) ? loc[0] : loc, u)
          if (r.status === 303 || ((r.status === 301 || r.status === 302) && method === 'POST')) {
            method = 'GET'
            body = undefined
            delete headers['content-length']
            delete headers['content-type']
          }
          delete headers.authorization // a credential meant for one host is not sent to the next
          delete headers.cookie
          continue
        }
        const h = new Headers()
        for (const [k, v] of Object.entries(r.headers || {})) for (const x of Array.isArray(v) ? v : [v]) h.append(k, String(x))
        return new Response(NO_BODY.has(r.status) ? null : r.body, { status: r.status, headers: h })
      }
    } catch (e) {
      if (e instanceof BlockedUrlError && e.reason !== 'timeout' && e.reason !== 'too_large' && e.reason !== 'dns_failed') report(e.reason, init)
      throw e
    }
  }
}
