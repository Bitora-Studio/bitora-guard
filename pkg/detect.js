// What the app answered, not only what was asked. A gate in front of the app sees requests; this module sees the status
// of each answer and who the user was, which is what tells a failed login from a good one and a missing page from a
// found one. Everything is counted in the memory of the process and nothing here sends anything: it returns findings.
//
// Account names, ids and paths are only used as keys of counters inside the process. They are reduced to a short hash
// before they are stored and never leave the server; what is reported is the rule, a count and the route template.

const MAX_LOG = 200 // entries kept per key: more than any threshold below, so memory per key is bounded

// cyrb53: a small, fast, non-cryptographic hash. Enough to avoid keeping names in memory; it protects nothing by itself.
export function hash(str, seed = 0) {
  let h1 = 0xdeadbeef ^ seed
  let h2 = 0x41c6ce57 ^ seed
  for (let i = 0; i < str.length; i++) {
    const c = str.charCodeAt(i)
    h1 = Math.imul(h1 ^ c, 2654435761)
    h2 = Math.imul(h2 ^ c, 1597334677)
  }
  h1 = Math.imul(h1 ^ (h1 >>> 16), 2246822507) ^ Math.imul(h2 ^ (h2 >>> 13), 3266489909)
  h2 = Math.imul(h2 ^ (h2 >>> 16), 2246822507) ^ Math.imul(h1 ^ (h1 >>> 13), 3266489909)
  return (4294967296 * (2097151 & h2) + (h1 >>> 0)).toString(36)
}

// A sliding log: exact "how many in the last W seconds" and "how many different items", with bounded memory.
class Log {
  constructor() {
    this.map = new Map()
  }
  push(key, windowMs, t, item) {
    let a = this.map.get(key)
    if (!a) {
      a = []
      this.map.set(key, a)
      if (this.map.size > 20000) this.sweep(t)
    }
    a.push([t, item])
    a.ms = windowMs
    const cut = t - windowMs
    let i = 0
    while (i < a.length && a[i][0] <= cut) i++
    if (i) a.splice(0, i)
    if (a.length > MAX_LOG) a.splice(0, a.length - MAX_LOG)
    const seen = new Set()
    for (const e of a) seen.add(e[1])
    return { count: a.length, distinct: seen.size }
  }
  drop(key) {
    this.map.delete(key)
  }
  sweep(t) {
    for (const [k, a] of this.map) if (!a.length || t - a[a.length - 1][0] >= a.ms) this.map.delete(k)
  }
}

// Segments that are an identifier and not a name: numbers, UUIDs, long hex strings (Mongo ObjectId, hashes) and long
// opaque tokens. A route template replaces them with ":id", so /api/users/42 and /api/users/43 are the same route.
const NUM = /^\d{1,19}$/
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i
const HEX = /^[0-9a-f]{16,}$/i
const OPAQUE = /^(?=.*\d)[A-Za-z0-9_-]{20,}$/

export function template(path, idValue) {
  const parts = path.split('/')
  let id = null
  for (let i = 0; i < parts.length; i++) {
    const s = parts[i]
    if (!s) continue
    let isId = NUM.test(s) || UUID.test(s) || HEX.test(s) || OPAQUE.test(s)
    if (idValue != null && s === String(idValue)) isId = true
    if (isId) {
      parts[i] = ':id'
      if (id === null) id = s
    }
  }
  return { template: parts.join('/') || '/', id }
}

// Paths a Next.js, Node, Deno or edge app never serves. A visitor asking for them is looking for somebody else's
// software, so there is almost no legitimate traffic to confuse with it. A site that really runs one of these
// (a WordPress, a phpMyAdmin) lists it in traps.except.
const TRAPS = [
  '/.env', '/.git/', '/.git', '/.svn/', '/.hg/', '/.aws/', '/.ssh/', '/.ds_store', '/.htaccess', '/.htpasswd', '/.npmrc', '/.dockerenv',
  '/wp-login.php', '/wp-admin', '/wp-content/plugins', '/wp-includes', '/xmlrpc.php', '/wp-config.php',
  '/phpmyadmin', '/pma/', '/adminer', '/phpinfo.php', '/info.php', '/config.php', '/vendor/phpunit', '/cgi-bin/',
  '/actuator', '/server-status', '/server-info', '/boaform', '/solr/', '/jenkins', '/manager/html', '/console/', '/_ignition',
  '/backup.sql', '/dump.sql', '/database.sql', '/db.sql',
]

export function isTrap(path, except = [], extra = []) {
  const p = path.toLowerCase()
  if (except.some((e) => p.startsWith(e.toLowerCase()))) return false
  // A hidden file or folder is a trap wherever it sits (/api/.env); the others only at the start of the path.
  return TRAPS.concat(extra).some((t) => p.startsWith(t) || (t.startsWith('/.') && p.includes(t.endsWith('/') ? t : t + '/')) || (t.startsWith('/.') && p.endsWith(t)))
}

const UNSAFE = new Set(['POST', 'PUT', 'PATCH', 'DELETE'])

// Shape of a JSON body: depth and number of keys, with a budget so that checking cannot cost more than it protects.
export function jsonShape(value, maxDepth = 64) {
  let keys = 0
  let depth = 0
  let budget = 100000
  const walk = (v, d) => {
    if (budget-- <= 0 || v === null || typeof v !== 'object') return
    if (d > depth) depth = d
    if (d > maxDepth) return
    for (const k of Array.isArray(v) ? v : Object.keys(v)) {
      keys++
      walk(Array.isArray(v) ? k : v[k], d + 1)
    }
  }
  walk(value, 1)
  return { depth, keys }
}

// Reputation of an address with two time scales. The short one is the sigmoid of the thesis: a score x that decays
// with e^(-lambda dt) and grows with the weight of each finding, S(x) = 1/(1+e^(-0.75(x-4))). The long one lives in the
// counters of the detections (per account and per day), because a slow attacker lets the short score fade between tries.
export const LAMBDA = 0.008 // per second: the score halves in about 87 s
export const sigmoid = (x) => 1 / (1 + Math.exp(-0.75 * (x - 4)))
export const REGIME = { slow: 0.65, block: 0.88 } // below 0.65 nothing is done; between, slow down (429); from 0.88, block

class Reputation {
  constructor() {
    this.map = new Map()
  }
  value(ip, t) {
    const e = this.map.get(ip)
    if (!e) return 0
    return e.x * Math.exp(-LAMBDA * Math.max(0, t - e.t) / 1000)
  }
  add(ip, weight, t) {
    const x = this.value(ip, t) + weight
    this.map.set(ip, { x, t })
    if (this.map.size > 20000) for (const [k] of this.map) if (this.value(k, t) < 0.05) this.map.delete(k)
    return x
  }
}

// Severity points of a finding (the scale of the OWASP Core Rule Set: critical 5, error 4, warning 3, notice 2).
const POINTS = {
  trap_hit: 5,
  credential_stuffing: 5,
  brute_force: 4,
  id_sweep: 4,
  scan_probe: 4,
  password_spraying: 0, // spread over many addresses on purpose: no single address is to blame
  user_enumeration: 3,
  forced_browsing: 3,
  csrf_cross_site: 2,
  request_abuse: 2,
  app_event: 3,
}

export const DETECTIONS = Object.keys(POINTS)

export function createDetector(options = {}) {
  const now = options.now || (() => Date.now())
  const cfg = {
    bruteForce: { perAccount: 10, perIp: 10, windowSec: 600, perAccountDay: 30, perIpDay: 40 },
    stuffing: { users: 8, networkUsers: 15, windowSec: 600 },
    spraying: { users: 25, windowSec: 600 },
    enumeration: { users: 5, windowSec: 600 },
    scan: { paths: 12, windowSec: 60 },
    forcedBrowsing: { paths: 10, windowSec: 60 },
    idSweep: { ids: 30, windowSec: 60 },
    ...options.detect,
  }
  const log = new Log()
  const rep = new Reputation()

  const networkOf = (ip) => (ip.includes(':') ? ip.split(':').slice(0, 4).join(':') : ip.split('.').slice(0, 3).join('.'))
  const out = []
  const found = (rule, ip, path, count, windowSec, extra = {}) => {
    out.push({ rule, ip, path, count, windowSec, points: POINTS[rule] || 0, ...extra })
  }
  // Each finding is reported once per window per address and rule, however many requests keep tripping it.
  const quiet = new Map()
  const once = (rule, who, windowSec, t) => {
    const k = rule + '|' + who
    const until = quiet.get(k)
    if (until && until > t) return false
    quiet.set(k, t + windowSec * 1000)
    if (quiet.size > 20000) for (const [q, u] of quiet) if (u < t) quiet.delete(q)
    return true
  }

  // A failed or successful attempt to sign in. account is the name the visitor tried (reduced to a hash here).
  function auth({ ip, account, ok, unknownUser, path }) {
    out.length = 0
    const t = now()
    const acct = account ? hash(String(account).trim().toLowerCase().slice(0, 256)) : ''
    if (ok) {
      if (ip) log.drop('af-ip|' + ip)
      return []
    }
    const b = cfg.bruteForce
    const ms = b.windowSec * 1000
    if (acct) {
      const n = log.push('af-acct|' + acct, ms, t, ip || '-').count
      const day = log.push('af-acct-d|' + acct, 86400000, t, ip || '-').count
      if (n >= b.perAccount && once('brute_force', 'a' + acct, b.windowSec, t)) found('brute_force', ip, path, n, b.windowSec, { scope: 'account' })
      else if (day >= b.perAccountDay && once('brute_force', 'ad' + acct, 86400, t)) found('brute_force', ip, path, day, 86400, { scope: 'account' })
    }
    if (ip) {
      const n = log.push('af-ip|' + ip, ms, t, acct).count
      const day = log.push('af-ip-d|' + ip, 86400000, t, acct).count
      if (n >= b.perIp && once('brute_force', 'i' + ip, b.windowSec, t)) found('brute_force', ip, path, n, b.windowSec, { scope: 'ip' })
      else if (day >= b.perIpDay && once('brute_force', 'id' + ip, 86400, t)) found('brute_force', ip, path, day, 86400, { scope: 'ip' })
      if (acct) {
        const s = cfg.stuffing
        const u = log.push('af-users|' + ip, s.windowSec * 1000, t, acct).distinct
        if (u >= s.users && once('credential_stuffing', ip, s.windowSec, t)) found('credential_stuffing', ip, path, u, s.windowSec)
        else {
          const net = log.push('af-net|' + networkOf(ip), s.windowSec * 1000, t, acct).distinct
          if (net >= s.networkUsers && once('credential_stuffing', 'n' + networkOf(ip), s.windowSec, t)) found('credential_stuffing', ip, path, net, s.windowSec, { scope: 'network' })
        }
        if (unknownUser) {
          const e = cfg.enumeration
          const k = log.push('enum|' + ip, e.windowSec * 1000, t, acct).distinct
          if (k >= e.users && once('user_enumeration', ip, e.windowSec, t)) found('user_enumeration', ip, path, k, e.windowSec)
        }
      }
    }
    if (acct) {
      // Many accounts failing across the whole site, each only once or twice: a spray, not a brute force.
      const sp = cfg.spraying
      const r = log.push('af-site', sp.windowSec * 1000, t, acct)
      if (r.distinct >= sp.users && r.count <= r.distinct * 2 && once('password_spraying', 'site', sp.windowSec, t)) found('password_spraying', '', path, r.distinct, sp.windowSec)
    }
    return out.slice()
  }

  // The answer to one request. ev: { ip, path, status, method, user, id }.
  function response(ev) {
    out.length = 0
    const t = now()
    const { ip, status } = ev
    const who = ev.user ? 'u' + hash(String(ev.user)) : ip ? 'i' + ip : ''
    if (!who) return []
    const tpl = template(ev.path, ev.id)
    if (status === 404 || status === 405) {
      const c = cfg.scan
      const d = ip ? log.push('scan|' + ip, c.windowSec * 1000, t, ev.path).distinct : 0
      if (d >= c.paths && once('scan_probe', ip, c.windowSec, t)) found('scan_probe', ip, tpl.template, d, c.windowSec)
    }
    if (status === 401 || status === 403) {
      const c = cfg.forcedBrowsing
      const d = log.push('fb|' + who, c.windowSec * 1000, t, tpl.template).distinct
      if (d >= c.paths && once('forced_browsing', who, c.windowSec, t)) found('forced_browsing', ip, tpl.template, d, c.windowSec)
    }
    if (tpl.id !== null && status < 500 && ev.method === 'GET') {
      const c = cfg.idSweep
      const d = log.push('ids|' + who + '|' + tpl.template, c.windowSec * 1000, t, tpl.id).distinct
      if (d >= c.ids && once('id_sweep', who + tpl.template, c.windowSec, t)) found('id_sweep', ip, tpl.template, d, c.windowSec)
    }
    return out.slice()
  }

  // Adds the points of findings to the short-scale score of an address and returns the new score.
  function score(ip, points, t = now()) {
    return points > 0 && ip ? rep.add(ip, points, t) : rep.value(ip, t)
  }

  // What the score of an address calls for: 'allow', 'slow' (429 with Retry-After) or 'block'.
  function regime(ip, t = now()) {
    const s = sigmoid(rep.value(ip, t))
    return { s, action: s >= REGIME.block ? 'block' : s >= REGIME.slow ? 'slow' : 'allow' }
  }

  return { auth, response, score, regime, unsafe: UNSAFE, cfg }
}
