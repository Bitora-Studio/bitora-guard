// @bitora/guard: protection that runs on your own server. It decides locally and fast (rate limits, per-route limits,
// a budget for the endpoints that cost money, automation on protected paths) and, if it is allowed to, asks Bitora about
// the reputation of the IP. If Bitora does not answer, the request goes through (fail-open): Bitora can be down and your
// site stays up. In "observe" mode (the default) it never blocks anything: it only reports what it would have done.

import { createDetector, isTrap, jsonShape, template } from './detect.js'
import { createBreaker } from './breaker.js'
import { createLicense } from './license.js'
import { scanResponse } from './leaks.js'
import { createSchema } from './schema.js'
import { createShield } from './shield.js'
import { memoryStore } from './store.js'

const DEFAULTS = {
  apiUrl: 'https://security.bitora.es',
  mode: 'observe', // 'observe' reports only; 'enforce' blocks
  rateLimit: { max: 300, windowSec: 60 }, // per IP, for the whole site
  routes: [], // [{ match: '/api/login', max: 10, windowSec: 60 }] per IP and route
  aiBudget: [], // [{ match: '/api/ai', max: 30, windowSec: 3600, key: (req) => userId }] per user (or IP)
  bots: { paths: [], block: true }, // known automation (curl, scripts, headless browsers) on these paths
  skip: ['/_next/', '/static/', '/favicon.ico', '/robots.txt'],
  // Where the address of the visitor comes from. It is never read from a header the visitor can write (see resolveIp).
  ipHeader: null, // a header your own proxy sets and a visitor cannot, e.g. 'cf-connecting-ip' behind Cloudflare
  trustProxy: 0, // how many proxies of yours sit in front of the app, to take the address from x-forwarded-for
  // 'list' downloads the addresses Bitora wants blocked every refreshMs and checks them in memory (one call per
  // refresh, however many visitors); 'ip' asks about each new address (needs a higher plan and a higher request volume).
  remote: { enabled: true, mode: 'list', refreshMs: 30000, blocking: false, timeoutMs: 100, cacheMs: 60000 },
  report: { enabled: true, flushMs: 20000, maxBatch: 50 },
  // Spend on calls to an AI provider, counted in tokens. perUser is charged to whoever the app says the user is (or to
  // the IP), global is the emergency ceiling for the whole site: it protects against an unauthenticated endpoint that
  // anybody can use to spend your money.
  ai: { maxOutputTokens: 1024, perUser: { tokens: 100000, windowSec: 86400 }, global: { tokens: 2000000, windowSec: 86400 } },
  // The checks guard.signup() makes on a new account.
  signup: { perIp: { max: 5, windowSec: 3600 }, perNetwork: { max: 20, windowSec: 3600 } },
  // Who the user is, for counting by user instead of by address: (req) => id or undefined.
  user: null,
  // Paths where a request is a sign-in attempt, so its answer says whether the attempt failed: { paths: ['/api/login'] }.
  // fields are the names of the form or JSON field that holds the account the visitor typed (it never leaves your server).
  login: { paths: [], fields: ['email', 'username', 'user', 'login'] },
  // Addresses a site like yours never serves (/.env, /wp-login.php, /.git/config...). Whoever asks for them is scanning.
  traps: { enabled: true, block: true, except: [], extra: [] },
  // Cross-site writes seen with Fetch Metadata (Sec-Fetch-Site). Report-only until you say block: true.
  csrf: { enabled: true, block: false, exempt: [] },
  // Size and shape of what arrives. 0 or null switches a limit off. methods: [{ match: '/api/login', allow: ['POST'] }].
  limits: { maxUrlLength: 8192, maxBodyBytes: 0, maxJsonDepth: 32, maxJsonKeys: 5000, methods: [] },
  // The Shield scores path, query, a few headers and (when the adapter can read it) the body with rules for SQL injection,
  // XSS, path traversal, command injection, NoSQL operators, prototype pollution and SSRF. A request is flagged at
  // threshold points (CRS: critical 5). paranoia 2 adds rules that catch more and are wrong more often.
  // exclusions: [{ match: '/api/posts', params: ['body.markdown'], rules: ['xss'] }] silence a rule on a route or parameter.
  shield: { enabled: true, block: true, paranoia: 1, threshold: 5, exclusions: [] },
  // Learn what each route normally receives and notice what does not fit (a field nobody sends, a field that changes type, a new method). Off by
  // default: turn it on after a few days of ordinary traffic. See schema.js.
  learn: { enabled: false, minSamples: 30 },
  // Budgets for business flows that cost money or can be abused (SMS, checkout, coupons), by name:
  // flows: { sms_send: { perUser: { max: 3, windowSec: 3600 }, perIp: { max: 10, windowSec: 3600 }, global: { max: 500, windowSec: 86400 } } }
  flows: {},
  // Pwned Passwords (k-anonymity): only the first five characters of the SHA-1 of a password are sent, never the password.
  breach: { apiUrl: 'https://api.pwnedpasswords.com/range/', timeoutMs: 1500 },
  // Thresholds of the detections that read the answers (see detect.js); override only what you need.
  detect: {},
  // Where the counters of guard.limit() live. The default is this instance only; for a budget that must add up across all the
  // instances of your server pass bitoraStore({ secret }), upstashStore({ url, token }) or redisStore(client) (see store.js).
  store: null,
  // guard.decide() asks Bitora for the few decisions that need a state shared by every instance (see the README).
  decide: { timeoutMs: 300 },
}

// Mail domains that exist to receive one message and be thrown away. A short list of the best known ones, kept here so
// the check needs no call to anybody; add your own with signup.extraDisposable.
const DISPOSABLE = new Set([
  'mailinator.com', 'guerrillamail.com', 'guerrillamail.net', 'guerrillamail.org', 'sharklasers.com', 'grr.la', 'guerrillamailblock.com',
  '10minutemail.com', '10minutemail.net', 'temp-mail.org', 'tempmail.com', 'tempmail.net', 'tempmailo.com', 'temp-mail.io', 'tempr.email',
  'yopmail.com', 'yopmail.fr', 'yopmail.net', 'trashmail.com', 'trashmail.net', 'trashmail.de', 'throwawaymail.com', 'getnada.com', 'nada.email',
  'dispostable.com', 'maildrop.cc', 'mailnesia.com', 'mohmal.com', 'emailondeck.com', 'fakeinbox.com', 'mintemail.com', 'mytemp.email',
  'spamgourmet.com', 'spam4.me', 'tmpmail.org', 'tmpmail.net', 'burnermail.io', 'discard.email', 'discardmail.com', 'dropmail.me', 'emailfake.com',
  'fakemail.net', 'getairmail.com', 'harakirimail.com', 'inboxbear.com', 'jetable.org', 'mail-temporaire.fr', 'mailcatch.com', 'mailforspam.com',
  'mailnull.com', 'mailtemp.info', 'moakt.com', 'mvrht.net', 'owlymail.com', 'spambox.us', 'tempinbox.com', 'tempail.com', 'tempmailaddress.com',
  'throwam.com', 'trbvm.com', 'wegwerfmail.de', 'zetmail.com', 'e4ward.com', 'filzmail.com', 'incognitomail.org', 'mailexpire.com', 'minuteinbox.com',
])

const EMAIL_RE = /^[^\s@<>()[\]\\,;:"]{1,64}@([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+)$/i

// The network an address belongs to for counting sign-ups: the /24 of an IPv4 address, the /64 of an IPv6 one.
function networkOf(ip) {
  if (ip.includes(':')) return ip.split(':').slice(0, 4).join(':')
  return ip.split('.').slice(0, 3).join('.')
}

export class GuardBudgetError extends Error {
  constructor(reason) {
    super('AI budget exceeded (' + reason + ')')
    this.name = 'GuardBudgetError'
    this.status = 429
    this.reason = reason
  }
}

// Tokens of a request, estimated as a quarter of its characters (providers count differently: this is an estimate and
// the real figure is taken from the answer afterwards).
const estimateTokens = (params) => {
  const parts = [params?.messages, params?.input, params?.system, params?.prompt, params?.instructions]
  let n = 0
  for (const p of parts) if (p != null) n += typeof p === 'string' ? p.length : JSON.stringify(p).length
  return Math.ceil(n / 4)
}
const usedTokens = (res) => {
  const u = res?.usage
  if (!u) return null
  if (typeof u.total_tokens === 'number') return u.total_tokens
  const t = (u.prompt_tokens ?? u.input_tokens ?? 0) + (u.completion_tokens ?? u.output_tokens ?? 0)
  return t > 0 ? t : null
}
const isCreate = (path) => {
  const p = path.join('.')
  return p === 'chat.completions.create' || p === 'responses.create' || p === 'messages.create'
}

const AUTOMATION = /(curl|wget|python-requests|python-urllib|httpx|aiohttp|go-http-client|okhttp|java\/|libwww|scrapy|node-fetch|axios|undici|headlesschrome|phantomjs|puppeteer|playwright|selenium|postmanruntime|insomnia)/i

const PRIVATE_IP = /^(10\.|127\.|192\.168\.|169\.254\.|172\.(1[6-9]|2\d|3[01])\.|::1$|fc|fd|fe80)/i

function merge(base, extra = {}) {
  const out = { ...base, ...extra }
  for (const k of ['rateLimit', 'bots', 'remote', 'report', 'ai', 'signup', 'login', 'traps', 'csrf', 'limits', 'shield', 'breach', 'decide', 'learn']) out[k] = { ...base[k], ...(extra[k] || {}) }
  return out
}

const first = (v) => String(v || '').split(',')[0].trim()

// resolveIp returns the address of the visitor and where it came from. A header is only believed when something the
// visitor cannot control wrote it: the platform (Vercel), a header the owner names (ipHeader), or the Nth proxy from
// the right of x-forwarded-for (trustProxy). The left-most entry of x-forwarded-for is whatever the visitor sent, so it
// is never used; without a trustworthy source the address is unknown and nothing is limited or reported by address.
export function resolveIp(req, h, o = {}) {
  if (o.ipHeader) {
    const v = first(h(o.ipHeader))
    if (v) return [v, 'header:' + o.ipHeader]
  }
  const env = typeof process !== 'undefined' && process.env ? process.env : {}
  if (env.VERCEL) {
    const v = first(h('x-vercel-forwarded-for')) || first(h('x-real-ip'))
    if (v) return [v, 'vercel']
  }
  const xff = String(h('x-forwarded-for') || '').split(',').map((x) => x.trim()).filter(Boolean)
  if (o.trustProxy > 0 && xff.length) return [xff[Math.max(0, xff.length - o.trustProxy)], 'xff-right']
  const socket = req.socket?.remoteAddress || ''
  if (socket && !PRIVATE_IP.test(socket.replace(/^::ffff:/, ''))) return [socket, 'socket'] // a direct connection: nothing can have been forged
  if (socket && xff.length) return [xff[xff.length - 1], 'xff-right'] // one proxy of yours in front: the address it saw
  if (socket) return [socket, 'socket']
  return ['', 'none']
}

function searchOf(req) {
  try {
    if (typeof req.headers?.get === 'function') return new URL(req.url).search
    const u = req.originalUrl || req.url || ''
    const i = u.indexOf('?')
    return i < 0 ? '' : u.slice(i)
  } catch {
    return ''
  }
}

// A request, whether it is a Web Request (Next.js, Hono, Workers) or a Node IncomingMessage (Express).
export function describe(req, opts = {}) {
  const o = typeof opts === 'string' ? { ipHeader: opts } : opts
  const h = (name) => (typeof req.headers?.get === 'function' ? req.headers.get(name) : req.headers?.[name.toLowerCase()]) || ''
  let path = '/'
  try {
    path = typeof req.headers?.get === 'function' ? new URL(req.url).pathname : (req.originalUrl || req.url || '/').split('?')[0]
  } catch {
    /* keep "/" */
  }
  const [ip, ipSource] = resolveIp(req, h, o)
  return {
    ip: ip.replace(/^::ffff:/, ''),
    ipSource,
    path,
    method: (req.method || 'GET').toUpperCase(),
    agent: h('user-agent'),
    fetchSite: String(h('sec-fetch-site')).toLowerCase(),
    contentLength: Number(h('content-length')) || 0,
    urlLength: String(req.originalUrl || req.url || '').length,
    search: searchOf(req),
    referer: h('referer'),
  }
}

class Windows {
  constructor() {
    this.map = new Map()
  }
  // Counts one hit in a fixed window; returns how many hits the window has and how long until it resets.
  hit(key, windowSec, now) {
    return this.add(key, windowSec, 1, now)
  }
  // Adds an amount (negative to give back what was reserved and not used).
  add(key, windowSec, amount, now) {
    const ms = windowSec * 1000
    let w = this.map.get(key)
    if (!w || now - w.start >= ms) {
      w = { start: now, count: 0, ms }
      this.map.set(key, w)
      if (this.map.size > 20000) this.sweep(now)
    }
    w.count = Math.max(0, w.count + amount)
    return { count: w.count, retryAfter: Math.max(1, Math.ceil((w.start + ms - now) / 1000)) }
  }
  sweep(now) {
    for (const [k, w] of this.map) if (now - w.start >= w.ms) this.map.delete(k)
  }
}

export function createGuard(options = {}) {
  const o = merge(DEFAULTS, options)
  const now = options.now || (() => Date.now())
  const doFetch = options.fetch || globalThis.fetch
  // The licence: this package works for a site of a Bitora Security subscriber (see license.js). Without one every call below lets the
  // traffic through and reports nothing. options.__license is only for this package's own tests.
  const realLic = options.__license || createLicense({ secret: o.secret, apiUrl: o.apiUrl, fetch: doFetch, now, token: options.license, publicKey: options.__licensePublicKey })
  // The off switch: options.disabled (true, or a function that says so) or BITORA_GUARD_DISABLED=1 in the environment. Nothing is inspected,
  // limited, reported or asked to Bitora while it is on, and the site behaves as if the package were not installed. It is read on every call, so
  // a runtime that lets you change the variable (or a function that reads your own flag) turns the package off without a deploy.
  const procEnv = typeof process !== 'undefined' && process.env ? process.env : {}
  const killed = () => {
    const d = typeof options.disabled === 'function' ? options.disabled() : options.disabled
    return d === true || /^(1|true|yes)$/i.test(String(procEnv.BITORA_GUARD_DISABLED || ''))
  }
  const lic = {
    usable: () => !killed() && realLic.usable(),
    ready: async () => !killed() && (await realLic.ready()),
    status: () => (killed() ? 'disabled' : realLic.status()),
    reason: () => (killed() ? 'Desactivado con BITORA_GUARD_DISABLED u options.disabled' : realLic.reason()),
  }
  // One breaker for everything that talks to Bitora: if it does not answer, the package stops asking for a while (see breaker.js).
  const breaker = options.__breaker || createBreaker({ now })
  const windows = new Windows()
  const learned = createSchema({ minSamples: o.learn.minSamples, now })
  const detector = createDetector({ now, detect: o.detect })
  const shield = createShield(o.shield)

  // The Shield on one request. Returns a verdict to apply (or null) and reports what matched: rule ids and parameter
  // NAMES, never values. In observe mode the finding says what would have been done.
  function inspect(r, body, t) {
    if (!o.shield.enabled) return null
    const res = shield.scan({ path: r.path, search: r.search, body, agent: r.agent, referer: r.referer })
    // Rules in shadow mode add no points and never refuse: they are reported as "would have" so they can be judged on real traffic first.
    if (res.shadow?.length) {
      reportFinding({ rule: 'shield', ip: r.ip, path: template(r.path).template, count: 1, windowSec: 0, points: 0, param: res.shadow[0].param, rules: [...new Set(res.shadow.map((m) => m.id))].slice(0, 8) }, r.ipSource, 'reported', true)
    }
    if (!res.matched.length) return null
    const points = Math.min(res.score, 5)
    const flagged = res.score >= shield.threshold
    if (flagged && r.ip && r.ipSource !== 'none') detector.score(r.ip, points, t)
    const v = flagged && o.shield.block ? deny(403, 'shield') : null
    reportFinding(
      { rule: 'shield', ip: r.ip, path: template(r.path).template, count: 1, windowSec: 0, points: flagged ? points : 0, param: res.matched[0].param, rules: [...new Set(res.matched.map((m) => m.id))].slice(0, 8) },
      r.ipSource,
      v && enforcing() ? 'blocked' : 'reported',
      Boolean(v) && !enforcing(),
    )
    return v
  }
  const cache = new Map() // ip -> { action, siteMode, until }
  const pending = new Set()
  let events = new Map() // kind|ip|path -> event
  let lastFlush = now()

  const startsWith = (path, prefix) => path.startsWith(prefix)
  const enforcing = () => o.mode === 'enforce'

  function record(kind, ip, path, extra = {}) {
    if (!o.report.enabled || !o.secret || !ip || PRIVATE_IP.test(ip)) return
    const key = kind + '|' + ip + '|' + path
    const e = events.get(key)
    if (e) e.count++
    else events.set(key, { kind, ip, path, count: 1, ...extra })
  }

  function flushIfDue() {
    if (!events.size) return
    if (events.size >= o.report.maxBatch || now() - lastFlush >= o.report.flushMs) flush()
  }

  // A finding of the detections, in the shape of events v2: the rule, how many, over how long, the points, what was done
  // and, in observe mode, what would have been done. Never a value: the route is a template and a parameter is a name.
  function reportFinding(f, ipSource, action, wouldHave) {
    if (!o.report.enabled || !o.secret) return
    if (f.ip && PRIVATE_IP.test(f.ip)) return
    const key = f.rule + '|' + (f.ip || '') + '|' + f.path
    const e = { kind: f.rule, ip: f.ip || '', path: f.path || '/', count: f.count, window_s: f.windowSec, score: f.points, action, ip_source: ipSource || 'none' }
    if (wouldHave) e.would_have = true
    if (f.param) e.param = f.param
    if (f.rules) e.rules = f.rules
    events.set(key, e)
    flushIfDue()
  }

  // Findings from the answers: they raise the score of the address, which decides the next requests.
  function applyFindings(list, ipSource) {
    const trusted = ipSource && ipSource !== 'none'
    for (const f of list) {
      if (f.ip && trusted) detector.score(f.ip, f.points)
      reportFinding(f, ipSource, 'reported', false)
    }
  }

  // Sends what has been seen as one batch. Never awaited by a request and never throws: reporting must not slow a page.
  function flush() {
    if (!events.size || !o.secret || !doFetch || !breaker.allow()) return Promise.resolve() // while Bitora does not answer, what was seen waits
    const batch = [...events.values()].slice(0, 100)
    events = new Map()
    lastFlush = now()
    return Promise.resolve(
      doFetch(o.apiUrl + '/api/v1/guard/events', {
        method: 'POST',
        headers: { authorization: 'Bearer ' + o.secret, 'content-type': 'application/json' },
        body: JSON.stringify({ events: batch }),
        keepalive: true,
      }),
    )
      .then((res) => (res && res.ok === false ? breaker.fail() : breaker.ok()))
      .catch(() => breaker.fail())
  }

  // The addresses Bitora wants blocked, downloaded in the background and checked in memory. If Bitora does not answer,
  // the list already held keeps working until each entry expires, and nothing new is blocked (fail-open).
  const list = { map: new Map(), mode: 'observe', at: 0, busy: false, etag: '' }
  async function refreshList() {
    if (list.busy || !breaker.allow()) return
    list.busy = true
    const ctl = typeof AbortController === 'function' ? new AbortController() : null
    const timer = ctl ? setTimeout(() => ctl.abort(), 3000) : null
    try {
      const headers = { authorization: 'Bearer ' + o.secret }
      if (list.etag) headers['if-none-match'] = list.etag // an unchanged list costs an empty 304
      const res = await doFetch(o.apiUrl + '/api/v1/decisions/active', { headers, signal: ctl?.signal })
      if (res.status === 304) {
        breaker.ok()
        list.at = now()
        return
      }
      if (!res.ok) throw new Error('status ' + res.status)
      const d = await res.json()
      list.etag = res.headers?.get?.('etag') || ''
      const next = new Map()
      for (const it of d.decisions || []) if (it.action === 'block' && it.ip) next.set(it.ip, Date.parse(it.expires_at) || now() + 60000)
      list.map = next
      list.mode = d.mode || 'observe'
      list.at = now()
      breaker.ok()
    } catch {
      breaker.fail()
      list.at = now() - o.remote.refreshMs + 5000 // try again in a few seconds
    } finally {
      if (timer) clearTimeout(timer)
      list.busy = false
    }
  }
  async function listDecision(ip) {
    if (!o.secret || !doFetch) return null
    if (now() - list.at >= o.remote.refreshMs) {
      const refreshing = refreshList()
      if (o.remote.blocking && list.at === 0) await refreshing // only the very first time, and only if asked to
    }
    const until = list.map.get(ip)
    return until && until > now() && list.mode !== 'observe' ? { action: 'block', siteMode: list.mode } : null
  }

  async function remoteDecision(ip) {
    const hit = cache.get(ip)
    if (hit && hit.until > now()) return hit
    if (!o.remote.enabled || !o.secret || !doFetch || PRIVATE_IP.test(ip) || pending.has(ip) || !breaker.allow()) return hit || null
    const ask = async () => {
      pending.add(ip)
      const ctl = typeof AbortController === 'function' ? new AbortController() : null
      const timer = ctl ? setTimeout(() => ctl.abort(), o.remote.timeoutMs) : null
      try {
        const res = await doFetch(o.apiUrl + '/api/v1/decisions/check?ip=' + encodeURIComponent(ip), {
          headers: { authorization: 'Bearer ' + o.secret },
          signal: ctl?.signal,
        })
        if (!res.ok) throw new Error('status ' + res.status)
        const d = await res.json()
        const entry = { action: d.action || 'allow', siteMode: d.mode || 'observe', until: now() + Math.min(Math.max(1, d.ttl || 60) * 1000, o.remote.cacheMs) }
        cache.set(ip, entry)
        breaker.ok()
        return entry
      } catch {
        breaker.fail()
        // Fail-open: Bitora did not answer, so the request is let through; do not ask again for a few seconds.
        const entry = { action: 'allow', siteMode: 'observe', until: now() + 5000 }
        cache.set(ip, entry)
        return entry
      } finally {
        if (timer) clearTimeout(timer)
        pending.delete(ip)
        if (cache.size > 20000) for (const [k, v] of cache) if (v.until < now()) cache.delete(k)
      }
    }
    // By default the first request of an IP is not held up: the answer is ready for the next one.
    if (o.remote.blocking) return ask()
    ask()
    return hit || null
  }

  const allow = { action: 'allow' }
  const deny = (status, reason, retryAfter) => ({ action: 'block', status, reason, headers: retryAfter ? { 'retry-after': String(retryAfter) } : {} })

  // check decides one request. It never throws: any failure means "allow".
  async function check(req, extra = {}) {
    try {
      const r = describe(req, o)
      if (r.method === 'OPTIONS' || o.skip.some((p) => r.path.startsWith(p))) return allow
      const t = now()
      const hasIp = Boolean(r.ip)
      const ipKey = r.ip
      let verdict = null // what would be done, whether or not it is enforced
      // What this address has already done on this server (scores come from the findings that read the answers).
      if (hasIp) {
        const reg = detector.regime(r.ip, t)
        if (reg.action === 'block') verdict = deny(403, 'reputation_local')
        // In serverless a delay is paid by the owner, not by the attacker: slowing down is a 429 with Retry-After.
        else if (reg.action === 'slow') verdict = deny(429, 'reputation_local', 30)
      }
      // A4: addresses nobody legitimate asks for
      if (o.traps.enabled && isTrap(r.path, o.traps.except, o.traps.extra)) {
        const f = { rule: 'trap_hit', ip: r.ip, path: r.path.split('/').slice(0, 3).join('/'), count: 1, windowSec: 0, points: 5 }
        if (hasIp && r.ipSource !== 'none') detector.score(r.ip, 5, t)
        const v = o.traps.block ? deny(403, 'trap') : null
        verdict = verdict || v
        reportFinding(f, r.ipSource, v && enforcing() ? 'blocked' : 'reported', Boolean(v) && !enforcing())
      }
      // A5: a write that another site made the browser send
      if (o.csrf.enabled && detector.unsafe.has(r.method) && r.fetchSite === 'cross-site' && !o.csrf.exempt.some((p) => r.path.startsWith(p))) {
        const v = o.csrf.block ? deny(403, 'cross_site') : null
        verdict = verdict || v
        reportFinding({ rule: 'csrf_cross_site', ip: r.ip, path: template(r.path).template, count: 1, windowSec: 0, points: 2 }, r.ipSource, v && enforcing() ? 'blocked' : 'reported', Boolean(v) && !enforcing())
      }
      // The Shield: path, query, headers and the body when it is already parsed (Express) or handed over by the adapter
      {
        const body = extra.body !== undefined ? extra.body : req.body && typeof req.body === 'object' && typeof req.body.getReader !== 'function' ? req.body : undefined
        const v = inspect(r, body, t)
        verdict = verdict || v
      }
      // A6: size and shape
      const lim = o.limits
      let abuse = null
      if (lim.maxUrlLength && r.urlLength > lim.maxUrlLength) abuse = deny(414, 'url_too_long')
      else if (lim.maxBodyBytes && r.contentLength > lim.maxBodyBytes) abuse = deny(413, 'body_too_large')
      else {
        const m = lim.methods.find((x) => r.path.startsWith(x.match))
        if (m && !m.allow.map((x) => x.toUpperCase()).includes(r.method)) abuse = deny(405, 'method_not_allowed')
      }
      if (abuse) {
        verdict = verdict || abuse
        reportFinding({ rule: 'request_abuse', ip: r.ip, path: template(r.path).template, count: 1, windowSec: 0, points: 2, param: abuse.reason }, r.ipSource, enforcing() ? 'blocked' : 'reported', !enforcing())
      }

      if (o.bots.paths.some((p) => startsWith(r.path, p)) && AUTOMATION.test(r.agent)) {
        const agent = (r.agent.match(AUTOMATION) || ['bot'])[0].toLowerCase()
        record('bot_blocked', r.ip, r.path, { agent, ip_source: r.ipSource })
        if (o.bots.block) verdict = deny(403, 'automation')
      }
      for (const b of o.aiBudget) {
        if (!startsWith(r.path, b.match)) continue
        const who = (b.key && b.key(req)) || ipKey
        if (!who) continue // nobody to charge it to
        const w = windows.hit('ai|' + b.match + '|' + who, b.windowSec, t)
        if (w.count > b.max) {
          record('ai_budget', r.ip, r.path, { window_s: b.windowSec, ip_source: r.ipSource })
          verdict = verdict || deny(429, 'ai_budget', w.retryAfter)
        }
      }
      for (const route of o.routes) {
        if (!hasIp || !startsWith(r.path, route.match)) continue
        const w = windows.hit('route|' + route.match + '|' + ipKey, route.windowSec || 60, t)
        if (w.count > route.max) {
          record('rate_limited', r.ip, r.path, { window_s: route.windowSec || 60, ip_source: r.ipSource })
          verdict = verdict || deny(429, 'rate_limited', w.retryAfter)
        }
      }
      if (hasIp) {
        const g = windows.hit('all|' + ipKey, o.rateLimit.windowSec, t)
        if (g.count > o.rateLimit.max) {
          record('rate_limited', r.ip, '/', { window_s: o.rateLimit.windowSec, ip_source: r.ipSource })
          verdict = verdict || deny(429, 'rate_limited', g.retryAfter)
        }
      }

      if (!verdict && hasIp && o.remote.enabled) {
        const d = o.remote.mode === 'ip' ? await remoteDecision(r.ip) : await listDecision(r.ip)
        if (d && d.action === 'block' && d.siteMode !== 'observe') verdict = deny(403, 'reputation')
      }
      flushIfDue()
      if (!verdict) return allow
      return enforcing() ? verdict : { ...allow, wouldHave: verdict.reason }
    } catch {
      return allow
    }
  }

  // ---- what the app answered ----
  const who = (req) => {
    try {
      return o.user ? o.user(req) : undefined
    } catch {
      return undefined
    }
  }
  const isLogin = (path) => o.login.paths.some((p) => path.startsWith(p))
  // The account a visitor typed, taken from an already parsed body (an object) with the field names of options.login.
  function accountOf(body) {
    if (!body || typeof body !== 'object') return ''
    for (const f of o.login.fields) if (typeof body[f] === 'string' && body[f]) return body[f]
    return ''
  }

  // guard.observe(req, { status }) is called by the adapters when the answer is known. It never throws.
  function observe(req, a = {}) {
    try {
      const r = describe(req, o)
      if (r.method === 'OPTIONS' || o.skip.some((p) => r.path.startsWith(p))) return
      const status = Number(a.status) || 0
      if (!status) return
      const user = a.user ?? who(req)
      const found = []
      if ((a.login || isLogin(r.path)) && r.method !== 'GET') {
        const ok = status < 400
        const failed = a.failed ?? [400, 401, 403, 422].includes(status)
        if (ok || failed) found.push(...detector.auth({ ip: r.ip, account: a.account, ok, unknownUser: a.reason === 'unknown_user', path: template(r.path).template }))
      }
      found.push(...detector.response({ ip: r.ip, path: r.path, status, method: r.method, user, id: a.id }))
      // What does not fit what this route normally receives (names and types only; it never blocks).
      if (o.learn.enabled) {
        const tpl = template(r.path).template
        const bodyIn = a.requestBody !== undefined ? a.requestBody : req && typeof req === 'object' && !(typeof Request !== 'undefined' && req instanceof Request) ? req.body : undefined
        for (const an of learned.observe({ method: r.method, tpl, body: bodyIn, status })) {
          found.push({ rule: 'unexpected_input', ip: '', path: tpl, count: 1, windowSec: 0, points: 0, param: an.kind + '.' + learned.safeName(an.name) })
        }
      }
      // What the answer itself gives away (a stack trace, a database error, a secret, a debug page). It blames nobody and carries only the kind.
      if (a.body !== undefined) {
        for (const kind of scanResponse({ status, contentType: a.contentType, body: a.body })) {
          found.push({ rule: 'response_leak', ip: '', path: template(r.path).template, count: 1, windowSec: 0, points: 0, param: kind })
        }
      }
      applyFindings(found, r.ipSource)
    } catch {
      /* the answer has already gone out: nothing to do */
    }
  }

  // guard.auth.failed / succeeded: for a login that does not answer 401 (it answers 200 with an error, or it is a
  // server action). Pass the request or the address; the account is only counted in memory and never sent.
  const addr = (a) => {
    if (a.ip) return { ip: String(a.ip).replace(/^::ffff:/, ''), ipSource: a.ipSource || 'header:' + (o.ipHeader || 'app') }
    if (a.req) {
      const d = describe(a.req, o)
      return { ip: d.ip, ipSource: d.ipSource }
    }
    return { ip: '', ipSource: 'none' }
  }
  const auth = {
    failed(a = {}) {
      try {
        const x = addr(a)
        applyFindings(detector.auth({ ip: x.ip, account: a.username, ok: false, unknownUser: a.reason === 'unknown_user', path: a.path || '/login' }), x.ipSource)
      } catch {
        /* never break a login */
      }
    },
    succeeded(a = {}) {
      try {
        const x = addr(a)
        detector.auth({ ip: x.ip, account: a.username, ok: true })
      } catch {
        /* never break a login */
      }
    },
  }

  // guard.event('price_tampered', { req }) lets the app report something only it can see. Only the name travels.
  function event(name, a = {}) {
    try {
      const x = addr(a)
      const clean = String(name || '').toLowerCase().replace(/[^a-z0-9_.-]/g, '').slice(0, 40)
      if (!clean) return
      applyFindings([{ rule: 'app_event', ip: x.ip, path: a.path || '/', count: 1, windowSec: 0, points: 3, param: clean }], x.ipSource)
    } catch {
      /* ignore */
    }
  }

  // guard.route(handler, { login, idParam, account }) wraps a Next.js route handler (or server action) so that the
  // answer is seen. It does not gate the request: proxy.ts or middleware.ts does that.
  function route(handler, opts = {}) {
    return async function wrapped(request, ctx) {
      let copy = null
      if (o.shield.enabled && opts.shield !== false && ['POST', 'PUT', 'PATCH', 'DELETE'].includes((request?.method || '').toUpperCase()) && typeof request?.clone === 'function' && Number(request.headers?.get?.('content-length') || 0) <= 65536) {
        try {
          const ct = request.headers.get('content-type') || ''
          const body = ct.includes('json') ? await request.clone().json() : ct.includes('form') ? Object.fromEntries(await request.clone().formData()) : undefined
          if (body !== undefined) {
            const v = inspect(describe(request, o), body, now())
            if (v && enforcing()) return new Response(JSON.stringify({ error: 'shield' }), { status: v.status, headers: { 'content-type': 'application/json' } })
          }
        } catch {
          /* fail-open: a body that cannot be read is let through */
        }
      }
      if (opts.login && typeof request?.clone === 'function' && Number(request.headers?.get?.('content-length') || 0) <= 65536) {
        try {
          copy = request.clone()
        } catch {
          copy = null
        }
      }
      let status = 500
      try {
        const res = await handler(request, ctx)
        status = res?.status || 200
        return res
      } finally {
        let account = ''
        let id
        try {
          if (copy) {
            const ct = copy.headers.get('content-type') || ''
            const body = ct.includes('json') ? await copy.json() : ct.includes('form') ? Object.fromEntries(await copy.formData()) : null
            account = typeof opts.account === 'function' ? opts.account(body) : accountOf(body)
          }
          if (opts.idParam) id = (await ctx?.params)?.[opts.idParam]
        } catch {
          /* observing must not change what the app answers */
        }
        observe(request, { status, account, id, login: opts.login })
      }
    }
  }

  // ---- AI spend ----
  // A streamed answer reports its usage inside the stream: OpenAI in the last chunk (ask for it with
  // stream_options: { include_usage: true }), Anthropic in message_start (input) and message_delta (output). The stream is
  // passed through untouched; when it ends (or the reader leaves early) the charge is corrected with what was counted.
  function meterStream(stream, done) {
    const u = { input: 0, output: 0, total: null }
    const take = (chunk) => {
      const x = chunk?.usage ?? chunk?.message?.usage ?? chunk?.response?.usage
      if (!x) return
      if (typeof x.total_tokens === 'number') u.total = x.total_tokens
      const i = x.input_tokens ?? x.prompt_tokens
      const out = x.output_tokens ?? x.completion_tokens
      if (typeof i === 'number') u.input = i
      if (typeof out === 'number') u.output = out
    }
    async function* gen() {
      try {
        for await (const chunk of stream) {
          take(chunk)
          yield chunk
        }
      } finally {
        const total = u.total ?? u.input + u.output
        if (total > 0) done(total) // without usage in the stream the estimate stays
      }
    }
    return new Proxy(stream, {
      get(t, k) {
        if (k === Symbol.asyncIterator) return () => gen()
        const v = Reflect.get(t, k, t)
        return typeof v === 'function' ? v.bind(t) : v
      },
    })
  }

  // guard.ai.wrap(client, { user, ip }) returns the same client (OpenAI or Anthropic) with its create() calls counted in
  // tokens: it charges an estimate before the call, refuses it when a budget is spent, caps the output when enforcing,
  // and settles with the real usage afterwards. Streaming calls keep the estimate (the real usage is not known).
  const ai = {
    wrap(client, opts = {}) {
      const charge = (params, ctx) => {
        const out = Math.min(params?.max_tokens ?? params?.max_completion_tokens ?? params?.max_output_tokens ?? o.ai.maxOutputTokens, o.ai.maxOutputTokens)
        const reserve = estimateTokens(params) + out
        const who = ctx.user || ctx.ip
        const t = now()
        const charged = []
        let over = null
        const take = (key, cfg, reason) => {
          if (!cfg) return
          const w = windows.add(key, cfg.windowSec, reserve, t)
          charged.push([key, cfg.windowSec])
          if (w.count > cfg.tokens && !over) over = reason
        }
        if (who) take('aiu|' + who, o.ai.perUser, 'user_budget')
        take('aig|', o.ai.global, 'site_budget')
        return { reserve, charged, over, out }
      }
      const settle = (c, actual) => {
        if (actual == null) return
        for (const [key, windowSec] of c.charged) windows.add(key, windowSec, actual - c.reserve, now())
      }
      const handler = async (call, params) => {
        if (!(await lic.ready())) return call(params)
        const ctx = { user: typeof opts.user === 'function' ? opts.user() : opts.user, ip: typeof opts.ip === 'function' ? opts.ip() : opts.ip }
        let c
        try {
          c = charge(params, ctx)
        } catch {
          return call(params) // never let the counting break the call
        }
        if (c.over) {
          record('ai_budget', ctx.ip, '/ai', { window_s: (c.over === 'site_budget' ? o.ai.global : o.ai.perUser).windowSec, ip_source: opts.ipSource || 'header:' + (o.ipHeader || 'app') })
          flushIfDue()
          if (enforcing()) {
            settle(c, 0) // nothing was spent
            throw new GuardBudgetError(c.over)
          }
        }
        let p = params
        if (enforcing() && o.ai.maxOutputTokens) {
          const key = 'max_completion_tokens' in (params || {}) ? 'max_completion_tokens' : 'max_output_tokens' in (params || {}) ? 'max_output_tokens' : 'max_tokens'
          if (!(params?.[key] <= o.ai.maxOutputTokens)) p = { ...params, [key]: o.ai.maxOutputTokens }
        }
        const res = await call(p)
        if (!(p && p.stream)) settle(c, usedTokens(res))
        else if (res && typeof res[Symbol.asyncIterator] === 'function') return meterStream(res, (t) => settle(c, t))
        return res
      }
      const proxy = (target, path) =>
        new Proxy(target, {
          get(t, k) {
            const v = Reflect.get(t, k, t)
            if (typeof k === 'symbol') return v
            const next = [...path, k]
            if (typeof v === 'function') return isCreate(next) ? (params, ...rest) => handler((x) => v.call(t, x ?? params, ...rest), params) : v.bind(t)
            return v && typeof v === 'object' ? proxy(v, next) : v
          },
        })
      return proxy(client, [])
    },
  }

  // ---- sign-ups ----
  // guard.signup({ email, ip }) says what to do with a new account: 'allow', or 'block' with the reasons. It checks the
  // shape of the address, whether its domain is a throw-away one, and how many accounts the same address and the same
  // network are creating. Call it in your sign-up handler before creating the account.
  function signup({ email, ip } = {}) {
    const reasons = []
    const m = EMAIL_RE.exec(String(email || '').trim())
    if (!m) reasons.push('invalid_email')
    else {
      const domain = m[1].toLowerCase()
      if (DISPOSABLE.has(domain) || (o.signup.extraDisposable || []).includes(domain)) reasons.push('disposable_email')
    }
    const t = now()
    if (ip) {
      if (windows.hit('su-ip|' + ip, o.signup.perIp.windowSec, t).count > o.signup.perIp.max) reasons.push('too_many_from_ip')
      if (windows.hit('su-net|' + networkOf(ip), o.signup.perNetwork.windowSec, t).count > o.signup.perNetwork.max) reasons.push('too_many_from_network')
    }
    if (reasons.length) note('signup_blocked', { ip: ip, ipSource: arguments[0]?.ipSource, param: reasons[0], points: 3 })
    return reasons.length ? { action: 'block', reasons } : { action: 'allow', reasons }
  }

  // ---- things the app tells us about, outside any request ----
  // note(kind, { ip, ipSource, param, points }) reports an event of the app or of a sink (guardFetch, signup, flow). Kinds
  // other than these three are ignored. It never throws.
  const NOTES = { ssrf_blocked: 0, signup_blocked: 3, flow_limited: 3, sink_blocked: 0 }
  function note(kind, a = {}) {
    try {
      if (!(kind in NOTES)) return
      const x = addr(a)
      const points = a.points ?? NOTES[kind]
      applyFindings([{ rule: kind, ip: x.ip, path: '/', count: 1, windowSec: 0, points, param: String(a.param || '').replace(/[^a-z0-9_.-]/gi, '').slice(0, 40) }], x.ipSource)
    } catch {
      /* ignore */
    }
  }

  // guard.flow('sms_send', { user, ip }) spends one unit of a named budget (options.flows). In observe mode it only says
  // what it would have done.
  function flow(name, { user, ip, ipSource } = {}) {
    try {
      const cfg = o.flows[name]
      if (!cfg) return { action: 'allow', reasons: [] }
      const t = now()
      const reasons = []
      let retry = 0
      const hit = (key, c, reason) => {
        if (!c) return
        const w = windows.hit('fl|' + name + '|' + key, c.windowSec, t)
        if (w.count > c.max) {
          reasons.push(reason)
          retry = Math.max(retry, w.retryAfter)
        }
      }
      if (user) hit('u|' + user, cfg.perUser, 'user_limit')
      if (ip) hit('i|' + ip, cfg.perIp, 'ip_limit')
      hit('all', cfg.global, 'site_limit')
      if (!reasons.length) return { action: 'allow', reasons }
      note('flow_limited', { ip, ipSource, param: name })
      return enforcing() ? { action: 'block', reasons, retryAfter: retry, status: 429 } : { action: 'allow', wouldHave: 'flow_limited', reasons, retryAfter: retry }
    } catch {
      return { action: 'allow', reasons: [] }
    }
  }

  // guard.limit('coupon', { key: userId, max: 3, windowSec: 3600 }): a counter that can be shared by every instance of the server
  // (options.store). It spends 'amount' (default 1) and says whether the window is over max. In observe mode it only says what it would
  // have done. If the store does not answer it lets the request through.
  const store = o.store || memoryStore({ now })
  async function limit(name, { key, max, windowSec = 60, amount = 1, ip, ipSource } = {}) {
    try {
      if (!/^[a-z0-9_.-]{1,40}$/.test(String(name)) || !key || !(max >= 1)) return { action: 'allow', allowed: true, count: 0, checked: false }
      const r = await store.hit(String(name), String(key).slice(0, 128), { windowSec, amount, max })
      if (!(r.count > max)) return { action: 'allow', allowed: true, count: r.count, checked: true }
      note('flow_limited', { ip, ipSource, param: name })
      return enforcing()
        ? { action: 'block', allowed: false, count: r.count, retryAfter: r.retryAfter, status: 429, checked: true }
        : { action: 'allow', allowed: true, wouldHave: 'flow_limited', count: r.count, retryAfter: r.retryAfter, checked: true }
    } catch {
      return { action: 'allow', allowed: true, count: 0, checked: false }
    }
  }

  // guard.decide('signup' | 'login', { email, user, ip, ipSource }): the decisions that need a state shared by every instance or a
  // lookup the package cannot make: whether an e-mail domain can receive mail (MX) and how many sign-ups an address or its network made,
  // and attempts per account and per address. The e-mail is read for its domain and dropped on Bitora's side; send an opaque identifier
  // for an account (guard.accountOf), never its name. Short timeout, and if Bitora does not answer the result is allow.
  async function decide(kind, a = {}) {
    try {
      if (!o.secret || !doFetch || !breaker.allow()) return { action: 'allow', reasons: [], checked: false }
      const x = addr(a)
      const ctl = typeof AbortController === 'function' ? new AbortController() : null
      const timer = ctl ? setTimeout(() => ctl.abort(), o.decide.timeoutMs) : null
      try {
        const res = await doFetch(o.apiUrl + '/api/v1/guard/decide', {
          method: 'POST',
          headers: { authorization: 'Bearer ' + o.secret, 'content-type': 'application/json' },
          body: JSON.stringify({ kind, email: a.email, user: a.user, ip: x.ip, ip_source: x.ipSource }),
          signal: ctl?.signal,
        })
        if (!res.ok) throw new Error('status ' + res.status)
        const d = await res.json()
        breaker.ok()
        if (d.action !== 'block') return { action: 'allow', reasons: [], checked: true }
        if (kind === 'signup') note('signup_blocked', { ip: x.ip, ipSource: x.ipSource, param: d.reasons?.[0], points: 3 })
        return enforcing()
          ? { action: 'block', reasons: d.reasons || [], retryAfter: d.retry_after, checked: true }
          : { action: 'allow', wouldHave: 'blocked', reasons: d.reasons || [], retryAfter: d.retry_after, checked: true }
      } finally {
        if (timer) clearTimeout(timer)
      }
    } catch {
      breaker.fail()
      return { action: 'allow', reasons: [], checked: false }
    }
  }

  // guard.isBreached(password): has this password appeared in a known leak? Only the first five characters of its SHA-1 go
  // out (Pwned Passwords, k-anonymity); the comparison happens here. If the service does not answer the result is
  // { breached: false, checked: false }: a sign-up must not fail because somebody else is down.
  async function isBreached(password) {
    try {
      const bytes = new TextEncoder().encode(String(password))
      const hex = [...new Uint8Array(await globalThis.crypto.subtle.digest('SHA-1', bytes))].map((b) => b.toString(16).padStart(2, '0')).join('').toUpperCase()
      const ctl = typeof AbortController === 'function' ? new AbortController() : null
      const timer = ctl ? setTimeout(() => ctl.abort(), o.breach.timeoutMs) : null
      try {
        const res = await doFetch(o.breach.apiUrl + hex.slice(0, 5), { headers: { 'add-padding': 'true' }, signal: ctl?.signal })
        if (!res.ok) throw new Error('status ' + res.status)
        const suffix = hex.slice(5)
        for (const line of (await res.text()).split('\n')) {
          const [s, n] = line.trim().split(':')
          if (s === suffix) return { breached: Number(n) > 0, count: Number(n) || 0, checked: true } // padded decoys have a count of 0
        }
        return { breached: false, count: 0, checked: true }
      } finally {
        if (timer) clearTimeout(timer)
      }
    } catch {
      return { breached: false, count: 0, checked: false }
    }
  }

  // Every public call goes through the licence. The asynchronous ones wait (up to a second and a half, once) for the first answer, which
  // is what a cold start in serverless needs; the synchronous ones only use what is already known. Without a licence they let everything pass.
  const idle = { action: 'allow', reasons: [], checked: false }
  lic.usable() // start asking now, so the first request is not the one that waits
  return {
    check: async (req, extra) => ((await lic.ready()) ? check(req, extra) : allow),
    inspect: (r, body, t) => (lic.usable() ? inspect(r, body, t) : null),
    observe: (req, a) => {
      if (lic.usable()) observe(req, a)
    },
    route: (handler, opts) => {
      const wrapped = route(handler, opts)
      return async (request, ctx) => ((await lic.ready()) ? wrapped(request, ctx) : handler(request, ctx))
    },
    auth: {
      failed: (a) => {
        if (lic.usable()) auth.failed(a)
      },
      succeeded: (a) => {
        if (lic.usable()) auth.succeeded(a)
      },
    },
    event: (name, a) => {
      if (lic.usable()) event(name, a)
    },
    note: (kind, a) => {
      if (lic.usable()) note(kind, a)
    },
    flow: (name, a) => (lic.usable() ? flow(name, a) : { action: 'allow', reasons: [] }),
    limit: async (name, a) => ((await lic.ready()) ? limit(name, a) : { action: 'allow', allowed: true, count: 0, checked: false }),
    decide: async (kind, a) => ((await lic.ready()) ? decide(kind, a) : idle),
    isBreached: async (password) => ((await lic.ready()) ? isBreached(password) : { breached: false, count: 0, checked: false }),
    accountOf,
    flush: () => (lic.usable() ? flush() : Promise.resolve()),
    ai,
    signup: (a) => (lic.usable() ? signup(a) : { action: 'allow', reasons: [] }),
    // The state of the licence: 'active', 'inactive' (with the reason: subscription_required, bad_key, no_key, unreachable) or 'checking'.
    license: { status: lic.status, reason: lic.reason, ready: lic.ready },
    // What the guard has learned about your routes (names and types, never values), as data, as an OpenAPI document or as Zod schemas.
    schema: {
      export: () => (lic.usable() ? learned.export() : { routes: [] }),
      openapi: () => (lic.usable() ? learned.openapi() : { openapi: '3.0.3', info: { title: 'inactive', version: '0' }, paths: {} }),
      zod: () => (lic.usable() ? learned.zod() : ''),
    },
    licensed: lic.usable,
    options: o,
  }
}
