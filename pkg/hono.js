// Hono (Node, Bun, Deno, Cloudflare Workers, Vercel):
//   import { createGuard } from '@bitora/guard'
//   import { bitoraHono } from '@bitora/guard/hono'
//   app.use('*', bitoraHono(createGuard({ secret: process.env.BITORA_SECRET, mode: 'enforce', login: { paths: ['/api/login'] } })))
//
// After the handler has answered it looks at the status (failed logins, scans, id sweeps).

export function bitoraHono(guard) {
  return async function bitora(c, next) {
    const report = await guard.reports(c.req.raw)
    if (report) return report
    let body
    try {
      const raw = c.req.raw
      if (['POST', 'PUT', 'PATCH', 'DELETE'].includes(raw.method) && (raw.headers.get('content-type') || '').includes('json') && Number(raw.headers.get('content-length') || 0) <= 65536) body = await raw.clone().json()
    } catch {
      body = undefined
    }
    const d = await guard.check(c.req.raw, { body })
    if (d.action !== 'allow') return c.json({ error: d.reason || 'blocked' }, d.status || 403, d.headers || {})
    let copy = null
    try {
      const path = new URL(c.req.raw.url).pathname
      if (c.req.raw.method !== 'GET' && guard.options.login.paths.some((p) => path.startsWith(p)) && Number(c.req.raw.headers.get('content-length') || 0) <= 65536) copy = c.req.raw.clone()
    } catch {
      copy = null
    }
    await next()
    try {
      let account = ''
      if (copy && (copy.headers.get('content-type') || '').includes('json')) account = guard.accountOf(await copy.json())
      guard.observe(c.req.raw, { status: c.res.status, account })
    } catch {
      /* observing never affects the answer */
    }
  }
}
