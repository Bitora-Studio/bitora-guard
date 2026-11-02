// Deno, Deno Deploy and Supabase Edge Functions:
//   import { createGuard } from '@bitora/guard'
//   import { bitoraDeno } from '@bitora/guard/deno'
//   const guard = createGuard({ secret: Deno.env.get('BITORA_SECRET'), mode: 'enforce', trustProxy: 1 })
//   Deno.serve(bitoraDeno(guard, (req) => new Response('hola')))
//
// On Deno the connection address is the second argument of the handler. It is used when no trusted header names the
// visitor, so a function that is reached directly still has an address to count.

export function bitoraDeno(guard, handler) {
  return async function (req, info) {
    const view = {
      headers: req.headers,
      url: req.url,
      method: req.method,
      socket: { remoteAddress: info?.remoteAddr?.hostname || '' },
    }
    const report = await guard.reports(req)
    if (report) return report
    const d = await guard.check(view)
    if (d.action !== 'allow') {
      return new Response(JSON.stringify({ error: d.reason || 'blocked' }), {
        status: d.status || 403,
        headers: { 'content-type': 'application/json', ...(d.headers || {}) },
      })
    }
    const res = await handler(req, info)
    guard.observe(view, { status: res.status })
    return res
  }
}
