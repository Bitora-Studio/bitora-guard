// Express / Connect:
//   import { createGuard } from '@bitora/guard'
//   import { bitoraExpress } from '@bitora/guard/express'
//   app.set('trust proxy', true)
//   app.use(express.json())   // before the guard, so the account of a login can be counted (it never leaves your server)
//   app.use(bitoraExpress(createGuard({ secret: process.env.BITORA_SECRET, mode: 'enforce', login: { paths: ['/api/login'] } })))
//
// Besides gating each request, it watches the answer (res "finish") to see failed logins, scans and id sweeps.

export function bitoraExpress(guard) {
  return function bitora(req, res, next) {
    if (typeof res.on === 'function') res.on('finish', () => {
      try {
        const account = guard.accountOf(req.body)
        guard.observe(req, { status: res.statusCode, account, user: req.user?.id ?? req.userId })
      } catch {
        /* observing never affects the answer */
      }
    })
    guard
      .check(req)
      .then((d) => {
        if (d.action === 'allow') return next()
        for (const [k, v] of Object.entries(d.headers || {})) res.setHeader(k, v)
        res.statusCode = d.status || 403
        res.setHeader('content-type', 'application/json')
        res.end(JSON.stringify({ error: d.reason || 'blocked' }))
      })
      .catch(() => next()) // fail-open
  }
}
