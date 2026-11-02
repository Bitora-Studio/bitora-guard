// Express / Connect:
//   import { createGuard } from '@bitora/guard'
//   import { bitoraExpress } from '@bitora/guard/express'
//   app.set('trust proxy', true)
//   app.use(express.json())   // before the guard, so the account of a login can be counted (it never leaves your server)
//   app.use(bitoraExpress(createGuard({ secret: process.env.BITORA_SECRET, mode: 'enforce', login: { paths: ['/api/login'] } })))
//
import { collector } from './leaks.js'

// The browser's CSP reports (see guard.headers()) arrive as a POST that express.json() does not parse, so the body is read here, up to 32 KB.
function receiveReports(guard, req, res) {
  let text = ''
  let size = 0
  req.on('data', (c) => {
    size += c.length
    if (size <= 32768) text += c
  })
  req.on('end', async () => {
    try {
      await guard.reports(req, size <= 32768 ? text : '')
    } catch {
      /* a report never breaks the site */
    }
    res.statusCode = 204
    res.end()
  })
  req.on('error', () => {
    res.statusCode = 204
    res.end()
  })
}

// Besides gating each request, it watches the answer (res "finish") to see failed logins, scans and id sweeps.

// bitoraExpress(guard, { leaks: true }) also reads the first 16 KB of each text answer to notice a stack trace, a database error, a secret or
// a debug page that your server is sending out (only the KIND is reported). It wraps res.write and res.end, which is why it is off by default.
export function bitoraExpress(guard, { leaks = false } = {}) {
  return function bitora(req, res, next) {
    if (req.method === 'POST' && req.path === guard.options.csp.reportPath) return receiveReports(guard, req, res)
    const seen = leaks ? collector() : null
    if (seen && typeof res.write === 'function' && typeof res.end === 'function') {
      const write = res.write
      const end = res.end
      res.write = function (chunk, ...rest) {
        try {
          seen.add(chunk)
        } catch {
          /* never affect the answer */
        }
        return write.call(this, chunk, ...rest)
      }
      res.end = function (chunk, ...rest) {
        try {
          seen.add(chunk)
        } catch {
          /* never affect the answer */
        }
        return end.call(this, chunk, ...rest)
      }
    }
    if (typeof res.on === 'function') res.on('finish', () => {
      try {
        const account = guard.accountOf(req.body)
        const type = typeof res.getHeader === 'function' ? String(res.getHeader('content-type') || '') : ''
        guard.observe(req, { status: res.statusCode, account, user: req.user?.id ?? req.userId, ...(seen ? { body: seen.text(), contentType: type } : {}) })
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
