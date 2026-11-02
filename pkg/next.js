// Next.js 16 (proxy.ts, runs on Node):
//   import { createGuard } from '@bitora/guard'
//   import { bitoraProxy } from '@bitora/guard/next'
//   export const proxy = bitoraProxy(createGuard({ secret: process.env.BITORA_SECRET, mode: 'enforce' }))
//   export const config = { matcher: ['/api/:path*'] }
//
// Next.js 15 and earlier, or the Edge runtime (middleware.ts):
//   import { bitoraMiddleware } from '@bitora/guard/next'
//   export default bitoraMiddleware(createGuard({ secret: process.env.BITORA_SECRET, mode: 'enforce' }))

export function bitoraMiddleware(guard, next) {
  return async function middleware(request, event) {
    const report = await guard.reports(request) // the browser's CSP reports (see guard.headers()): answered here, never blocked
    if (report) return report
    const d = await guard.check(request)
    if (d.action !== 'allow') {
      return new Response(JSON.stringify({ error: d.reason || 'blocked' }), {
        status: d.status || 403,
        headers: { 'content-type': 'application/json', ...(d.headers || {}) },
      })
    }
    if (typeof next === 'function') return next(request, event)
    // What NextResponse.next() does, without importing next here.
    return new Response(null, { headers: { 'x-middleware-next': '1' } })
  }
}

// Next.js 16 renamed middleware to proxy: the same function, a clearer name for the new file.
export const bitoraProxy = bitoraMiddleware
