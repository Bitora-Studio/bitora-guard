// Schema learning: what each route of YOUR app normally receives. After enough ordinary traffic the guard knows, for a route like
// POST /api/orders/:id, which top-level fields of the JSON body arrive and of what type, and which methods the route accepts. Then it notices
// what does not fit: a field nobody sends (role, is_admin, price: the shape of a mass-assignment attempt), a field that changes type (a string
// that suddenly is an object: the shape of a NoSQL operator), or a method the route never saw.
//
// It only ever keeps NAMES and TYPES, never values, in memory; it blocks nothing (it is a detector); and it does not learn from a request it
// has just flagged, so an attacker cannot teach it that the attack is normal. Its limits: a legitimate new optional field looks "unexpected"
// until it has been seen, and an attacker who sends the odd field during the first requests of a route's life is learned as normal. That is why
// it is off by default (learn: { enabled: true }): turn it on after the app has had a few days of traffic.
//
// It can also write down what it learned as an OpenAPI document or as Zod schemas, to paste into your code.

const BODY_METHODS = new Set(['POST', 'PUT', 'PATCH'])
const HOUR = 3600 * 1000

const typeOf = (v) => (v === null ? 'null' : Array.isArray(v) ? 'array' : typeof v)
const safe = (s) => String(s).replace(/[^a-z0-9_.-]/gi, '').slice(0, 40)

export function createSchema({ minSamples = 30, maxRoutes = 200, maxFields = 60, now = () => Date.now() } = {}) {
  const routes = new Map() // "METHOD /path/:id" -> { n, fields: Map(name -> { types: Set, count }) }
  const methods = new Map() // "/path/:id" -> { n, set: Map(method -> count) }
  const reported = new Map() // anomaly key -> last time it was reported

  const fresh = (key) => {
    const t = now()
    if (reported.size > 2000) reported.clear()
    if (t - (reported.get(key) || 0) < HOUR) return false
    reported.set(key, t)
    return true
  }

  // observe({ method, tpl, body, status }) -> [{ kind: 'field' | 'type' | 'method', name }]. Learns from the request when it was accepted and nothing was odd.
  function observe({ method, tpl, body, status }) {
    const m = String(method || '').toUpperCase()
    if (!m || m === 'OPTIONS' || m === 'HEAD' || !tpl) return []
    // What is odd (found) is separate from what is reported (out): the same oddity is reported once an hour, but a request that looked odd is NEVER
    // learned, however many times it repeats, so an attacker cannot teach the guard that the attack is normal.
    const found = []
    const out = []
    const note = (a) => {
      found.push(a)
      if (fresh(a.kind[0] + '|' + a.key)) out.push({ kind: a.kind, name: a.name })
    }

    const mm = methods.get(tpl)
    if (mm && mm.n >= minSamples && !mm.set.has(m)) note({ kind: 'method', name: m, key: m + ' ' + tpl })

    const key = m + ' ' + tpl
    const r = routes.get(key)
    const hasBody = BODY_METHODS.has(m) && body && typeof body === 'object' && !Array.isArray(body)
    if (hasBody && r && r.n >= minSamples) {
      let reportedHere = 0
      for (const [k, v] of Object.entries(body)) {
        if (reportedHere >= 3) break
        const f = r.fields.get(k)
        if (!f) {
          note({ kind: 'field', name: k, key: key + '|' + k })
          reportedHere++
        } else if (v !== null && f.count >= 5 && !f.types.has(typeOf(v))) {
          note({ kind: 'type', name: k, key: key + '|' + k })
          reportedHere++
        }
      }
    }

    // Learn only from what the app accepted and did not look odd.
    if (found.length === 0 && status > 0 && status < 400) {
      const entry = mm || { n: 0, set: new Map() }
      if (!mm && methods.size < maxRoutes) methods.set(tpl, entry)
      if (mm || methods.has(tpl)) {
        entry.n++
        entry.set.set(m, (entry.set.get(m) || 0) + 1)
      }
      if (hasBody && (r || routes.size < maxRoutes)) {
        const rt = r || { n: 0, fields: new Map() }
        if (!r) routes.set(key, rt)
        rt.n++
        for (const [k, v] of Object.entries(body).slice(0, maxFields)) {
          const f = rt.fields.get(k) || (rt.fields.size < maxFields ? { types: new Set(), count: 0 } : null)
          if (!f) continue
          if (!rt.fields.has(k)) rt.fields.set(k, f)
          f.count++
          if (v !== null) f.types.add(typeOf(v))
        }
      }
    }
    return out
  }

  function exported() {
    const list = []
    for (const [key, r] of routes) {
      const [method, ...rest] = key.split(' ')
      list.push({
        method,
        path: rest.join(' '),
        samples: r.n,
        fields: [...r.fields].map(([name, f]) => ({ name, types: [...f.types], required: f.count === r.n })),
      })
    }
    return { routes: list }
  }

  const OPENAPI_TYPE = { string: 'string', number: 'number', boolean: 'boolean', object: 'object', array: 'array' }
  function openapi() {
    const paths = {}
    for (const r of exported().routes) {
      const props = {}
      for (const f of r.fields) props[f.name] = f.types.length === 1 ? { type: OPENAPI_TYPE[f.types[0]] || 'string' } : { oneOf: f.types.map((t) => ({ type: OPENAPI_TYPE[t] || 'string' })) }
      const op = { requestBody: { content: { 'application/json': { schema: { type: 'object', properties: props, required: r.fields.filter((f) => f.required).map((f) => f.name), additionalProperties: false } } } }, responses: { 200: { description: 'ok' } } }
      ;(paths[r.path] ||= {})[r.method.toLowerCase()] = op
    }
    return { openapi: '3.0.3', info: { title: 'Learned by @bitora/guard', version: 'learned' }, paths }
  }

  const ZOD_TYPE = { string: 'z.string()', number: 'z.number()', boolean: 'z.boolean()', object: 'z.record(z.unknown())', array: 'z.array(z.unknown())' }
  function zod() {
    const lines = ["import { z } from 'zod'", '', 'export const schemas = {']
    for (const r of exported().routes) {
      const fields = r.fields.map((f) => {
        const t = f.types.length === 0 ? 'z.null()' : f.types.length === 1 ? ZOD_TYPE[f.types[0]] || 'z.unknown()' : 'z.union([' + f.types.map((x) => ZOD_TYPE[x] || 'z.unknown()').join(', ') + '])'
        return '    ' + JSON.stringify(f.name) + ': ' + t + (f.required ? '' : '.optional()') + ','
      })
      lines.push('  ' + JSON.stringify(r.method + ' ' + r.path) + ': z.object({', ...fields, '  }).strict(),')
    }
    lines.push('}')
    return lines.join('\n')
  }

  return { observe, export: exported, openapi, zod, safeName: safe }
}
