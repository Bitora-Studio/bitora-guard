# @bitora/guard

Protection that runs on **your** server. It limits requests, caps the endpoints that cost money (AI), checks
automation on the paths you choose, **reads the answers of your app** to spot brute force, credential stuffing, scans and
id sweeps, and tells Bitora Security what it saw so it shows up in your panel. **It needs an active Bitora Security subscription** (see [Licence](#licence-and-subscription)).

- **Fast and local.** The decision is made in your process in well under a millisecond.
- **Fail-open.** If Bitora does not answer, the request goes through. Your site does not depend on ours.
- **Observe first.** The default mode only reports what it would have done. Switch to `mode: 'enforce'` when you are happy.
- **No dependencies.** Node 18+ and edge runtimes.

## What it detects from the answers (2.0)

A gate in front of the app only sees requests. This package also sees the status of each answer and who the user was, which
is what separates a failed login from a good one. Adapters call `guard.observe(req, { status })` after your app answers
(Express and Hono do it for you; in Next.js wrap the handler with `guard.route`, because `proxy.ts` / `middleware.ts` never
see the answer; Deno does it in `bitoraDeno`).

| Rule | Fires when | Default |
| --- | --- | --- |
| `brute_force` | 10 failed logins on one account or from one address in 10 min, or 30 / 40 in a day (slow attacks) | on, for `login.paths` |
| `credential_stuffing` | one address fails on 8 different accounts in 10 min (15 for a whole /24) | on |
| `password_spraying` | 25 different accounts fail once or twice across the site in 10 min. Blames no address | on |
| `user_enumeration` | 5 unknown accounts from one address (you say it: `guard.auth.failed({ reason: 'unknown_user' })`) | on |
| `scan_probe` | 12 different pages answering 404/405 from one address in a minute | on |
| `forced_browsing` | a user or address denied (401/403) on 10 different routes in a minute | on |
| `id_sweep` | 30 different ids of the same route (`/api/invoices/:id`) read by one user or address in a minute | on |
| `trap_hit` | a request for `/.env`, `/.git/`, `/wp-login.php`, `/phpmyadmin`... A site that really runs one lists it in `traps.except` | on, blocks when enforcing |
| `csrf_cross_site` | a POST/PUT/PATCH/DELETE with `Sec-Fetch-Site: cross-site` (exempt: `csrf.exempt`) | **report only** until `csrf.block: true` |
| `request_abuse` | URL over 8192 characters; a body over `limits.maxBodyBytes`; a method not in `limits.methods` | URL on; the rest off |

Tell it who the user is (`user: (req) => id`) and where logins happen (`login: { paths: ['/api/login'] }`). Events from your own
code: `guard.auth.failed({ req, username })`, `guard.auth.succeeded(...)` and `guard.event('price_tampered', { req })`.

Each finding adds points to the address (OWASP CRS scale: critical 5, error 4, warning 3, notice 2) in a score that fades
(`x·e^(-0.008·t)`, half in about 87 s) and goes through `S(x)=1/(1+e^(-0.75(x-4)))`: from 0.65 the next requests get a
`429` with `Retry-After`, from 0.88 a `403` (only when `mode: 'enforce'`; in observe the answer says `wouldHave`). The long
counters (per account and per day) catch what a score that fades would forget. A delay is never used: on serverless the owner
pays for it, so slowing down is a `429`.

**What leaves your server:** the rule, a count, the window, the points, the action, whether it would have blocked, the route
*template* (`/api/invoices/:id`) and, for your own events, a name. Never account names, passwords, ids, bodies or parameter
values: they are only counted in memory, reduced to a hash.

## The Shield (content)

It scores the path, the query, the user agent, the referer and the body when it can be read (Express after your body parser;
Hono and `guard.route` read a JSON or form body up to 64 KB). Like the OWASP Core Rule Set, each rule that matches adds points
and a request is flagged at 5. Rules: SQL injection (UNION SELECT, tautologies after a quote, stacked queries, time functions,
schema names), XSS (script tags, event handlers, `javascript:` calls), path traversal and sensitive files, wrappers (`php://`,
`file://`), shell commands, Log4Shell, NoSQL operators (`$ne`, `$where`...), prototype pollution (`__proto__`,
`constructor.prototype`), URLs to the cloud metadata address, and scanners that name themselves (sqlmap, nikto, nuclei...).

An apostrophe, a quote or `--` alone means nothing: `O'Brien`, a password like `it's--fine`, or a sentence that mentions
`select` and `from` are not flagged at level 1. `shield.paranoia: 2` adds rules that catch more and are wrong more often
(SQL-looking sentences, dangerous tags, private hosts, template expressions); it is meant to run in observe mode first.

```js
createGuard({
  secret: process.env.BITORA_SECRET,
  shield: { paranoia: 1, threshold: 5, block: true,
    exclusions: [{ match: '/api/posts', params: ['body.markdown'], rules: ['xss'] }] }, // a rich-text field
})
```

Only the id of each rule (`sqli.union`) and the NAME of the parameter (`query.q`, `body.email`) are reported. Never the value.
A flagged request adds points to the address like any other finding. **The Shield is defence in depth**: parameterised queries
and output escaping are what fix an injection. A lone `admin'--` is not blocked at level 1 (it scores less than the threshold).
It does not hook your database driver, does not read multipart uploads or bodies over 64 KB, and the rules are code in the
package, not a downloadable signed ruleset.

## Sinks and flows

**`guardFetch` (Node only, `@bitora/guard/node`)** is a `fetch` that cannot be aimed at your own network:

```js
import { guardFetch } from '@bitora/guard/node'
const safeFetch = guardFetch(guard, { allow: ['api.stripe.com', '.example.com'] }) // allow is optional
const res = await safeFetch(urlFromTheUser)   // throws BlockedUrlError (reason: private_address, scheme, port, redirect...)
```

Only http/https on ports 80/443, no `user:password@`, the name is resolved by the library and **every** address must be
public (private, loopback, link-local such as 169.254.169.254, carrier-grade NAT, IPv6 unique-local, and IPv4 hidden in
IPv6 forms are refused); the connection goes to the address that was checked, not to the name again (so DNS rebinding gets
nothing); each redirect goes through the same checks and drops `Authorization` and cookies; timeout and a size ceiling
(5 MB). A block is reported to Bitora with the reason only. `allowPrivate: true` exists for local development and turns the
protection off. It protects the requests that go through it, not other HTTP clients in your code.

**`guard.isBreached(password)`** asks Pwned Passwords with k-anonymity: only the first five characters of the SHA-1 leave your
server. Returns `{ breached, count, checked }`; if the service is down it returns `checked: false` instead of failing a sign-up.

**`guard.flow(name, { user, ip })`** spends one unit of a named budget from the `flows` option (SMS, coupons, checkout):
per user, per address and for the whole site. It answers `{ action, reasons, retryAfter }`; in observe mode `action` stays
`allow` and `wouldHave` says what it would have done.

**Sign-ups** are now reported to Bitora (reason only, never the address typed). **Streams**: `ai.wrap` follows streamed
answers and corrects the charge with the usage the stream reports (OpenAI: pass `stream_options: { include_usage: true }`;
Anthropic reports it by default); a stream that reports nothing keeps the estimate.

## Shared counters (2.1)

The detections count in the memory of each instance. For the few budgets that must add up across **every** instance of your
server (SMS, coupons, the spend of an AI endpoint, sign-ups) there is a shared store and two calls:

```js
import { createGuard } from "@bitora/guard"
import { bitoraStore, upstashStore, redisStore } from "@bitora/guard/store"

const guard = createGuard({
  secret: process.env.BITORA_SECRET,
  store: bitoraStore({ secret: process.env.BITORA_SECRET }), // or upstashStore({ url, token }) or redisStore(ioredisClient)
})

const r = await guard.limit("coupon", { key: userId, max: 3, windowSec: 3600 }) // { allowed, count, retryAfter, status }
if (!r.allowed) return res.status(r.status).end()

const s = await guard.decide("signup", { email, ip, ipSource }) // MX of the domain and sign-ups per address and per network
```

- **Stores.** `memoryStore()` (the default: this instance only), `bitoraStore` (Bitora keeps the counters, nothing to install; one
  call to Bitora per `limit`), `upstashStore` (REST, works on the edge and on Cloudflare) and `redisStore(client)` (any client with
  `incrby`, `expire` and `ttl`: ioredis, node-redis). A counter is a fixed window that starts with its first hit.
- **`guard.decide(kind, ...)`** asks Bitora for what needs a state shared by every instance or a lookup the package cannot make:
  `signup` (does the e-mail domain receive mail, MX; sign-ups per address and per /24 or /64) and `login` (attempts per account and per
  address; send an opaque identifier from `guard.accountOf`, never the name). Bitora reads the e-mail only for its domain and drops it.
  An address whose source cannot be trusted is not counted.
- Short timeout and **fail-open** everywhere: if the store or Bitora does not answer, the request goes through (`checked: false`). In
  observe mode the answer is `allow` with `wouldHave` and the event is reported.
- The list of blocked addresses is now downloaded with its tag (`ETag`): an unchanged list costs an empty `304`.

### What it does not do
- The Shield is lexical and regular-expression based (no libinjection), so an obfuscated payload can pass and a strange text
  can trip level 2. It does not replace parameterised queries or output escaping.
- Counters live in the memory of each instance. On serverless each instance counts for itself: limits are per instance, not
  global, and `password_spraying` only sees the traffic of its own instance.
- No proof-of-work challenge: where a challenge would apply, the answer is a `429`.
- Anything that goes straight from the browser to your database (Supabase, Firebase) never passes through here.
- It does not stop volumetric DDoS; that belongs to your platform's firewall.
- Next.js `proxy.ts` / `middleware.ts` alone cannot read answers, so use `guard.route` on the handlers that matter.

## Sinks: check what a value does when your code uses it

The Shield guesses from the shape of a request. A sink checks the exact moment a visitor's value does something on your server, so it catches
what the Shield missed with almost no false positives.

```js
import { createSinks } from '@bitora/guard/sinks'   // Node
const sink = createSinks(guard)

sink.sql(query, [req.query.id])          // SQL you build as text: did a value change the structure of the statement?
sink.path('/srv/uploads', req.query.f)   // the path must stay inside its folder
sink.filterValue(req.query.name)         // a value you put inside a PostgREST .or('name.eq.' + v)
sink.pick(req.body, ['name', 'email'])   // only the fields you allow reach .insert() / .update()
```

In `observe` a sink never throws: it lets the call through and reports the NAME of the sink (never the value). In `enforce` it throws a
`BlockedSinkError`; `pick` always drops the extra fields, which is the fix, and reports their names. Parameterised queries remain the right
fix for SQL: `sink.sql` is for the places where you still build it as text.

## Leaks in your own answers

`bitoraExpress(guard, { leaks: true })` reads the first 16 KB of each text answer your server sends and reports when it shows a **stack trace, a
database error, a secret (a Stripe or AWS key, a private key, the Supabase service role key, a connection string with its password) or a debug
page**. Only the KIND of leak and the route are reported, never the text. It wraps `res.write` and `res.end` (without changing what the client
receives), which is why it is off by default. For other frameworks pass the body yourself: `guard.observe(req, { status, body, contentType })`.

## Learning what each route receives

`createGuard({ learn: { enabled: true } })` learns, per route, which top-level JSON fields arrive (names and types, never values) and which methods
are used. Once it has seen enough, it reports a **field nobody sends** (the shape of a mass-assignment attempt: `role`, `is_admin`, `price`), a
**field that changes type** (a string that is suddenly an object: a NoSQL operator) and a **method the route never saw**. It blocks nothing, and it
never learns from a request it flagged. Turn it on after a few days of ordinary traffic; a legitimate new optional field looks odd until it is
seen. What it has learned can be written down for your code: `guard.schema.zod()` (strict Zod schemas) and `guard.schema.openapi()`.

## Shadow rules

Try a rule on real traffic before it is allowed to refuse anybody: `createGuard({ shield: { shadow: ['sqli.union', 'xss'] } })`. A rule (or a
whole family, without the dot) in shadow mode is evaluated and reported as "would have" but adds no points and never blocks.

## When Bitora does not answer, and the off switch

Everything the package asks of Bitora (the list of blocked addresses, per-address checks, `guard.decide`, the event batches) goes through
one circuit breaker. After five failures in a row it stops asking for 5 seconds, then lets one call through to see whether Bitora is back;
each failed probe doubles the pause (up to 5 minutes) and one answer closes the breaker. Meanwhile the traffic goes through and what was
seen waits to be sent. Your site never waits on ours.

To turn the package off completely (nothing inspected, limited or sent; the site behaves as if it were not installed) set
`BITORA_GUARD_DISABLED=1`, or pass `createGuard({ disabled: () => myFlag() })` to read your own flag on every call. `guard.license.status()`
then says `disabled`.

## Licence and subscription

From 3.0 this package works for the sites of a Bitora Security subscriber. At start it asks Bitora for a licence with the API key of your site
(`BITORA_SECRET`), checks its signature locally and renews it in the background every few hours. A licence lasts seven days, so a short
outage of Bitora does not switch anything off.

Without an active subscription, a valid key or a licence that verifies, the package **does nothing and lets all traffic through**: it never
takes your site down, and it never sends anything. It writes one line to your log saying why. `guard.license.status()` returns
`'active'`, `'inactive'` or `'checking'`, and `guard.license.reason()` tells you why it is inactive (`subscription_required`, `bad_key`,
`no_key`, `unreachable`).

In serverless, the first request of a cold instance waits up to a second and a half for the licence. To avoid even that, pass the licence you
last received: `createGuard({ secret, license: process.env.BITORA_LICENSE })`.

The terms are in [LICENSE](./LICENSE). Versions 2.0 to 2.1.2 were released under the MIT licence.

## Install

```sh
npm i @bitora/guard
```

Put the API key of your site (Sitios → Clave de la API) in an environment variable, for example `BITORA_SECRET`.

## Next.js (`middleware.ts`)

```ts
import { createGuard } from '@bitora/guard'
import { bitoraMiddleware } from '@bitora/guard/next'

const guard = createGuard({
  secret: process.env.BITORA_SECRET,
  mode: 'enforce',
  routes: [{ match: '/api/auth', max: 10, windowSec: 60 }],
  aiBudget: [{ match: '/api/ai', max: 30, windowSec: 3600 }],
  bots: { paths: ['/api/'] },
})
export default bitoraMiddleware(guard)
export const config = { matcher: ['/api/:path*'] }
```

## Next.js 16 (`proxy.ts`)

```ts
import { createGuard } from '@bitora/guard'
import { bitoraProxy } from '@bitora/guard/next'

export const proxy = bitoraProxy(createGuard({ secret: process.env.BITORA_SECRET, mode: 'enforce' }))
export const config = { matcher: ['/api/:path*'] }
```

## Deno and Supabase Edge Functions

```js
import { createGuard } from '@bitora/guard'
import { bitoraDeno } from '@bitora/guard/deno'

const guard = createGuard({ secret: Deno.env.get('BITORA_SECRET'), mode: 'enforce', trustProxy: 1 })
Deno.serve(bitoraDeno(guard, (req) => new Response('hola')))
```

## Express

```js
import { createGuard } from '@bitora/guard'
import { bitoraExpress } from '@bitora/guard/express'

app.set('trust proxy', true)
app.use(bitoraExpress(createGuard({ secret: process.env.BITORA_SECRET, mode: 'enforce' })))
```

## Hono

```js
import { createGuard } from '@bitora/guard'
import { bitoraHono } from '@bitora/guard/hono'

app.use('*', bitoraHono(createGuard({ secret: process.env.BITORA_SECRET, mode: 'enforce' })))
```

## Options

| Option | Default | What it does |
| --- | --- | --- |
| `secret` | none | The API key of your site. Without it nothing is sent to Bitora. |
| `mode` | `'observe'` | `'observe'` reports only; `'enforce'` blocks. |
| `rateLimit` | `{ max: 300, windowSec: 60 }` | Requests per IP for the whole site. |
| `routes` | `[]` | Per IP and route: `{ match, max, windowSec }`. Use it for login, sign-up and contact forms. |
| `aiBudget` | `[]` | Calls to endpoints that cost money: `{ match, max, windowSec, key }`. `key(req)` returns the user id; the IP is used otherwise. |
| `bots` | `{ paths: [], block: true }` | Known automation (curl, scripts, headless browsers) on these paths. |
| `skip` | static files | Path prefixes that are never checked. |
| `ipHeader` | none | A header your own proxy sets and a visitor cannot, for example `cf-connecting-ip` behind Cloudflare. |
| `trustProxy` | `0` | How many proxies of yours sit in front of the app. The address is then the entry that many places from the right of `x-forwarded-for`. |
| `remote` | `{ enabled: true, mode: 'list', refreshMs: 30000, blocking: false, timeoutMs: 100, cacheMs: 60000 }` | `'list'` downloads the addresses Bitora wants blocked every `refreshMs` and checks them in memory (one call per refresh, however many visitors). `'ip'` asks about each new address and caches the answer for at most `cacheMs`. Not blocking: no request waits for Bitora. |
| `report` | `{ enabled: true, flushMs: 20000, maxBatch: 50 }` | Send what was seen to Bitora in batches. |

### AI spend

`guard.ai.wrap(client, { user })` returns your OpenAI or Anthropic client with its `create()` calls counted in tokens:

```js
const openai = guard.ai.wrap(new OpenAI(), { user: () => session.userId })
await openai.chat.completions.create({ model: 'gpt-4o-mini', messages })   // throws GuardBudgetError (status 429) when a budget is spent
```

Before the call it charges an estimate (a quarter of the characters of the request plus the output it may ask for), after it
settles with the `usage` of the answer. When enforcing it also caps the output a request may ask for (`ai.maxOutputTokens`).
Two budgets apply: `ai.perUser` (per user, or per IP if you give none) and `ai.global`, a ceiling for the whole site that
protects against an open endpoint spending your money. Streaming calls keep the estimate, because their usage is not known.
Pass `{ ip, ipSource }` to have the refusals reported to Bitora. The counters are in memory, per instance.

### Sign-ups

`guard.signup({ email, ip })` returns `{ action: 'allow' | 'block', reasons }`. It checks the shape of the address, whether its
domain is a throw-away one (a short built-in list, plus `signup.extraDisposable`), and how many sign-ups come from the same
address (`signup.perIp`) and the same network, a /24 or a /64 (`signup.perNetwork`). Call it in your sign-up handler before
creating the account.

### Where the address comes from

The address of the visitor is never read from a header the visitor can write. It comes from: the header you name in `ipHeader`; on Vercel, `x-vercel-forwarded-for`; `trustProxy` entries from the right of `x-forwarded-for`; or, on Node, the socket (and, when the socket is a private address because a proxy of yours is in front, the last entry of `x-forwarded-for`). With none of these the address is unknown: nothing is limited or reported by address, and the events carry no reputation. Every event says where its address came from (`ip_source`).

The counters live in the memory of each instance. On a serverless platform each instance counts for itself, so a
limit is an upper bound per instance, not a global one.

What it cannot do: it does not protect traffic that never reaches your server (for example a browser talking straight to
your database), and it does not replace validating input in your code.
