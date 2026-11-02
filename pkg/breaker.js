// A circuit breaker for the calls the package makes to Bitora (the list of blocked addresses, the per-address check, the decisions and
// the event batches). When Bitora does not answer several times in a row, the package stops asking for a while and lets the traffic
// through, instead of spending a connection and a timeout on every request of a server that is already having a bad time. After the
// pause it lets one call through to see whether Bitora is back; one answer closes the breaker, one more failure doubles the pause.
//
// createBreaker({ now, threshold, baseMs, maxMs }) -> { allow, ok, fail, state }
//   allow()  may a call be made now?  (closed: yes; open: no, until the pause is over; then exactly one probe at a time)
//   ok()     the call worked
//   fail()   the call failed or timed out
export function createBreaker({ now = () => Date.now(), threshold = 5, baseMs = 5000, maxMs = 300000 } = {}) {
  let failures = 0
  let openUntil = 0
  let pause = baseMs
  let probing = false
  return {
    allow() {
      if (failures < threshold) return true
      if (now() < openUntil || probing) return false
      probing = true // the pause is over: one call tries, the rest wait for its answer
      return true
    },
    ok() {
      failures = 0
      pause = baseMs
      probing = false
      openUntil = 0
    },
    fail() {
      failures++
      probing = false
      if (failures >= threshold) {
        openUntil = now() + pause
        pause = Math.min(pause * 2, maxMs)
      }
    },
    state: () => (failures < threshold ? 'closed' : now() < openUntil || probing ? 'open' : 'half-open'),
  }
}
