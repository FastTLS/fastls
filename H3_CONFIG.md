# Go H3 controlled configuration — v0.2.0

`Options.HTTP3 *HTTP3Config` is Go-only and requires `HTTPVersion3`. A non-nil
configuration with auto, H1/H2, or only the legacy q selector is rejected before
DNS/dial. Nil and an empty configuration preserve the existing explicit-H3
defaults. Dependencies remain unchanged, including quic-go v0.57.1.

```go
keepAlive := time.Duration(0) // Explicitly disabled; nil preserves H3's default.
options := fastls.Options{
    HTTPVersion: fastls.HTTPVersion3,
    VerifyTLS: true,
    HTTP3: &fastls.HTTP3Config{
        InitialStreamReceiveWindow: 64 << 10,
        MaxStreamReceiveWindow: 1 << 20,
        InitialConnectionReceiveWindow: 128 << 10,
        MaxConnectionReceiveWindow: 2 << 20,
        MaxIdleTimeout: 30 * time.Second,
        KeepAlivePeriod: &keepAlive,
        MaxResponseHeaderBytes: 64 << 10,
    },
}
effective, err := options.EffectiveHTTP3Config() // No network I/O.
if err != nil { return err }
_ = effective
session, err := fastls.NewSession(options)
if err != nil { return err }
defer session.Close()
fixed, ok := session.EffectiveHTTP3Config() // Independent value copy.
_, _ = fixed, ok
```

This function-body fragment imports `time` and `github.com/FastTLS/fastls` and
returns an error. `HTTP3Capabilities()` returns a fresh seven-field discovery
list with names, units, defaults and ranges. It does not claim peer negotiation.
The executable `ExampleHTTP3Config` checks default normalization and snapshotting.

## Defaults and accepted values

- Initial stream receive window: zero selects 512 KiB.
- Maximum stream receive window: zero selects 6 MiB.
- Initial connection receive window: zero selects 512 KiB.
- Maximum connection receive window: zero selects 15 MiB.
- All four windows accept 4 KiB..64 MiB inclusive; each normalized initial value
  must be no greater than its corresponding maximum. Receive credit limits
  buffered outstanding data, not total transferred bytes. Auto-tuning can grow
  the receive window to its maximum; cumulative MAX_DATA/MAX_STREAM_DATA offsets
  can exceed that maximum as the application consumes data. This is not a
  preallocation or a process-wide memory cap.
- `MaxIdleTimeout`: zero selects 30s; otherwise whole milliseconds in 100ms..24h.
  It is the local post-handshake inactivity limit. Backend PTO/ACK behavior and
  the peer's limit affect observed timing; it is not a precise wall-clock timer.
  The fixed backend normalizes a received peer idle parameter to at least 5s
  before its peer-side qlog reports it. A local 400ms setting can therefore appear
  as 5s in that server's parsed trace while actually closing locally near 400ms.
- `KeepAlivePeriod`: nil selects min(10s, normalized local idle timeout/2),
  preserving the H3 transport default; a pointer to zero disables periodic
  keepalive. Explicit nonzero values accept 10ms..local idle timeout/2. Negotiated
  peer idle limits can further shorten the actual interval. Disabling periodic
  keepalive does not prohibit QUIC recovery/PTO PING packets.
- `MaxResponseHeaderBytes`: zero selects 10 MiB; explicit 1 KiB..16 MiB inclusive.
  The backend checks each encoded HEADERS frame and initial decoded header field
  section (including its per-field overhead). Informational sections have the
  backend's separate count limit. Response trailers receive the encoded-frame
  check, **not an equivalent aggregate decoded trailer check**. This is not a
  combined header+trailer, body, decompression, or total-memory limit. Use
  request contexts, `MaxDecodedBytes` with decoding enabled, and bounded body
  reads independently. No unbounded option is provided.

Negative durations, fractional-millisecond idle values, oversized integers,
initial/max conflicts and unsupported combinations fail locally. Window zero
means a documented default, not a zero-byte wire window or unlimited memory.
The implementation rejects out-of-range values before backend clipping.

## Identity, ownership and security

Request preparation and Session creation deep-copy the seven fields, including
KeepAlivePeriod's target. Caller mutation after creation and mutation of an
inspection result do not affect an existing Session. Do not race caller writes
with request preparation. The normalized configuration belongs to that owner's
round tripper and its origin transports; there is no global H3 pool, and
RequestOptions cannot replace it. Different owners, configurations and policies
therefore never share a QUIC transport. Create another Session to change limits.

Set `VerifyTLS: true` explicitly; Go's historical zero value remains unchanged.
CA trust/SNI and [AddressPolicy](ADDRESS_POLICY.md) remain independent. Under a
policy every new connection checks all DNS answers, binds a connected numeric
UDP peer, and rejects migration to another peer. Configuring these budgets never
changes TLS, peer selection or proxy support. Existing proxy, TCP/H1/H2 Spec,
TLS override, header-order and request-trailer conflicts still fail. Only HTTPS
is allowed on every forced-H3 hop; no TCP fallback or automatic Alt-Svc is added.
Keepalive does not extend request total/stage deadlines. An active response owns
its transport until body EOF/error/Close; cancellation/Close releases uploads
and sockets without canceling a sibling or another owner.

ABI, Python, Node, Fetch/RPC and MITM retain their published fields and fixed
core versions. This Go release does not update their dependency pins or establish
browser H3 fingerprints, arbitrary SETTINGS/QPACK/order, 0-RTT or UDP proxies.

## Frozen validation and resource budget

Development uses affected tests and live faults. The main candidate runs three
systems × Go 1.26.10/1.27.3, Linux race, and one clean immutable Go consumer with
legacy profile requests and the new Go snapshot API. Live server-side QUIC
traces prove the initial windows, cumulative credit growth and upper bounds;
fast then slow 2 MiB consumption must exercise growth beyond both initial
windows. The predeclared outstanding-credit allowance is the configured maximum
plus 16 KiB for H3 framing/control bytes; cumulative offsets are not compared
against window sizes. Other tests cover idle vs keepalive, header/trailer
rejection, trusted policy/SNI, denials, deadlines, active ownership, cancellation,
blocked uploads, owner isolation and reconnect. A rejected header can evict a
connection from the backend cache; independent ownership keeps it available for
graceful close once active sibling bodies finish, before destroying its UDP
socket. A live peer regression checks both sibling survival and prompt peer
connection retirement. Default H1/H2/q tests remain.

One opt-in Linux test (`FASTLS_H3_RESOURCE=1`) runs for 300 seconds without race
instrumentation. Four concurrent workers repeatedly create/close owners: two
use defaults; two use 16/64 KiB stream and 32/128 KiB connection windows, 1 KiB
headers and periodic keepalive disabled. Each cycle consumes a 256 KiB bounded
body with a 256 KiB decoded cap, tests a 4 KiB header, and cancels a live response
after 20ms. Normal requests have a two-second bound and cycles pause 50ms.

Samples use GC then /proc RSS/FD, Go heap and goroutine counts once per second.
Baseline is the median samples 6..10; tail is the median of the final 10th..6th
samples. All samples count toward peaks. Minimum 290 samples; all four workers
must complete; up to two seconds cleanup must leave zero active peer handlers.
Frozen limits: peak RSS <=384 MiB and baseline+128 MiB; tail RSS <=baseline+64
MiB; tail heap <=baseline+32 MiB; peak/tail FD <=baseline+32/+16;
peak/tail goroutines <=baseline+128/+32. Two default 15 MiB connection caps plus
two 128 KiB caps account for about 31 MiB outstanding receive credit; the growth
allowance also reserves server buffers, TLS/QUIC state and Go allocator/runtime
headroom. These are scenario regression budgets, not universal process limits
or throughput claims. Inputs and thresholds are frozen before the run.

Only changes to H3/resource inputs select this observation; unrelated patches
and documentation do not rerun it. Release tags verify successful exact-commit
main CI instead of running the same matrix or five-minute observation again.
The standalone external-consumer matrix remains manual/module-change coverage.
