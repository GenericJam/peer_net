# PeerNet — Implementation plan

> Status: in-progress, v1 scoped to walkie-talkie chat + asymmetric BEAM-dist
> compatibility. Initiated 2026-05-05.

## Why this exists

The Erlang/Elixir ecosystem has nothing in the gap between:

- **BEAM distribution** — ergonomic, but cookie-based trust = remote shell on
  every cluster member. Unsafe between mutually-suspicious peers.
- **HTTP / Phoenix Channels** — safe, but client-server, needs infrastructure.
- **WebRTC, libp2p, Iroh** — peer-to-peer, but heavyweight and not BEAM-native.

PeerNet aims to fill it: BEAM-dist-shaped ergonomics (`expose` / `call` / `send`)
between mutually-suspicious peers, with cryptographic identity and default-deny
authorization. Pure-Elixir, transport-pluggable, no infrastructure.

## Goals (v1)

- **Default-deny.** No handle is reachable from a peer until explicitly
  `expose`'d. No `:rpc.call` shell, no remote code load, no remote process
  introspection.
- **Cryptographic peer identity.** Ed25519 keypairs; pubkey is the address;
  trust list is explicit (paired peers only).
- **Network resilience.** Pubkey = logical address. Peers reconnect across
  IP changes, network switches, and transient disconnects without app code
  knowing.
- **BEAM dist coexistence.** Runs alongside regular Erlang dist on the same
  node; no port conflicts. Optional `PeerNet.BeamDist` convenience module
  for asymmetric full-access scenarios (e.g. phone controlling Nerves).
- **Walkie-talkie semantics.** Drop-by-default on offline send. No
  store-and-forward, no ack/retry, no message ordering guarantees beyond
  per-connection FIFO.
- **Same-network discovery.** mDNS for peer discovery. Internet-spanning is
  out of scope for v1.

## Non-goals (v1)

- Group chat / multi-recipient messaging
- NAT traversal / hole punching
- Offline message queueing
- File transfer / large payload streaming
- iOS background mode workarounds
- Cross-language wire interop (BEAM-only for v1)

## Architecture

```
                  ┌──────────────────────────────────────┐
                  │       PeerNet (public API)           │
                  │  expose / call / send / pair / list  │
                  └──────────────────────────────────────┘
                                    │
        ┌───────────────────────────┼───────────────────────────┐
        │                           │                           │
   ┌────────────┐            ┌──────────────┐            ┌──────────────┐
   │ Identity   │            │ Trust        │            │ Handlers     │
   │ keypair    │            │ allowlist    │            │ registered   │
   │ persisted  │            │ persisted    │            │ {name → fn}  │
   └────────────┘            └──────────────┘            └──────────────┘
                                    │
                    ┌───────────────┴────────────────┐
                    │                                │
              ┌──────────┐                    ┌──────────────┐
              │ Registry │  ← pubkey → state  │ Discovery    │
              │ (state)  │ ←─────────────────→│ (mDNS)       │
              └──────────┘                    └──────────────┘
                    │
                    │  manages connections (DynamicSupervisor)
                    ▼
   ┌─────────────────────────────────────────────────────────────┐
   │  Connection (1 per peer)                                    │
   │  ├─ Handshake (Noise XX, Ed25519 verify, AEAD wrap)         │
   │  ├─ Frame (length-prefixed safe ETF)                        │
   │  ├─ Liveness (app-level ping/pong)                          │
   │  └─ Reconnector (exponential backoff)                       │
   └─────────────────────────────────────────────────────────────┘
                    │
              ┌─────┴──────┐
              │ TCP socket │
              └────────────┘
```

## Module breakdown + line estimates

| Module                       | Est. lines | Pure? | Notes                                   |
|------------------------------|-----------:|:-----:|-----------------------------------------|
| `PeerNet`                    |     ~80    |   N   | Public API surface                      |
| `PeerNet.Application`        |     ~30    |   N   | OTP app                                 |
| `PeerNet.Supervisor`         |     ~40    |   N   | Top-level supervision tree              |
| `PeerNet.Identity`           |    ~100    |   Y   | Ed25519 keypair gen / load / save       |
| `PeerNet.Trust`              |     ~80    |   Y   | Allowlist of peer pubkeys               |
| `PeerNet.Handlers`           |     ~80    |   Y   | Exposed handle registry + dispatch      |
| `PeerNet.Frame`              |     ~80    |   Y   | Length-prefix framing + safe ETF        |
| `PeerNet.Registry`           |    ~120    |   N   | Pubkey-keyed state, transitions         |
| `PeerNet.Discovery`          |    ~100    |   N   | mDNS announce + listen via mdns_lite    |
| `PeerNet.Connection`         |    ~250    |   N   | TCP + Noise + framing + lifecycle       |
| `PeerNet.Connection.Sup`     |     ~30    |   N   | DynamicSupervisor                       |
| `PeerNet.Handshake`          |    ~150    |   ~   | Noise XX state machine                  |
| `PeerNet.Liveness`           |     ~50    |   N   | App-level heartbeat                     |
| `PeerNet.Reconnector`        |     ~60    |   N   | Exponential backoff                     |
| `PeerNet.NetworkMonitor`     |     ~80    |   N   | IP-change events (polling default impl) |
| `PeerNet.BeamDist`           |     ~80    |   Y   | Opt-in RPC-like handle for asym trust   |
| **Total**                    |  **~1410** |       | + tests ≈ 2–3× the impl size            |

## Wire format

Length-prefixed framing over TCP. Each frame:

```
| 4-byte big-endian length | Noise-AEAD-encrypted payload |
```

Inner payload, after Noise decrypt:

```elixir
{:call,    request_id, handle_name, args}    # → reply expected
{:reply,   request_id, result}               # match by request_id
{:send,    handle_name, args}                # fire-and-forget
{:ping,    nonce}                            # liveness
{:pong,    nonce}                            # liveness reply
{:error,   request_id, reason}               # call failed
```

Encoded via `:erlang.term_to_binary/2` with `[:safe]` decoding via
`:erlang.binary_to_term/2` — defends against atom-exhaustion attacks.

`request_id` is a 64-bit random integer. Replies match on it.

## Cryptography

- **Identity**: Ed25519 keypair via `:crypto.generate_key(:eddsa, :ed25519)`.
- **Handshake**: Noise XX pattern (mutual auth, both sides learn each
  other's static keys). Both sides verify the other's static key against
  the trust list before completing the handshake.
- **Transport AEAD**: ChaCha20-Poly1305 via the Noise CipherState.
- **Library decision**: Depend on a maintained Noise crate for v1
  (e.g. `noise_ex`). If none is suitable, vendor a minimal Noise XX
  implementation built on `:crypto` primitives. Document the choice in
  `lib/peer_net/handshake.ex` so it can be swapped later.

## BEAM dist compatibility (asymmetric trust)

PeerNet does **not** speak the disterl wire protocol. It coexists with
disterl (different ports, different transport, no conflict).

The asymmetric-trust use case (e.g. phone controlling Nerves) is served by
an opt-in convenience module:

```elixir
# On the Nerves device — explicit grant per peer:
PeerNet.expose(:beam_admin, &PeerNet.BeamDist.handle/2,
  authorize: fn pubkey -> pubkey == @phone_pubkey end)

# On the phone — RPC-style sugar:
PeerNet.BeamDist.call(nerves_pubkey, MyMod, :restart_wifi, [])
PeerNet.BeamDist.cast(nerves_pubkey, Logger, :info, ["hi from phone"])
```

Internally, `BeamDist.handle/2` accepts `{:rpc, mod, fun, args}` tuples and
calls `apply(mod, fun, args)`. The grant is explicit per pubkey; without
it, the handle is unreachable. This gives BEAM-dist-equivalent semantics
where you actually want them, gated by cryptographic identity.

Asymmetric: only the granted peer can make calls. The Nerves device cannot
reciprocally RPC the phone unless the phone separately grants.

## TDD order

Implement bottom-up so each module's tests can run without mocking the
next layer:

### Phase 1 — pure modules (no network)

1. **`PeerNet.Identity`** — keypair generation, persistence, fingerprinting.
   Pure functions, file I/O. Tests use `tmp_dir` fixtures.
2. **`PeerNet.Trust`** — pubkey allowlist with persistence. Pure logic.
3. **`PeerNet.Frame`** — encode / decode roundtrip, malformed input rejection,
   atom-exhaustion defense.
4. **`PeerNet.Handlers`** — register, lookup, default-deny. Pure logic.

### Phase 2 — networked modules

5. **`PeerNet.Handshake`** — Noise XX state machine. Test via in-process
   pairs (initiator + responder in the same BEAM, byte-buffer transport).
6. **`PeerNet.Connection`** — full connection lifecycle. Test via two
   connections on `127.0.0.1` in the same BEAM.
7. **`PeerNet.Registry`** — peer state tracking. Test in isolation with
   simulated events.
8. **`PeerNet.Liveness` + `Reconnector`** — small modules, tested with
   simulated time / process-message-injection.
9. **`PeerNet.NetworkMonitor`** — define behaviour, ship a polling default,
   test with a mock implementation.

### Phase 3 — discovery + integration

10. **`PeerNet.Discovery`** — mdns_lite wrapper. Hardware-dependent
    integration tests under `@tag :integration`.
11. **End-to-end integration tests** — two PeerNet instances in the same
    BEAM, full pair / send / call / disconnect / reconnect flow.

### Phase 4 — convenience

12. **`PeerNet.BeamDist`** — RPC-style sugar layer, ~80 lines on top of the
    primitives.

## Documentation

- `@moduledoc` on every module describing purpose + when to use it.
- `@doc` on every public function with examples.
- `@spec` on every public function.
- `README.md` — quick-start, architecture diagram, threat model.
- `guides/protocol.md` — wire-format specification + handshake walkthrough.
- `guides/cookbook.md` — common patterns (pairing flow, BEAM-dist usage).
- Doctests where they make sense (Identity, Trust, Frame).

## Threat model (must document, not just code)

- **Adversary**: a peer on the same network who can observe and inject
  packets, but is not in the trust list.
- **Defended against**: passive eavesdropping (Noise AEAD); MITM (Noise XX
  with pubkey verification); replay (Noise nonces); denial-of-service via
  malformed wire (Frame validation, safe ETF); resource exhaustion via
  atom interning (`:safe` ETF flag); impersonation (Ed25519 sigs).
- **Not defended against**: side-channel timing, traffic analysis, peers
  in the trust list misbehaving, OS-level compromise.

## Milestones

- **M1** ✅ — Phase 1 complete. Pure modules: Identity, Trust, Frame,
  Handlers. 49 tests + 8 doctests, all green.
- **M2 (POC)** ✅ — Phase 2 transport landed in challenge-response form:
  Handshake (Ed25519 signed nonces), Connection, PeerIndex, Acceptor,
  full per-instance supervision. Two PeerNet instances in the same BEAM
  can `expose`/`call`/`send` over loopback TCP. End-to-end integration
  tests cover happy path, untrusted-peer rejection, no-such-handle, and
  fire-and-forget send.

  **Caveat**: v0 transport is **plaintext over TCP** — the channel is
  authenticated but not encrypted. Local-trusted-network only until M2.5.

- **M2.5** ✅ — Replaced challenge-response with **Noise XX**
  (`Noise_XX_25519_ChaChaPoly_SHA256`). Hand-rolled SymmetricState +
  CipherState + HandshakeState on `:crypto` primitives, ~440 lines.
  All post-handshake traffic is AEAD-encrypted via the new
  `PeerNet.Channel` module (ChaCha20-Poly1305, Noise nonce format,
  per-direction CipherStates). Identity migrated from Ed25519 to
  X25519 (the curve Noise uses for both DH and the static key). No
  public API changes — `PeerNet.expose/4`, `call/5`, `send/4` are
  unchanged. Frame layer gained a raw-bytes encode/decode path
  (`Frame.encode_raw/1`, `Frame.decode_raw/1`) so AEAD ciphertexts
  pass through without ETF double-wrapping.
- **M3 (almost complete)** ✅ — Liveness, Registry with auto-
  reconnect via exponential backoff, Discovery behaviour + Manual +
  UDP impls. Auto-discovery on a LAN works:
  `PeerNet.Discovery.UDP` broadcasts a compact 39-byte announce
  (magic + version + port + pubkey) every 5s and listens for the same
  on UDP `4040`. Discovered trusted peers are auto-dialled by the
  Registry; the resulting connection is callable as soon as the
  handshake completes.

  **Notes on mDNS vs UDP**: `mdns_lite` exposes only the announce side;
  it has no public browse API. Rolling proper mDNS browsing on
  `:gen_udp` + `:inet_dns` is ~1 session of work and gets us interop
  with iOS Bonjour and Android NSD. UDP broadcast (what we shipped) is
  simpler, works on desktop / Nerves, but needs platform-specific
  permissions on mobile (`NSLocalNetworkUsageDescription` etc).

  **For mobile**: the right layering is for the host app's NIF to
  provide a `Discovery.Bonjour` / `Discovery.NSD` impl that wraps
  platform mDNS APIs. PeerNet ships the Behaviour and the UDP
  reference impl; mob plugs in the platform-specific one.

  **NetworkMonitor** ✅ — behaviour + polling default
  implementation. Subscribers (the Registry by default) get
  `{:network_changed, change}` events. On change, Registry tears
  down all live connections so reconnect logic dials fresh sockets
  on the new network immediately.

  **Pending**: `Discovery.MDNS` (true mDNS via `:inet_dns`).

- **M4 (partial)** ✅ — `BeamDist` convenience module landed.
  Asymmetric-trust RPC: receiver exposes `:beam_admin` with an
  `authorize:` predicate per pubkey; caller invokes via
  `BeamDist.call/6` or `cast/6`. Tests cover happy path + forbidden
  + unknown-op.

  Docs polish complete: protocol.md fully describes Noise XX wire
  format and frame layering; cookbook.md has working patterns for
  every use case with test references. CHANGELOG.md tracks the
  v0.1 features.

  **Pending**: Hex `0.1.0` release (mostly admin — see
  `RELEASING.md`).
