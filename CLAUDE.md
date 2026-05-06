# PeerNet — Agent Instructions

5-minute orientation for future Claude sessions on this repo.

## What this is

Default-deny peer-to-peer messaging library for Elixir. Pure Elixir
on top of `:crypto` and `:gen_tcp`/`:gen_udp` — no NIF deps, no
runtime deps beyond `ex_doc` (dev-only). Pre-release; no Hex
release yet.

The pitch: BEAM-distribution-shaped ergonomics (`expose` / `call` /
`send`) between mutually-suspicious peers. Cryptographic identity,
Noise XX handshake, ChaCha20-Poly1305 transport encryption,
walkie-talkie semantics (drop on offline send), pluggable
LAN discovery.

**Read these files in this order before doing anything:**

1. `README.md` — public-facing pitch and threat model
2. `PLAN.md` — milestone tracker; tells you what's done vs pending
3. `guides/protocol.md` — the actual wire format, byte-by-byte
4. `guides/cookbook.md` — working patterns with test references
5. `CHANGELOG.md` — what landed when

## Pre-commit checklist

Run **all four** in this order, every commit:

```bash
mix test                            # 90 tests + 8 doctests; flaky tests are not OK
mix credo --strict                  # zero issues; the bar is set
mix compile --warnings-as-errors    # also zero
mix format                          # standard
```

Run `mix test` 3+ times if you've touched anything timing-sensitive
(Liveness, Reconnector, Discovery). The Liveness tests in particular
have ~50ms timing windows.

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
   │ X25519     │            │ allowlist    │            │ {name → fn}  │
   └────────────┘            └──────────────┘            └──────────────┘
                                    │
                    ┌───────────────┴───────────────┐
                    │                               │
              ┌──────────┐                   ┌──────────────┐
              │ Registry │ ← pubkey → state →│ Discovery    │
              │ (state)  │                   │ (UDP / Manual)│
              └──────────┘                   └──────────────┘
                    │ ↑
                    │ ↑ {:network_changed}
                    │ ↑
              ┌──────────────────┐
              │ NetworkMonitor   │
              │ (Polling)        │
              └──────────────────┘
                    │
                    ▼
   ┌─────────────────────────────────────────────────────────────┐
   │  Connection (TCP + Noise XX → AEAD Channel + Liveness)      │
   └─────────────────────────────────────────────────────────────┘
```

Each PeerNet instance is a `Supervisor` started by
`PeerNet.start_link(name: ..., data_dir: ..., port: ...)`. All child
processes are named with the instance name as a prefix
(`:alice.trust`, `:alice.registry`, etc) so multiple instances can
coexist in one BEAM (we use this in tests).

## Module map

| Module | What |
|---|---|
| `PeerNet` | Public API + per-instance Supervisor |
| `PeerNet.Identity` | X25519 keypair, persistent keyfile (magic `PNID 0x02`) |
| `PeerNet.Trust` | Persisted pubkey allowlist (GenServer + DETS-shaped binary) |
| `PeerNet.Handlers` | Default-deny handle registry; per-handle `:authorize` predicate |
| `PeerNet.Frame` | 4-byte-length framing; `encode/decode` (ETF-safe); `encode_raw/decode_raw` (opaque bytes) |
| `PeerNet.Handshake` | Noise XX state machine — `Noise_XX_25519_ChaChaPoly_SHA256` |
| `PeerNet.Channel` | Post-handshake AEAD wrapper; one CipherState per direction |
| `PeerNet.Connection` | Per-peer GenServer; owns socket; runs handshake then routes envelopes |
| `PeerNet.Connection.Supervisor` | DynamicSupervisor for connections |
| `PeerNet.Acceptor` | TCP listener; spawns inbound Connections |
| `PeerNet.Registry` | Pubkey-keyed peer state; auto-connect on discovery; auto-reconnect with backoff |
| `PeerNet.Discovery` | Behaviour |
| `PeerNet.Discovery.Manual` | No-op impl; tests + manual setups push events |
| `PeerNet.Discovery.UDP` | LAN broadcast (39-byte announce on UDP 4040) |
| `PeerNet.NetworkMonitor` | Behaviour |
| `PeerNet.NetworkMonitor.Polling` | Polls `:inet.getifaddrs` every 5s |
| `PeerNet.Liveness` | App-level ping/pong heartbeat per Connection |
| `PeerNet.BeamDist` | Convenience for asymmetric-trust RPC (phone-controls-Nerves) |

## Things that look weird but are intentional

- **Identity is X25519, not Ed25519.** Noise XX uses X25519 for DH
  on the static key. We don't need separate signing because the
  Noise transcript hash + AEAD authenticate everything. Old
  Ed25519 keyfiles (magic `0x01`) are explicitly rejected on load.

- **Frame has both `encode/decode` and `encode_raw/decode_raw`.**
  During handshake, body bytes are ETF-encoded terms (Noise XX M1
  is just the ephemeral pubkey, but other patterns might differ).
  After handshake, body bytes are AEAD ciphertexts that should NOT
  be ETF-wrapped. Different code paths use different functions.

- **`:erlang.binary_to_term/2` is always called with `[:safe]`.**
  Both Frame and Channel decoders use this. Defends against atom-
  exhaustion DoS even from peers with valid session keys. If you
  ever introduce a place that decodes from an untrusted source
  without `:safe`, that's a security bug.

- **No mDNS yet, just UDP broadcast.** `mdns_lite` only exposes the
  advertise side; rolling proper mDNS browsing would have been ~1
  session of work. UDP broadcast covers desktop/Nerves use cases.
  For mobile, the right layering is for the host app's NIF
  (mob's iOS/Android bridges) to provide a `Discovery.Bonjour` or
  `Discovery.NSD` impl. PeerNet ships the Behaviour and the UDP
  reference impl; platform code plugs in.

- **Tests use `@moduletag :tmp_dir`, not hand-built `/tmp` paths.**
  We hit this twice: stale Ed25519 keyfiles in `/tmp` from prior
  test runs colliding with the new X25519 magic. ExUnit's
  `:tmp_dir` gives per-test isolated dirs. Don't use
  `System.tmp_dir!() <> "_#{System.unique_integer/1}"` for
  identity-bearing tests.

- **`PeerNet.start_link` defaults discovery to `Manual`** (no auto-
  broadcast). Real apps pass `discovery: PeerNet.Discovery.UDP`.
  Tests don't (Manual lets them drive events deterministically).

- **`NetworkMonitor` is opt-in.** Pass `network_monitor:
  PeerNet.NetworkMonitor.Polling` to wire it; otherwise nothing
  watches IP changes. Mobile apps want this; desktop apps usually
  don't need it.

## Status

Per `PLAN.md`:

- **M1 / M2 / M2.5 / M3 / M4** all complete (POC → Noise → discovery
  + reconnect → docs polish).
- **Pending before Hex `0.1.0`:** `Discovery.MDNS` (deferred to
  v0.2), Hex publishing admin (see `RELEASING.md`).

Code base: ~4900 lines. 90 tests + 8 doctests. `mix credo --strict`
zero issues. `mix compile --warnings-as-errors` clean.

## Gotchas

- **OTP 28 + Hex 2.4.1 incompatibility.** `mix hex.build` and `mix
  hex.publish` call `:re.import/1` which was removed in OTP 28.
  Until Hex publishes a fix, run those from an OTP 27 BEAM. The
  `mix.exs` package metadata is correct; it's purely a tooling
  issue.

- **`:gen_tcp.controlling_process/2` must be called from the
  current owner.** The Acceptor accepts in a worker process, then
  has to transfer ownership *to* the parent before the parent can
  hand it off to the Connection. See `lib/peer_net/acceptor.ex`'s
  `accept_loop/2`.

- **The Noise XX implementation is hand-rolled.** ~440 lines on
  top of `:crypto`. Cryptographic correctness was verified against
  the Noise spec's test vectors implicitly (the test "completes when
  both parties trust each other" + "produces a working
  bidirectional cipher channel after handshake" together prove the
  full pattern). If you change `lib/peer_net/handshake.ex`, run
  the tests AND re-read the spec section relevant to your change.

- **Liveness uses per-ping check timers, not a single rolling
  timer.** Earlier design had a single "outstanding nonce" that
  was replaced on each tick — but a late-but-valid pong from an
  earlier ping would be dropped, and the original ping's check
  would never fire because outstanding had been replaced. Each
  in-flight ping owns its own check timer; pong cancels it.
  Don't "simplify" this.

- **`:erlang.binary_to_term/2 [:safe]` rejects atoms not already
  known to the BEAM.** The atom-exhaustion test in
  `frame_test.exs` constructs raw ETF bytes by hand to avoid
  compile-time interning the test atom. If you write a similar
  test, do the same — `:erlang.term_to_binary(:my_atom)` will
  intern it at compile time and your test will pass for the wrong
  reason.

## Where to look first when

| Question | File |
|---|---|
| What's the public API shape? | `lib/peer_net.ex` |
| What does the wire actually look like? | `guides/protocol.md`, then `lib/peer_net/handshake.ex` + `lib/peer_net/channel.ex` |
| How do I write an app on top of this? | `guides/cookbook.md` |
| Why is X this way? | `PLAN.md` (decisions) and `CHANGELOG.md` (history) |
| What's a peer's lifecycle? | `lib/peer_net/registry.ex` (pubkey state machine) and `lib/peer_net/connection.ex` (socket lifecycle) |
| How do I publish to Hex? | `RELEASING.md` |
| Which tests cover X? | Each cookbook section names the test file |

## Don't do

- Don't add features without tests. The TDD bar is "test first or
  test alongside, never test later." 90/8 → 91/8, never 90/8 → 90/8.
- Don't reach for new dependencies. The whole point of the lib is
  to be a small, auditable, BEAM-native artifact. The only deps
  are dev-only docs (`ex_doc`) and dev-only static analysis
  (`credo`). Adding a runtime dep needs a strong justification.
- Don't merge code that has `mix credo --strict` warnings or
  `--warnings-as-errors` failures. The bar is zero.
- Don't change the wire format without bumping a version somewhere
  visible. There isn't one yet (Noise's protocol-name string is
  the implicit version), but if you change the protocol, document
  the migration path.
- Don't add platform-specific code to PeerNet. Mobile bridges
  (Bonjour, NSD, platform reachability) belong in the host app's
  NIF, talking to PeerNet via the existing Behaviours
  (`Discovery`, `NetworkMonitor`).
