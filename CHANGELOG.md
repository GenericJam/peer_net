# Changelog

All notable changes to PeerNet are documented here. The format is
based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and
this project follows [Semantic Versioning](https://semver.org/) once
it reaches `1.0.0`.

## [Unreleased]

### Added

- **`PeerNet.NetworkMonitor`** behaviour + **`Polling`** default
  implementation. Notices when local IP set changes (e.g. WiFi
  switch) and notifies subscribers. Wires into Registry so a
  network change triggers immediate teardown of all live connections
  — much faster than waiting for TCP keepalive or app-level
  Liveness to time out the dead links.
- **Noise XX handshake** — full
  `Noise_XX_25519_ChaChaPoly_SHA256` implementation in pure Elixir
  on `:crypto`. SymmetricState, CipherState, HandshakeState, all
  message-pattern processing per the Noise spec.
- **`PeerNet.Channel`** — post-handshake AEAD wrapper. ChaCha20-
  Poly1305 with the Noise nonce format, per-direction
  CipherStates, counter-exhaustion protection.
- **`PeerNet.BeamDist`** — convenience module for asymmetric-trust
  RPC. The "phone controlling Nerves" use case in 5 lines on each
  side.
- **`PeerNet.Discovery.UDP`** — LAN broadcast discovery. Compact
  39-byte announce frame, configurable cadence and listen port,
  pluggable transport for testability.
- **Auto-reconnect** — Registry redials trusted peers with
  exponential backoff (500ms → 1s → 2s → ... → 30s cap) when their
  connection drops.
- **`PeerNet.Liveness`** — app-level heartbeat. Per-ping check
  timers detect dead peers in seconds rather than waiting for TCP
  keepalive.
- **`PeerNet.Discovery`** behaviour with **`Manual`** and **`UDP`**
  reference implementations.
- **`PeerNet.Registry`** — pubkey-keyed peer state with auto-
  connect on discovery and reconnect on disconnect.
- **`PeerNet.Frame.encode_raw/1` and `decode_raw/1`** — bypass ETF
  for already-encoded bytes (used by Channel for AEAD ciphertexts).

### Changed

- **`PeerNet.Identity` migrated from Ed25519 to X25519** — Noise's
  DH primitive is X25519. The keyfile magic bumped from `0x01` →
  `0x02`; old keyfiles return `{:error, :invalid_keyfile}` on load
  rather than silently misbehaving. Apps must regenerate identities
  after upgrading.

### Removed

- `PeerNet.PeerIndex` — replaced by `PeerNet.Registry`, which
  subsumes its responsibilities and adds discovery / reconnect.
- `PeerNet.Identity.sign/2` and `verify/3` — Noise XX cryptographic-
  ally binds peer identity into the transcript hash; explicit
  per-message signatures are no longer used. Apps that need long-
  term-key sigs for app-level data should layer that themselves.

### Security

- The wire is now end-to-end AEAD-encrypted. Previous milestones
  (M2 POC) shipped plaintext over TCP — never use a v0.0 build for
  anything beyond local-network testing.
- Frame and Channel both use `:erlang.binary_to_term/2` with
  `:safe` to defend against atom-table exhaustion from malformed
  or hostile peers.

## [0.0.1] — 2026-05-05 (POC)

Initial walkable POC. Identity, Trust, Frame, Handlers (pure layer);
Connection, Acceptor, Handshake (transport layer with plaintext +
Ed25519 challenge-response). Not released to Hex.
