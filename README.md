# PeerNet

Default-deny peer-to-peer messaging for Elixir.

PeerNet gives you BEAM-distribution-shaped ergonomics — `expose` a named
handler on one node, `call` it from another — between mutually-suspicious
peers, with cryptographic identity, walkie-talkie delivery semantics, and no
servers.

It is **not** a reimplementation of Erlang distribution. It coexists with
disterl on the same node, on different ports, with a fundamentally different
trust model: every handle is closed by default, and peers are addressed by
their public key rather than their (host, port).

## Status

**Pre-release.** All core layers are landed and tested:

- Identity, Trust, Handlers, Frame
- Noise XX handshake + ChaCha20-Poly1305 AEAD transport
- Acceptor, Connection, per-instance supervision
- Registry with auto-connect on discovery + auto-reconnect on disconnect
- Discovery: behaviour + Manual + UDP reference impls
- Liveness (app-level heartbeat)
- BeamDist (asymmetric-trust RPC convenience)

See [PLAN.md](PLAN.md) for the milestone history,
[CHANGELOG.md](CHANGELOG.md) for the change log, and
[guides/protocol.md](guides/protocol.md) for the wire format
specification. [guides/cookbook.md](guides/cookbook.md) has working
patterns for common use cases.

Remaining before a Hex `0.1.0` release: documentation polish + a
`NetworkMonitor` for IP-change events on mobile (the desktop /
Nerves use cases work without it).

## Why

The Erlang/Elixir ecosystem already has good answers to most communication
problems:

- **BEAM distribution** — perfect ergonomics, but trust is one shared cookie
  per cluster. Anyone with the cookie has a remote shell on every member. Fine
  for trusted infrastructure; unsafe between mutually-suspicious peers.
- **Phoenix Channels / WebSockets** — safe, well-trodden, but client-server.
  Needs servers running somewhere; introduces a relay you must trust.
- **WebRTC, libp2p, Iroh** — peer-to-peer, but heavyweight, not BEAM-native,
  and designed primarily for streaming or distributed-storage workloads.

PeerNet fills the gap: BEAM-native, safe by default, peer-to-peer.

## Quick start

```elixir
# In your supervision tree:
children = [
  {PeerNet, [data_dir: "/var/lib/myapp/peer_net"]}
]

# On every node — the "server" facet. Default-deny, opt-in expose.
PeerNet.expose(:chat, fn _from, %{text: text} ->
  IO.puts("got: #{text}")
  :ok
end)

# Discover peers on the local network:
PeerNet.list_peers()
#=> [%{pubkey: <<...>>, status: :online, last_seen: ~U[2026-...]}]

# Pair with a peer (out-of-band, e.g. via QR):
PeerNet.pair(peer_pubkey)

# Send a message — addressed by pubkey, not IP:
PeerNet.send(peer_pubkey, :chat, %{text: "hi"})
```

## Threat model

PeerNet defends against:

- **Passive eavesdropping** — Noise XX with ChaCha20-Poly1305 AEAD.
- **Active MITM** — handshake verifies the peer's static key against the
  trust list before completing.
- **Replay** — Noise nonces.
- **Atom-exhaustion attacks** — incoming wire is decoded with `:safe` ETF.
- **Unsolicited execution** — every handle is closed by default; nothing is
  reachable until explicitly `expose`'d.
- **Impersonation** — Ed25519 signatures bind every message to its sender's
  pubkey.

PeerNet does **not** defend against:

- Side-channel timing attacks.
- Traffic analysis (a passive observer can see who talks to whom and when).
- Trusted peers misbehaving — once you've added a pubkey to the trust list,
  you've vouched for it.
- OS-level compromise of either endpoint.

## BEAM distribution compatibility

PeerNet runs alongside regular Erlang distribution on the same node — they
use different ports and don't conflict.

For the case where you want full BEAM-dist semantics with a specific trusted
peer (a phone controlling a Nerves device, say), the opt-in
`PeerNet.BeamDist` module gives you `:rpc.call`-equivalent calls between
two peers who have explicitly granted each other access:

```elixir
# On the Nerves device — explicit grant per peer:
PeerNet.expose(:beam_admin, &PeerNet.BeamDist.handle/2,
  authorize: fn pubkey -> pubkey == @phone_pubkey end)

# On the phone — RPC-style sugar:
PeerNet.BeamDist.call(nerves_pubkey, MyMod, :restart_wifi, [])
```

Asymmetric: only the granted peer can make calls. The Nerves device cannot
reciprocally call the phone unless the phone separately grants.

## Installation

When published:

```elixir
def deps do
  [
    {:peer_net, "~> 0.1.0"}
  ]
end
```

## License

Apache-2.0. See [LICENSE](LICENSE).
