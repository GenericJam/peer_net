# PeerNet wire protocol

> **Status: implemented as of M2.5.** This document describes what
> PeerNet actually puts on the wire as of v0.x. The implementation in
> `lib/peer_net/handshake.ex` and `lib/peer_net/channel.ex` is the
> source of truth; this document is the human-readable companion.

## Goals

1. Bytes-on-the-wire are auditable from this document — no
   implementation reading required to reproduce a frame.
2. Hostile or malformed input cannot intern atoms, allocate unbounded
   memory, or execute code on the receiving node.
3. Both peers verify each other's permanent identity (X25519 static
   key) before any application-layer message crosses.
4. Forward secrecy: compromising a long-term static key does not
   reveal past sessions.
5. Protocol carries no host metadata — peer addresses are public keys,
   never IPs or hostnames.

## Layers

```
┌────────────────────────────────────────────┐
│   Application: handle name + args          │  ← user code
├────────────────────────────────────────────┤
│   Envelope: tagged tuples                  │  ← {:call, id, name, args}
├────────────────────────────────────────────┤
│   Cipher: ChaCha20-Poly1305 AEAD           │  ← PeerNet.Channel
├────────────────────────────────────────────┤
│   Frame: 4-byte length + body              │  ← PeerNet.Frame
├────────────────────────────────────────────┤
│   Transport: TCP                           │  ← :gen_tcp
└────────────────────────────────────────────┘
```

## Frame layer

Every PeerNet frame on the wire:

```
| 4 bytes (big-endian unsigned) length N | N bytes of body |
```

The length prefix bounds buffering. Frames where `N >
PeerNet.Frame.max_frame_bytes/0` (default 1 MiB) are rejected before
any body byte is read.

Two body types travel through Frame:

- **During the handshake**, body bytes are interpreted by
  `PeerNet.Handshake` per the Noise XX message structure (see below).
  `Frame.encode/1` ETF-wraps the body before length-prefixing during
  handshake, and `Frame.decode/1` ETF-decodes it on receipt — using
  `:erlang.binary_to_term(_, [:safe])` to defend against atom
  exhaustion.
- **After the handshake**, body bytes are AEAD ciphertexts produced
  by `PeerNet.Channel`. These are framed with `Frame.encode_raw/1`
  and decoded with `Frame.decode_raw/1` — no ETF on the framing
  layer because Channel handles the deserialisation after AEAD
  decryption.

## Cipher layer (post-handshake)

After the handshake completes, every envelope is encrypted with
`Noise_XX_25519_ChaChaPoly_SHA256`'s AEAD: ChaCha20-Poly1305.

Each direction has its own `CipherState`:

```
struct CipherState {
  key:     <<32 bytes>>,
  counter: u64
}
```

Per-message wire body:

```
| ciphertext (variable) | 16-byte Poly1305 tag |
```

The nonce is derived from the counter per the Noise spec: 4 zero
bytes followed by the counter as an 8-byte little-endian integer.
The counter is monotonic per direction; PeerNet aborts the connection
if it would wrap past `2^64 - 1`.

AAD is empty by design — the ordering relationship between
ciphertexts is preserved by the nonce sequence; rebinding to a
header would add complexity without changing the security
guarantees in our threat model.

The plaintext, after decryption, is `:erlang.term_to_binary/1` of an
envelope tuple (next section). Decoded with `:safe` to defend against
atom exhaustion even from peers with valid session keys.

## Envelope layer

After Channel decrypt, every payload is one of these tagged tuples:

| Tag       | Shape                                | Direction    | Purpose             |
|-----------|--------------------------------------|--------------|---------------------|
| `:call`   | `{:call, request_id, name, args}`    | C → S        | Reply expected      |
| `:reply`  | `{:reply, request_id, result}`       | S → C        | Match by request_id |
| `:send`   | `{:send, name, args}`                | C → S        | Fire-and-forget     |
| `:ping`   | `{:ping, nonce}`                     | both         | App-level liveness  |
| `:pong`   | `{:pong, nonce}`                     | both         | Liveness reply      |

`request_id` is a 64-bit non-zero integer chosen by the caller.
Replies are matched on it; unknown reply IDs are dropped silently
(they may be late replies for already-timed-out calls).

`name` is always an atom. The atoms PeerNet uses internally
(`:call`, `:reply`, `:send`, `:ping`, `:pong`) are baked into the
library at compile time, so `:safe` decoding accepts them.

## Noise XX handshake

Pattern: `Noise_XX_25519_ChaChaPoly_SHA256`. Three messages.

### Initialisation (both sides)

```
protocol_name = "Noise_XX_25519_ChaChaPoly_SHA256"  # 32 bytes exactly
h  = protocol_name                                   # used directly (length match)
ck = h
k  = nil
n  = 0
```

### M1 (initiator → responder): `e`

```
| 32 bytes initiator ephemeral X25519 pubkey |
```

Initiator generates an ephemeral X25519 keypair, mixes the public key
into `h` (transcript hash), and sends it.

Responder mixes the received pubkey into its own `h`.

### M2 (responder → initiator): `e, ee, s, es`

```
| 32 bytes responder ephemeral pubkey |
| 32 + 16 bytes encrypted responder static pubkey |
| 0  + 16 bytes encrypted empty payload |
```

Responder operations (in order):

1. Generate ephemeral keypair, `MixHash(my_eph_pub)`.
2. `MixKey(DH(my_eph_priv, peer_eph_pub))` — derives the first session key.
3. `EncryptAndHash(my_static_pub)` — encrypts the responder's static
   pubkey under the new session key; ciphertext is mixed into `h`.
4. `MixKey(DH(my_static_priv, peer_eph_pub))` — derives a new key
   binding the static identity into the session.
5. `EncryptAndHash(<<>>)` — encrypts an empty payload (purely a
   transcript-binding step).

Initiator on receipt: same operations in mirror, recovering the
responder's static pubkey. **Trust check happens here**: if the
revealed static pubkey is not in the local `Trust` set, the handshake
aborts with `:untrusted_peer`.

### M3 (initiator → responder): `s, se`

```
| 32 + 16 bytes encrypted initiator static pubkey |
| 0  + 16 bytes encrypted empty payload |
```

Initiator:

1. `EncryptAndHash(my_static_pub)`.
2. `MixKey(DH(my_static_priv, peer_eph_pub))` — same DH the
   responder will compute.
3. `EncryptAndHash(<<>>)`.

Responder on receipt: recovers the initiator's static pubkey and
performs its own trust check — same `:untrusted_peer` semantics.

### Finalisation (both sides)

After M3, both sides hold the same chaining key `ck`. Split it:

```
{k1, k2} = HKDF-SHA256(ck, <<>>, 2)
```

Initiator's transport CipherStates: `tx = k1`, `rx = k2`.
Responder's: `tx = k2`, `rx = k1`. So initiator's outbound key is
responder's inbound key and vice versa, with independent nonce
counters per direction.

## Discovery

Out of scope for the protocol per se — the wire format above is
agnostic to how peers find each other. PeerNet ships two reference
discovery implementations:

- **`PeerNet.Discovery.UDP`** — periodically broadcasts a 39-byte
  announce frame on UDP `4040`:

  ```
  | 4 bytes magic "PNET" | 1 byte version | 2 bytes port | 32 bytes pubkey |
  ```

  Sufficient for desktop/Nerves on a known LAN. Hosts may need to
  declare `NSLocalNetworkUsageDescription` (iOS) or equivalent for
  mobile use.

- **`PeerNet.Discovery.Manual`** — no-op; the host app drives
  `:peer_discovered` / `:peer_lost` events programmatically. Used
  in tests, scripted setups, and as the integration point for
  platform-native discovery (Bonjour on iOS via NIF, NSD on Android).

## Versioning

Every PeerNet frame on the wire uses the same protocol version
implicitly via the Noise protocol name string. A peer running a
different protocol name will fail the handshake at the first M2 / M3
DecryptAndHash step (the AEAD won't authenticate because the
transcript hashes differ).

There is no separate version byte at the protocol level — Noise's
protocol-name binding is the version negotiation.
