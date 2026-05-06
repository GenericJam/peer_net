# PeerNet cookbook

Working patterns for common PeerNet use cases. Every snippet here is
exercised by the test suite — if anything stops working, the test
file referenced in each section will catch it.

## Two-node setup with manual addressing

For tests, scripted environments, or any case where peers know each
other's address by other means.

```elixir
# In your supervision tree:
children = [
  {PeerNet, [name: :alice, data_dir: "/var/lib/myapp/alice", port: 7100]},
]

# Pair with a peer (out of band — typically QR-scanned):
:ok = PeerNet.pair(:alice, peer_pubkey, label: "Bob's laptop")

# Expose a handle:
:ok = PeerNet.expose(:alice, :greet, fn _from, name -> "hi #{name}" end)

# Open a connection:
:ok = PeerNet.connect(:alice, peer_pubkey, {192, 168, 1, 50}, 7100)

# Wait for handshake to complete (test pattern):
true = PeerNet.connected?(:alice, peer_pubkey)

# Call:
{:ok, "hi world"} = PeerNet.call(:alice, peer_pubkey, :greet, "world")
```

See `test/peer_net/integration_test.exs`.

## Two-node setup with auto-discovery (UDP)

For walkie-talkie demos on a trusted LAN.

```elixir
children = [
  {PeerNet,
   [
     name: :alice,
     data_dir: "/var/lib/myapp/alice",
     port: 0,                              # OS-assigned ephemeral
     discovery: PeerNet.Discovery.UDP,
     discovery_opts: [listen_port: 4040]   # default; override per app
   ]}
]

# Pair both ways out-of-band (QR scan, typed pubkeys, etc).
:ok = PeerNet.pair(:alice, bob_pubkey)

# Expose handles:
:ok = PeerNet.expose(:alice, :chat, fn _from, %{text: text} ->
  IO.puts("got: #{text}")
  :ok
end)

# That's it. The Discovery.UDP process broadcasts every 5 seconds;
# Bob's matching instance hears the announce, the Registry sees a
# trusted-peer event, and dials. After ~5-10s the connection is up.

PeerNet.connected?(:alice, bob_pubkey)  # true once handshake completes
```

See `test/peer_net/discovery_integration_test.exs`.

## Auto-reconnect after a transient drop

No code required — built into the Registry. When a connection
process terminates (peer crashes, network blip, socket reset), the
Registry observes the `:DOWN` and schedules a redial with
exponential backoff (500ms → 1s → 2s → ... → 30s cap).

```elixir
# Connection drops:
{:ok, conn_pid} = PeerNet.Registry.lookup_connection(:"alice.registry", bob_pubkey)
Process.exit(conn_pid, :kill)

# Wait — the Registry will redial.
# In ~500ms - 1s, this becomes true again:
PeerNet.connected?(:alice, bob_pubkey)
```

See `test/peer_net/reconnect_test.exs`.

## Phone controlling a Nerves device (BeamDist)

Asymmetric trust: the controlled peer (Nerves) gates access by
pubkey; the controller (phone) calls without any extra ceremony.

On the controlled side (Nerves), once the controller's pubkey is
known:

```elixir
@controller_pubkey Base.decode16!("…32-byte hex…")

# After PeerNet.start_link in your supervision tree:
PeerNet.expose(:beam_admin, &PeerNet.BeamDist.handle/2,
  authorize: fn pubkey -> pubkey == @controller_pubkey end)
```

On the controller side (phone), once the device pubkey is known and
paired:

```elixir
# Synchronous: get a return value.
{:ok, status} = PeerNet.BeamDist.call(device_pubkey, MyApp.WiFi, :status, [])

# Fire-and-forget: no return value, but acks delivery on the wire.
:ok = PeerNet.BeamDist.cast(device_pubkey, Logger, :info, ["restarting"])
```

The `authorize:` predicate is the entire access control. Other peers
calling `:beam_admin` see `{:error, :forbidden}`. The handler never
runs for them.

See `test/peer_net/beam_dist_test.exs`.

## Per-row authorization

The `authorize:` predicate isn't limited to a single pubkey. Any
function `(pubkey -> boolean)` works:

```elixir
admins = MapSet.new([alice_pubkey, bob_pubkey])

PeerNet.expose(:moderate, &handle_moderate/2,
  authorize: fn pubkey -> MapSet.member?(admins, pubkey) end)
```

The predicate runs on every call, so changes to the set take effect
immediately (no need to revoke/re-expose).

## Multiple instances in one BEAM (testing pattern)

PeerNet's name-based supervision lets you run any number of
instances in the same BEAM, each fully isolated.

```elixir
{:ok, _} = PeerNet.start_link(name: :a, data_dir: "tmp/a", port: 0)
{:ok, _} = PeerNet.start_link(name: :b, data_dir: "tmp/b", port: 0)
{:ok, _} = PeerNet.start_link(name: :c, data_dir: "tmp/c", port: 0)

# Each call takes the instance name as the first argument.
PeerNet.identity(:a)
PeerNet.expose(:a, :handle, fun)
PeerNet.call(:a, peer_pubkey, :handle, args)
```

Used throughout the integration test suite.

## Extracting your pubkey for QR pairing

```elixir
id = PeerNet.identity(:alice)
qr_payload = Base.encode32(id.public, padding: false)
# Render qr_payload as a QR code in your UI.

# On the scanning side:
{:ok, peer_pubkey} = Base.decode32(scanned, padding: false)
:ok = PeerNet.pair(:bob, peer_pubkey, label: "Alice")
```

Pubkeys are 32 bytes; Base32 (no padding) yields a 52-character
alphanumeric string — comfortable for a QR code at any resolution.

## Inspecting peer state

```elixir
# All known peers (from the Registry — includes status):
PeerNet.list_peers(:alice)
#=> [%{pubkey: <<...>>, label: "Bob", added_at: ~U[2026-...]}]

# Is a specific peer connected right now?
PeerNet.connected?(:alice, peer_pubkey)
#=> true | false

# Get the live connection process (rarely needed):
{:ok, pid} = PeerNet.Registry.lookup_connection(:"alice.registry", peer_pubkey)
```

## Choosing a port

- `port: 0` — OS-assigned ephemeral. Read it back with
  `PeerNet.port(:alice)` after start. Best for tests and one-off
  scripts.
- `port: <fixed>` — fixed port (e.g. `7100`). Best for production
  where you want a stable address. Make sure no other app on the host
  uses the same port.
- For mobile (mob), the port is opaque to the user — discovery
  handles the address sharing.

## What NOT to do

- **Don't share keyfiles between hosts.** Each PeerNet instance
  needs its own identity. Two hosts sharing the same private key are
  the same peer from the network's perspective; the second one will
  conflict with the first.
- **Don't use the same `data_dir` for two PeerNet instances.** Trust
  list and identity collide.
- **Don't `expose/4` something with no `authorize:` if it does
  anything destructive.** Default-deny applies to *unknown handles*;
  once you `expose`, every paired peer can call it. Use `authorize:`
  to narrow.
- **Don't call `PeerNet.connect/4` if you have UDP discovery
  running.** Discovery + Registry will dial trusted peers
  automatically. Manual `connect/4` is for setups without discovery.
