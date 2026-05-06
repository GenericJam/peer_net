defmodule PeerNet.Discovery.UDP do
  @moduledoc """
  LAN UDP-broadcast discovery. Each instance:

  1. Opens a UDP socket on `:listen_port` (default `4040`).
  2. Periodically (every `:interval_ms`, default 5_000) broadcasts a
     `PeerNet.Discovery.UDP.Wire` frame containing its pubkey + TCP
     listen port to `255.255.255.255:listen_port`.
  3. Listens for the same shape from other instances. Each parsed
     announce becomes a `{:peer_discovered, pubkey, address}` message
     to the configured Registry.

  ## When this works

  - Same LAN with broadcast permitted (typical home WiFi, dev networks).
  - Desktop, Nerves, and other "trusted local network" deployments.
  - The walkie-talkie demo on a laptop's local WiFi.

  ## When this doesn't work

  - Across NAT boundaries (broadcast doesn't traverse routers).
  - On corporate / cellular networks that suppress broadcast traffic.
  - On iOS / Android without the appropriate platform permissions
    declared (`NSLocalNetworkUsageDescription` on iOS).

  For mobile, the right layering is for the host app's NIF to provide
  a `Discovery` impl that wraps Bonjour / NSD — those use the same
  multicast protocol but go through OS-blessed APIs that don't trip
  permission prompts.

  ## Self-suppression

  We drop announces matching our own pubkey on the listen path —
  otherwise the broadcast would loop back to ourselves and noise up
  the Registry.

  ## Cadence

  Default cadence is 5s broadcast. Pair this with a Registry-side TTL
  of (say) `2 * interval_ms` to detect peers leaving the network — the
  Registry treats peers it hasn't heard from in that window as stale.
  (TTL handling lives in the Registry, not here.)

  ## Testability

  The `:transport` option (default `PeerNet.Discovery.UDP.Transport.GenUDP`)
  lets tests inject a mock that doesn't actually open a socket, so unit
  tests can drive packets in/out without binding ports.
  """

  @behaviour PeerNet.Discovery
  use GenServer

  require Logger

  alias PeerNet.Discovery.UDP.Wire

  @default_listen_port 4040
  @default_interval_ms 5_000

  # ── Public API ──────────────────────────────────────────────────────

  @impl true
  def start_link(opts) do
    {name, opts} = Keyword.pop(opts, :name, __MODULE__)
    GenServer.start_link(__MODULE__, opts, name: name)
  end

  @impl true
  def announce_self(server, peer_net_port) do
    GenServer.call(server, {:announce_self, peer_net_port})
  end

  @impl true
  def stop(server), do: GenServer.stop(server, :normal)

  # ── GenServer ───────────────────────────────────────────────────────

  @impl true
  def init(opts) do
    state = %{
      registry: Keyword.fetch!(opts, :registry),
      identity: Keyword.fetch!(opts, :identity),
      listen_port: Keyword.get(opts, :listen_port, @default_listen_port),
      interval_ms: Keyword.get(opts, :interval_ms, @default_interval_ms),
      peer_net_port: Keyword.get(opts, :peer_net_port),
      transport: Keyword.get(opts, :transport, __MODULE__.Transport.GenUDP),
      socket: nil
    }

    case state.transport.open(state.listen_port) do
      {:ok, socket} ->
        Process.send_after(self(), :tick, state.interval_ms)
        {:ok, %{state | socket: socket}}

      {:error, reason} ->
        # Don't crash the whole supervision tree if discovery can't bind
        # — the caller may not have wanted UDP discovery at all on this
        # network. Log loudly and stay alive doing nothing.
        Logger.warning("[PeerNet] Discovery.UDP could not bind: #{inspect(reason)}")
        {:ok, state}
    end
  end

  @impl true
  def handle_call({:announce_self, port}, _from, state) do
    {:reply, :ok, %{state | peer_net_port: port}}
  end

  @impl true
  def handle_info(:tick, state) do
    if state.socket && state.peer_net_port do
      bytes = Wire.encode(state.identity.public, state.peer_net_port)

      case state.transport.broadcast(state.socket, state.listen_port, bytes) do
        :ok -> :ok
        {:error, reason} -> Logger.debug("[PeerNet] discovery broadcast: #{inspect(reason)}")
      end
    end

    Process.send_after(self(), :tick, state.interval_ms)
    {:noreply, state}
  end

  # The pluggable transport delivers received packets as
  # `{:peer_net_udp_packet, source_ip, bytes}` so we don't depend on the
  # specific `:gen_udp` :inet message shape.
  def handle_info({:peer_net_udp_packet, source_ip, bytes}, state) do
    case Wire.decode(bytes) do
      {:ok, %{pubkey: pubkey, port: port}} ->
        if pubkey == state.identity.public do
          # Self-loopback — drop silently.
          {:noreply, state}
        else
          send(
            state.registry,
            {:peer_discovered, pubkey, %{ip: source_ip, port: port, source: :udp}}
          )

          {:noreply, state}
        end

      :error ->
        # Some other UDP traffic on our port — ignore.
        {:noreply, state}
    end
  end

  # Pass through `:gen_udp`'s native message shape too, for callers using
  # the default GenUDP transport.
  def handle_info({:udp, _socket, source_ip, _src_port, bytes}, state) do
    handle_info({:peer_net_udp_packet, source_ip, bytes}, state)
  end

  def handle_info(_other, state), do: {:noreply, state}

  @impl true
  def terminate(_reason, state) do
    if state.socket, do: state.transport.close(state.socket)
    :ok
  end
end
