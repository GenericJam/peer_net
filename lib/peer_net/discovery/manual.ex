defmodule PeerNet.Discovery.Manual do
  @moduledoc """
  No-op discovery implementation — exposes inject points so tests and
  manually-configured setups can drive discovery events at will.

  Use this when:

  - You're testing the Registry's auto-connect logic without involving
    the network.
  - Your deployment uses a static peer list (config-driven, hand-typed,
    or distributed via your own mechanism — pre-shared `mob.exs`, etc.)
    and doesn't need automatic detection.
  - You need to drive a controlled scenario for debugging.

  Production peer-to-peer use will typically swap this out for
  `PeerNet.Discovery.MDNS` (planned).

  ## Driving discovery events

      # Tell the registry a peer is now reachable:
      PeerNet.Discovery.Manual.announce_peer(disc_pid, peer_pubkey,
        %{ip: {127, 0, 0, 1}, port: 7100, source: :manual})

      # Tell the registry a peer disappeared:
      PeerNet.Discovery.Manual.lose_peer(disc_pid, peer_pubkey)
  """

  @behaviour PeerNet.Discovery
  use GenServer

  # ── Public API ──────────────────────────────────────────────────────

  @impl true
  def start_link(opts) do
    {name, opts} = Keyword.pop(opts, :name, __MODULE__)
    GenServer.start_link(__MODULE__, opts, name: name)
  end

  @impl true
  def announce_self(server, _port), do: GenServer.call(server, :noop)

  @impl true
  def stop(server), do: GenServer.stop(server, :normal)

  @doc "Push a discovery event for `pubkey` at `address` to the Registry."
  @spec announce_peer(GenServer.server(), binary(), PeerNet.Discovery.address()) :: :ok
  def announce_peer(server, pubkey, address) when is_binary(pubkey) and is_map(address) do
    GenServer.cast(server, {:announce_peer, pubkey, address})
  end

  @doc "Push a peer-lost event for `pubkey` to the Registry."
  @spec lose_peer(GenServer.server(), binary()) :: :ok
  def lose_peer(server, pubkey) when is_binary(pubkey) do
    GenServer.cast(server, {:lose_peer, pubkey})
  end

  # ── GenServer ───────────────────────────────────────────────────────

  @impl true
  def init(opts) do
    registry = Keyword.fetch!(opts, :registry)
    {:ok, %{registry: registry}}
  end

  @impl true
  def handle_call(:noop, _from, state), do: {:reply, :ok, state}

  @impl true
  def handle_cast({:announce_peer, pubkey, address}, state) do
    send(state.registry, {:peer_discovered, pubkey, address})
    {:noreply, state}
  end

  def handle_cast({:lose_peer, pubkey}, state) do
    send(state.registry, {:peer_lost, pubkey, %{source: :manual}})
    {:noreply, state}
  end
end
