defmodule PeerNet.Liveness do
  @moduledoc """
  Application-level heartbeat for one peer connection.

  TCP keepalive is OS-level and slow (default ~2 hours). For peer-to-peer
  apps that need to detect a dropped peer in seconds rather than hours, we
  layer a short-period ping/pong on top. Each `Liveness` process owns the
  cadence for one connection; the connection is responsible for actually
  transmitting the ping nonce and routing the pong back.

  ## Wiring

      # Start one Liveness per Connection, supplying the emit + on_dead callbacks.
      {:ok, lv} = Liveness.start_link(
        interval_ms: 30_000,
        timeout_ms: 60_000,
        emit:    fn nonce -> Connection.send_ping(self(), nonce) end,
        on_dead: fn -> Connection.peer_died(self()) end
      )

      # When the connection receives a {:pong, nonce} envelope:
      Liveness.handle_pong(lv, nonce)

  ## Cadence

  Every `:interval_ms` the Liveness:

  1. Generates a fresh 16-byte nonce.
  2. Calls `:emit` with the nonce — the caller is expected to send a
     `{:ping, nonce}` envelope to the peer.
  3. Schedules a `:check` after `:timeout_ms`.

  When `:check` fires:

  - If `handle_pong/2` was called with the matching nonce → the peer is
    alive, schedule the next ping (`interval_ms` after the previous one
    was emitted, not after the pong arrived — keeps cadence steady).
  - Otherwise → call `:on_dead`. The Liveness then stays idle until told
    otherwise; the connection is expected to terminate.
  """

  use GenServer

  @typedoc "Options accepted by `start_link/1`."
  @type opts :: [
          interval_ms: pos_integer(),
          timeout_ms: pos_integer(),
          emit: (binary() -> any()),
          on_dead: (-> any()),
          name: GenServer.name()
        ]

  # ── Public API ──────────────────────────────────────────────────────

  @spec start_link(opts()) :: GenServer.on_start()
  def start_link(opts) do
    {name, opts} = Keyword.pop(opts, :name)
    if name, do: GenServer.start_link(__MODULE__, opts, name: name),
       else: GenServer.start_link(__MODULE__, opts)
  end

  @doc """
  Tell the liveness process that a `:pong` came back with `nonce`.

  Mismatched nonces are silently ignored — they're either late acks of
  earlier pings (already replaced by the current outstanding nonce) or a
  peer misbehaving. Either way they shouldn't reset the dead-detection
  window.
  """
  @spec handle_pong(GenServer.server(), binary()) :: :ok
  def handle_pong(server, nonce) when is_binary(nonce) do
    GenServer.cast(server, {:pong, nonce})
  end

  # ── GenServer ───────────────────────────────────────────────────────

  @impl true
  def init(opts) do
    state = %{
      interval_ms: Keyword.get(opts, :interval_ms, 30_000),
      timeout_ms: Keyword.get(opts, :timeout_ms, 60_000),
      emit: Keyword.fetch!(opts, :emit),
      on_dead: Keyword.fetch!(opts, :on_dead),
      # Each in-flight ping has its own check timer. Tracking them
      # independently lets a late-but-valid pong cancel its specific
      # check, even if newer pings have been emitted in the meantime —
      # which is the realistic case for a peer running near the
      # interval/timeout boundary.
      pending: %{},
      dead?: false
    }

    Process.send_after(self(), :tick, state.interval_ms)
    {:ok, state}
  end

  @impl true
  def handle_info(:tick, %{dead?: true} = state), do: {:noreply, state}

  def handle_info(:tick, state) do
    nonce = :crypto.strong_rand_bytes(16)
    state.emit.(nonce)
    timer = Process.send_after(self(), {:check, nonce}, state.timeout_ms)
    Process.send_after(self(), :tick, state.interval_ms)
    {:noreply, %{state | pending: Map.put(state.pending, nonce, timer)}}
  end

  def handle_info({:check, nonce}, state) do
    cond do
      state.dead? ->
        {:noreply, state}

      Map.has_key?(state.pending, nonce) ->
        # This specific ping was never acked → peer dead.
        state.on_dead.()
        {:noreply, %{state | dead?: true}}

      true ->
        {:noreply, state}
    end
  end

  def handle_info(_other, state), do: {:noreply, state}

  @impl true
  def handle_cast({:pong, nonce}, state) do
    case Map.pop(state.pending, nonce) do
      {nil, _} ->
        # Mismatched / late-late nonce — ignore.
        {:noreply, state}

      {timer, rest} ->
        # Cancel this ping's dead-check; peer responded.
        Process.cancel_timer(timer)
        {:noreply, %{state | pending: rest}}
    end
  end
end
