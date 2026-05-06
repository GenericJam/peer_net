defmodule PeerNet.Registry do
  @moduledoc """
  Per-instance registry of peer state — pubkey → {connection, last-seen
  address, status} — plus the auto-connect dispatcher.

  Sits between `PeerNet.Discovery` (which emits "this pubkey is at this
  address") and `PeerNet.Connection.Supervisor` (which spins up sockets).
  When a discovery event arrives for a pubkey in the trust list, the
  Registry dials the address; the resulting Connection registers itself
  back here once authenticated.

  ## State per peer

      %{
        pubkey: <<...>>,
        status: :unknown | :discovered | :connecting | :connected | :disconnected,
        last_address: %{ip: ..., port: ...} | nil,
        last_seen: DateTime.t() | nil,
        conn_pid: pid() | nil
      }

  ## Public API

  - `lookup_connection/2` — returns `{:ok, pid}` or `:not_connected`
    (drop-in replacement for the previous `PeerIndex` behaviour the
    public `PeerNet.send/4` and `PeerNet.call/5` functions use).
  - `register_connection/3` — called by Connection when its handshake
    completes.
  - `list/1` — returns all known peers' state for UI / diagnostics.
  - `connected?/2` — convenience boolean.

  ## Discovery integration

  Receives `{:peer_discovered, pubkey, address}` and `{:peer_lost,
  pubkey, _}` messages from any `PeerNet.Discovery` implementation.
  Trust-checks the pubkey before acting.
  """

  use GenServer

  require Logger

  alias PeerNet.{Connection, Trust}

  # ── Reconnect backoff ──────────────────────────────────────────────
  #
  # When a connection to a trusted peer drops and we have a recent
  # address for them, we redial with exponential backoff. The schedule
  # below recovers from transient drops in ~30s while never hammering
  # an unreachable peer more than once every 30s long-term.
  @reconnect_initial_ms 500
  @reconnect_max_ms 30_000
  @reconnect_multiplier 2

  # ── Public API ──────────────────────────────────────────────────────

  def start_link(opts) do
    {name, opts} = Keyword.pop(opts, :name, __MODULE__)
    GenServer.start_link(__MODULE__, opts, name: name)
  end

  @doc "Look up the live connection for `pubkey`."
  @spec lookup_connection(GenServer.server(), binary()) :: {:ok, pid()} | :not_connected
  def lookup_connection(server \\ __MODULE__, pubkey) when is_binary(pubkey) do
    GenServer.call(server, {:lookup_connection, pubkey})
  end

  @doc "Register `pid` as the live connection for `pubkey`. Idempotent."
  @spec register_connection(GenServer.server(), binary(), pid()) :: :ok
  def register_connection(server \\ __MODULE__, pubkey, pid)
      when is_binary(pubkey) and is_pid(pid) do
    GenServer.call(server, {:register_connection, pubkey, pid})
  end

  @doc "Return all known peer entries."
  @spec list(GenServer.server()) :: [map()]
  def list(server \\ __MODULE__), do: GenServer.call(server, :list)

  @doc "True iff there's a live connection for `pubkey`."
  @spec connected?(GenServer.server(), binary()) :: boolean()
  def connected?(server \\ __MODULE__, pubkey) when is_binary(pubkey) do
    match?({:ok, _pid}, lookup_connection(server, pubkey))
  end

  # ── GenServer ───────────────────────────────────────────────────────

  @impl true
  def init(opts) do
    state = %{
      trust: Keyword.fetch!(opts, :trust),
      conn_sup: Keyword.fetch!(opts, :conn_sup),
      identity: Keyword.fetch!(opts, :identity),
      handlers: Keyword.fetch!(opts, :handlers),
      peers: %{},
      monitors: %{}
    }

    # Optionally subscribe to a NetworkMonitor for fast network-change
    # detection. If passed, on every change we tear down all live
    # connections so the auto-reconnect path can dial fresh sockets
    # against the new local network — much faster than waiting for
    # TCP keepalive or app-level Liveness to time out the dead links.
    case Keyword.get(opts, :network_monitor) do
      nil ->
        :ok

      {mod, server} when is_atom(mod) ->
        :ok = mod.subscribe(server, self())
    end

    {:ok, state}
  end

  @impl true
  def handle_call({:lookup_connection, pubkey}, _from, state) do
    reply =
      case Map.get(state.peers, pubkey) do
        %{conn_pid: pid} when is_pid(pid) -> {:ok, pid}
        _ -> :not_connected
      end

    {:reply, reply, state}
  end

  def handle_call({:register_connection, pubkey, pid}, _from, state) do
    state = drop_existing_conn(state, pubkey)
    ref = Process.monitor(pid)

    entry =
      Map.get(state.peers, pubkey, blank_entry(pubkey))
      |> Map.merge(%{conn_pid: pid, status: :connected, last_seen: DateTime.utc_now()})

    new_state =
      state
      |> put_in([:peers, pubkey], entry)
      |> put_in([:monitors, ref], pubkey)

    {:reply, :ok, new_state}
  end

  def handle_call(:list, _from, state) do
    {:reply, Map.values(state.peers), state}
  end

  @impl true
  def handle_info({:peer_discovered, pubkey, address}, state) do
    cond do
      not Trust.trusted?(state.trust, pubkey) ->
        Logger.debug("[PeerNet] discovered untrusted peer #{inspect(pubkey)}, ignoring")
        {:noreply, state}

      already_connected?(state, pubkey) ->
        # Already have a live connection — just refresh last-seen.
        new_state = touch_peer(state, pubkey, address)
        {:noreply, new_state}

      true ->
        # Trust + not connected → auto-dial.
        new_state =
          state
          |> touch_peer(pubkey, address, :discovered)
          |> dial_peer(pubkey, address)

        {:noreply, new_state}
    end
  end

  def handle_info({:peer_lost, pubkey, _meta}, state) do
    new_state =
      case Map.get(state.peers, pubkey) do
        nil ->
          state

        entry ->
          # Don't immediately tear down a live connection — the
          # discovery layer might be flapping. The Liveness ping/pong
          # is responsible for actually deciding when a connection is
          # dead. Just mark the peer as last-not-discovered.
          put_in(state.peers[pubkey], %{entry | status: status_after_loss(entry.status)})
      end

    {:noreply, new_state}
  end

  def handle_info({:DOWN, ref, :process, _pid, _reason}, state) do
    case Map.pop(state.monitors, ref) do
      {nil, _} ->
        {:noreply, state}

      {pubkey, monitors} ->
        {:noreply, on_connection_down(%{state | monitors: monitors}, pubkey)}
    end
  end

  def handle_info({:network_changed, change}, state) do
    Logger.info("[PeerNet] network changed: added=#{inspect(change.added)} removed=#{inspect(change.removed)}")

    # Tear down all live connections — they're talking over sockets
    # bound to addresses that may no longer exist. The DOWN handlers
    # will mark each peer disconnected and (since they're trusted with
    # known last addresses) schedule a redial.
    Enum.each(state.peers, fn {_pubkey, entry} ->
      if pid = entry.conn_pid, do: send(pid, :superseded)
    end)

    {:noreply, state}
  end

  def handle_info({:reconnect_attempt, pubkey, attempt}, state) do
    case Map.get(state.peers, pubkey) do
      %{status: :connected} ->
        # Already reconnected via some other path (e.g. discovery
        # re-fired). Drop this scheduled attempt.
        {:noreply, state}

      %{last_address: %{} = address} = entry ->
        {:noreply, attempt_reconnect(state, pubkey, entry, address, attempt)}

      _ ->
        # No address to dial; wait for discovery to give us one.
        {:noreply, state}
    end
  end

  def handle_info(_other, state), do: {:noreply, state}

  # ── Internal ────────────────────────────────────────────────────────

  # If the peer is still trusted, perform the dial and either let the
  # in-flight :connecting state ride or queue another backoff attempt.
  defp attempt_reconnect(state, pubkey, entry, address, attempt) do
    if Trust.trusted?(state.trust, pubkey) do
      state
      |> put_in([:peers, pubkey], %{entry | status: :reconnecting})
      |> dial_peer(pubkey, address)
      |> reschedule_if_dial_failed(pubkey, attempt)
    else
      state
    end
  end

  defp reschedule_if_dial_failed(state, pubkey, attempt) do
    case Map.get(state.peers, pubkey) do
      %{status: :connecting} ->
        # Dial in flight; Connection's eventual register or DOWN
        # drives subsequent state changes.
        state

      _ ->
        schedule_reconnect_if_eligible(state, pubkey, attempt + 1)
    end
  end

  # Mark the peer as disconnected and (if eligible) schedule a redial.
  # Connection termination is a normal lifecycle event — we don't drop
  # the peer record itself, just clear the conn pid and try again.
  defp on_connection_down(state, pubkey) do
    case Map.get(state.peers, pubkey) do
      nil ->
        state

      entry ->
        entry = %{entry | conn_pid: nil, status: :disconnected}

        state
        |> put_in([:peers, pubkey], entry)
        |> schedule_reconnect_if_eligible(pubkey, 0)
    end
  end

  defp blank_entry(pubkey) do
    %{
      pubkey: pubkey,
      status: :unknown,
      last_address: nil,
      last_seen: nil,
      conn_pid: nil
    }
  end

  defp already_connected?(state, pubkey) do
    case Map.get(state.peers, pubkey) do
      %{conn_pid: pid} when is_pid(pid) -> Process.alive?(pid)
      _ -> false
    end
  end

  defp touch_peer(state, pubkey, address, status \\ nil) do
    entry =
      Map.get(state.peers, pubkey, blank_entry(pubkey))
      |> Map.merge(%{
        last_address: address,
        last_seen: DateTime.utc_now()
      })

    entry =
      case status do
        nil -> entry
        s -> %{entry | status: s}
      end

    put_in(state.peers[pubkey], entry)
  end

  defp dial_peer(state, pubkey, %{ip: ip, port: port}) do
    case Connection.Supervisor.start_connection(state.conn_sup,
           identity: state.identity,
           trust: state.trust,
           handlers: state.handlers,
           peer_index: self(),
           direction: :outbound,
           expected_peer: pubkey
         ) do
      {:ok, conn_pid} ->
        connect_socket(state, pubkey, ip, port, conn_pid)

      {:error, reason} ->
        Logger.warning("[PeerNet] failed to spawn outbound connection: #{inspect(reason)}")
        state
    end
  end

  defp connect_socket(state, pubkey, ip, port, conn_pid) do
    case :gen_tcp.connect(ip, port, [:binary, packet: :raw, active: false]) do
      {:ok, socket} ->
        :ok = :gen_tcp.controlling_process(socket, conn_pid)
        Connection.hand_off_socket(conn_pid, socket)

        entry = state.peers[pubkey]
        put_in(state.peers[pubkey], %{entry | status: :connecting})

      {:error, reason} ->
        Logger.warning(
          "[PeerNet] dial failed for #{inspect(pubkey)} at #{inspect(ip)}:#{port}: #{inspect(reason)}"
        )

        # Stop the orphan connection process.
        if Process.alive?(conn_pid), do: GenServer.stop(conn_pid, :normal)
        state
    end
  end

  defp drop_existing_conn(state, pubkey) do
    case Map.get(state.peers, pubkey) do
      %{conn_pid: old_pid} = entry when is_pid(old_pid) ->
        new_monitors = drop_monitors_for(state.monitors, pubkey)
        if Process.alive?(old_pid), do: send(old_pid, :superseded)

        %{
          state
          | monitors: new_monitors,
            peers: Map.put(state.peers, pubkey, %{entry | conn_pid: nil})
        }

      _ ->
        state
    end
  end

  defp drop_monitors_for(monitors, pubkey) do
    Enum.reduce(monitors, %{}, fn {ref, pk}, acc ->
      if pk == pubkey do
        Process.demonitor(ref, [:flush])
        acc
      else
        Map.put(acc, ref, pk)
      end
    end)
  end

  defp status_after_loss(:connected), do: :connected
  defp status_after_loss(_), do: :unknown

  # Schedule a redial if the peer is trusted and we have an address.
  # Backoff is exponential with a hard cap. The next attempt is sent
  # to ourselves as `{:reconnect_attempt, pubkey, attempt + 1}`.
  defp schedule_reconnect_if_eligible(state, pubkey, attempt) do
    cond do
      not Trust.trusted?(state.trust, pubkey) ->
        state

      match?(%{last_address: %{}}, Map.get(state.peers, pubkey)) ->
        delay = backoff_delay(attempt)
        Process.send_after(self(), {:reconnect_attempt, pubkey, attempt}, delay)
        state

      true ->
        state
    end
  end

  defp backoff_delay(attempt) do
    @reconnect_initial_ms
    |> Kernel.*(:math.pow(@reconnect_multiplier, attempt))
    |> trunc()
    |> min(@reconnect_max_ms)
  end
end
