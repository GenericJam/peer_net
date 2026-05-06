defmodule PeerNet.Connection do
  @moduledoc """
  One connection to one peer — a `GenServer` that owns a TCP socket, drives
  the `PeerNet.Handshake` to completion, and then multiplexes
  `:call`/`:reply`/`:send` envelopes over the wire.

  ## Lifecycle

  1. **Spawned** with `:inbound` (from `PeerNet.Acceptor`) or `:outbound`
     (from `PeerNet.connect/4`) plus an open TCP socket.
  2. **Handshake**: drives `PeerNet.Handshake` in a tight loop until the
     peer's pubkey is verified against the trust list. Bad input → terminate.
  3. **Registered**: once authenticated, registers itself with
     `PeerNet.Registry` under the verified peer pubkey.
  4. **Active**: receives envelopes, dispatches `:call` and `:send` through
     `PeerNet.Handlers`, matches `:reply` envelopes to in-flight callers.
  5. **Terminated**: socket close, peer revoke, or supersede event.

  ## Caller registration

  An outbound `PeerNet.call/4` arrives here as a `GenServer.call`. Each call
  is assigned a 64-bit non-zero `request_id`; the GenServer stores
  `{request_id => GenServer.from}` and replies asynchronously when the
  matching `:reply` envelope arrives. Unknown reply IDs are dropped — they
  may be late replies for already-timed-out calls.

  ## v0 limitations

  - Plaintext over TCP (no Noise yet — see `PeerNet.Handshake` notes).
  - No reconnect logic. If the socket dies, the connection terminates and
    the peer must be re-`connect/4`'d.
  - No application-level liveness ping. Detection of dead peers waits on
    TCP-level events.
  """

  use GenServer

  require Logger

  alias PeerNet.{Channel, Frame, Handlers, Handshake, Liveness, Trust}
  alias PeerNet.Registry, as: Reg

  @typedoc "How the socket was created."
  @type direction :: :inbound | :outbound

  @timeout_default 5_000

  # Liveness defaults — production cadence. Tests override via opts.
  @liveness_interval_default 30_000
  @liveness_timeout_default 60_000

  # ── Public API ──────────────────────────────────────────────────────

  @doc """
  Start a connection process owning `socket`.

  After this call the GenServer takes ownership: the caller must not read
  or write `socket` afterwards. Usually called by `Acceptor` or via
  `PeerNet.connect/4`.

  Required opts: `:identity`, `:trust`, `:handlers`, `:peer_index`,
  `:direction`. Optional: `:expected_peer` (the pubkey the dialer expects
  on the other end of an outbound connection).
  """
  @spec start_link(keyword()) :: GenServer.on_start()
  def start_link(opts), do: GenServer.start_link(__MODULE__, opts)

  @doc """
  Take ownership of an inbound socket. Used by Acceptor after `:gen_tcp.accept/1`.
  """
  @spec hand_off_socket(pid(), :gen_tcp.socket()) :: :ok
  def hand_off_socket(pid, socket) do
    :ok = :gen_tcp.controlling_process(socket, pid)
    GenServer.cast(pid, {:socket, socket})
  end

  @doc "Send a `:call` envelope and await `{:reply, _, result}` (or timeout)."
  @spec call(pid(), atom(), term(), pos_integer()) ::
          {:ok, term()} | {:error, term()}
  def call(pid, name, args, timeout \\ @timeout_default) do
    GenServer.call(pid, {:peer_call, name, args}, timeout)
  catch
    :exit, {:timeout, _} -> {:error, :timeout}
    :exit, {:noproc, _} -> {:error, :not_connected}
    :exit, {:normal, _} -> {:error, :not_connected}
  end

  @doc "Send a fire-and-forget `:send` envelope. No reply expected."
  @spec send(pid(), atom(), term()) :: :ok
  def send(pid, name, args), do: GenServer.cast(pid, {:peer_send, name, args})

  # ── GenServer ───────────────────────────────────────────────────────

  @impl true
  def init(opts) do
    identity = Keyword.fetch!(opts, :identity)
    trust = Keyword.fetch!(opts, :trust)
    handlers = Keyword.fetch!(opts, :handlers)
    # Naming carryover: callers may still pass `:peer_index` (legacy
    # term) or the newer `:registry`. Either resolves to the same
    # process — the Registry that tracks pubkey → conn pid mappings.
    registry = Keyword.get(opts, :registry) || Keyword.fetch!(opts, :peer_index)
    direction = Keyword.fetch!(opts, :direction)
    expected_peer = Keyword.get(opts, :expected_peer)
    socket = Keyword.get(opts, :socket)

    # Build trust set from the live Trust GenServer at handshake time.
    role =
      case direction do
        :outbound -> :initiator
        :inbound -> :responder
      end

    state = %{
      identity: identity,
      trust_pid: trust,
      handlers_pid: handlers,
      peer_index: registry,
      direction: direction,
      expected_peer: expected_peer,
      socket: socket,
      handshake: Handshake.init(role, identity, current_trust(trust)),
      pending: %{},
      buffer: <<>>,
      liveness: nil,
      liveness_interval_ms: Keyword.get(opts, :liveness_interval_ms, @liveness_interval_default),
      liveness_timeout_ms: Keyword.get(opts, :liveness_timeout_ms, @liveness_timeout_default)
    }

    if socket do
      {:ok, after_socket(state)}
    else
      {:ok, state}
    end
  end

  @impl true
  def handle_cast({:socket, socket}, state) do
    {:noreply, after_socket(%{state | socket: socket})}
  end

  def handle_cast({:peer_send, name, args}, state) do
    case state.handshake.phase do
      :authenticated ->
        case write_envelope(state, {:send, name, args}) do
          {:ok, new_state} -> {:noreply, new_state}
          {:error, _, new_state} -> {:stop, :normal, fail_pending(new_state, :transport_lost)}
        end

      _ ->
        # Drop sends issued before handshake completes — fire-and-forget
        # semantics mean the caller can't be notified anyway.
        {:noreply, state}
    end
  end

  @impl true
  def handle_call({:peer_call, name, args}, from, state) do
    case state.handshake.phase do
      :authenticated ->
        request_id = next_request_id()
        envelope = {:call, request_id, name, args}

        case write_envelope(state, envelope) do
          {:ok, new_state} ->
            new_state = put_in(new_state.pending[request_id], from)
            {:noreply, new_state}

          {:error, reason, _new_state} ->
            {:reply, {:error, {:transport_failed, reason}}, state}
        end

      _ ->
        {:reply, {:error, :not_authenticated}, state}
    end
  end

  @impl true
  def handle_info({:tcp, socket, data}, %{socket: socket} = state) do
    state = %{state | buffer: state.buffer <> data}
    handle_inbound_bytes(state)
  end

  def handle_info({:tcp_closed, socket}, %{socket: socket} = state) do
    {:stop, :normal, fail_pending(state, :connection_closed)}
  end

  def handle_info({:tcp_error, socket, reason}, %{socket: socket} = state) do
    {:stop, {:tcp_error, reason}, fail_pending(state, {:tcp_error, reason})}
  end

  def handle_info(:superseded, state) do
    {:stop, :normal, fail_pending(state, :superseded)}
  end

  def handle_info({:liveness_send_ping, nonce}, state) do
    case write_envelope(state, {:ping, nonce}) do
      {:ok, new_state} -> {:noreply, new_state}
      {:error, _, new_state} -> {:stop, :normal, fail_pending(new_state, :transport_lost)}
    end
  end

  def handle_info(:liveness_peer_dead, state) do
    Logger.info("[PeerNet] peer #{inspect(state.handshake.peer_pubkey)} unresponsive")
    {:stop, :normal, fail_pending(state, :peer_unresponsive)}
  end

  def handle_info(_other, state), do: {:noreply, state}

  @impl true
  def terminate(_reason, state) do
    if state.socket, do: :gen_tcp.close(state.socket)
    if state.liveness && Process.alive?(state.liveness), do: GenServer.stop(state.liveness, :normal)
    :ok
  end

  # ── Internal: handshake driver ──────────────────────────────────────

  defp after_socket(state) do
    :ok = :inet.setopts(state.socket, active: :once, packet: :raw, mode: :binary)
    drive_handshake(state)
  end

  defp drive_handshake(%{handshake: %{phase: :authenticated}} = state) do
    :ok = Reg.register_connection(state.peer_index, state.handshake.peer_pubkey, self())

    if state.expected_peer && state.expected_peer != state.handshake.peer_pubkey do
      Logger.warning("[PeerNet] outbound peer mismatch — expected #{inspect(state.expected_peer)}")
    end

    start_liveness(state)
  end

  defp drive_handshake(state) do
    case Handshake.step(state.handshake, <<>>) do
      {:ok, new_hs, out_bytes} ->
        if out_bytes != <<>>, do: :ok = :gen_tcp.send(state.socket, out_bytes)
        %{state | handshake: new_hs}

      {:error, _reason, _side} ->
        # Step with no input may still error (rare); fall through.
        state
    end
  end

  defp handle_inbound_bytes(state) do
    case state.handshake.phase do
      :authenticated ->
        consume_envelopes(state)

      _ ->
        case Handshake.step(state.handshake, state.buffer) do
          {:error, reason, _side} ->
            Logger.info("[PeerNet] handshake failed: #{inspect(reason)}")
            {:stop, :normal, state}

          {:ok, new_hs, out_bytes} ->
            if out_bytes != <<>>, do: :ok = :gen_tcp.send(state.socket, out_bytes)

            new_state = %{state | handshake: new_hs, buffer: new_hs.inbox}
            new_state = %{new_state | handshake: %{new_state.handshake | inbox: <<>>}}

            new_state =
              if new_hs.phase == :authenticated, do: drive_handshake(new_state), else: new_state

            :ok = :inet.setopts(state.socket, active: :once)
            {:noreply, new_state}
        end
    end
  end

  defp consume_envelopes(state) do
    case Frame.decode_raw(state.buffer) do
      :incomplete ->
        :ok = :inet.setopts(state.socket, active: :once)
        {:noreply, state}

      {:error, reason} ->
        Logger.info("[PeerNet] wire error: #{inspect(reason)}")
        {:stop, :normal, state}

      {:ok, frame_body, rest} ->
        case Channel.decrypt(state.handshake.rx, frame_body) do
          {:ok, envelope, new_rx} ->
            new_state = %{
              state
              | buffer: rest,
                handshake: %{state.handshake | rx: new_rx}
            }

            case dispatch_envelope(envelope, new_state) do
              {:ok, ns} -> consume_envelopes(ns)
              {:stop, ns} -> {:stop, :normal, ns}
            end

          {:error, reason, _} ->
            Logger.info("[PeerNet] AEAD decrypt failed: #{inspect(reason)}")
            {:stop, :normal, state}
        end
    end
  end

  # Encrypt one envelope through the tx CipherState and write it.
  # Returns {:ok, new_state} on success or {:error, reason, new_state}
  # on transport failure.
  defp write_envelope(state, envelope) do
    case Channel.encrypt(state.handshake.tx, envelope) do
      {wire, new_tx} ->
        new_state = %{state | handshake: %{state.handshake | tx: new_tx}}

        case :gen_tcp.send(state.socket, wire) do
          :ok -> {:ok, new_state}
          {:error, reason} -> {:error, reason, new_state}
        end

      {:error, :counter_exhausted, _} ->
        {:error, :counter_exhausted, state}
    end
  end

  defp dispatch_envelope({:call, id, name, args}, state) do
    result = Handlers.dispatch(state.handlers_pid, name, state.handshake.peer_pubkey, args)

    reply_env =
      case result do
        {:ok, value} -> {:reply, id, {:ok, value}}
        {:error, reason} -> {:reply, id, {:error, reason}}
      end

    case write_envelope(state, reply_env) do
      {:ok, new_state} -> {:ok, new_state}
      {:error, _, _} -> {:stop, state}
    end
  end

  defp dispatch_envelope({:reply, id, result}, state) do
    case Map.pop(state.pending, id) do
      {nil, _} ->
        # Late or unknown reply — drop silently.
        {:ok, state}

      {from, pending} ->
        GenServer.reply(from, result)
        {:ok, %{state | pending: pending}}
    end
  end

  defp dispatch_envelope({:send, name, args}, state) do
    _ = Handlers.dispatch(state.handlers_pid, name, state.handshake.peer_pubkey, args)
    {:ok, state}
  end

  defp dispatch_envelope({:ping, nonce}, state) when is_binary(nonce) do
    case write_envelope(state, {:pong, nonce}) do
      {:ok, new_state} -> {:ok, new_state}
      {:error, _, _} -> {:stop, state}
    end
  end

  defp dispatch_envelope({:pong, nonce}, state) when is_binary(nonce) do
    if state.liveness, do: Liveness.handle_pong(state.liveness, nonce)
    {:ok, state}
  end

  defp dispatch_envelope(_unknown, state) do
    # Unknown envelope shape — close the connection rather than risk an
    # injection going unnoticed.
    {:stop, state}
  end

  # ── Internal: helpers ───────────────────────────────────────────────

  # Spawn the heartbeat process. Pings travel as `{:ping, nonce}`
  # envelopes over the same Frame transport as everything else. Pongs
  # come back the same way and are routed via `dispatch_envelope/2`.
  defp start_liveness(state) do
    me = self()

    emit = fn nonce -> Process.send(me, {:liveness_send_ping, nonce}, []) end
    on_dead = fn -> Process.send(me, :liveness_peer_dead, []) end

    {:ok, lv_pid} =
      Liveness.start_link(
        interval_ms: state.liveness_interval_ms,
        timeout_ms: state.liveness_timeout_ms,
        emit: emit,
        on_dead: on_dead
      )

    %{state | liveness: lv_pid}
  end

  defp current_trust(trust_pid) do
    trust_pid
    |> Trust.list()
    |> Enum.map(& &1.pubkey)
    |> MapSet.new()
  end

  defp next_request_id do
    # 63-bit positive integer; collisions are vanishingly unlikely within
    # the lifetime of a single connection.
    :rand.uniform(0xFFFFFFFFFFFFFFFF)
  end

  defp fail_pending(state, reason) do
    for {_id, from} <- state.pending do
      GenServer.reply(from, {:error, reason})
    end

    %{state | pending: %{}}
  end
end
