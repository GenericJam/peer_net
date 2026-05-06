defmodule PeerNet.Acceptor do
  @moduledoc """
  TCP listener for one PeerNet instance. Accepts inbound connections and
  spawns one `PeerNet.Connection` per accepted socket.

  The acceptor is intentionally tiny — all the state lives on the
  per-connection process. The acceptor's only job is to call
  `:gen_tcp.accept/1` in a loop and hand each accepted socket off to a
  fresh connection process.

  Bind on port `0` to let the OS pick an ephemeral port; read it back with
  `port/1` afterwards (used in tests and in places where the listener's
  address needs to be advertised externally).
  """

  use GenServer

  require Logger

  alias PeerNet.Connection.Supervisor, as: ConnSup

  # ── Public API ──────────────────────────────────────────────────────

  def start_link(opts) do
    {name, opts} = Keyword.pop(opts, :name, __MODULE__)
    GenServer.start_link(__MODULE__, opts, name: name)
  end

  @doc "Return the OS-assigned listen port (resolved from `port: 0`)."
  @spec port(GenServer.server()) :: :inet.port_number()
  def port(server \\ __MODULE__), do: GenServer.call(server, :port)

  # ── GenServer ───────────────────────────────────────────────────────

  @impl true
  def init(opts) do
    port = Keyword.get(opts, :port, 0)
    conn_sup = Keyword.fetch!(opts, :conn_sup)
    identity = Keyword.fetch!(opts, :identity)
    trust = Keyword.fetch!(opts, :trust)
    handlers = Keyword.fetch!(opts, :handlers)
    peer_index = Keyword.fetch!(opts, :peer_index)

    listen_opts = [
      :binary,
      packet: :raw,
      active: false,
      reuseaddr: true,
      ip: {127, 0, 0, 1}
    ]

    case :gen_tcp.listen(port, listen_opts) do
      {:ok, lsock} ->
        {:ok, actual_port} = :inet.port(lsock)
        parent = self()
        worker = spawn_link(fn -> accept_loop(lsock, parent) end)

        {:ok,
         %{
           lsock: lsock,
           port: actual_port,
           worker: worker,
           conn_sup: conn_sup,
           identity: identity,
           trust: trust,
           handlers: handlers,
           peer_index: peer_index
         }}

      {:error, reason} ->
        {:stop, {:listen_failed, reason}}
    end
  end

  @impl true
  def handle_call(:port, _from, state), do: {:reply, state.port, state}

  @impl true
  def handle_info({:accepted, socket}, state) do
    case ConnSup.start_connection(state.conn_sup,
           identity: state.identity,
           trust: state.trust,
           handlers: state.handlers,
           peer_index: state.peer_index,
           direction: :inbound
         ) do
      {:ok, pid} ->
        # Connection process must own the socket *before* we hand off, so
        # set controlling_process from THIS process (which currently owns
        # the socket since the worker passed it via message).
        :ok = :gen_tcp.controlling_process(socket, pid)
        PeerNet.Connection.hand_off_socket(pid, socket)

      {:error, reason} ->
        Logger.warning("[PeerNet] failed to start inbound connection: #{inspect(reason)}")
        :gen_tcp.close(socket)
    end

    {:noreply, state}
  end

  def handle_info(_, state), do: {:noreply, state}

  @impl true
  def terminate(_reason, %{lsock: lsock}) when is_port(lsock) do
    :gen_tcp.close(lsock)
    :ok
  end

  def terminate(_, _), do: :ok

  # ── Accept worker ───────────────────────────────────────────────────

  # The worker blocks indefinitely in `:gen_tcp.accept/1` so the parent
  # GenServer can serve `:port` calls without contention. Each accepted
  # socket is handed back to the parent for connection spawning, then the
  # worker loops. Owns no state — restart on crash via the spawn_link.
  defp accept_loop(lsock, parent) do
    case :gen_tcp.accept(lsock) do
      {:ok, socket} ->
        # Transfer ownership to the parent so it can hand off to the
        # connection process. (controlling_process must be called from
        # the current owner.)
        :ok = :gen_tcp.controlling_process(socket, parent)
        send(parent, {:accepted, socket})
        accept_loop(lsock, parent)

      {:error, :closed} ->
        :ok

      {:error, reason} ->
        Logger.warning("[PeerNet] accept worker: #{inspect(reason)}")
        accept_loop(lsock, parent)
    end
  end
end
