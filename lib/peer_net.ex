defmodule PeerNet do
  @moduledoc """
  Public API for the PeerNet library and the per-instance supervisor.

  See [`README`](readme.html) for an overview, [`PLAN`](plan.html) for the
  v1 roadmap and module breakdown, and
  [`guides/protocol.md`](protocol.html) for the wire-format specification.

  ## Starting an instance

      children = [
        {PeerNet, [name: :my_node, data_dir: "/var/lib/myapp/peer_net", port: 4040]}
      ]

  Options:

  - `:name` (required) — atom; root name for this instance's processes.
    All public API functions take this name as their first argument.
  - `:data_dir` (required) — directory where the identity keyfile and
    trust list are persisted.
  - `:port` (required) — TCP port to listen on; pass `0` for an
    OS-assigned ephemeral port.

  ## Multiple instances

  More than one PeerNet instance can run inside the same BEAM (used in
  tests and in apps that need to expose multiple identities). Each takes a
  unique `:name`, and its child processes derive their names from it
  (e.g. `:my_node.trust`, `:my_node.handlers`).

  ## Threat model

  See [`README`](readme.html#threat-model). v0 (the current state) speaks
  authenticated-but-plaintext TCP — the channel is not encrypted yet. Use
  on local trusted networks only until Noise XX lands.
  """

  use Supervisor

  alias PeerNet.{Acceptor, Connection, Discovery, Handlers, Identity, NetworkMonitor, Trust}
  alias PeerNet.Registry, as: Reg

  @typedoc "A peer's permanent address — a 32-byte Ed25519 public key."
  @type pubkey :: <<_::256>>

  # ── Lifecycle ───────────────────────────────────────────────────────

  @doc false
  def child_spec(opts) do
    %{
      id: {__MODULE__, Keyword.get(opts, :name, __MODULE__)},
      start: {__MODULE__, :start_link, [opts]},
      type: :supervisor
    }
  end

  @doc "Start a PeerNet instance. See module docs for options."
  @spec start_link(keyword()) :: Supervisor.on_start()
  def start_link(opts) do
    name = Keyword.fetch!(opts, :name)
    Supervisor.start_link(__MODULE__, opts, name: sup_name(name))
  end

  @impl true
  def init(opts) do
    name = Keyword.fetch!(opts, :name)
    data_dir = Keyword.fetch!(opts, :data_dir)
    port = Keyword.fetch!(opts, :port)
    discovery_mod = Keyword.get(opts, :discovery, Discovery.Manual)
    discovery_opts = Keyword.get(opts, :discovery_opts, [])
    network_monitor_mod = Keyword.get(opts, :network_monitor)
    network_monitor_opts = Keyword.get(opts, :network_monitor_opts, [])

    File.mkdir_p!(data_dir)
    {:ok, identity, _origin} = Identity.load_or_create(data_dir)

    # Cache identity per instance so public API can look it up.
    :persistent_term.put({__MODULE__, :identity, name}, identity)

    network_monitor_arg =
      if network_monitor_mod, do: {network_monitor_mod, network_monitor_name(name)}

    base_children = [
      {Trust, [data_dir: data_dir, name: trust_name(name)]},
      {Handlers, [name: handlers_name(name)]},
      {Connection.Supervisor, [name: conn_sup_name(name)]}
    ]

    network_monitor_child =
      if network_monitor_mod do
        [{network_monitor_mod, [name: network_monitor_name(name)] ++ network_monitor_opts}]
      else
        []
      end

    registry_child = [
      {Reg,
       [
         name: registry_name(name),
         trust: trust_name(name),
         conn_sup: conn_sup_name(name),
         identity: identity,
         handlers: handlers_name(name),
         network_monitor: network_monitor_arg
       ]}
    ]

    acceptor_child = [
      {Acceptor,
       [
         name: acceptor_name(name),
         port: port,
         conn_sup: conn_sup_name(name),
         identity: identity,
         trust: trust_name(name),
         handlers: handlers_name(name),
         peer_index: registry_name(name)
       ]}
    ]

    base_children = base_children ++ network_monitor_child ++ registry_child ++ acceptor_child
    _ = NetworkMonitor

    discovery_child =
      if discovery_mod do
        merged_opts =
          [
            name: discovery_name(name),
            registry: registry_name(name),
            identity: identity
          ] ++ discovery_opts

        [{discovery_mod, merged_opts}]
      else
        []
      end

    # Schedule a post-init step to tell Discovery what port Acceptor
    # actually bound (matters for `port: 0` ephemeral). Runs as a
    # separate Task so it can't deadlock supervisor startup.
    bind_task =
      if discovery_mod do
        [
          {Task,
           fn ->
             # Wait for Acceptor to be reachable, then publish its port.
             port = wait_for_acceptor_port(acceptor_name(name))
             discovery_mod.announce_self(discovery_name(name), port)
           end}
        ]
      else
        []
      end

    Supervisor.init(base_children ++ discovery_child ++ bind_task, strategy: :one_for_one)
  end

  defp wait_for_acceptor_port(name, attempts \\ 50) do
    case Process.whereis(name) do
      nil when attempts > 0 ->
        Process.sleep(20)
        wait_for_acceptor_port(name, attempts - 1)

      pid when is_pid(pid) ->
        Acceptor.port(name)

      _ ->
        # Give up — discovery just won't know the port. Caller can
        # always set `peer_net_port:` in `discovery_opts` explicitly.
        0
    end
  end

  # ── Public API ──────────────────────────────────────────────────────

  @doc "Return this instance's `PeerNet.Identity`."
  @spec identity(atom()) :: Identity.t()
  def identity(name \\ __MODULE__) do
    :persistent_term.get({__MODULE__, :identity, name})
  end

  @doc "Return the OS-assigned listen port for this instance."
  @spec port(atom()) :: :inet.port_number()
  def port(name \\ __MODULE__), do: Acceptor.port(acceptor_name(name))

  @doc """
  Register a handler for inbound calls/sends from peers.

  See `PeerNet.Handlers.expose/4` for option details.
  """
  @spec expose(atom(), atom(), Handlers.handler(), Handlers.expose_opts()) ::
          :ok | {:error, term()}
  def expose(name \\ __MODULE__, handle, fun, opts \\ []) do
    Handlers.expose(handlers_name(name), handle, fun, opts)
  end

  @doc "Revoke a previously-exposed handle."
  @spec revoke(atom(), atom()) :: :ok
  def revoke(name \\ __MODULE__, handle) do
    Handlers.revoke(handlers_name(name), handle)
  end

  @doc "Add `pubkey` to this instance's trust list."
  @spec pair(atom(), pubkey(), keyword()) :: :ok | {:error, :invalid_pubkey}
  def pair(name \\ __MODULE__, pubkey, opts \\ []) do
    Trust.add(trust_name(name), pubkey, opts)
  end

  @doc "Remove `pubkey` from this instance's trust list."
  @spec unpair(atom(), pubkey()) :: :ok
  def unpair(name \\ __MODULE__, pubkey) do
    Trust.remove(trust_name(name), pubkey)
  end

  @doc """
  Open a new outbound connection to `pubkey` at `host:port`.

  This is the manual-pairing path used in tests and in setups without mDNS
  discovery. Once mDNS discovery (M3) lands, peers will be auto-connected
  on detection.

  Returns `:ok` once the socket is open and the connection process is
  spawned. Use `connected?/2` to wait for handshake completion before
  issuing calls.
  """
  @spec connect(atom(), pubkey(), :inet.ip_address() | charlist() | binary(), :inet.port_number()) ::
          :ok | {:error, term()}
  def connect(name \\ __MODULE__, pubkey, host, port) when is_binary(pubkey) do
    case :gen_tcp.connect(host_arg(host), port, [
           :binary,
           packet: :raw,
           active: false
         ]) do
      {:ok, socket} ->
        {:ok, pid} =
          Connection.Supervisor.start_connection(conn_sup_name(name),
            identity: identity(name),
            trust: trust_name(name),
            handlers: handlers_name(name),
            peer_index: registry_name(name),
            direction: :outbound,
            expected_peer: pubkey
          )

        Connection.hand_off_socket(pid, socket)

      {:error, reason} ->
        {:error, reason}
    end
  end

  @doc """
  Call `handle` on `pubkey` with `args`. Awaits a reply.

  Returns `{:ok, result}`, `{:error, :not_connected}` if no live connection
  exists, or `{:error, reason}` for transport/handler errors.
  """
  @spec call(atom(), pubkey(), atom(), term(), pos_integer()) ::
          {:ok, term()} | {:error, term()}
  def call(name \\ __MODULE__, pubkey, handle, args, timeout \\ 5_000) do
    case Reg.lookup_connection(registry_name(name), pubkey) do
      {:ok, pid} -> Connection.call(pid, handle, args, timeout)
      :not_connected -> {:error, :not_connected}
    end
  end

  @doc "Send `args` to `handle` on `pubkey`. Fire-and-forget."
  @spec send(atom(), pubkey(), atom(), term()) :: :ok | {:error, :not_connected}
  def send(name \\ __MODULE__, pubkey, handle, args) do
    case Reg.lookup_connection(registry_name(name), pubkey) do
      {:ok, pid} ->
        Connection.send(pid, handle, args)
        :ok

      :not_connected ->
        {:error, :not_connected}
    end
  end

  @doc "True iff a live, authenticated connection to `pubkey` exists."
  @spec connected?(atom(), pubkey()) :: boolean()
  def connected?(name \\ __MODULE__, pubkey) do
    Reg.connected?(registry_name(name), pubkey)
  end

  @doc "Return all known peers' pubkeys (currently just the trust list)."
  @spec list_peers(atom()) :: [map()]
  def list_peers(name \\ __MODULE__), do: Trust.list(trust_name(name))

  # ── Internal: per-instance process names ────────────────────────────

  defp sup_name(name), do: :"#{name}.sup"
  defp trust_name(name), do: :"#{name}.trust"
  defp handlers_name(name), do: :"#{name}.handlers"
  defp registry_name(name), do: :"#{name}.registry"
  defp conn_sup_name(name), do: :"#{name}.conn_sup"
  defp acceptor_name(name), do: :"#{name}.acceptor"
  defp discovery_name(name), do: :"#{name}.discovery"
  defp network_monitor_name(name), do: :"#{name}.network_monitor"

  defp host_arg(host) when is_binary(host), do: String.to_charlist(host)
  defp host_arg(host), do: host
end
