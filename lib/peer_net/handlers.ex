defmodule PeerNet.Handlers do
  @moduledoc """
  Default-deny registry of named, peer-callable handlers.

  This module is the entire authorisation surface that PeerNet exposes to the
  network. Until a handle is registered via `expose/3`, peers calling that
  handle name see `{:error, :no_such_handle}` — no module names, no stack
  traces, no information about whether the handle existed at any prior time.

  Each handler is a 2-arity function `(caller_pubkey, args) -> result`. The
  caller's verified Ed25519 public key is the first argument, so handlers
  can make per-peer authorisation decisions inline — and so a misbehaving
  peer can't masquerade as another even if they spoof addressing fields in
  the wire format.

  ## Authorisation

  An optional `:authorize` predicate gates which peers can reach the handle
  at all. The predicate runs before the handler body, so a forbidden caller
  never gets a chance to trigger handler logic:

      Handlers.expose(:beam_admin, &MyMod.handle/2,
        authorize: fn pubkey -> pubkey == @admin_pubkey end)

  Forbidden callers see `{:error, :forbidden}`. The handler body never runs.

  ## Crash containment

  If a handler raises, throws, or exits, the crash is caught and reported as
  `{:error, {:handler_crash, info}}` — the connection process handling the
  call stays alive and the connection is not torn down. A handler crashing is
  not a connection-level fault; it's an app-level bug that should be visible
  to the calling peer (in dev) but should not destabilise the link.

  ## Examples

      iex> name = :"handlers_doctest_\#{System.unique_integer([:positive])}"
      iex> {:ok, pid} = PeerNet.Handlers.start_link(name: name)
      iex> :ok = PeerNet.Handlers.expose(pid, :echo, fn from, args -> {from, args} end)
      iex> PeerNet.Handlers.dispatch(pid, :echo, <<1::256>>, %{x: 1})
      {:ok, {<<1::256>>, %{x: 1}}}
  """

  use GenServer

  @typedoc "A handler function: receives caller pubkey + args, returns any term."
  @type handler :: (binary(), term() -> term())

  @typedoc "Per-handle options passed at expose time."
  @type expose_opts :: [authorize: (binary() -> boolean())]

  # ── Public API ─────────────────────────────────────────────────────────

  @doc "Start the handlers registry."
  @spec start_link(keyword()) :: GenServer.on_start()
  def start_link(opts \\ []) do
    {name, opts} = Keyword.pop(opts, :name, __MODULE__)
    GenServer.start_link(__MODULE__, opts, name: name)
  end

  @doc """
  Register `handler` under `name` so peers can `call` or `send` to it.

  `handler` must be a 2-arity function `(caller_pubkey, args) -> result`.

  Options:

  - `:authorize` — `(pubkey -> boolean)` predicate gating access. Peers
    that fail this check see `{:error, :forbidden}` and the handler body
    never runs.

  Returns `:ok`, or `{:error, :invalid_name}` if `name` isn't an atom, or
  `{:error, :invalid_handler}` if `handler` isn't a 2-arity function.

  Re-exposing an existing name silently replaces the previous handler.
  """
  @spec expose(GenServer.server(), term(), term(), expose_opts()) ::
          :ok | {:error, :invalid_name | :invalid_handler}
  def expose(server \\ __MODULE__, name, handler, opts \\ [])

  def expose(_server, name, _handler, _opts) when not is_atom(name),
    do: {:error, :invalid_name}

  def expose(server, name, handler, opts) when is_function(handler, 2) do
    GenServer.call(server, {:expose, name, handler, opts})
  end

  def expose(_server, _name, _handler, _opts), do: {:error, :invalid_handler}

  @doc "Remove a previously-exposed handle. No-op if absent."
  @spec revoke(GenServer.server(), atom()) :: :ok
  def revoke(server \\ __MODULE__, name) when is_atom(name) do
    GenServer.call(server, {:revoke, name})
  end

  @doc "List all registered handle names."
  @spec list(GenServer.server()) :: [atom()]
  def list(server \\ __MODULE__), do: GenServer.call(server, :list)

  @doc """
  Look up a handle's handler + options.

  Returns `{:ok, opts, handler}` or `:error`. Useful for diagnostics; normal
  callers should use `dispatch/4`.
  """
  @spec lookup(GenServer.server(), atom()) :: {:ok, expose_opts(), handler()} | :error
  def lookup(server \\ __MODULE__, name) when is_atom(name) do
    GenServer.call(server, {:lookup, name})
  end

  @doc """
  Dispatch a call from `caller_pubkey` to handle `name` with `args`.

  Returns:

  - `{:ok, result}` — handler returned normally.
  - `{:error, :no_such_handle}` — handle isn't registered.
  - `{:error, :forbidden}` — `:authorize` predicate rejected this caller.
  - `{:error, {:handler_crash, info}}` — handler raised, threw, or exited.
  """
  @spec dispatch(GenServer.server(), atom(), binary(), term()) ::
          {:ok, term()}
          | {:error, :no_such_handle | :forbidden | {:handler_crash, term()}}
  def dispatch(server \\ __MODULE__, name, caller_pubkey, args)
      when is_atom(name) and is_binary(caller_pubkey) do
    case lookup(server, name) do
      :error ->
        {:error, :no_such_handle}

      {:ok, opts, handler} ->
        if authorized?(opts, caller_pubkey) do
          run(handler, caller_pubkey, args)
        else
          {:error, :forbidden}
        end
    end
  end

  defp authorized?(opts, caller_pubkey) do
    case Keyword.get(opts, :authorize) do
      nil -> true
      fun when is_function(fun, 1) -> fun.(caller_pubkey) == true
      _ -> false
    end
  end

  defp run(handler, caller_pubkey, args) do
    {:ok, handler.(caller_pubkey, args)}
  rescue
    e -> {:error, {:handler_crash, {:error, e, __STACKTRACE__}}}
  catch
    kind, reason -> {:error, {:handler_crash, {kind, reason}}}
  end

  # ── GenServer ──────────────────────────────────────────────────────────

  @impl true
  def init(_opts), do: {:ok, %{handlers: %{}}}

  @impl true
  def handle_call(:list, _from, state) do
    {:reply, Map.keys(state.handlers), state}
  end

  def handle_call({:lookup, name}, _from, state) do
    case Map.fetch(state.handlers, name) do
      {:ok, {handler, opts}} -> {:reply, {:ok, opts, handler}, state}
      :error -> {:reply, :error, state}
    end
  end

  def handle_call({:expose, name, handler, opts}, _from, state) do
    new = Map.put(state.handlers, name, {handler, opts})
    {:reply, :ok, %{state | handlers: new}}
  end

  def handle_call({:revoke, name}, _from, state) do
    {:reply, :ok, %{state | handlers: Map.delete(state.handlers, name)}}
  end
end
