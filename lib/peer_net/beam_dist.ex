defmodule PeerNet.BeamDist do
  @moduledoc """
  Convenience layer that gives a specifically-trusted peer
  BEAM-distribution-like RPC access — `apply(mod, fun, args)` over the
  PeerNet wire, with the peer's identity verified cryptographically.

  ## When this is the right tool

  When you want one peer (the **controller** — typically a phone) to
  invoke arbitrary functions on another peer (the **controlled** —
  typically a Nerves device) without giving every peer a remote shell.

  Asymmetric: the grant is per-peer, on the *receiving* side. The
  controller doesn't gain anything just by calling
  `BeamDist.call/4` — only peers that have explicitly exposed the
  `:beam_admin` handle (and authorized this caller) will respond.

  ## Setup

  On the side that wants to be controlled:

      # In your supervision tree (or anywhere with init access to PeerNet):
      PeerNet.expose(:beam_admin, &PeerNet.BeamDist.handle/2,
        authorize: fn pubkey -> pubkey == @controller_pubkey end)

  That's it. The `authorize:` predicate is the entire ACL — peers
  outside it see `{:error, :forbidden}` and the handle never runs.

  ## Use

  On the controller side:

      # Synchronous call (waits for return value):
      {:ok, result} = PeerNet.BeamDist.call(controlled_pubkey, MyMod, :status, [])

      # Fire-and-forget (returns immediately, no result available):
      :ok = PeerNet.BeamDist.cast(controlled_pubkey, Logger, :info, ["hi from phone"])

  ## What you're trusting

  When you authorize a peer for `:beam_admin`, you're handing them
  effectively-unrestricted code execution on this node. They can read
  any module's state, mutate any process, write any file you have
  permissions for. The only restrictions are OS-level (file
  permissions, network sandbox).

  Treat the authorize predicate as you would treat sshd's
  `authorized_keys` — narrow, audited, and changed when devices are
  lost or compromised.

  ## Why expose this at all

  The same critique applies to BEAM distribution itself: anyone with
  the cookie has root on every node. PeerNet's default-deny posture
  rejects that model. `BeamDist` exists for cases where the
  ergonomics are genuinely worth the trade — Nerves devices that
  need to be controllable by their owner's phone, IoT setups where
  one trusted controller manages many endpoints — and makes the
  trust grant *explicit and per-peer* instead of implicit and global.
  """

  alias PeerNet

  @typedoc "The handle name `expose`'d on the receiving side. Conventional, not enforced."
  @type handle :: :beam_admin

  # ── Receiving side: handler exposed via `PeerNet.expose/4` ─────────

  @doc """
  Handler implementation. Wire this into `PeerNet.expose/4`:

      PeerNet.expose(:beam_admin, &PeerNet.BeamDist.handle/2, authorize: ...)

  Accepts two envelope shapes:

  - `{:rpc, mod, fun, args}` — synchronous; returns the result of
    `apply(mod, fun, args)` to the caller.
  - `{:cast, mod, fun, args}` — fire-and-forget; spawns the apply
    and returns `:ok` immediately.

  Anything else returns `{:error, :unknown_beam_dist_op}` so a
  protocol-mismatch caller gets a clear signal.
  """
  @spec handle(binary(), term()) :: term()
  def handle(_caller_pubkey, {:rpc, mod, fun, args})
      when is_atom(mod) and is_atom(fun) and is_list(args) do
    apply(mod, fun, args)
  end

  def handle(_caller_pubkey, {:cast, mod, fun, args})
      when is_atom(mod) and is_atom(fun) and is_list(args) do
    spawn(fn -> apply(mod, fun, args) end)
    :ok
  end

  def handle(_caller_pubkey, _other), do: {:error, :unknown_beam_dist_op}

  # ── Caller side: convenience wrappers ──────────────────────────────

  @doc """
  Synchronously invoke `apply(mod, fun, args)` on the peer.

  Default handle name is `:beam_admin`; pass `:handle` to address a
  differently-named exposed handler. Default timeout is 5000ms.

  Returns whatever the remote `apply/3` returned, wrapped in
  `{:ok, result}`. Returns `{:error, reason}` on transport / handler
  failure — typically `:not_connected`, `:forbidden`,
  `:no_such_handle`, or `{:handler_crash, _}`.
  """
  @spec call(atom(), PeerNet.pubkey(), module(), atom(), [term()], keyword()) ::
          {:ok, term()} | {:error, term()}
  def call(name \\ PeerNet, peer_pubkey, mod, fun, args, opts \\ []) do
    handle = Keyword.get(opts, :handle, :beam_admin)
    timeout = Keyword.get(opts, :timeout, 5_000)
    PeerNet.call(name, peer_pubkey, handle, {:rpc, mod, fun, args}, timeout)
  end

  @doc """
  Fire-and-forget `apply(mod, fun, args)` on the peer. No result.

  Returns `:ok` if the request was put on the wire, or
  `{:error, :not_connected}` if no live connection to the peer exists.
  """
  @spec cast(atom(), PeerNet.pubkey(), module(), atom(), [term()], keyword()) ::
          :ok | {:error, :not_connected}
  def cast(name \\ PeerNet, peer_pubkey, mod, fun, args, opts \\ []) do
    handle = Keyword.get(opts, :handle, :beam_admin)
    PeerNet.send(name, peer_pubkey, handle, {:cast, mod, fun, args})
  end
end
