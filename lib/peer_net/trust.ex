defmodule PeerNet.Trust do
  @moduledoc """
  Persistent allowlist of peer public keys this node will talk to.

  PeerNet's whole security model rests on this list. A peer is "trusted" iff
  their Ed25519 public key (32 bytes) appears here. Untrusted peers are
  rejected at handshake time — they cannot complete the Noise XX exchange,
  so the connection is closed before any application-level message is
  exchanged.

  Pairing flow: out-of-band exchange of public keys (e.g. via QR code), then
  both sides call `add/3` with the other's pubkey.

  ## Pubkey format

  All pubkeys are 32-byte binaries. Anything else is rejected with
  `{:error, :invalid_pubkey}`. This shape check is the entire input
  validation — no parsing, no decoding, no Base64. If a caller has a hex or
  Base64 representation, decode it first.

  ## Persistence

  The trust list is written to `data_dir/trust.bin` after every change. The
  file format is intentionally simple (a list of `%{pubkey, label, added_at}`
  maps serialized via `:erlang.term_to_binary/2` with `:safe` decoding) so
  it can be inspected and recovered without this module.

  ## Process model

  Implemented as a `GenServer` so multiple callers can read and write
  concurrently without races. The list is held in memory; persistence is a
  side-effect of mutations, not the source of truth at runtime.

  ## Examples

      iex> uniq = "\#{:os.system_time(:nanosecond)}_\#{System.unique_integer([:positive])}"
      iex> dir = Path.join(System.tmp_dir!(), "peer_net_doctest_\#{uniq}")
      iex> name = :"trust_doctest_\#{uniq}"
      iex> {:ok, pid} = PeerNet.Trust.start_link(data_dir: dir, name: name)
      iex> PeerNet.Trust.list(pid)
      []
      iex> :ok = PeerNet.Trust.add(pid, <<1::256>>, label: "test")
      iex> PeerNet.Trust.trusted?(pid, <<1::256>>)
      true
  """

  use GenServer

  @typedoc """
  An entry in the trust list.

  - `pubkey`: the peer's Ed25519 public key (32 bytes).
  - `label`: optional human-readable name for UI display.
  - `added_at`: when this peer was first added, for the trust UI.
  """
  @type entry :: %{
          pubkey: <<_::256>>,
          label: String.t() | nil,
          added_at: DateTime.t()
        }

  @trust_filename "trust.bin"

  # ── Public API ─────────────────────────────────────────────────────────

  @doc """
  Start the trust process.

  Options:

  - `:data_dir` (required) — directory under which `trust.bin` will be read
    and written.
  - `:name` (optional) — process registration name.
  """
  @spec start_link(keyword()) :: GenServer.on_start()
  def start_link(opts) do
    {name, opts} = Keyword.pop(opts, :name, __MODULE__)
    GenServer.start_link(__MODULE__, opts, name: name)
  end

  @doc "Return all trusted peer entries."
  @spec list(GenServer.server()) :: [entry()]
  def list(server \\ __MODULE__), do: GenServer.call(server, :list)

  @doc """
  True iff `pubkey` (a 32-byte binary) is in the trust list.

  Returns false (not an error) for any non-32-byte input — this lets call
  sites screen unknown peers without a guard.
  """
  @spec trusted?(GenServer.server(), term()) :: boolean()
  def trusted?(server \\ __MODULE__, pubkey)
  def trusted?(server, <<_::256>> = pubkey), do: GenServer.call(server, {:trusted?, pubkey})
  def trusted?(_server, _other), do: false

  @doc """
  Add `pubkey` to the trust list.

  Options:

  - `:label` — optional human-readable name shown in trust UI.

  Returns `:ok` whether the pubkey was newly added or already present
  (idempotent). Returns `{:error, :invalid_pubkey}` if `pubkey` isn't a
  32-byte binary.
  """
  @spec add(GenServer.server(), binary(), keyword()) :: :ok | {:error, :invalid_pubkey}
  def add(server \\ __MODULE__, pubkey, opts \\ [])

  def add(server, <<_::256>> = pubkey, opts) do
    label = Keyword.get(opts, :label)
    GenServer.call(server, {:add, pubkey, label})
  end

  def add(_server, _pubkey, _opts), do: {:error, :invalid_pubkey}

  @doc "Remove `pubkey` from the trust list. No-op if it wasn't present."
  @spec remove(GenServer.server(), binary()) :: :ok
  def remove(server \\ __MODULE__, pubkey)
  def remove(server, <<_::256>> = pubkey), do: GenServer.call(server, {:remove, pubkey})
  def remove(_server, _other), do: :ok

  # ── GenServer ──────────────────────────────────────────────────────────

  @impl true
  def init(opts) do
    data_dir = Keyword.fetch!(opts, :data_dir)
    File.mkdir_p!(data_dir)
    state = %{data_dir: data_dir, entries: load(data_dir)}
    {:ok, state}
  end

  @impl true
  def handle_call(:list, _from, state), do: {:reply, state.entries, state}

  def handle_call({:trusted?, pubkey}, _from, state) do
    {:reply, Enum.any?(state.entries, &(&1.pubkey == pubkey)), state}
  end

  def handle_call({:add, pubkey, label}, _from, state) do
    if Enum.any?(state.entries, &(&1.pubkey == pubkey)) do
      {:reply, :ok, state}
    else
      entry = %{pubkey: pubkey, label: label, added_at: DateTime.utc_now()}
      new_entries = [entry | state.entries]
      :ok = persist(state.data_dir, new_entries)
      {:reply, :ok, %{state | entries: new_entries}}
    end
  end

  def handle_call({:remove, pubkey}, _from, state) do
    new_entries = Enum.reject(state.entries, &(&1.pubkey == pubkey))

    if length(new_entries) == length(state.entries) do
      {:reply, :ok, state}
    else
      :ok = persist(state.data_dir, new_entries)
      {:reply, :ok, %{state | entries: new_entries}}
    end
  end

  # ── Persistence ────────────────────────────────────────────────────────

  defp load(data_dir) do
    path = Path.join(data_dir, @trust_filename)

    case File.read(path) do
      {:ok, bin} ->
        # `:safe` rejects atoms not already known to this BEAM and rejects
        # function references — the two ETF features that are unsafe to
        # decode from untrusted-or-corrupted bytes.
        try do
          :erlang.binary_to_term(bin, [:safe])
        rescue
          _ -> []
        else
          entries when is_list(entries) -> entries
          _ -> []
        end

      {:error, _} ->
        []
    end
  end

  defp persist(data_dir, entries) do
    path = Path.join(data_dir, @trust_filename)
    File.write(path, :erlang.term_to_binary(entries))
  end
end
