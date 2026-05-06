defmodule PeerNet.Identity do
  @moduledoc """
  Cryptographic identity for a PeerNet node — an X25519 keypair that uniquely
  identifies one peer to all the others.

  Each PeerNet node has exactly one identity. The public key is the peer's
  permanent address: anyone wanting to talk to this node names it by its
  public key, never by an IP/port pair. The private key is the static
  Diffie-Hellman key the Noise XX handshake uses to authenticate this node
  to peers and to derive forward-secret session keys.

  ## Why X25519 (not Ed25519)

  PeerNet's handshake is `Noise_XX_25519_ChaChaPoly_SHA256` — a standard
  Noise pattern. Noise's DH primitive on 25519 is X25519, not Ed25519.
  Identity needs to do DH operations during the handshake, so the static
  key has to be an X25519 key.

  We could carry both an Ed25519 (for signing) and an X25519 (for DH) key
  per identity, but the handshake authenticates the static X25519 key
  cryptographically by binding it into the transcript hash — no separate
  signing layer is needed.

  Apps that need long-term-key signatures for app-level data can layer
  that on top with their own keypair.

  ## Persistence

  `load_or_create/1` writes a keyfile under the supplied data directory so
  the node's identity survives restarts. The keyfile is a fixed-format binary
  that can only be parsed by this module.

  Treat the keyfile as a secret. Anyone holding it can impersonate the node
  to any peer that has paired with it. PeerNet does not encrypt the keyfile
  at rest; that is delegated to the host (filesystem permissions, full-disk
  encryption, etc.).

  ## Cryptographic primitives

  - **Algorithm**: X25519 (`:ecdh` / `:x25519` via `:crypto`)
  - **Public key size**: 32 bytes
  - **Private key size**: 32 bytes
  - **Fingerprint**: first 8 bytes of `SHA-256(public)`, hex-encoded — for
    UI display only, never for security decisions.

  ## Examples

      iex> id = PeerNet.Identity.generate()
      iex> byte_size(id.public)
      32
      iex> byte_size(id.private)
      32
  """

  @typedoc "An X25519 keypair. `public` is the permanent peer address."
  @type t :: %__MODULE__{public: binary(), private: binary()}

  @enforce_keys [:public, :private]
  defstruct [:public, :private]

  @keyfile_name "identity.keys"
  # Magic header lets us reject random files that happen to land in the
  # data dir without claiming they're corrupt keyfiles. v2 = X25519
  # (was 0x01 = Ed25519). Old keyfiles do not migrate — apps must
  # re-pair after upgrading to Noise.
  @keyfile_magic <<"PNID", 0x02>>

  @doc """
  Generate a fresh X25519 keypair.

  Pure function — no I/O. Use `load_or_create/1` for the normal node-
  lifecycle case where the identity should persist across restarts.
  """
  @spec generate() :: t()
  def generate do
    {public, private} = :crypto.generate_key(:ecdh, :x25519)
    %__MODULE__{public: public, private: private}
  end

  @doc """
  Compute the X25519 shared secret between this identity's private key and
  `peer_public`. Used by the Noise handshake.

  ## Examples

      iex> a = PeerNet.Identity.generate()
      iex> b = PeerNet.Identity.generate()
      iex> PeerNet.Identity.dh(a, b.public) == PeerNet.Identity.dh(b, a.public)
      true
  """
  @spec dh(t(), binary()) :: binary()
  def dh(%__MODULE__{private: private}, <<_::256>> = peer_public) do
    :crypto.compute_key(:ecdh, peer_public, private, :x25519)
  end

  @doc """
  Short, human-readable fingerprint of a public key. Use in logs and UI for
  identifying a peer at a glance.

  **Not** for security decisions — fingerprints are short and could collide
  under adversarial conditions. Always compare full public keys for trust
  decisions.

  ## Examples

      iex> fp = PeerNet.Identity.fingerprint(<<0::256>>)
      iex> String.length(fp)
      16
  """
  @spec fingerprint(binary()) :: String.t()
  def fingerprint(public_key) when is_binary(public_key) do
    <<short::binary-size(8), _::binary>> = :crypto.hash(:sha256, public_key)
    Base.encode16(short, case: :lower)
  end

  @doc """
  Load an existing identity from `data_dir`, or create one and persist it.

  Returns `{:ok, identity, :created | :loaded, ...}` where the third element
  tells the caller whether this is a fresh node (UI may want to show a
  "first-run" pairing screen).

  ## Errors

  - `{:error, :invalid_keyfile}` — the keyfile exists but is malformed.
  - `{:error, posix_reason}` — filesystem permission or I/O error.
  """
  @spec load_or_create(Path.t()) ::
          {:ok, t(), :created | :loaded} | {:error, :invalid_keyfile | File.posix()}
  def load_or_create(data_dir) when is_binary(data_dir) do
    path = Path.join(data_dir, @keyfile_name)

    case File.read(path) do
      {:ok, bin} ->
        case parse_keyfile(bin) do
          {:ok, identity} -> {:ok, identity, :loaded}
          :error -> {:error, :invalid_keyfile}
        end

      {:error, :enoent} ->
        with :ok <- ensure_dir(data_dir),
             identity = generate(),
             :ok <- write_keyfile(path, identity) do
          {:ok, identity, :created}
        end

      {:error, reason} ->
        {:error, reason}
    end
  end

  # ── Internal: keyfile encoding ──────────────────────────────────────────

  # Format: magic ‖ pubkey_len(1) ‖ pubkey ‖ privkey_len(1) ‖ privkey
  # Lengths are 1-byte because Ed25519 keys never exceed 64 bytes.
  defp write_keyfile(path, %__MODULE__{public: pub, private: priv}) do
    body =
      @keyfile_magic <>
        <<byte_size(pub)::8>> <> pub <> <<byte_size(priv)::8>> <> priv

    File.write(path, body)
  end

  defp parse_keyfile(<<@keyfile_magic, rest::binary>>) do
    with <<pub_len::8, rest::binary>> <- rest,
         <<pub::binary-size(pub_len), rest::binary>> <- rest,
         <<priv_len::8, rest::binary>> <- rest,
         <<priv::binary-size(priv_len)>> <- rest do
      {:ok, %__MODULE__{public: pub, private: priv}}
    else
      _ -> :error
    end
  end

  defp parse_keyfile(_), do: :error

  defp ensure_dir(dir) do
    case File.mkdir_p(dir) do
      :ok -> :ok
      {:error, reason} -> {:error, reason}
    end
  end
end
