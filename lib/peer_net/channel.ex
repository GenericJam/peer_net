defmodule PeerNet.Channel do
  @moduledoc """
  Post-handshake transport: ChaCha20-Poly1305 AEAD over the same Frame
  layer used during the handshake.

  Each side of a connection holds two `CipherState` structs:

  - `tx` — for outbound application messages
  - `rx` — for inbound application messages

  Initiator's `tx` is the responder's `rx` and vice-versa, so each
  direction has its own key and independent nonce counter (see Noise
  spec §5.2 "Split").

  ## Wire shape per message

      Frame(<<ciphertext::binary, tag::binary-size(16)>>)

  - `Frame` is the same length-prefixed wrapper used during handshake,
    so the read loop in `PeerNet.Connection` doesn't need to switch
    framing modes when transitioning from handshake to active.
  - `ciphertext` is the ChaCha20-Poly1305 ciphertext of the
    `:erlang.term_to_binary/1` ETF of the application envelope
    (`:call`, `:reply`, `:send`, `:ping`, `:pong`, etc).
  - `tag` is the 16-byte Poly1305 authentication tag.

  AAD is **empty** by design — this channel doesn't bind the encrypted
  payload to any header beyond the implicit ordering provided by the
  nonce counter. Replay across connections is impossible because the
  key is derived from the per-session ephemeral DH; replay within a
  connection is impossible because each AEAD failure aborts the link.

  ## Nonce management

  Per Noise spec §5.1 nonce format: 4 zero bytes followed by the
  8-byte little-endian counter. Counter starts at zero and increments
  monotonically. PeerNet aborts the connection if the counter reaches
  `2^64 - 1` (an attacker would have to send ~10^19 messages to
  trigger this — any actual occurrence is a bug, not a real attack).
  """

  alias PeerNet.Frame

  @taglen 16
  @counter_max 0xFFFFFFFFFFFFFFFE

  defmodule CipherState do
    @moduledoc """
    Per-direction AEAD key + counter. Treat as opaque; mutate only via
    `PeerNet.Channel.encrypt/2` and `PeerNet.Channel.decrypt/2` (which
    return updated structs).
    """

    @typedoc "Half of a Channel — one key, one nonce counter."
    @type t :: %__MODULE__{key: binary(), counter: non_neg_integer()}

    @enforce_keys [:key]
    defstruct [:key, counter: 0]

    @doc "Build a fresh CipherState from a 32-byte key."
    @spec new(binary()) :: t()
    def new(<<_::256>> = key), do: %__MODULE__{key: key, counter: 0}
  end

  @doc """
  Encrypt `term` and return `{frame_bytes, new_cipher_state}`.

  The result is a complete length-prefixed frame ready to be written
  to the socket. Caller updates its handshake/connection state with
  the returned cipher state.

  Returns `{:error, :counter_exhausted, cipher_state}` if the cipher
  has hit its nonce limit. PeerNet treats this as connection-fatal.
  """
  @spec encrypt(CipherState.t(), term()) ::
          {binary(), CipherState.t()} | {:error, :counter_exhausted, CipherState.t()}
  def encrypt(%CipherState{counter: c} = cs, _term) when c > @counter_max do
    {:error, :counter_exhausted, cs}
  end

  def encrypt(%CipherState{key: key, counter: counter} = cs, term) do
    plaintext = :erlang.term_to_binary(term)
    nonce = noise_nonce(counter)

    {ciphertext, tag} =
      :crypto.crypto_one_time_aead(
        :chacha20_poly1305,
        key,
        nonce,
        plaintext,
        <<>>,
        @taglen,
        true
      )

    body = ciphertext <> tag
    {Frame.encode_raw(body), %{cs | counter: counter + 1}}
  end

  @doc """
  Decrypt one frame body. Returns:

  - `{:ok, term, new_cipher_state}` — successful decode + AEAD verify.
  - `{:error, :bad_decrypt, cipher_state}` — auth failed (wire
    tampering or key/nonce mismatch). Caller should close the link.
  - `{:error, :invalid_term, cipher_state}` — AEAD ok but the
    decrypted bytes don't safely deserialise to a term. Caller should
    close the link (a peer producing valid AEAD with garbage payload
    is misbehaving).
  - `{:error, :counter_exhausted, cipher_state}` — nonce wrap.
  """
  @spec decrypt(CipherState.t(), binary()) ::
          {:ok, term(), CipherState.t()}
          | {:error, :bad_decrypt | :invalid_term | :counter_exhausted, CipherState.t()}
  def decrypt(%CipherState{counter: c} = cs, _frame_body) when c > @counter_max do
    {:error, :counter_exhausted, cs}
  end

  def decrypt(%CipherState{key: key, counter: counter} = cs, frame_body) do
    ct_len = byte_size(frame_body) - @taglen

    if ct_len < 0 do
      {:error, :bad_decrypt, cs}
    else
      <<ct::binary-size(ct_len), tag::binary-size(@taglen)>> = frame_body
      try_aead_decrypt(cs, key, counter, ct, tag)
    end
  end

  defp try_aead_decrypt(cs, key, counter, ct, tag) do
    nonce = noise_nonce(counter)

    case :crypto.crypto_one_time_aead(
           :chacha20_poly1305,
           key,
           nonce,
           ct,
           <<>>,
           tag,
           false
         ) do
      plaintext when is_binary(plaintext) ->
        case safe_deserialise(plaintext) do
          {:ok, term} -> {:ok, term, %{cs | counter: counter + 1}}
          :error -> {:error, :invalid_term, cs}
        end

      _ ->
        {:error, :bad_decrypt, cs}
    end
  rescue
    _ -> {:error, :bad_decrypt, cs}
  end

  defp noise_nonce(counter), do: <<0::32, counter::little-unsigned-64>>

  # `:safe` decoding rejects atoms the receiver doesn't already know,
  # plus function refs. Defends against a peer with a valid session
  # key sending a payload designed to OOM the atom table.
  defp safe_deserialise(bin) do
    {:ok, :erlang.binary_to_term(bin, [:safe])}
  rescue
    _ -> :error
  catch
    _, _ -> :error
  end
end
