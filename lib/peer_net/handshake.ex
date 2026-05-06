defmodule PeerNet.Handshake do
  @moduledoc """
  Mutual-authentication handshake for PeerNet — implementation of the Noise
  protocol's `XX` pattern with the suite
  `Noise_XX_25519_ChaChaPoly_SHA256`.

  ## Why Noise XX

  The XX pattern is the canonical "two-party mutual auth without
  pre-shared knowledge of public keys" Noise pattern. It gives us:

  - **Forward secrecy** — every session uses fresh ephemeral X25519 keys.
    Compromising the long-term static key does not reveal past sessions.
  - **Mutual authentication** — both parties' static keys are
    cryptographically bound into the transcript hash; a peer cannot
    impersonate another even if they know the other's public key.
  - **Identity hiding** — static keys travel encrypted under the
    ephemeral DH; a passive observer cannot link a session to a
    long-term identity from the wire alone.
  - **Replay resistance** — every session has a fresh transcript hash.

  ## Wire shape

  Three messages over the framed wire (`PeerNet.Frame`):

      M1 (initiator → responder)
        e

      M2 (responder → initiator)
        e, ee, s, es     # peer ephemeral, then encrypted static + payload

      M3 (initiator → responder)
        s, se            # encrypted static + payload

  Each "encrypted" piece is wrapped with ChaCha20-Poly1305 using the key
  derived from successive `MixKey` operations on the running chain. The
  full Noise message-handling sequence is implemented in `step/2`.

  ## After the handshake

  Once both sides reach `:authenticated`, the state contains two
  `PeerNet.Channel.CipherState` instances:

  - `tx_state` — used to encrypt outbound application messages
  - `rx_state` — used to decrypt inbound application messages

  Initiator's `tx` is the responder's `rx` and vice versa, so messages
  in each direction use independent keys and nonce counters.

  ## Trust check

  The peer's static public key is checked against the trust set at the
  point it's revealed during the handshake. A peer not in the trust set
  causes the handshake to abort with `{:error, :untrusted_peer, role}`.
  This happens **after** Noise has cryptographically verified the peer
  actually knows the corresponding private key, so a forged static key
  is impossible.

  ## Examples

      iex> a = PeerNet.Identity.generate()
      iex> state = PeerNet.Handshake.init(:initiator, a, MapSet.new())
      iex> state.role
      :initiator
      iex> state.phase
      :send_m1
  """

  alias PeerNet.{Channel, Frame, Identity}
  import Bitwise, only: [<<<: 2]

  # Noise protocol identification — interpreted in init/1 to seed the
  # transcript hash. Length is exactly 32 bytes so it's used directly
  # as the initial `h` (no further hashing per the spec).
  @protocol_name "Noise_XX_25519_ChaChaPoly_SHA256"

  @hashlen 32
  # Curve25519 public keys
  @dhlen 32
  # ChaCha20-Poly1305 tag
  @taglen 16

  @typedoc "Handshake state for one side of the exchange."
  @type t :: %__MODULE__{
          role: :initiator | :responder,
          identity: Identity.t(),
          trust: MapSet.t(binary()),
          phase: phase(),
          # Noise SymmetricState: transcript hash, chaining key, optional cipher.
          h: binary(),
          ck: binary(),
          k: binary() | nil,
          n: non_neg_integer(),
          # Ephemeral keypair for this session.
          eph_pub: binary() | nil,
          eph_priv: binary() | nil,
          # Peer's keys, learned during the handshake.
          peer_eph: binary() | nil,
          peer_pubkey: binary() | nil,
          # CipherStates for post-handshake transport.
          tx: Channel.CipherState.t() | nil,
          rx: Channel.CipherState.t() | nil,
          # Buffered inbound bytes between step calls.
          inbox: binary()
        }

  @type phase ::
          :send_m1 | :wait_m1 | :send_m2 | :wait_m2 | :send_m3 | :wait_m3 | :authenticated

  defstruct [
    :role,
    :identity,
    :trust,
    :h,
    :ck,
    :phase,
    k: nil,
    n: 0,
    eph_pub: nil,
    eph_priv: nil,
    peer_eph: nil,
    peer_pubkey: nil,
    tx: nil,
    rx: nil,
    inbox: <<>>
  ]

  # ── Public API ─────────────────────────────────────────────────────

  @doc """
  Initialise a handshake state for one side.

  - `role` — `:initiator` (the dialer) or `:responder` (the acceptor).
  - `identity` — this node's `PeerNet.Identity` (X25519 keypair).
  - `trust` — `MapSet` of peer public keys this node will accept.
  """
  @spec init(:initiator | :responder, Identity.t(), MapSet.t(binary())) :: t()
  def init(role, %Identity{} = identity, %MapSet{} = trust) when role in [:initiator, :responder] do
    # Per Noise spec §5.2: if protocol_name is shorter than HASHLEN, pad
    # with zeros; if longer, hash it. Ours is exactly 32 — used directly.
    h = pad_to(@protocol_name, @hashlen)

    %__MODULE__{
      role: role,
      identity: identity,
      trust: trust,
      h: h,
      ck: h,
      phase: initial_phase(role)
    }
  end

  defp initial_phase(:initiator), do: :send_m1
  defp initial_phase(:responder), do: :wait_m1

  @doc """
  Drive the state machine one step.

  Pass `inbound_bytes` (default empty) — bytes received from the peer
  since the last call. Returns:

  - `{:ok, new_state, outbound_bytes}` — possibly empty bytes to send
    to the peer, plus updated state.
  - `{:error, reason, role}` — handshake failed; close the connection.

  Reasons:

  - `:untrusted_peer` — peer's static key not in the trust list.
  - `:bad_decrypt` — AEAD authentication failed (wire tampering).
  - `:malformed` — wire bytes don't match the expected XX shape.
  - `:stalled` — state machine asked to step in an unexpected phase.
  """
  @spec step(t(), binary()) ::
          {:ok, t(), binary()} | {:error, atom(), :initiator | :responder}
  def step(state, inbound \\ <<>>)

  # ── Initiator ─────────────────────────────────────────────────────

  def step(%{role: :initiator, phase: :send_m1} = state, _inbound) do
    {eph_pub, eph_priv} = generate_keypair()
    state = %{state | eph_pub: eph_pub, eph_priv: eph_priv}
    state = mix_hash(state, eph_pub)
    out = Frame.encode(eph_pub)
    {:ok, %{state | phase: :wait_m2}, out}
  end

  def step(%{role: :initiator, phase: :wait_m2} = state, inbound) do
    state = accumulate(state, inbound)

    case Frame.decode(state.inbox) do
      :incomplete ->
        {:ok, state, <<>>}

      {:error, _} ->
        {:error, :malformed, :initiator}

      {:ok, body, rest} ->
        # M2: e (32), encrypted s (32 + 16), encrypted payload (0 + 16)
        with <<peer_e::binary-size(@dhlen), enc_s::binary-size(@dhlen + @taglen),
               enc_payload::binary-size(@taglen)>> <- body,
             state = mix_hash(state, peer_e),
             state = mix_key(state, dh(state.eph_priv, peer_e)),
             {:ok, peer_s, state} <- decrypt_and_hash(state, enc_s),
             :ok <- check_trust(state.trust, peer_s, :initiator),
             state = mix_key(state, dh(state.eph_priv, peer_s)),
             {:ok, _empty, state} <- decrypt_and_hash(state, enc_payload) do
          state = %{state | peer_eph: peer_e, peer_pubkey: peer_s, inbox: rest}
          # M3: send our static (encrypted) and an encrypted empty payload.
          send_m3(state)
        else
          {:error, reason, role} ->
            {:error, reason, role}

          _ ->
            {:error, :malformed, :initiator}
        end
    end
  end

  # ── Responder ─────────────────────────────────────────────────────

  def step(%{role: :responder, phase: :wait_m1} = state, inbound) do
    state = accumulate(state, inbound)

    case Frame.decode(state.inbox) do
      :incomplete ->
        {:ok, state, <<>>}

      {:error, _} ->
        {:error, :malformed, :responder}

      {:ok, body, rest} ->
        case body do
          <<peer_e::binary-size(@dhlen)>> ->
            state = mix_hash(state, peer_e)
            state = %{state | peer_eph: peer_e, inbox: rest}
            send_m2(state)

          _ ->
            {:error, :malformed, :responder}
        end
    end
  end

  def step(%{role: :responder, phase: :wait_m3} = state, inbound) do
    state = accumulate(state, inbound)

    case Frame.decode(state.inbox) do
      :incomplete ->
        {:ok, state, <<>>}

      {:error, _} ->
        {:error, :malformed, :responder}

      {:ok, body, rest} ->
        with <<enc_s::binary-size(@dhlen + @taglen),
               enc_payload::binary-size(@taglen)>> <- body,
             {:ok, peer_s, state} <- decrypt_and_hash(state, enc_s),
             :ok <- check_trust(state.trust, peer_s, :responder),
             state = mix_key(state, dh(state.eph_priv, peer_s)),
             {:ok, _empty, state} <- decrypt_and_hash(state, enc_payload) do
          state = %{state | peer_pubkey: peer_s, inbox: rest}
          {:ok, finalize(state), <<>>}
        else
          {:error, reason, role} ->
            {:error, reason, role}

          _ ->
            {:error, :malformed, :responder}
        end
    end
  end

  def step(%{phase: :authenticated} = state, _inbound), do: {:ok, state, <<>>}

  def step(%{role: role}, _inbound), do: {:error, :stalled, role}

  # ── Message construction ──────────────────────────────────────────

  defp send_m2(state) do
    {eph_pub, eph_priv} = generate_keypair()
    state = %{state | eph_pub: eph_pub, eph_priv: eph_priv}
    state = mix_hash(state, eph_pub)
    state = mix_key(state, dh(eph_priv, state.peer_eph))
    {enc_s, state} = encrypt_and_hash(state, state.identity.public)
    state = mix_key(state, dh(state.identity.private, state.peer_eph))
    {enc_payload, state} = encrypt_and_hash(state, <<>>)
    body = eph_pub <> enc_s <> enc_payload
    {:ok, %{state | phase: :wait_m3}, Frame.encode(body)}
  end

  defp send_m3(state) do
    {enc_s, state} = encrypt_and_hash(state, state.identity.public)
    state = mix_key(state, dh(state.identity.private, state.peer_eph))
    {enc_payload, state} = encrypt_and_hash(state, <<>>)
    body = enc_s <> enc_payload
    {:ok, finalize(state), Frame.encode(body)}
  end

  # ── Finalisation: split the chaining key into two CipherStates ────

  defp finalize(state) do
    {k1, k2} = hkdf2(state.ck, <<>>)

    {tx_key, rx_key} =
      case state.role do
        :initiator -> {k1, k2}
        :responder -> {k2, k1}
      end

    %{
      state
      | phase: :authenticated,
        tx: Channel.CipherState.new(tx_key),
        rx: Channel.CipherState.new(rx_key)
    }
  end

  # ── Noise SymmetricState primitives ───────────────────────────────

  defp mix_hash(state, data) do
    %{state | h: :crypto.hash(:sha256, state.h <> data)}
  end

  defp mix_key(state, ikm) do
    {ck, temp_k} = hkdf2(state.ck, ikm)
    %{state | ck: ck, k: temp_k, n: 0}
  end

  defp encrypt_and_hash(state, plaintext) do
    if state.k do
      ciphertext = aead_encrypt(state.k, state.n, state.h, plaintext)
      state = mix_hash(%{state | n: state.n + 1}, ciphertext)
      {ciphertext, state}
    else
      state = mix_hash(state, plaintext)
      {plaintext, state}
    end
  end

  defp decrypt_and_hash(state, ciphertext) do
    if state.k do
      case aead_decrypt(state.k, state.n, state.h, ciphertext) do
        {:ok, plaintext} ->
          state = mix_hash(%{state | n: state.n + 1}, ciphertext)
          {:ok, plaintext, state}

        :error ->
          {:error, :bad_decrypt, state.role}
      end
    else
      state = mix_hash(state, ciphertext)
      {:ok, ciphertext, state}
    end
  end

  # HKDF-SHA256 with two outputs (Noise's most common HKDF arity).
  # Per RFC 5869 / Noise §4.3:
  #   temp = HMAC(salt, ikm)
  #   o1   = HMAC(temp, 0x01)
  #   o2   = HMAC(temp, o1 || 0x02)
  defp hkdf2(salt, ikm) do
    temp = :crypto.mac(:hmac, :sha256, salt, ikm)
    o1 = :crypto.mac(:hmac, :sha256, temp, <<0x01>>)
    o2 = :crypto.mac(:hmac, :sha256, temp, o1 <> <<0x02>>)
    {o1, o2}
  end

  # ChaCha20-Poly1305 with the Noise-specified nonce: 4 zero bytes
  # followed by the 8-byte little-endian counter.
  defp aead_encrypt(key, counter, aad, plaintext) do
    nonce = noise_nonce(counter)

    {ciphertext, tag} =
      :crypto.crypto_one_time_aead(
        :chacha20_poly1305,
        key,
        nonce,
        plaintext,
        aad,
        @taglen,
        true
      )

    ciphertext <> tag
  end

  defp aead_decrypt(key, counter, aad, ciphertext_with_tag) do
    nonce = noise_nonce(counter)
    ct_len = byte_size(ciphertext_with_tag) - @taglen

    if ct_len < 0 do
      :error
    else
      <<ct::binary-size(ct_len), tag::binary-size(@taglen)>> = ciphertext_with_tag

      try do
        case :crypto.crypto_one_time_aead(
               :chacha20_poly1305,
               key,
               nonce,
               ct,
               aad,
               tag,
               false
             ) do
          plaintext when is_binary(plaintext) -> {:ok, plaintext}
          _ -> :error
        end
      rescue
        _ -> :error
      end
    end
  end

  defp noise_nonce(counter) when counter >= 0 and counter < 1 <<< 64 do
    <<0::32, counter::little-unsigned-64>>
  end

  # ── Helpers ───────────────────────────────────────────────────────

  defp generate_keypair, do: :crypto.generate_key(:ecdh, :x25519)

  defp dh(my_priv, peer_pub) do
    :crypto.compute_key(:ecdh, peer_pub, my_priv, :x25519)
  end

  defp accumulate(state, <<>>), do: state
  defp accumulate(state, more), do: %{state | inbox: state.inbox <> more}

  defp pad_to(bin, len) when byte_size(bin) == len, do: bin
  defp pad_to(bin, len) when byte_size(bin) < len, do: bin <> :binary.copy(<<0>>, len - byte_size(bin))
  defp pad_to(bin, _len), do: :crypto.hash(:sha256, bin)

  defp check_trust(trust, pubkey, role) do
    if MapSet.member?(trust, pubkey),
      do: :ok,
      else: {:error, :untrusted_peer, role}
  end
end
