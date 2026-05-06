defmodule PeerNet.Frame do
  @moduledoc """
  Wire framing for PeerNet — length-prefixed Erlang Term Format payloads
  with safety guards against malformed or hostile input.

  ## Wire shape

      | 4-byte big-endian length N | N bytes of safe ETF |

  The length prefix bounds how much we'll buffer before attempting a decode.
  The body is decoded with `:erlang.binary_to_term/2` in `:safe` mode.

  ## Safety guarantees

  - **Atom exhaustion** — `:safe` mode rejects ETF that contains atoms not
    already present in the BEAM's atom table. Without this, a malicious or
    confused peer could permanently leak atoms by sending random binaries.
  - **Frame size cap** — `max_frame_bytes/0` (default 1 MiB) bounds the
    largest single frame we'll buffer. A peer claiming a frame larger than
    this is rejected before any allocation happens.
  - **Function references** — `:safe` mode also rejects function term
    references, which would otherwise let a peer inject closures.

  ## Decoder return values

  `decode/1` returns one of:

  - `{:ok, term, leftover}` — successful decode, with any bytes after the
    frame returned for the next decode call.
  - `:incomplete` — not enough bytes to make a complete frame yet; caller
    should accumulate more bytes and retry.
  - `{:error, reason}` — wire is malformed and the connection should be
    closed. `reason` is one of `:invalid_term` or `:frame_too_large`.

  ## Examples

      iex> bin = PeerNet.Frame.encode({:hello, :world})
      iex> {:ok, term, ""} = PeerNet.Frame.decode(bin)
      iex> term
      {:hello, :world}
  """

  # 1 MiB. Comfortably larger than any single chat message, presence ping,
  # or RPC envelope. If a use case eventually needs streaming larger
  # payloads it should split them into multiple frames at the application
  # layer rather than raise this cap — large frames have memory and DoS
  # implications.
  @max_frame_bytes 1 * 1024 * 1024

  @doc """
  The maximum frame size, in bytes, that `decode/1` will accept.

  Frames whose length prefix exceeds this cap are rejected with
  `{:error, :frame_too_large}` before any body bytes are buffered.
  """
  @spec max_frame_bytes() :: pos_integer()
  def max_frame_bytes, do: @max_frame_bytes

  @doc """
  Encode an arbitrary term to a complete frame.

  No size check on output — encoders are trusted (we control what we send).
  Decoders apply the cap.
  """
  @spec encode(term()) :: binary()
  def encode(term) do
    body = :erlang.term_to_binary(term)
    <<byte_size(body)::big-unsigned-32, body::binary>>
  end

  @doc """
  Wrap an opaque binary in the same length-prefixed frame, **without**
  ETF-wrapping the body. Use this for already-encoded bytes — the
  AEAD-ciphertext-plus-tag payloads emitted by `PeerNet.Channel`,
  for example. The matching decoder is `decode_raw/1`.
  """
  @spec encode_raw(binary()) :: binary()
  def encode_raw(body) when is_binary(body) do
    <<byte_size(body)::big-unsigned-32, body::binary>>
  end

  @doc """
  Pull one length-prefixed frame's body out of `binary`, **without**
  ETF-decoding it.

  Returns:

  - `{:ok, body, leftover}` — the body bytes plus anything after the
    frame in the stream.
  - `:incomplete` — caller should buffer more bytes and retry.
  - `{:error, :frame_too_large}` — frame size exceeded the cap.
  """
  @spec decode_raw(binary()) ::
          {:ok, binary(), binary()} | :incomplete | {:error, :frame_too_large}
  def decode_raw(<<len::big-unsigned-32, _rest::binary>>) when len > @max_frame_bytes do
    {:error, :frame_too_large}
  end

  def decode_raw(<<len::big-unsigned-32, body::binary-size(len), rest::binary>>) do
    {:ok, body, rest}
  end

  def decode_raw(_partial), do: :incomplete

  @doc """
  Try to decode a complete frame from `binary`.

  See module docs for return shapes.
  """
  @spec decode(binary()) ::
          {:ok, term(), binary()}
          | :incomplete
          | {:error, :invalid_term | :frame_too_large}
  def decode(<<len::big-unsigned-32, _rest::binary>>) when len > @max_frame_bytes do
    {:error, :frame_too_large}
  end

  def decode(<<len::big-unsigned-32, body::binary-size(len), rest::binary>>) do
    case safe_decode(body) do
      {:ok, term} -> {:ok, term, rest}
      :error -> {:error, :invalid_term}
    end
  end

  def decode(_partial), do: :incomplete

  defp safe_decode(body) do
    {:ok, :erlang.binary_to_term(body, [:safe])}
  rescue
    _ -> :error
  catch
    _, _ -> :error
  end
end
