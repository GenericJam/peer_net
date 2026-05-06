defmodule PeerNet.Discovery.UDP.Wire do
  @moduledoc """
  Compact wire format for UDP-broadcast peer announcements.

  ## Shape

      | 4 bytes magic | 1 byte version | 2 bytes port | 32 bytes pubkey |

  - **Magic** (`"PNET"`) — quickly rejects non-PeerNet packets without
    parsing further. Cheap before any allocation.
  - **Version** — currently `0x01`. Mismatched versions are rejected.
  - **Port** — the sender's PeerNet TCP listen port (big-endian).
  - **Pubkey** — the sender's Ed25519 public key.

  Total: 39 bytes — small enough to fit hundreds per second on any LAN
  without breaking a sweat, and well below typical IPv4 fragmentation
  thresholds.

  ## Why fixed-shape, not ETF or JSON

  This packet is broadcast to anyone listening, so it must:

  1. Be cheap to reject for non-PeerNet senders (the magic prefix).
  2. Not invoke any general-purpose decoder on attacker-controlled
     bytes (no `:erlang.binary_to_term`, no JSON parser).
  3. Be a single fixed length so we never try to allocate a buffer for
     a peer-claimed length.

  Hand-shaped binary format hits all three.

  ## Examples

      iex> pubkey = :crypto.strong_rand_bytes(32)
      iex> bin = PeerNet.Discovery.UDP.Wire.encode(pubkey, 7100)
      iex> {:ok, decoded} = PeerNet.Discovery.UDP.Wire.decode(bin)
      iex> decoded.port
      7100
      iex> decoded.pubkey == pubkey
      true
  """

  @magic "PNET"
  @version 0x01

  @typedoc "Decoded peer announcement."
  @type announce :: %{
          version: pos_integer(),
          port: :inet.port_number(),
          pubkey: binary()
        }

  @doc "Magic prefix every announce frame starts with."
  @spec magic() :: binary()
  def magic, do: @magic

  @doc """
  Encode an announce frame for a peer with `pubkey` listening on `port`.

  Pubkey must be a 32-byte binary (Ed25519). Port is a u16.
  """
  @spec encode(binary(), :inet.port_number()) :: binary()
  def encode(<<_::256>> = pubkey, port) when is_integer(port) and port in 0..65_535 do
    <<@magic, @version::8, port::big-unsigned-16, pubkey::binary>>
  end

  @doc """
  Try to parse `bytes` as an announce frame.

  Returns `{:ok, announce}` on success or `:error` on any malformation —
  no fine-grained error reasons because the caller (the UDP listener)
  has nothing useful to do with them; just log and drop.
  """
  @spec decode(binary()) :: {:ok, announce()} | :error
  def decode(<<@magic, @version::8, port::big-unsigned-16, pubkey::binary-size(32)>>) do
    {:ok, %{version: @version, port: port, pubkey: pubkey}}
  end

  def decode(_), do: :error
end
