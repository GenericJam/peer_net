defmodule PeerNet.FrameTest do
  use ExUnit.Case, async: true
  doctest PeerNet.Frame

  alias PeerNet.Frame

  describe "encode/1 and decode/1 round-trip" do
    test "encodes a simple map and decodes it back" do
      payload = %{type: :hello, value: 42}
      encoded = Frame.encode(payload)
      assert {:ok, ^payload, ""} = Frame.decode(encoded)
    end

    test "encodes a tagged tuple (the call shape)" do
      payload = {:call, 12345, :chat, %{text: "hi"}}
      encoded = Frame.encode(payload)
      assert {:ok, ^payload, ""} = Frame.decode(encoded)
    end

    test "leftover bytes after a complete frame are returned" do
      a = Frame.encode(:first)
      b = Frame.encode(:second)
      combined = a <> b

      assert {:ok, :first, rest} = Frame.decode(combined)
      assert {:ok, :second, ""} = Frame.decode(rest)
    end
  end

  describe "encode/1" do
    test "produces a 4-byte big-endian length prefix" do
      bin = Frame.encode(:ok)
      <<len::big-unsigned-32, body::binary>> = bin
      assert len == byte_size(body)
    end

    test "is deterministic for the same input" do
      assert Frame.encode({:tagged, 1, 2}) == Frame.encode({:tagged, 1, 2})
    end
  end

  describe "decode/1 — incomplete input" do
    test "returns :incomplete when fewer than 4 length bytes" do
      assert Frame.decode(<<1, 2, 3>>) == :incomplete
    end

    test "returns :incomplete when length-prefix says more than we have" do
      # Length 100, only 5 body bytes.
      assert Frame.decode(<<100::big-unsigned-32, 1, 2, 3, 4, 5>>) == :incomplete
    end

    test "returns :incomplete when a single byte short" do
      payload = Frame.encode(:short_test)
      truncated = binary_part(payload, 0, byte_size(payload) - 1)
      assert Frame.decode(truncated) == :incomplete
    end
  end

  describe "decode/1 — malformed input" do
    test "rejects garbage that isn't valid ETF" do
      bin = <<5::big-unsigned-32, "garba">>
      assert {:error, :invalid_term} = Frame.decode(bin)
    end

    test "rejects an oversized frame above the per-frame max" do
      # The max frame size guards against a malicious peer claiming
      # gigabytes of incoming bytes.
      oversized_len = Frame.max_frame_bytes() + 1
      bin = <<oversized_len::big-unsigned-32>>
      assert {:error, :frame_too_large} = Frame.decode(bin)
    end
  end

  describe "atom-exhaustion defense" do
    test "rejects ETF that contains a never-before-seen atom" do
      # Forge raw ETF directly so we don't compile-time-intern the test
      # atom. Format: 131 (version) | 119 (SMALL_ATOM_UTF8_EXT) | len | name.
      # If `:safe` is honoured the decode raises and we surface
      # :invalid_term; without it a new atom would be permanently interned.
      atom_bytes = :crypto.strong_rand_bytes(16) |> Base.encode16(case: :lower)
      atom_name = "fresh_atom_" <> atom_bytes
      etf = <<131, 119, byte_size(atom_name)::8, atom_name::binary>>
      framed = <<byte_size(etf)::big-unsigned-32, etf::binary>>

      assert {:error, :invalid_term} = Frame.decode(framed)
    end

    test "accepts known atoms" do
      payload = {:hello, :world, :ok}
      encoded = Frame.encode(payload)
      assert {:ok, ^payload, ""} = Frame.decode(encoded)
    end
  end

  describe "max_frame_bytes/0" do
    test "is set to a sensible value" do
      max = Frame.max_frame_bytes()
      assert is_integer(max)
      # At least 64 KiB (room for chat messages, presence updates), at most
      # 16 MiB (a single PeerNet frame should never need that much).
      assert max >= 64 * 1024
      assert max <= 16 * 1024 * 1024
    end
  end
end
