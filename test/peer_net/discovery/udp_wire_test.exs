defmodule PeerNet.Discovery.UDP.WireTest do
  use ExUnit.Case, async: true
  doctest PeerNet.Discovery.UDP.Wire

  alias PeerNet.Discovery.UDP.Wire

  describe "encode/2 and decode/1 round-trip" do
    test "round-trips a typical announce" do
      pubkey = :crypto.strong_rand_bytes(32)
      bytes = Wire.encode(pubkey, 7100)
      assert {:ok, %{pubkey: ^pubkey, port: 7100, version: 1}} = Wire.decode(bytes)
    end

    test "encode is deterministic for the same input" do
      pubkey = :crypto.strong_rand_bytes(32)
      assert Wire.encode(pubkey, 7100) == Wire.encode(pubkey, 7100)
    end
  end

  describe "decode/1 — malformed input" do
    test "rejects packets without the magic prefix" do
      bin = <<"NOPE", 1::8, 7100::16, :crypto.strong_rand_bytes(32)::binary>>
      assert :error = Wire.decode(bin)
    end

    test "rejects packets with the wrong version byte" do
      bin = <<Wire.magic()::binary, 99::8, 7100::16, :crypto.strong_rand_bytes(32)::binary>>
      assert :error = Wire.decode(bin)
    end

    test "rejects truncated packets" do
      pubkey = :crypto.strong_rand_bytes(32)
      bytes = Wire.encode(pubkey, 7100)
      truncated = binary_part(bytes, 0, byte_size(bytes) - 1)
      assert :error = Wire.decode(truncated)
    end

    test "rejects packets with a non-32-byte pubkey region" do
      bin = <<Wire.magic()::binary, 1::8, 7100::16, "short">>
      assert :error = Wire.decode(bin)
    end

    test "rejects pure garbage" do
      assert :error = Wire.decode(<<>>)
      assert :error = Wire.decode("hello")
    end
  end

  describe "frame size" do
    test "every announce is exactly the same compact size" do
      a = Wire.encode(:crypto.strong_rand_bytes(32), 7100)
      b = Wire.encode(:crypto.strong_rand_bytes(32), 65000)
      assert byte_size(a) == byte_size(b)
      # 4 magic + 1 version + 2 port + 32 pubkey = 39 bytes.
      assert byte_size(a) == 39
    end
  end
end
