defmodule PeerNet.HandshakeTest do
  use ExUnit.Case, async: true
  doctest PeerNet.Handshake

  alias PeerNet.{Channel, Handshake, Identity}

  describe "Noise XX between two in-memory peers" do
    test "completes when both parties trust each other" do
      a = Identity.generate()
      b = Identity.generate()

      a_trusts = MapSet.new([b.public])
      b_trusts = MapSet.new([a.public])

      assert {:ok, %{a: a_state, b: b_state}} = simulate(a, a_trusts, b, b_trusts)

      # Both ended up authenticated.
      assert a_state.phase == :authenticated
      assert b_state.phase == :authenticated

      # Each side learned the other's static pubkey.
      assert a_state.peer_pubkey == b.public
      assert b_state.peer_pubkey == a.public

      # Both ended up with the same transcript hash (proves they saw
      # the same wire bytes — defends against transcript-tampering MITMs).
      assert a_state.h == b_state.h
    end

    test "produces a working bidirectional cipher channel after handshake" do
      a = Identity.generate()
      b = Identity.generate()

      {:ok, %{a: a_state, b: b_state}} =
        simulate(a, MapSet.new([b.public]), b, MapSet.new([a.public]))

      # Sanity: keys MUST be paired correctly across initiator/responder.
      assert a_state.tx.key == b_state.rx.key,
             "A.tx.key=#{Base.encode16(a_state.tx.key)} != B.rx.key=#{Base.encode16(b_state.rx.key)}"

      assert a_state.rx.key == b_state.tx.key,
             "A.rx.key=#{Base.encode16(a_state.rx.key)} != B.tx.key=#{Base.encode16(b_state.tx.key)}"

      # A → B
      {wire, a_tx2} = Channel.encrypt(a_state.tx, {:hello, "from a"})
      <<len::big-unsigned-32, body::binary-size(len)>> = wire
      assert {:ok, {:hello, "from a"}, _b_rx2} = Channel.decrypt(b_state.rx, body)

      # B → A
      {wire2, _b_tx2} = Channel.encrypt(b_state.tx, {:reply, 42})
      <<len2::big-unsigned-32, body2::binary-size(len2)>> = wire2
      assert {:ok, {:reply, 42}, _a_rx2} = Channel.decrypt(a_state.rx, body2)

      # Counter persists — also verify a_tx2 advanced.
      assert a_tx2.counter == 1
    end

    test "fails when responder doesn't trust initiator" do
      a = Identity.generate()
      b = Identity.generate()
      assert {:error, :untrusted_peer, _} = simulate(a, MapSet.new([b.public]), b, MapSet.new())
    end

    test "fails when initiator doesn't trust responder" do
      a = Identity.generate()
      b = Identity.generate()
      assert {:error, :untrusted_peer, _} = simulate(a, MapSet.new(), b, MapSet.new([a.public]))
    end

    test "tampered ciphertext between the parties causes handshake failure" do
      a = Identity.generate()
      b = Identity.generate()

      forge = fn bytes, side ->
        case {side, bytes} do
          # Flip the last byte of B → A's M2 to corrupt one of the
          # encrypted blocks. The initiator should fail to authenticate.
          {:b, <<rest::binary-size(byte_size(bytes) - 1), last::8>>} ->
            <<rest::binary, Bitwise.bxor(last, 0x01)::8>>

          _ ->
            bytes
        end
      end

      assert {:error, _reason, _role} =
               simulate(a, MapSet.new([b.public]), b, MapSet.new([a.public]), %{forge: forge})
    end

    test "an honest run leaves no peer-pubkey state on the initiator until M2 has been processed" do
      a = Identity.generate()
      b = Identity.generate()

      # Run only the initiator's M1 step.
      a0 = Handshake.init(:initiator, a, MapSet.new([b.public]))
      assert {:ok, a1, _m1_bytes} = Handshake.step(a0)

      assert a1.phase == :wait_m2
      assert a1.peer_pubkey == nil
    end
  end

  # ── simulator ──────────────────────────────────────────────────────

  defp simulate(a, a_trusts, b, b_trusts, opts \\ %{}) do
    init_a = Handshake.init(:initiator, a, a_trusts)
    init_b = Handshake.init(:responder, b, b_trusts)

    do_drive(init_a, <<>>, init_b, <<>>, opts, 16)
  end

  defp do_drive(_a, _ai, _b, _bi, _opts, 0), do: {:error, :stalled, :both}

  defp do_drive(a, a_in, b, b_in, opts, steps) do
    if both_authenticated?(a, b) do
      {:ok, %{a: a, b: b}}
    else
      step_then_continue(a, a_in, b, b_in, opts, steps)
    end
  end

  defp both_authenticated?(a, b),
    do: a.phase == :authenticated and b.phase == :authenticated

  defp step_then_continue(a, a_in, b, b_in, opts, steps) do
    with {:ok, new_a, out_a} <- Handshake.step(a, a_in),
         out_a_for_b = maybe_forge(opts, out_a, :a),
         {:ok, new_b, out_b} <- Handshake.step(b, b_in <> out_a_for_b) do
      out_b_for_a = maybe_forge(opts, out_b, :b)
      do_drive(new_a, out_b_for_a, new_b, <<>>, opts, steps - 1)
    end
  end

  defp maybe_forge(%{forge: forge}, bytes, side), do: forge.(bytes, side)
  defp maybe_forge(_, bytes, _side), do: bytes
end
