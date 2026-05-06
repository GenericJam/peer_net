defmodule PeerNet.BeamDistTest do
  @moduledoc """
  Verifies the BeamDist convenience layer over a real PeerNet pair.
  """

  use ExUnit.Case, async: false

  alias PeerNet.{BeamDist, Discovery}

  @moduletag :tmp_dir

  setup %{tmp_dir: tmp_dir} do
    a_dir = Path.join(tmp_dir, "controller")
    b_dir = Path.join(tmp_dir, "controlled")
    File.mkdir_p!(a_dir)
    File.mkdir_p!(b_dir)

    {:ok, _} =
      start_supervised(
        {PeerNet, [name: :ctrl, data_dir: a_dir, port: 0, discovery: Discovery.Manual]},
        id: :ctrl
      )

    {:ok, _} =
      start_supervised(
        {PeerNet, [name: :ctrled, data_dir: b_dir, port: 0, discovery: Discovery.Manual]},
        id: :ctrled
      )

    ctrl = PeerNet.identity(:ctrl)
    ctrled = PeerNet.identity(:ctrled)

    :ok = PeerNet.pair(:ctrl, ctrled.public)
    :ok = PeerNet.pair(:ctrled, ctrl.public)

    :ok = PeerNet.connect(:ctrl, ctrled.public, {127, 0, 0, 1}, PeerNet.port(:ctrled))
    :ok = wait_until_connected(:ctrl, ctrled.public)

    %{ctrl: ctrl, ctrled: ctrled}
  end

  describe "call/6" do
    test "controller can call a granted handle and get the apply result", %{ctrl: ctrl, ctrled: ctrled} do
      :ok =
        PeerNet.expose(:ctrled, :beam_admin, &BeamDist.handle/2,
          authorize: fn pubkey -> pubkey == ctrl.public end
        )

      # `Enum.sum/1` is a stable stdlib function — known input, known output.
      assert {:ok, 6} = BeamDist.call(:ctrl, ctrled.public, Enum, :sum, [[1, 2, 3]])
    end

    test "rejects calls from peers not in the authorize predicate", %{ctrl: _, ctrled: ctrled} do
      # Authorize ONLY a fake pubkey, not the controller's real one.
      fake = :crypto.strong_rand_bytes(32)

      :ok =
        PeerNet.expose(:ctrled, :beam_admin, &BeamDist.handle/2,
          authorize: fn pubkey -> pubkey == fake end
        )

      # Forbidden errors come back through the call as the result.
      # Both shapes are valid: {:error, :forbidden} from the dispatch
      # layer, or {:ok, ...} containing the error tuple if the layer
      # surfaces handler errors as call results — verify whichever
      # shape happens.
      assert match?(
               {:error, :forbidden},
               BeamDist.call(:ctrl, ctrled.public, Enum, :sum, [[1]])
             )
    end

    test "returns the unknown-op error for malformed BeamDist envelopes", %{ctrl: ctrl, ctrled: ctrled} do
      :ok =
        PeerNet.expose(:ctrled, :beam_admin, &BeamDist.handle/2,
          authorize: fn pubkey -> pubkey == ctrl.public end
        )

      # Use the underlying PeerNet.call to send a non-BeamDist envelope.
      assert {:ok, {:error, :unknown_beam_dist_op}} =
               PeerNet.call(:ctrl, ctrled.public, :beam_admin, {:bogus, :stuff}, 1_000)
    end
  end

  describe "cast/6" do
    test "controller can cast a fire-and-forget invocation", %{ctrl: ctrl, ctrled: ctrled} do
      test_pid = self()

      :ok =
        PeerNet.expose(:ctrled, :beam_admin, &BeamDist.handle/2,
          authorize: fn pubkey -> pubkey == ctrl.public end
        )

      # Cast something that signals back to us so we can confirm it ran.
      assert :ok = BeamDist.cast(:ctrl, ctrled.public, Kernel, :send, [test_pid, :hi_from_remote])
      assert_receive :hi_from_remote, 1_000
    end
  end

  defp wait_until_connected(name, peer_pubkey, timeout \\ 1_500) do
    deadline = System.monotonic_time(:millisecond) + timeout

    Stream.repeatedly(fn -> :ok end)
    |> Enum.find_value(fn _ ->
      cond do
        PeerNet.connected?(name, peer_pubkey) -> :ok
        System.monotonic_time(:millisecond) > deadline -> {:error, :timeout}
        true -> Process.sleep(20) && nil
      end
    end)
  end
end
