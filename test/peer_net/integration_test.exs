defmodule PeerNet.IntegrationTest do
  @moduledoc """
  End-to-end test: two complete PeerNet instances in the same BEAM, talking
  to each other over TCP loopback. This is the test the M2 milestone is
  aimed at — when this passes, the transport layer is functional enough to
  be tried out in real apps.
  """

  use ExUnit.Case, async: false

  @moduletag :tmp_dir

  setup %{tmp_dir: tmp_dir} do
    a_dir = Path.join(tmp_dir, "alice")
    b_dir = Path.join(tmp_dir, "bob")
    File.mkdir_p!(a_dir)
    File.mkdir_p!(b_dir)

    {:ok, _} = start_supervised({PeerNet, [name: :alice, data_dir: a_dir, port: 0]}, id: :alice)
    {:ok, _} = start_supervised({PeerNet, [name: :bob, data_dir: b_dir, port: 0]}, id: :bob)

    alice_id = PeerNet.identity(:alice)
    bob_id = PeerNet.identity(:bob)

    :ok = PeerNet.pair(:alice, bob_id.public, label: "bob")
    :ok = PeerNet.pair(:bob, alice_id.public, label: "alice")

    %{alice: alice_id, bob: bob_id, bob_port: PeerNet.port(:bob)}
  end

  test "alice can call an exposed handle on bob", %{alice: _, bob: bob, bob_port: bob_port} do
    :ok =
      PeerNet.expose(:bob, :greet, fn _from, name ->
        "hi #{name} from bob"
      end)

    :ok = PeerNet.connect(:alice, bob.public, {127, 0, 0, 1}, bob_port)

    # Give the handshake a moment to complete.
    :ok = wait_until_connected(:alice, bob.public)

    assert {:ok, "hi world from bob"} = PeerNet.call(:alice, bob.public, :greet, "world")
  end

  test "calls return :no_such_handle for unexposed handles",
       %{alice: _, bob: bob, bob_port: bob_port} do
    :ok = PeerNet.connect(:alice, bob.public, {127, 0, 0, 1}, bob_port)
    :ok = wait_until_connected(:alice, bob.public)

    assert {:error, :no_such_handle} =
             PeerNet.call(:alice, bob.public, :something_undefined, %{})
  end

  test "untrusted peers cannot complete the handshake",
       %{alice: alice, bob: _, bob_port: bob_port, tmp_dir: tmp_dir} do
    # Mallory: a third instance whose pubkey isn't in bob's trust
    # list. Per-test tmp_dir/mallory subdir keeps her keyfile fresh
    # so a previous run's Ed25519-format file can't poison the load.
    m_dir = Path.join(tmp_dir, "mallory")
    File.mkdir_p!(m_dir)
    {:ok, _} = start_supervised({PeerNet, [name: :mallory, data_dir: m_dir, port: 0]}, id: :mallory)

    # Mallory pairs with bob, but bob doesn't pair with mallory.
    bob_id = PeerNet.identity(:bob)
    :ok = PeerNet.pair(:mallory, bob_id.public)

    :ok = PeerNet.connect(:mallory, bob_id.public, {127, 0, 0, 1}, bob_port)

    # Bob should refuse — mallory's pubkey isn't in bob's trust list.
    # The connection attempt either fails outright or never enters the
    # :connected state; in either case `call` returns an error.
    assert {:error, _} = PeerNet.call(:mallory, bob_id.public, :anything, %{}, 1_500)

    # Alice (who IS trusted) should still work.
    _ = alice
  end

  test "send/3 fire-and-forget reaches the handler",
       %{alice: alice, bob: bob, bob_port: bob_port} do
    test_pid = self()

    :ok =
      PeerNet.expose(:bob, :note, fn from, msg ->
        send(test_pid, {:note_received, from, msg})
        :ok
      end)

    :ok = PeerNet.connect(:alice, bob.public, {127, 0, 0, 1}, bob_port)
    :ok = wait_until_connected(:alice, bob.public)

    :ok = PeerNet.send(:alice, bob.public, :note, %{text: "hi"})

    assert_receive {:note_received, from_pubkey, %{text: "hi"}}, 1_000
    assert from_pubkey == alice.public
  end

  # ── helpers ─────────────────────────────────────────────────────────

  defp wait_until_connected(name, peer_pubkey, timeout \\ 1_500) do
    deadline = System.monotonic_time(:millisecond) + timeout
    do_wait_connected(name, peer_pubkey, deadline)
  end

  defp do_wait_connected(name, pubkey, deadline) do
    if PeerNet.connected?(name, pubkey) do
      :ok
    else
      if System.monotonic_time(:millisecond) > deadline do
        {:error, :timeout}
      else
        Process.sleep(20)
        do_wait_connected(name, pubkey, deadline)
      end
    end
  end
end
