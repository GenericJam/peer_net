defmodule PeerNet.DiscoveryIntegrationTest do
  @moduledoc """
  End-to-end test of the discovery → registry → auto-connect path.

  Both PeerNet instances run an attached `PeerNet.Discovery.Manual` —
  test code drives discovery events directly. The Registry is expected
  to:

  1. Trust-check incoming `:peer_discovered` events.
  2. Dial trusted peers automatically.
  3. Make the resulting connection callable via `PeerNet.call/5` once
     the handshake completes.
  """

  use ExUnit.Case, async: false

  alias PeerNet.Discovery

  @moduletag :tmp_dir

  setup %{tmp_dir: tmp_dir} do
    a_dir = Path.join(tmp_dir, "alice")
    b_dir = Path.join(tmp_dir, "bob")
    File.mkdir_p!(a_dir)
    File.mkdir_p!(b_dir)

    {:ok, _} =
      start_supervised(
        {PeerNet, [name: :alice2, data_dir: a_dir, port: 0, discovery: Discovery.Manual]},
        id: :a
      )

    {:ok, _} =
      start_supervised(
        {PeerNet, [name: :bob2, data_dir: b_dir, port: 0, discovery: Discovery.Manual]},
        id: :b
      )

    alice_id = PeerNet.identity(:alice2)
    bob_id = PeerNet.identity(:bob2)

    :ok = PeerNet.pair(:alice2, bob_id.public)
    :ok = PeerNet.pair(:bob2, alice_id.public)

    # Use the Discovery.Manual that PeerNet auto-spawned.
    alice_disc = Process.whereis(:"alice2.discovery")

    %{alice: alice_id, bob: bob_id, bob_port: PeerNet.port(:bob2), alice_disc: alice_disc}
  end

  test "auto-connects when discovery announces a trusted peer", %{
    alice: _,
    bob: bob,
    bob_port: bob_port,
    alice_disc: disc
  } do
    :ok = PeerNet.expose(:bob2, :greet, fn _from, name -> "auto-#{name}" end)

    # Drive discovery on alice's side. The Registry should auto-dial bob.
    Discovery.Manual.announce_peer(disc, bob.public, %{
      ip: {127, 0, 0, 1},
      port: bob_port,
      source: :manual
    })

    # Wait for the handshake to complete (via the Registry side).
    :ok = wait_until_connected(:alice2, bob.public)

    assert {:ok, "auto-pat"} = PeerNet.call(:alice2, bob.public, :greet, "pat")
  end

  test "ignores discovery for untrusted peers", %{
    alice: alice,
    bob: bob,
    bob_port: _bob_port,
    alice_disc: disc
  } do
    # Announce a totally unknown pubkey. Registry should not dial.
    fake_pubkey = :crypto.strong_rand_bytes(32)
    Discovery.Manual.announce_peer(disc, fake_pubkey, %{ip: {127, 0, 0, 1}, port: 9999, source: :manual})

    # Give the Registry a moment to (not) react.
    Process.sleep(50)

    refute PeerNet.connected?(:alice2, fake_pubkey)
    refute PeerNet.connected?(:alice2, alice.public)
    refute PeerNet.connected?(:alice2, bob.public)
  end

  defp wait_until_connected(name, peer_pubkey, timeout \\ 1_500) do
    deadline = System.monotonic_time(:millisecond) + timeout

    Stream.repeatedly(fn ->
      cond do
        PeerNet.connected?(name, peer_pubkey) -> :ok
        System.monotonic_time(:millisecond) > deadline -> :timeout
        true -> Process.sleep(20) && :loop
      end
    end)
    |> Enum.reduce_while(:loop, fn
      :ok, _ -> {:halt, :ok}
      :timeout, _ -> {:halt, {:error, :timeout}}
      :loop, _ -> {:cont, :loop}
    end)
  end
end
