defmodule PeerNet.ReconnectTest do
  @moduledoc """
  Verifies the Registry's automatic redial after a connection drops.

  Sequence:
  1. Two PeerNet instances pair and exchange a discovery announcement
     so the Registry has a known address for each peer.
  2. Initiator dials, handshake completes, `connected?/2` is true.
  3. Force-kill the connection process. Registry observes the DOWN
     and schedules a reconnect attempt.
  4. The reconnect dials again; eventually `connected?/2` is true again.
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
        {PeerNet, [name: :a_recon, data_dir: a_dir, port: 0, discovery: Discovery.Manual]},
        id: :a
      )

    {:ok, _} =
      start_supervised(
        {PeerNet, [name: :b_recon, data_dir: b_dir, port: 0, discovery: Discovery.Manual]},
        id: :b
      )

    a_id = PeerNet.identity(:a_recon)
    b_id = PeerNet.identity(:b_recon)
    :ok = PeerNet.pair(:a_recon, b_id.public)
    :ok = PeerNet.pair(:b_recon, a_id.public)

    %{a: a_id, b: b_id, b_port: PeerNet.port(:b_recon)}
  end

  test "reconnects automatically after the live connection dies", %{
    a: _,
    b: b,
    b_port: b_port
  } do
    :ok = PeerNet.expose(:b_recon, :ok?, fn _, _ -> :alive end)

    # Drive discovery so Registry stores the address (this is what
    # the reconnect logic needs — last_address — and what production
    # would also have via mDNS or whatever).
    a_disc = Process.whereis(:"a_recon.discovery")

    Discovery.Manual.announce_peer(a_disc, b.public, %{
      ip: {127, 0, 0, 1},
      port: b_port,
      source: :test
    })

    :ok = wait_until_connected(:a_recon, b.public)
    assert {:ok, :alive} = PeerNet.call(:a_recon, b.public, :ok?, %{})

    # Snapshot the connection pid, then kill it. The DOWN event in
    # the Registry should schedule a reconnect.
    {:ok, conn_pid} =
      PeerNet.Registry.lookup_connection(:"a_recon.registry", b.public)

    ref = Process.monitor(conn_pid)
    Process.exit(conn_pid, :kill)
    assert_receive {:DOWN, ^ref, :process, _, _}, 500

    refute PeerNet.connected?(:a_recon, b.public)

    # Now wait for the auto-redial. Initial backoff is 500ms; allow up
    # to ~3s for the reconnect to land.
    :ok = wait_until_connected(:a_recon, b.public, 3_000)
    assert {:ok, :alive} = PeerNet.call(:a_recon, b.public, :ok?, %{})
  end

  defp wait_until_connected(name, peer_pubkey, timeout \\ 1_500) do
    deadline = System.monotonic_time(:millisecond) + timeout
    do_wait(name, peer_pubkey, deadline)
  end

  defp do_wait(name, pubkey, deadline) do
    if PeerNet.connected?(name, pubkey) do
      :ok
    else
      if System.monotonic_time(:millisecond) > deadline do
        {:error, :timeout}
      else
        Process.sleep(20)
        do_wait(name, pubkey, deadline)
      end
    end
  end
end
