defmodule PeerNet.Discovery.UDPTest do
  use ExUnit.Case, async: true

  alias PeerNet.{Discovery, Identity}
  alias PeerNet.Discovery.UDP.Wire

  defmodule MockTransport do
    @moduledoc false
    @behaviour PeerNet.Discovery.UDP.Transport

    # The mock looks up the owning test process by reading from a
    # per-test :persistent_term key that the setup block writes before
    # starting the GenServer. This avoids polluting production code
    # with a test-only callback while still letting tests assert on
    # what the GenServer broadcasts.

    @impl true
    def open(_port) do
      target = :persistent_term.get({__MODULE__, self_test_key()}, nil)
      {:ok, target || self()}
    end

    @impl true
    def broadcast(owner, _port, bytes) when is_pid(owner) do
      send(owner, {:mock_broadcast, bytes})
      :ok
    end

    @impl true
    def close(_), do: :ok

    defp self_test_key, do: :discovery_udp_test_target
  end

  setup do
    me = self()
    :persistent_term.put({MockTransport, :discovery_udp_test_target}, me)
    on_exit(fn -> :persistent_term.erase({MockTransport, :discovery_udp_test_target}) end)

    identity = Identity.generate()

    {:ok, pid} =
      start_supervised(
        {Discovery.UDP,
         [
           registry: me,
           identity: identity,
           listen_port: 14040,
           interval_ms: 50,
           transport: MockTransport,
           peer_net_port: 7100
         ]}
      )

    %{pid: pid, identity: identity}
  end

  test "broadcasts a Wire-encoded announce on its tick", %{identity: id} do
    expected = Wire.encode(id.public, 7100)
    assert_receive {:mock_broadcast, ^expected}, 200
  end

  test "delivers an inbound peer announce to the registry", %{pid: pid, identity: _self_id} do
    other = Identity.generate()
    bytes = Wire.encode(other.public, 7777)

    # Simulate a packet arriving on the socket. The UDP GenServer accepts
    # both :gen_udp's native shape and the mock-friendly tuple.
    send(pid, {:peer_net_udp_packet, {192, 168, 1, 42}, bytes})

    assert_receive {:peer_discovered, pubkey, %{ip: {192, 168, 1, 42}, port: 7777, source: :udp}},
                   200

    assert pubkey == other.public
  end

  test "drops packets matching our own pubkey (loopback suppression)", %{pid: pid, identity: id} do
    bytes = Wire.encode(id.public, 7100)
    send(pid, {:peer_net_udp_packet, {192, 168, 1, 1}, bytes})

    refute_receive {:peer_discovered, _, _}, 100
  end

  test "ignores malformed packets", %{pid: pid} do
    send(pid, {:peer_net_udp_packet, {1, 2, 3, 4}, "this is not an announce"})
    refute_receive {:peer_discovered, _, _}, 100
  end

  test "announce_self/2 updates the broadcast port", %{pid: pid, identity: id} do
    Discovery.UDP.announce_self(pid, 8888)

    expected = Wire.encode(id.public, 8888)
    assert_receive {:mock_broadcast, ^expected}, 200
  end
end
