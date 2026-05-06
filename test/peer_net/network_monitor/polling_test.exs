defmodule PeerNet.NetworkMonitor.PollingTest do
  use ExUnit.Case, async: true

  alias PeerNet.NetworkMonitor.Polling

  defp ip_seq(ips) do
    {:ok, agent} = Agent.start_link(fn -> {ips, []} end)

    probe = fn ->
      Agent.get_and_update(agent, fn
        {[final], history} -> {final, {[final], [final | history]}}
        {[head | tail], history} -> {head, {tail, [head | history]}}
        {[], history} -> {[], {[], history}}
      end)
    end

    %{agent: agent, probe: probe}
  end

  test "publishes the current IPs immediately" do
    %{probe: probe} = ip_seq([[{192, 168, 1, 5}]])
    {:ok, pid} = start_supervised({Polling, [probe: probe, poll_interval_ms: 50]})

    assert Polling.current_ips(pid) == [{192, 168, 1, 5}]
  end

  test "notifies subscribers when the IP set changes" do
    %{probe: probe} = ip_seq([[{192, 168, 1, 5}], [{192, 168, 1, 5}, {10, 0, 0, 1}]])

    {:ok, pid} = start_supervised({Polling, [probe: probe, poll_interval_ms: 30]})
    :ok = Polling.subscribe(pid, self())

    assert_receive {:network_changed, change}, 200
    assert {10, 0, 0, 1} in change.added
    refute {192, 168, 1, 5} in change.removed
    assert {10, 0, 0, 1} in change.current
    assert {192, 168, 1, 5} in change.current
  end

  test "does not notify when the IP set is unchanged" do
    %{probe: probe} = ip_seq([[{192, 168, 1, 5}], [{192, 168, 1, 5}]])

    {:ok, pid} = start_supervised({Polling, [probe: probe, poll_interval_ms: 30]})
    :ok = Polling.subscribe(pid, self())

    refute_receive {:network_changed, _}, 200
  end

  test "drops a subscriber when its process dies" do
    %{probe: probe} =
      ip_seq([[{192, 168, 1, 5}], [{192, 168, 1, 5}], [{10, 0, 0, 1}]])

    {:ok, pid} = start_supervised({Polling, [probe: probe, poll_interval_ms: 30]})

    test = self()

    sub =
      spawn(fn ->
        :ok = Polling.subscribe(pid, self())
        send(test, :subscribed)

        receive do
          :stop -> :ok
        end
      end)

    assert_receive :subscribed, 500
    Process.exit(sub, :kill)
    Process.sleep(80)

    # The polling process should still be running normally.
    assert is_list(Polling.current_ips(pid))
  end

  describe "default_probe/0" do
    test "returns a list of IP tuples" do
      ips = Polling.default_probe()
      assert is_list(ips)

      Enum.each(ips, fn ip ->
        assert tuple_size(ip) in [4, 8]
      end)
    end

    test "filters out loopback and 0.0.0.0" do
      ips = Polling.default_probe()
      refute {127, 0, 0, 1} in ips
      refute {0, 0, 0, 0} in ips
    end
  end
end
