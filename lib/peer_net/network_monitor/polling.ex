defmodule PeerNet.NetworkMonitor.Polling do
  @moduledoc """
  Default `PeerNet.NetworkMonitor` implementation. Polls
  `:inet.getifaddrs/0` on a configurable interval (default 5 seconds)
  and notifies subscribers when the local IP set changes.

  ## What's filtered out

  - Loopback (`127.0.0.0/8`, `::1`) — never useful to peers.
  - `0.0.0.0`, `255.255.255.255` — degenerate.
  - Interfaces in `:down` state — Erlang reports them, peers can't
    use them.

  ## Probing

  The probe function is injectable via the `:probe` option for
  testability. The default reads `:inet.getifaddrs/0` and projects
  out a flat list of usable IPs.

      Polling.start_link(
        probe: fn -> [{192, 168, 1, 50}] end,
        poll_interval_ms: 100
      )

  ## Subscribers

  Subscribers can come and go. The polling process monitors each one
  and drops it from the dispatch list on `:DOWN`, so a subscriber
  crashing doesn't accumulate dead pids in state.
  """

  @behaviour PeerNet.NetworkMonitor

  use GenServer

  @default_poll_interval_ms 5_000

  # ── Public API ──────────────────────────────────────────────────────

  @impl true
  def start_link(opts) do
    {name, opts} = Keyword.pop(opts, :name, __MODULE__)
    GenServer.start_link(__MODULE__, opts, name: name)
  end

  @impl true
  def subscribe(server, pid) when is_pid(pid) do
    GenServer.call(server, {:subscribe, pid})
  end

  @impl true
  def current_ips(server), do: GenServer.call(server, :current_ips)

  # ── GenServer ───────────────────────────────────────────────────────

  @impl true
  def init(opts) do
    state = %{
      poll_interval_ms: Keyword.get(opts, :poll_interval_ms, @default_poll_interval_ms),
      probe: Keyword.get(opts, :probe, &__MODULE__.default_probe/0),
      ips: [],
      subscribers: %{}
    }

    state = %{state | ips: Enum.sort(state.probe.())}
    Process.send_after(self(), :poll, state.poll_interval_ms)
    {:ok, state}
  end

  @impl true
  def handle_call({:subscribe, pid}, _from, state) do
    ref = Process.monitor(pid)
    {:reply, :ok, put_in(state.subscribers[ref], pid)}
  end

  def handle_call(:current_ips, _from, state), do: {:reply, state.ips, state}

  @impl true
  def handle_info(:poll, state) do
    new_ips = Enum.sort(state.probe.())

    state =
      if new_ips != state.ips do
        change = %{
          added: new_ips -- state.ips,
          removed: state.ips -- new_ips,
          current: new_ips
        }

        for {_ref, pid} <- state.subscribers, do: send(pid, {:network_changed, change})
        %{state | ips: new_ips}
      else
        state
      end

    Process.send_after(self(), :poll, state.poll_interval_ms)
    {:noreply, state}
  end

  def handle_info({:DOWN, ref, :process, _pid, _reason}, state) do
    {:noreply, %{state | subscribers: Map.delete(state.subscribers, ref)}}
  end

  def handle_info(_other, state), do: {:noreply, state}

  # ── Default probe ───────────────────────────────────────────────────

  @doc """
  Default IP probe — reads `:inet.getifaddrs/0` and returns a flat
  list of usable, non-loopback IPv4/IPv6 addresses on up interfaces.

  Public so tests and alternate impls can call it directly.
  """
  @spec default_probe() :: [PeerNet.NetworkMonitor.ip()]
  def default_probe do
    case :inet.getifaddrs() do
      {:ok, ifaces} -> Enum.flat_map(ifaces, &interface_ips/1) |> Enum.uniq()
      _ -> []
    end
  end

  defp interface_ips({_name, props}) do
    flags = Keyword.get(props, :flags, [])

    cond do
      :loopback in flags -> []
      :up not in flags -> []
      true -> Keyword.get_values(props, :addr) |> Enum.filter(&usable_ip?/1)
    end
  end

  # IPv4 0.0.0.0 / 255.255.255.255 / IPv6 :: are not useful peer
  # addresses; multicast / link-local handling is platform-specific
  # and we punt for v0.1.
  defp usable_ip?({0, 0, 0, 0}), do: false
  defp usable_ip?({255, 255, 255, 255}), do: false
  defp usable_ip?({0, 0, 0, 0, 0, 0, 0, 0}), do: false
  defp usable_ip?(addr) when tuple_size(addr) == 4, do: true
  defp usable_ip?(addr) when tuple_size(addr) == 8, do: true
  defp usable_ip?(_), do: false
end
