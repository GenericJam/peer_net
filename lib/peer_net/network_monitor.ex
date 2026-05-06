defmodule PeerNet.NetworkMonitor do
  @moduledoc """
  Behaviour for noticing when this host's network situation changes —
  primarily, when the set of local IP addresses gains or loses entries.

  ## Why bother

  When a phone moves between WiFi networks, the local IP changes and
  every existing TCP connection is dead. Without something watching,
  PeerNet will only notice when the OS gives up on the dead sockets
  (TCP keepalive defaults are measured in hours; our app-level
  Liveness ping is measured in tens of seconds). NetworkMonitor lets
  us detect the change in seconds and proactively tear down dead
  connections so the auto-reconnect path fires immediately.

  Discovery implementations also benefit — `Discovery.UDP` rebroadcasts
  every 5s anyway, but on a network switch you'd rather not wait that
  long for peers on the new network to learn the new address.

  ## Implementations

  - `PeerNet.NetworkMonitor.Polling` — calls `:inet.getifaddrs/0`
    every `poll_interval_ms` (default 5_000) and notifies subscribers
    when the IP set changes. Works on every platform Erlang runs on,
    no platform-specific dependencies.
  - Mobile NIFs would typically provide their own implementation of
    this Behaviour bridged to platform reachability APIs (iOS
    `NSNotification` for `Reachability`, Android
    `ConnectivityManager.NetworkCallback`). PeerNet ships the
    Behaviour and the polling default; platform code plugs in.

  ## Subscriber contract

  Subscribers (typically `PeerNet.Registry`) call `subscribe/2`. They
  receive messages of the form:

      {:network_changed, %{
         added:   [ip],   # IPs present now that weren't before
         removed: [ip],   # IPs present before that aren't now
         current: [ip]    # the current set
       }}

  IPs are `:inet.ip_address/0` tuples (`{a, b, c, d}` for IPv4,
  `{a, b, c, d, e, f, g, h}` for IPv6).

  Subscribers also receive `{:DOWN, ...}` if they monitor the monitor
  (recommended; lets Registry restart its subscription if the monitor
  crashes).
  """

  @typedoc "An IP address as returned by `:inet.getifaddrs/0`."
  @type ip :: :inet.ip_address()

  @typedoc "Network-change event payload."
  @type change :: %{added: [ip()], removed: [ip()], current: [ip()]}

  @doc "Start the monitor."
  @callback start_link(opts :: keyword()) :: GenServer.on_start()

  @doc "Subscribe `pid` to receive `{:network_changed, change}` messages."
  @callback subscribe(server :: GenServer.server(), pid :: pid()) :: :ok

  @doc "Return the current set of non-loopback local IPs."
  @callback current_ips(server :: GenServer.server()) :: [ip()]
end
