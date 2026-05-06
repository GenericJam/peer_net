defmodule PeerNet.Discovery do
  @moduledoc """
  Behaviour for discovering peers on a network.

  Implementations announce this node's presence (own pubkey + listen
  address) and emit `{:peer_discovered, ...}` / `{:peer_lost, ...}`
  notifications to the `PeerNet.Registry` when other peers appear or
  disappear.

  ## Implementations shipped

  - `PeerNet.Discovery.Manual` — does nothing automatically. Tests and
    apps that want full control over connection lifetime use this.
    Discovery events are pushed via `Manual.announce_peer/3` and
    `Manual.lose_peer/2`.
  - `PeerNet.Discovery.MDNS` (planned, M3) — mdns_lite-backed
    announcement and discovery on the local network. Cross-platform
    interop with iOS Bonjour and Android NSD.

  ## Why a Behaviour

  Different deployment environments need different discovery strategies:
  Bluetooth on phones with no WiFi, mDNS on local networks, manual peer
  lists in CI / scripted setups. The Behaviour lets PeerNet stay
  agnostic and lets users compose what they need.

  ## Notifications

  Implementations send these messages to the Registry process:

      {:peer_discovered, pubkey, %{ip: ip, port: port, source: :mdns}}
      {:peer_lost, pubkey, %{source: :mdns}}

  The Registry decides what to do. Default: if the pubkey is in the
  trust list, dial it. Otherwise log + drop.
  """

  @typedoc "Where the discovery event came from. Used for logging."
  @type source :: atom()

  @typedoc """
  Address record handed to the Registry. Currently IP+port; future
  extensions could include transport hints (Bluetooth, WebRTC, etc.).
  """
  @type address :: %{ip: :inet.ip_address(), port: :inet.port_number(), source: source()}

  @doc """
  Start the discovery process for one PeerNet instance.

  Receives the per-instance config (own identity, listen port, registry
  pid to notify). Returns a `:gen_statem` / `GenServer.on_start` tuple.
  """
  @callback start_link(opts :: keyword()) :: GenServer.on_start()

  @doc """
  Update the discovery's view of the local listen address. Called once
  the Acceptor has resolved an OS-assigned port.
  """
  @callback announce_self(server :: GenServer.server(), :inet.port_number()) :: :ok

  @doc "Stop discovery cleanly."
  @callback stop(server :: GenServer.server()) :: :ok
end
