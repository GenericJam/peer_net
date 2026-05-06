defmodule PeerNet.Discovery.UDP.Transport.GenUDP do
  @moduledoc """
  Production transport for `PeerNet.Discovery.UDP` — wraps Erlang
  `:gen_udp` with broadcast enabled.

  Opens the socket bound to `0.0.0.0:port` so it receives broadcasts
  arriving on any local interface. Uses `reuseaddr: true` so multiple
  PeerNet instances on the same host can share the listen port if the
  OS allows it (Linux + macOS with `SO_REUSEPORT`).
  """

  @behaviour PeerNet.Discovery.UDP.Transport

  @impl true
  def open(port) do
    :gen_udp.open(port, [
      :binary,
      active: true,
      broadcast: true,
      reuseaddr: true
    ])
  end

  @impl true
  def broadcast(socket, port, bytes) when is_port(socket) do
    :gen_udp.send(socket, {255, 255, 255, 255}, port, bytes)
  end

  @impl true
  def close(socket) when is_port(socket), do: :gen_udp.close(socket)
end
