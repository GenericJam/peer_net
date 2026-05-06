defmodule PeerNet.Discovery.UDP.Transport do
  @moduledoc """
  Behaviour for the UDP transport used by `PeerNet.Discovery.UDP`.

  Two implementations:

  - `PeerNet.Discovery.UDP.Transport.GenUDP` — wraps `:gen_udp`. Default.
  - Test mocks — see `test/support/` for examples used in unit tests.

  The behaviour exists so the discovery GenServer can be tested without
  binding real sockets and without depending on broadcast routing in the
  test environment (which is fragile across machines).

  ## Contract

  - `open/1` returns `{:ok, socket_handle}` or `{:error, reason}`. The
    handle is opaque to PeerNet; only the transport interprets it.
  - `broadcast/3` sends `bytes` to all peers on `port`. Returns `:ok` or
    `{:error, reason}`.
  - `close/1` releases the socket.

  Inbound packets are delivered to the owning process as
  `{:udp, socket, src_ip, src_port, bytes}` (matching `:gen_udp`'s
  default message shape) or `{:peer_net_udp_packet, src_ip, bytes}`
  (used by mock transports that don't have a socket port to embed).
  """

  @callback open(:inet.port_number()) :: {:ok, term()} | {:error, term()}
  @callback broadcast(term(), :inet.port_number(), binary()) :: :ok | {:error, term()}
  @callback close(term()) :: :ok
end
