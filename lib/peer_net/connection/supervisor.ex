defmodule PeerNet.Connection.Supervisor do
  @moduledoc """
  `DynamicSupervisor` for live `PeerNet.Connection` processes.

  One supervisor per PeerNet instance. Connections come and go as peers
  appear and disappear; the supervisor enforces process isolation (one
  misbehaving connection cannot bring down another) and provides a clean
  shutdown surface.
  """

  use DynamicSupervisor

  def start_link(opts) do
    {name, _} = Keyword.pop(opts, :name, __MODULE__)
    DynamicSupervisor.start_link(__MODULE__, [], name: name)
  end

  @impl true
  def init(_), do: DynamicSupervisor.init(strategy: :one_for_one)

  @doc "Start a `PeerNet.Connection` under this supervisor."
  @spec start_connection(GenServer.server(), keyword()) ::
          DynamicSupervisor.on_start_child()
  def start_connection(server, opts) do
    DynamicSupervisor.start_child(server, {PeerNet.Connection, opts})
  end
end
