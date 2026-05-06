defmodule PeerNet.Application do
  @moduledoc false

  # PeerNet does not auto-start anything when the application loads. Hosts
  # opt in by adding `{PeerNet, opts}` to their own supervision tree, which
  # gives them control over data_dir, transport selection, and (eventually)
  # the discovery backend. An auto-start would have to make all of those
  # choices on the host's behalf.
  use Application

  @impl true
  def start(_type, _args) do
    Supervisor.start_link([], strategy: :one_for_one, name: PeerNet.Supervisor)
  end
end
