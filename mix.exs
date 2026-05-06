defmodule PeerNet.MixProject do
  use Mix.Project

  @version "0.1.0"
  @source_url "https://github.com/GenericJam/peer_net"

  def project do
    [
      app: :peer_net,
      version: @version,
      elixir: "~> 1.15",
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      description: description(),
      package: package(),
      docs: docs(),
      name: "PeerNet",
      source_url: @source_url,
      homepage_url: @source_url
    ]
  end

  def application do
    [
      extra_applications: [:logger, :crypto],
      mod: {PeerNet.Application, []}
    ]
  end

  defp description do
    """
    Default-deny peer-to-peer messaging for Elixir. BEAM-distribution-shaped
    ergonomics (expose / call / send) between mutually-suspicious peers, with
    Noise XX cryptographic handshake, ChaCha20-Poly1305 transport encryption,
    pluggable LAN discovery, and walkie-talkie semantics.
    """
  end

  defp package do
    [
      maintainers: ["GenericJam"],
      licenses: ["Apache-2.0"],
      links: %{
        "GitHub" => @source_url,
        "Changelog" => "#{@source_url}/blob/main/CHANGELOG.md"
      },
      files: ~w(lib LICENSE mix.exs README.md CHANGELOG.md PLAN.md guides .formatter.exs)
    ]
  end

  defp docs do
    [
      main: "readme",
      extras: [
        "README.md",
        "guides/protocol.md",
        "guides/cookbook.md",
        "CHANGELOG.md",
        "PLAN.md"
      ],
      groups_for_extras: [
        Guides: ~r"^guides/"
      ],
      groups_for_modules: [
        "Identity & trust": [PeerNet.Identity, PeerNet.Trust],
        "Wire & dispatch": [PeerNet.Frame, PeerNet.Handlers, PeerNet.Channel],
        "Handshake": [PeerNet.Handshake],
        "Transport": [
          PeerNet.Connection,
          PeerNet.Connection.Supervisor,
          PeerNet.Acceptor,
          PeerNet.Liveness
        ],
        "Discovery": [
          PeerNet.Discovery,
          PeerNet.Discovery.Manual,
          PeerNet.Discovery.UDP,
          PeerNet.Discovery.UDP.Wire,
          PeerNet.Discovery.UDP.Transport,
          PeerNet.Discovery.UDP.Transport.GenUDP
        ],
        "Network monitor": [
          PeerNet.NetworkMonitor,
          PeerNet.NetworkMonitor.Polling
        ],
        "Registry & convenience": [PeerNet.Registry, PeerNet.BeamDist]
      ]
    ]
  end

  defp deps do
    [
      {:ex_doc, "~> 0.31", only: :dev, runtime: false}
    ]
  end
end
