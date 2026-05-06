defmodule PeerNetTest do
  use ExUnit.Case, async: false

  @moduletag :tmp_dir

  setup %{tmp_dir: tmp_dir} do
    name = :"unit_#{System.unique_integer([:positive])}"
    {:ok, _} = start_supervised({PeerNet, [name: name, data_dir: tmp_dir, port: 0]})
    %{name: name}
  end

  test "starts and exposes its identity + port", %{name: name} do
    id = PeerNet.identity(name)
    assert is_binary(id.public)
    assert byte_size(id.public) == 32

    port = PeerNet.port(name)
    assert is_integer(port) and port > 0
  end

  test "expose / revoke round-trip via the public API", %{name: name} do
    :ok = PeerNet.expose(name, :greet, fn _from, _ -> :ok end)
    assert PeerNet.list_peers(name) == []
    :ok = PeerNet.revoke(name, :greet)
  end

  test "send/4 returns :not_connected when there's no live connection", %{name: name} do
    assert {:error, :not_connected} = PeerNet.send(name, <<1::256>>, :anything, %{})
  end

  test "call/5 returns :not_connected when there's no live connection", %{name: name} do
    assert {:error, :not_connected} = PeerNet.call(name, <<1::256>>, :anything, %{}, 100)
  end
end
