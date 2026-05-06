defmodule PeerNet.TrustTest do
  use ExUnit.Case, async: false
  doctest PeerNet.Trust

  alias PeerNet.Trust

  setup tags do
    if dir = tags[:tmp_dir] do
      {:ok, pid} = start_supervised({Trust, [data_dir: dir, name: __MODULE__]})
      %{trust: pid, dir: dir}
    else
      :ok
    end
  end

  @tag :tmp_dir
  test "starts empty", %{trust: pid} do
    assert Trust.list(pid) == []
    refute Trust.trusted?(pid, <<1::256>>)
  end

  describe "add/2" do
    @tag :tmp_dir
    test "adds a peer pubkey to the trust list", %{trust: pid} do
      assert :ok = Trust.add(pid, <<1::256>>)
      assert Trust.trusted?(pid, <<1::256>>)
      assert <<1::256>> in Enum.map(Trust.list(pid), & &1.pubkey)
    end

    @tag :tmp_dir
    test "adding the same peer twice is idempotent", %{trust: pid} do
      assert :ok = Trust.add(pid, <<1::256>>)
      assert :ok = Trust.add(pid, <<1::256>>)
      assert length(Trust.list(pid)) == 1
    end

    @tag :tmp_dir
    test "supports an optional human-readable label", %{trust: pid} do
      assert :ok = Trust.add(pid, <<1::256>>, label: "alice's phone")
      [%{label: label}] = Trust.list(pid)
      assert label == "alice's phone"
    end

    @tag :tmp_dir
    test "rejects non-32-byte pubkeys (Ed25519 keys are always 32 bytes)",
         %{trust: pid} do
      assert {:error, :invalid_pubkey} = Trust.add(pid, <<1, 2, 3>>)
      assert {:error, :invalid_pubkey} = Trust.add(pid, "not a binary key")
      assert Trust.list(pid) == []
    end
  end

  describe "remove/2" do
    @tag :tmp_dir
    test "removes a previously-added peer", %{trust: pid} do
      :ok = Trust.add(pid, <<1::256>>)
      :ok = Trust.add(pid, <<2::256>>)

      assert :ok = Trust.remove(pid, <<1::256>>)
      refute Trust.trusted?(pid, <<1::256>>)
      assert Trust.trusted?(pid, <<2::256>>)
    end

    @tag :tmp_dir
    test "removing an unknown peer is a no-op", %{trust: pid} do
      assert :ok = Trust.remove(pid, <<99::256>>)
      assert Trust.list(pid) == []
    end
  end

  describe "persistence" do
    @tag :tmp_dir
    test "trust list survives a restart", %{dir: dir} do
      {:ok, pid1} = start_supervised({Trust, [data_dir: dir, name: :trust_persist_a]}, id: :a)
      :ok = Trust.add(pid1, <<7::256>>, label: "labelled")
      :ok = Trust.add(pid1, <<8::256>>)
      :ok = stop_supervised(:a)

      {:ok, pid2} = start_supervised({Trust, [data_dir: dir, name: :trust_persist_b]}, id: :b)
      assert Trust.trusted?(pid2, <<7::256>>)
      assert Trust.trusted?(pid2, <<8::256>>)

      [%{pubkey: <<7::256>>, label: label}] = Enum.filter(Trust.list(pid2), &(&1.pubkey == <<7::256>>))
      assert label == "labelled"
    end
  end

  describe "trusted?/2" do
    @tag :tmp_dir
    test "returns false for any non-binary input without crashing", %{trust: pid} do
      refute Trust.trusted?(pid, nil)
      refute Trust.trusted?(pid, "not a key")
      refute Trust.trusted?(pid, <<1, 2, 3>>)
    end
  end
end
