defmodule PeerNet.IdentityTest do
  use ExUnit.Case, async: true
  doctest PeerNet.Identity

  alias PeerNet.Identity

  describe "generate/0" do
    test "produces a 32-byte X25519 public + private key" do
      identity = Identity.generate()

      assert is_binary(identity.public)
      assert is_binary(identity.private)
      assert byte_size(identity.public) == 32
      assert byte_size(identity.private) == 32
    end

    test "successive calls return distinct keypairs" do
      a = Identity.generate()
      b = Identity.generate()

      refute a.public == b.public
      refute a.private == b.private
    end
  end

  describe "dh/2 — Diffie-Hellman" do
    test "two parties derive the same shared secret" do
      a = Identity.generate()
      b = Identity.generate()

      shared_a = Identity.dh(a, b.public)
      shared_b = Identity.dh(b, a.public)

      assert shared_a == shared_b
      assert byte_size(shared_a) == 32
    end

    test "different peer pubkeys produce different shared secrets" do
      a = Identity.generate()
      b = Identity.generate()
      c = Identity.generate()

      assert Identity.dh(a, b.public) != Identity.dh(a, c.public)
    end
  end

  describe "fingerprint/1" do
    test "returns a stable hex string for a given public key" do
      identity = Identity.generate()
      f1 = Identity.fingerprint(identity.public)
      f2 = Identity.fingerprint(identity.public)

      assert f1 == f2
      assert is_binary(f1)
      # Sha-256 hex is 64 chars; we shorten to 16 (8 bytes) for human display.
      assert String.length(f1) == 16
      assert String.match?(f1, ~r/\A[0-9a-f]+\z/)
    end

    test "different keys produce different fingerprints" do
      a = Identity.generate()
      b = Identity.generate()

      refute Identity.fingerprint(a.public) == Identity.fingerprint(b.public)
    end
  end

  describe "load_or_create/1" do
    @tag :tmp_dir
    test "creates a new identity on first call and persists it", %{tmp_dir: dir} do
      assert {:ok, id1, :created} = Identity.load_or_create(dir)
      assert is_binary(id1.public)
      assert is_binary(id1.private)
      assert File.exists?(Path.join(dir, "identity.keys"))
    end

    @tag :tmp_dir
    test "subsequent calls return the same identity from disk", %{tmp_dir: dir} do
      assert {:ok, id1, :created} = Identity.load_or_create(dir)
      assert {:ok, id2, :loaded} = Identity.load_or_create(dir)

      assert id1.public == id2.public
      assert id1.private == id2.private
    end

    @tag :tmp_dir
    test "loaded identity can do DH consistently", %{tmp_dir: dir} do
      assert {:ok, id, :created} = Identity.load_or_create(dir)
      assert {:ok, id_again, :loaded} = Identity.load_or_create(dir)

      peer = Identity.generate()
      assert Identity.dh(id, peer.public) == Identity.dh(id_again, peer.public)
    end

    @tag :tmp_dir
    test "errors cleanly when keyfile is corrupt", %{tmp_dir: dir} do
      File.mkdir_p!(dir)
      File.write!(Path.join(dir, "identity.keys"), "not a keyfile")

      assert {:error, :invalid_keyfile} = Identity.load_or_create(dir)
    end
  end
end
