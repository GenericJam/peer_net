defmodule PeerNet.HandlersTest do
  use ExUnit.Case, async: true
  doctest PeerNet.Handlers

  alias PeerNet.Handlers

  setup do
    name = :"handlers_#{System.unique_integer([:positive])}"
    {:ok, pid} = start_supervised({Handlers, name: name})
    %{handlers: pid}
  end

  describe "default-deny" do
    test "an unregistered handle is unreachable", %{handlers: pid} do
      assert Handlers.lookup(pid, :nonexistent) == :error
    end

    test "dispatch to an unregistered handle returns :no_such_handle",
         %{handlers: pid} do
      caller_pubkey = <<1::256>>
      assert {:error, :no_such_handle} =
               Handlers.dispatch(pid, :nonexistent, caller_pubkey, %{})
    end

    test "list/1 starts empty", %{handlers: pid} do
      assert Handlers.list(pid) == []
    end
  end

  describe "expose/3" do
    test "registers a handler under a name", %{handlers: pid} do
      :ok = Handlers.expose(pid, :chat, fn _from, _args -> :ok end)
      assert {:ok, _opts, _fun} = Handlers.lookup(pid, :chat)
      assert :chat in Handlers.list(pid)
    end

    test "re-exposing a handle replaces the old one", %{handlers: pid} do
      :ok = Handlers.expose(pid, :chat, fn _from, _args -> :first end)
      :ok = Handlers.expose(pid, :chat, fn _from, _args -> :second end)

      assert {:ok, :second} = Handlers.dispatch(pid, :chat, <<1::256>>, %{})
    end

    test "rejects non-atom handle names", %{handlers: pid} do
      assert {:error, :invalid_name} =
               Handlers.expose(pid, "string_name", fn _, _ -> :ok end)
      assert {:error, :invalid_name} = Handlers.expose(pid, 42, fn _, _ -> :ok end)
    end

    test "rejects non-function handlers", %{handlers: pid} do
      assert {:error, :invalid_handler} = Handlers.expose(pid, :chat, "not a function")
    end

    test "rejects functions of wrong arity", %{handlers: pid} do
      assert {:error, :invalid_handler} = Handlers.expose(pid, :chat, fn -> :ok end)
      assert {:error, :invalid_handler} = Handlers.expose(pid, :chat, fn _ -> :ok end)
      assert {:error, :invalid_handler} = Handlers.expose(pid, :chat, fn _, _, _ -> :ok end)
    end
  end

  describe "dispatch/4" do
    test "calls the handler with caller_pubkey and args, returning {:ok, result}",
         %{handlers: pid} do
      :ok =
        Handlers.expose(pid, :echo, fn from, args -> {:got, from, args} end)

      assert {:ok, {:got, <<1::256>>, %{x: 1}}} =
               Handlers.dispatch(pid, :echo, <<1::256>>, %{x: 1})
    end

    test "wraps a raised exception in {:error, {:handler_crash, _}}",
         %{handlers: pid} do
      :ok = Handlers.expose(pid, :boom, fn _, _ -> raise "kaboom" end)

      assert {:error, {:handler_crash, _info}} =
               Handlers.dispatch(pid, :boom, <<1::256>>, %{})
    end

    test "wraps a thrown value in {:error, {:handler_crash, _}}",
         %{handlers: pid} do
      :ok = Handlers.expose(pid, :nope, fn _, _ -> throw(:nope) end)

      assert {:error, {:handler_crash, _}} =
               Handlers.dispatch(pid, :nope, <<1::256>>, %{})
    end
  end

  describe "authorize option" do
    test "rejects callers that fail the authorize fn",
         %{handlers: pid} do
      allowed = <<7::256>>
      blocked = <<8::256>>

      :ok =
        Handlers.expose(pid, :restricted, fn _, _ -> :allowed end,
          authorize: fn pubkey -> pubkey == allowed end
        )

      assert {:ok, :allowed} = Handlers.dispatch(pid, :restricted, allowed, %{})
      assert {:error, :forbidden} = Handlers.dispatch(pid, :restricted, blocked, %{})
    end
  end

  describe "revoke/2" do
    test "removes a previously-exposed handle", %{handlers: pid} do
      :ok = Handlers.expose(pid, :chat, fn _, _ -> :ok end)
      assert :chat in Handlers.list(pid)

      :ok = Handlers.revoke(pid, :chat)
      refute :chat in Handlers.list(pid)
      assert {:error, :no_such_handle} = Handlers.dispatch(pid, :chat, <<1::256>>, %{})
    end

    test "revoking an unknown handle is a no-op", %{handlers: pid} do
      assert :ok = Handlers.revoke(pid, :nonexistent)
    end
  end
end
