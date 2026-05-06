defmodule PeerNet.LivenessTest do
  use ExUnit.Case, async: true

  alias PeerNet.Liveness

  setup do
    me = self()

    # Capture pings: when the liveness GenServer wants to send a ping, it
    # calls the configured `:emit` fn with the chosen nonce. Tests inject
    # the response (or don't) via `Liveness.handle_pong/2`.
    emit = fn nonce -> send(me, {:ping_emitted, nonce}) end
    on_dead = fn -> send(me, :dead_fired) end

    {:ok, pid} =
      start_supervised(
        {Liveness,
         [
           # Tight timings for tests; production defaults are 30s/60s.
           interval_ms: 50,
           timeout_ms: 200,
           emit: emit,
           on_dead: on_dead
         ]}
      )

    %{pid: pid}
  end

  test "emits a ping after every interval", %{pid: _pid} do
    assert_receive {:ping_emitted, nonce1}, 200
    assert is_binary(nonce1) and byte_size(nonce1) == 16

    assert_receive {:ping_emitted, _nonce2}, 200
  end

  test "stays alive when each ping is acked", %{pid: pid} do
    # Receive a ping, immediately ack with matching nonce.
    assert_receive {:ping_emitted, nonce}, 200
    :ok = Liveness.handle_pong(pid, nonce)

    refute_receive :dead_fired, 250
  end

  test "fires on_dead when no ack arrives within timeout_ms", %{pid: _pid} do
    assert_receive {:ping_emitted, _nonce}, 200
    # Don't ack. on_dead should fire after timeout_ms.
    assert_receive :dead_fired, 500
  end

  test "ignores acks for the wrong nonce", %{pid: pid} do
    assert_receive {:ping_emitted, _real_nonce}, 200
    # Send a fake ack with a fresh nonce.
    :ok = Liveness.handle_pong(pid, :crypto.strong_rand_bytes(16))

    # on_dead should still fire because the real nonce was never acked.
    assert_receive :dead_fired, 500
  end
end
