"""Comprehensive AETHER test suite & remediation regression tests (AETHER-01 through AETHER-05)."""

from __future__ import annotations

import concurrent.futures
import socket
import struct
import time
from pathlib import Path

from fastapi.testclient import TestClient

from aether.gateway import AetherSecurityGateway, ClientCredential, build_auth_envelope
from aether.modbus import ModbusFrame, ModbusPLCServer, ModbusStreamFramer
from aether.process import OperatingMode, ProcessState
from aether.web import create_app


def _send_tcp(port: int, payload: bytes) -> bytes:
    with socket.create_connection(("127.0.0.1", port), timeout=2.0) as s:
        s.settimeout(2.0)
        s.sendall(payload)
        return s.recv(1024)


def test_modbus_stream_framer_fragmentation_and_coalescing() -> None:
    framer = ModbusStreamFramer()
    f1 = ModbusFrame(1, 0, 1, struct.pack(">BHH", 0x03, 0, 1)).to_bytes()
    f2 = ModbusFrame(2, 0, 1, struct.pack(">BHH", 0x04, 0, 2)).to_bytes()
    stream = f1 + f2

    recovered = []
    for i in range(len(stream)):
        recovered.extend(framer.feed(stream[i : i + 1]))
    assert len(recovered) == 2
    assert recovered[0].transaction_id == 1 and recovered[1].transaction_id == 2

    both = framer.feed(stream)
    assert len(both) == 2


def test_aether01_rate_limit_no_deadlock_and_concurrent_consistency() -> None:
    """AETHER-01: Exceeding rate limit must reject within bounded time without deadlocking non-reentrant lock."""
    state = ProcessState(profile="observatory", operating_mode=int(OperatingMode.OBSERVING), enforce_local_safety_interlocks=True)
    plc = ModbusPLCServer(state)
    plc_port = plc.start()
    creds = {
        "op-1": ClientCredential("op-1", "OPERATOR", b"rate-test-op-key-2027"),
        "mon-1": ClientCredential("mon-1", "MONITOR", b"rate-test-mon-key-2027"),
    }
    gw = AetherSecurityGateway("127.0.0.1", plc_port, creds, rate_limit_per_sec=3)
    gw_port = gw.start()

    try:
        read_f = ModbusFrame(1, 0, 1, struct.pack(">BHH", 0x03, 0, 1)).to_bytes()
        t0 = time.perf_counter()
        results = [
            _send_tcp(gw_port, build_auth_envelope("op-1", creds["op-1"].secret_key, read_f))
            for _ in range(6)
        ]
        elapsed = time.perf_counter() - t0
        assert elapsed < 3.0, f"Rate-limit path hung or deadlocked ({elapsed:.2f}s)"
        # First 3 succeed, remaining 3 rejected via Modbus exception
        assert sum(1 for r in results if r[7] == 0x03) == 3
        assert sum(1 for r in results if r[7] & 0x80) == 3

        # Independent client MUST still succeed immediately (no global deadlock)
        r_mon = _send_tcp(gw_port, build_auth_envelope("mon-1", creds["mon-1"].secret_key, read_f))
        assert r_mon[7] == 0x03

        # Concurrent burst across both clients must complete cleanly
        def _call(idx: int) -> int:
            cid = "mon-1" if idx % 2 == 0 else "op-1"
            rf = ModbusFrame(10 + idx, 0, 1, struct.pack(">BHH", 0x03, 0, 1)).to_bytes()
            return _send_tcp(gw_port, build_auth_envelope(cid, creds[cid].secret_key, rf))[7]

        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as ex:
            codes = list(ex.map(_call, range(12)))
        assert len(codes) == 12
    finally:
        gw.stop()
        plc.stop()


def test_aether02_tcp_stream_fragmentation_coalescing_and_malformed_handling() -> None:
    """AETHER-02: Gateway TCP handler must reassemble byte-fragmented and coalesced envelopes without hanging."""
    state = ProcessState(profile="observatory", enforce_local_safety_interlocks=True)
    plc = ModbusPLCServer(state)
    plc_port = plc.start()
    creds = {"op-1": ClientCredential("op-1", "OPERATOR", b"tcp-stream-key-2027")}
    gw = AetherSecurityGateway("127.0.0.1", plc_port, creds, rate_limit_per_sec=100)
    gw_port = gw.start()

    try:
        f1 = ModbusFrame(101, 0, 1, struct.pack(">BHH", 0x03, 0, 1)).to_bytes()
        f2 = ModbusFrame(102, 0, 1, struct.pack(">BHH", 0x04, 0, 2)).to_bytes()
        env1 = build_auth_envelope("op-1", creds["op-1"].secret_key, f1)
        env2 = build_auth_envelope("op-1", creds["op-1"].secret_key, f2)

        # 1. Byte-by-byte fragmented delivery over single TCP socket
        with socket.create_connection(("127.0.0.1", gw_port), timeout=2.0) as s:
            s.settimeout(2.0)
            for b in env1:
                s.sendall(bytes([b]))
            r1 = s.recv(1024)
            assert r1[7] == 0x03

        # 2. Two coalesced envelopes in a single sendall()
        with socket.create_connection(("127.0.0.1", gw_port), timeout=2.0) as s:
            s.settimeout(2.0)
            s.sendall(env1 + env2)  # Note: env1 reused -> replay exception; env2 fresh -> valid FC 0x04!
            framer = ModbusStreamFramer()
            got: list[ModbusFrame] = []
            while len(got) < 2:
                chunk = s.recv(1024)
                if not chunk:
                    break
                got.extend(framer.feed(chunk))
            assert len(got) == 2
            assert got[0].function_code & 0x80  # env1 replay blocked
            assert got[1].function_code == 0x04 and got[1].transaction_id == 102

        # 3. Truncated connection closes cleanly without hanging
        with socket.create_connection(("127.0.0.1", gw_port), timeout=2.0) as s:
            s.sendall(env2[:10])
        # 4. Invalid magic rejected with exception
        r_bad = _send_tcp(gw_port, b"NOPE" + b"\x00" * 40)
        assert r_bad[7] & 0x80
    finally:
        gw.stop()
        plc.stop()


def test_aether03_atomic_replay_protection_and_bounded_cache() -> None:
    """AETHER-03: Identical authenticated envelope replayed concurrently or sequentially must execute at most once."""
    state = ProcessState(profile="observatory", enforce_local_safety_interlocks=True)
    plc = ModbusPLCServer(state)
    plc_port = plc.start()
    creds = {"op-1": ClientCredential("op-1", "OPERATOR", b"replay-key-2027")}
    gw = AetherSecurityGateway("127.0.0.1", plc_port, creds, max_replay_cache_entries=50, rate_limit_per_sec=200)
    gw_port = gw.start()

    try:
        wr = ModbusFrame(201, 0, 1, struct.pack(">BHH", 0x06, 0, 1900)).to_bytes()
        env = build_auth_envelope("op-1", creds["op-1"].secret_key, wr)

        # Concurrent duplicate replays -> strictly 1 allowed, 7 rejected!
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as ex:
            resps = list(ex.map(lambda _: _send_tcp(gw_port, env), range(8)))
        assert sum(1 for r in resps if r[7] == 0x06) == 1
        assert sum(1 for r in resps if r[7] & 0x80) == 7

        # Replay cache remains strictly bounded
        for i in range(65):
            rf = ModbusFrame(300 + i, 0, 1, struct.pack(">BHH", 0x03, 0, 1)).to_bytes()
            r = _send_tcp(gw_port, build_auth_envelope("op-1", creds["op-1"].secret_key, rf))
            assert r[7] == 0x03
        assert len(gw._seen_nonces) <= 50
    finally:
        gw.stop()
        plc.stop()


def test_aether04_and_05_default_deny_ranges_and_concurrent_safety_invariants() -> None:
    """AETHER-04 & AETHER-05: Strict read/write register bounds, unknown roles denied, and concurrent PLC safety invariants."""
    state = ProcessState(profile="observatory", operating_mode=int(OperatingMode.OBSERVING), enforce_local_safety_interlocks=True)
    plc = ModbusPLCServer(state)
    plc_port = plc.start()
    creds = {
        "op-1": ClientCredential("op-1", "OPERATOR", b"authz-op-key-2027"),
        "mon-1": ClientCredential("mon-1", "MONITOR", b"authz-mon-key-2027"),
        "maint-1": ClientCredential("maint-1", "MAINTENANCE", b"authz-maint-key-2027"),
        "rogue-1": ClientCredential("rogue-1", "UNKNOWN_ROLE", b"authz-rogue-key-2027"),
    }
    gw = AetherSecurityGateway("127.0.0.1", plc_port, creds, policy_mode="process_aware", rate_limit_per_sec=200)
    gw_port = gw.start()

    try:
        # Unknown role denied even on reads
        r_rogue = _send_tcp(gw_port, build_auth_envelope("rogue-1", creds["rogue-1"].secret_key, ModbusFrame(1, 0, 1, struct.pack(">BHH", 0x03, 0, 1)).to_bytes()))
        assert r_rogue[7] & 0x80

        # Out-of-bounds read spanning authorized into unauthorized holding register (addr=1, qty=2 -> registers 1,2 where max is 1)
        r_span = _send_tcp(gw_port, build_auth_envelope("mon-1", creds["mon-1"].secret_key, ModbusFrame(2, 0, 1, struct.pack(">BHH", 0x03, 1, 2)).to_bytes()))
        assert r_span[7] == (0x03 | 0x80)

        # Multi-register write FC 0x10 rejected
        r_fc16 = _send_tcp(gw_port, build_auth_envelope("maint-1", creds["maint-1"].secret_key, ModbusFrame(3, 0, 1, struct.pack(">BHHBHH", 0x10, 0, 2, 4, 1500, 1)).to_bytes()))
        assert r_fc16[7] == (0x10 | 0x80)

        # Process-aware safety blocks overspeed & pump shutdown in OBSERVING
        assert _send_tcp(gw_port, build_auth_envelope("op-1", creds["op-1"].secret_key, ModbusFrame(4, 0, 1, struct.pack(">BHH", 0x06, 0, 4500)).to_bytes()))[7] & 0x80
        assert _send_tcp(gw_port, build_auth_envelope("op-1", creds["op-1"].secret_key, ModbusFrame(5, 0, 1, struct.pack(">BHH", 0x05, 0, 0x0000)).to_bytes()))[7] & 0x80

        # AETHER-05: Concurrent mode transitions + pump trip attempts must NEVER leave PLC in unsafe state!
        def _race_worker(i: int) -> None:
            if i % 3 == 0:
                fr = ModbusFrame(500 + i, 0, 1, struct.pack(">BHH", 0x06, 1, int(OperatingMode.MAINTENANCE))).to_bytes()
                _send_tcp(gw_port, build_auth_envelope("maint-1", creds["maint-1"].secret_key, fr))
            elif i % 3 == 1:
                fr = ModbusFrame(500 + i, 0, 1, struct.pack(">BHH", 0x05, 0, 0x0000)).to_bytes()
                _send_tcp(gw_port, build_auth_envelope("op-1", creds["op-1"].secret_key, fr))
            else:
                fr = ModbusFrame(500 + i, 0, 1, struct.pack(">BHH", 0x06, 1, int(OperatingMode.OBSERVING))).to_bytes()
                _send_tcp(gw_port, build_auth_envelope("maint-1", creds["maint-1"].secret_key, fr))
            assert state.is_safe_state(), f"Safety invariant violated during race: {state.snapshot()}"

        with concurrent.futures.ThreadPoolExecutor(max_workers=9) as ex:
            list(ex.map(_race_worker, range(27)))
        assert state.is_safe_state()
    finally:
        gw.stop()
        plc.stop()


def test_aether_dashboard_both_profiles(tmp_path: Path) -> None:
    client = TestClient(create_app(evidence_path=tmp_path / "missing.json"))
    assert client.get("/api/health").status_code == 200
    assert client.get("/api/telemetry?profile=observatory").json()["telemetry"]["profile"] == "observatory"
    assert client.get("/api/telemetry?profile=generic_industrial").json()["telemetry"]["profile"] == "generic_industrial"
    assert "AETHER — Industrial" in client.get("/?profile=observatory").text
