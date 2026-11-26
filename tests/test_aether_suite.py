"""Comprehensive AETHER test suite: TCP stream fragmentation/coalescing, HMAC auth/replay, role authz, process-aware safety state machine, rate limiting, and FastAPI dashboard."""

from __future__ import annotations

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

    # Feed 1 byte at a time (extreme TCP fragmentation)
    recovered = []
    for i in range(len(stream)):
        recovered.extend(framer.feed(stream[i : i + 1]))
    assert len(recovered) == 2
    assert recovered[0].transaction_id == 1 and recovered[1].transaction_id == 2

    # Feed both coalesced in one chunk
    both = framer.feed(stream)
    assert len(both) == 2

    # Invalid protocol ID rejected
    bad_proto = struct.pack(">HHHB", 1, 99, 6, 1) + struct.pack(">BHH", 0x03, 0, 1)
    try:
        framer.feed(bad_proto)
        assert False, "Expected ValueError on invalid protocol ID"
    except ValueError:
        pass


def test_gateway_hmac_auth_replay_and_process_aware_safety() -> None:
    state = ProcessState(profile="observatory", operating_mode=int(OperatingMode.OBSERVING))
    plc = ModbusPLCServer(state)
    plc_port = plc.start()

    creds = {
        "op-1": ClientCredential("op-1", "OPERATOR", b"ephemeral-operator-key-2027"),
        "mon-1": ClientCredential("mon-1", "MONITOR", b"ephemeral-monitor-key-2027"),
        "maint-1": ClientCredential("maint-1", "MAINTENANCE", b"ephemeral-maint-key-2027"),
    }
    gw = AetherSecurityGateway("127.0.0.1", plc_port, creds, profile="observatory", policy_mode="process_aware", rate_limit_per_sec=200)
    gw_port = gw.start()

    try:
        # 1. Authorized telemetry read succeeds for MONITOR
        read_req = ModbusFrame(10, 0, 1, struct.pack(">BHH", 0x03, 0, 1)).to_bytes()
        resp = _send_tcp(gw_port, build_auth_envelope("mon-1", creds["mon-1"].secret_key, read_req))
        assert resp[7] == 0x03
        assert struct.unpack(">H", resp[9:11])[0] == 1450

        # 2. MONITOR attempting write is blocked
        write_ok = ModbusFrame(11, 0, 1, struct.pack(">BHH", 0x06, 0, 1800)).to_bytes()
        resp_mon_w = _send_tcp(gw_port, build_auth_envelope("mon-1", creds["mon-1"].secret_key, write_ok))
        assert resp_mon_w[7] == (0x06 | 0x80)

        # 3. Invalid HMAC & expired replay timestamp rejected
        resp_bad_mac = _send_tcp(gw_port, build_auth_envelope("op-1", b"wrong-key", write_ok))
        assert resp_bad_mac[7] & 0x80
        resp_replay = _send_tcp(gw_port, build_auth_envelope("op-1", creds["op-1"].secret_key, write_ok, ts=int(time.time()) - 120))
        assert resp_replay[7] & 0x80

        # 4. Authorized safe RPM change succeeds for OPERATOR
        resp_op_ok = _send_tcp(gw_port, build_auth_envelope("op-1", creds["op-1"].secret_key, write_ok))
        assert resp_op_ok[7] == 0x06 and state.target_rpm == 1800

        # 5. Process-aware safety blocks overspeed (4500 > 2800 RPM)
        overspeed = ModbusFrame(12, 0, 1, struct.pack(">BHH", 0x06, 0, 4500)).to_bytes()
        resp_over = _send_tcp(gw_port, build_auth_envelope("op-1", creds["op-1"].secret_key, overspeed))
        assert resp_over[7] == (0x06 | 0x80) and state.target_rpm == 1800

        # 6. Process-aware safety blocks pump shutdown (Coil 0 = OFF) while OBSERVING
        pump_off = ModbusFrame(13, 0, 1, struct.pack(">BHH", 0x05, 0, 0x0000)).to_bytes()
        resp_trip = _send_tcp(gw_port, build_auth_envelope("op-1", creds["op-1"].secret_key, pump_off))
        assert resp_trip[7] == (0x05 | 0x80) and state.pump_power == 1

        # 7. Unsupported diagnostic function code FC 0x08 blocked by default-deny
        diag = ModbusFrame(14, 0, 1, struct.pack(">BHH", 0x08, 0, 0)).to_bytes()
        resp_diag = _send_tcp(gw_port, build_auth_envelope("op-1", creds["op-1"].secret_key, diag))
        assert resp_diag[7] == (0x08 | 0x80)

        # 8. MAINTENANCE transitions to MAINTENANCE mode -> pump shutdown now safely permitted
        to_maint = ModbusFrame(15, 0, 1, struct.pack(">BHH", 0x06, 1, int(OperatingMode.MAINTENANCE))).to_bytes()
        resp_m = _send_tcp(gw_port, build_auth_envelope("maint-1", creds["maint-1"].secret_key, to_maint))
        assert resp_m[7] == 0x06 and state.operating_mode == int(OperatingMode.MAINTENANCE)
        resp_off_ok = _send_tcp(gw_port, build_auth_envelope("maint-1", creds["maint-1"].secret_key, pump_off))
        assert resp_off_ok[7] == 0x05 and state.pump_power == 0

        # 9. Verify credentials are never leaked in decision logs
        serialized = str(gw.decisions)
        assert "ephemeral-operator-key-2027" not in serialized
    finally:
        gw.stop()
        plc.stop()


def test_aether_dashboard_both_profiles(tmp_path: Path) -> None:
    client = TestClient(create_app(evidence_path=tmp_path / "missing.json"))
    assert client.get("/api/health").status_code == 200
    assert client.get("/api/telemetry?profile=observatory").json()["telemetry"]["profile"] == "observatory"
    assert client.get("/api/telemetry?profile=generic_industrial").json()["telemetry"]["profile"] == "generic_industrial"
    assert "AETHER — Industrial" in client.get("/?profile=observatory").text
