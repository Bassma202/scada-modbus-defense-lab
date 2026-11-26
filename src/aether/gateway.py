"""AETHER Process-Aware Zero-Trust Modbus Security Gateway.

Enforces:
- HMAC-SHA256 timestamped client authentication with replay window (no static plaintext tokens in logs).
- Default-deny function-code and register-level authorization by role (OPERATOR, MONITOR, MAINTENANCE).
- Original process-aware safety state machine: queries live process state and blocks physically
  hazardous commands (e.g., overspeed > safe ceiling, pump shutdown during active OBSERVING mode,
  or cooling RPM drop below active minimum).
- Full TCP stream reassembly, sliding-window rate limiting, timeouts, and redacted audit events.
"""

from __future__ import annotations

import hashlib
import hmac
import socket
import struct
import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from aether.modbus import (
    EXC_ILLEGAL_DATA_ADDRESS,
    EXC_ILLEGAL_DATA_VALUE,
    EXC_ILLEGAL_FUNCTION,
    EXC_SERVER_DEVICE_FAILURE,
    ModbusFrame,
    ModbusStreamFramer,
    build_exception_frame,
)
from aether.process import OperatingMode, PROFILES


@dataclass
class ClientCredential:
    client_id: str
    role: str  # MONITOR | OPERATOR | MAINTENANCE
    secret_key: bytes


def build_auth_envelope(client_id: str, secret_key: bytes, modbus_frame: bytes, ts: int | None = None) -> bytes:
    """Wrap a raw Modbus TCP frame in an HMAC-SHA256 authenticated client-to-gateway envelope.

    Wire format: MAGIC(4='AETH') | ts(8 uint64) | cid_len(1) | cid | mac(32) | frame_len(2) | frame
    """
    timestamp = int(time.time()) if ts is None else ts
    cid_b = client_id.encode("utf-8")
    msg = struct.pack(">Q B", timestamp, len(cid_b)) + cid_b + modbus_frame
    mac = hmac.new(secret_key, msg, hashlib.sha256).digest()
    return b"AETH" + struct.pack(">Q B", timestamp, len(cid_b)) + cid_b + mac + struct.pack(">H", len(modbus_frame)) + modbus_frame


def parse_auth_envelope(data: bytes) -> tuple[int, str, bytes, bytes]:
    if len(data) < 4 + 8 + 1 + 32 + 2 or not data.startswith(b"AETH"):
        raise ValueError("Malformed AETHER authentication envelope.")
    ts, cid_len = struct.unpack(">QB", data[4:13])
    pos = 13 + cid_len
    if len(data) < pos + 32 + 2:
        raise ValueError("Truncated AETHER authentication envelope.")
    cid = data[13:pos].decode("utf-8", errors="strict")
    mac = data[pos : pos + 32]
    frame_len = struct.unpack(">H", data[pos + 32 : pos + 34])[0]
    frame = data[pos + 34 : pos + 34 + frame_len]
    if len(frame) != frame_len:
        raise ValueError("Incomplete Modbus frame inside AETHER envelope.")
    return ts, cid, mac, frame


@dataclass
class GatewayDecision:
    timestamp: str
    client_id: str
    role: str
    function_code: int
    allowed: bool
    reason: str
    policy_mode: str  # protocol_only | process_aware
    latency_ms: float = 0.0


class AetherSecurityGateway:
    """TCP reverse proxy mediating authenticated clients and an isolated Modbus TCP PLC."""

    def __init__(
        self,
        plc_host: str,
        plc_port: int,
        credentials: dict[str, ClientCredential],
        profile: str = "observatory",
        policy_mode: str = "process_aware",  # protocol_only | process_aware
        listen_host: str = "127.0.0.1",
        listen_port: int = 0,
        rate_limit_per_sec: int = 120,
        replay_window_sec: int = 30,
    ) -> None:
        self.plc_host = plc_host
        self.plc_port = plc_port
        self.credentials = credentials
        self.profile = profile
        self.policy_mode = policy_mode
        self.listen_host = listen_host
        self.listen_port = listen_port
        self.rate_limit_per_sec = rate_limit_per_sec
        self.replay_window_sec = replay_window_sec
        self.decisions: list[GatewayDecision] = []
        self._buckets: dict[str, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._sock: socket.socket | None = None
        self._thread: threading.Thread | None = None

    def _record(self, client_id: str, role: str, fc: int, allowed: bool, reason: str, latency_ms: float) -> None:
        with self._lock:
            # Never log raw keys or MACs
            self.decisions.append(
                GatewayDecision(
                    timestamp=datetime.now(timezone.utc).isoformat(),
                    client_id=client_id,
                    role=role,
                    function_code=fc,
                    allowed=allowed,
                    reason=reason,
                    policy_mode=self.policy_mode,
                    latency_ms=round(latency_ms, 3),
                )
            )

    def _query_plc_mode(self) -> int:
        """Query Holding Register 1 (operating_mode) from the internal PLC for process-aware checks."""
        req = ModbusFrame(0xBEEF, 0, 1, struct.pack(">BHH", 0x03, 1, 1)).to_bytes()
        resp = self._forward_raw(req)
        if len(resp) >= 11 and resp[7] == 0x03:
            return struct.unpack(">H", resp[9:11])[0]
        return int(OperatingMode.OBSERVING)

    def _forward_raw(self, raw_frame: bytes) -> bytes:
        with socket.create_connection((self.plc_host, self.plc_port), timeout=2.0) as s:
            s.settimeout(2.0)
            s.sendall(raw_frame)
            framer = ModbusStreamFramer()
            while True:
                chunk = s.recv(1024)
                if not chunk:
                    raise OSError("PLC closed connection without response.")
                frames = framer.feed(chunk)
                if frames:
                    return frames[0].to_bytes()

    def evaluate_frame(self, client_id: str, role: str, frame: ModbusFrame) -> tuple[bool, int, str]:
        spec = PROFILES.get(self.profile, PROFILES["observatory"])
        fc = frame.function_code
        pdu = frame.pdu

        # Default-deny: only explicitly allowed function codes
        if fc in (0x01, 0x03, 0x04):
            return True, 0, "Authorized read telemetry."

        if fc not in (0x05, 0x06):
            return False, EXC_ILLEGAL_FUNCTION, f"Default-deny blocked unsupported/diagnostic FC 0x{fc:02X}."

        if role == "MONITOR":
            return False, EXC_SERVER_DEVICE_FAILURE, f"Role MONITOR is read-only; write FC 0x{fc:02X} denied."

        if len(pdu) != 5:
            return False, EXC_ILLEGAL_DATA_VALUE, "Malformed write PDU length."

        addr, val = struct.unpack(">HH", pdu[1:5])

        # Basic protocol-only tier stops here (only checks register bounds & static syntax)
        if self.policy_mode == "protocol_only":
            if fc == 0x06 and addr == 0 and val > spec["max_rpm_physical"]:
                return False, EXC_ILLEGAL_DATA_VALUE, "Protocol limit exceeded."
            return True, 0, "Allowed by basic protocol filter."

        # Process-aware enforcement tier (original contribution)
        current_mode = self._query_plc_mode()

        if fc == 0x05:
            if addr == 0 and val == 0x0000 and current_mode == int(OperatingMode.OBSERVING):
                return (
                    False,
                    EXC_SERVER_DEVICE_FAILURE,
                    "PROCESS_SAFETY_BLOCK: Refused pump shutdown (Coil 0=OFF) while system is in OBSERVING mode.",
                )
            if addr not in (0, 1):
                return False, EXC_ILLEGAL_DATA_ADDRESS, f"Unauthorized coil address {addr}."
            return True, 0, f"Authorized coil write (addr={addr}, val=0x{val:04X})."

        if fc == 0x06:
            if addr == 0:  # Pump speed RPM
                if val > spec["max_rpm_safe"]:
                    return (
                        False,
                        EXC_ILLEGAL_DATA_VALUE,
                        f"PROCESS_SAFETY_BLOCK: RPM {val} exceeds safe operational ceiling ({spec['max_rpm_safe']} RPM).",
                    )
                if current_mode == int(OperatingMode.OBSERVING) and val < spec["min_rpm_active"]:
                    return (
                        False,
                        EXC_ILLEGAL_DATA_VALUE,
                        f"PROCESS_SAFETY_BLOCK: RPM {val} below minimum cooling threshold ({spec['min_rpm_active']} RPM) during OBSERVING mode.",
                    )
                return True, 0, f"Authorized safe RPM setpoint ({val} RPM)."
            if addr == 1:  # Operating mode transition
                if role != "MAINTENANCE" and val == int(OperatingMode.MAINTENANCE):
                    return False, EXC_SERVER_DEVICE_FAILURE, "Only MAINTENANCE role may transition to MAINTENANCE mode."
                if val > 3:
                    return False, EXC_ILLEGAL_DATA_VALUE, f"Invalid operating mode {val}."
                return True, 0, f"Authorized mode change to {OperatingMode(val).name}."
            return False, EXC_ILLEGAL_DATA_ADDRESS, f"Unauthorized holding register {addr}."

        return False, EXC_ILLEGAL_FUNCTION, "Default-deny fallback."

    def process_envelope(self, raw_envelope: bytes) -> bytes:
        t0 = time.perf_counter()
        try:
            ts, cid, mac, raw_modbus = parse_auth_envelope(raw_envelope)
        except ValueError as exc:
            self._record("unknown", "NONE", -1, False, f"AUTH_ENVELOPE_ERROR: {exc}", (time.perf_counter() - t0) * 1000)
            return build_exception_frame(0, 1, 0, EXC_SERVER_DEVICE_FAILURE)

        cred = self.credentials.get(cid)
        if not cred:
            self._record(cid, "UNKNOWN", -1, False, "AUTH_FAIL: Unknown client identity.", (time.perf_counter() - t0) * 1000)
            return build_exception_frame(0, 1, 0, EXC_SERVER_DEVICE_FAILURE)

        if abs(int(time.time()) - ts) > self.replay_window_sec:
            self._record(cid, cred.role, -1, False, "AUTH_FAIL: Timestamp outside replay window.", (time.perf_counter() - t0) * 1000)
            return build_exception_frame(0, 1, 0, EXC_SERVER_DEVICE_FAILURE)

        cid_b = cid.encode("utf-8")
        expected_mac = hmac.new(cred.secret_key, struct.pack(">QB", ts, len(cid_b)) + cid_b + raw_modbus, hashlib.sha256).digest()
        if not hmac.compare_digest(mac, expected_mac):
            self._record(cid, cred.role, -1, False, "AUTH_FAIL: Invalid HMAC-SHA256 signature.", (time.perf_counter() - t0) * 1000)
            return build_exception_frame(0, 1, 0, EXC_SERVER_DEVICE_FAILURE)

        # Sliding-window rate limit per client
        now = time.monotonic()
        with self._lock:
            q = self._buckets[cid]
            while q and now - q[0] > 1.0:
                q.popleft()
            if len(q) >= self.rate_limit_per_sec:
                self._record(cid, cred.role, -1, False, "RATE_LIMIT: Exceeded client request rate.", (time.perf_counter() - t0) * 1000)
                return build_exception_frame(0, 1, 0, EXC_SERVER_DEVICE_FAILURE)
            q.append(now)

        framer = ModbusStreamFramer()
        try:
            frames = framer.feed(raw_modbus)
            if len(frames) != 1:
                raise ValueError("Expected single complete Modbus ADU per authenticated envelope.")
            frame = frames[0]
        except ValueError as exc:
            self._record(cid, cred.role, -1, False, f"PROTOCOL_MALFORMED: {exc}", (time.perf_counter() - t0) * 1000)
            return build_exception_frame(0, 1, 0, EXC_ILLEGAL_DATA_VALUE)

        allowed, exc_code, reason = self.evaluate_frame(cid, cred.role, frame)
        if not allowed:
            self._record(cid, cred.role, frame.function_code, False, reason, (time.perf_counter() - t0) * 1000)
            return build_exception_frame(frame.transaction_id, frame.unit_id, frame.function_code, exc_code)

        resp = self._forward_raw(frame.to_bytes())
        self._record(cid, cred.role, frame.function_code, True, reason, (time.perf_counter() - t0) * 1000)
        return resp

    def _handle_conn(self, conn: socket.socket) -> None:
        conn.settimeout(3.0)
        try:
            buf = conn.recv(4096)
            if buf:
                resp = self.process_envelope(buf)
                conn.sendall(resp)
        except OSError:
            pass
        finally:
            conn.close()

    def start(self) -> int:
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((self.listen_host, self.listen_port))
        self.listen_port = self._sock.getsockname()[1]
        self._sock.listen(32)
        self._sock.settimeout(0.5)
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()
        return self.listen_port

    def _loop(self) -> None:
        assert self._sock is not None
        while not self._stop.is_set():
            try:
                conn, _ = self._sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(target=self._handle_conn, args=(conn,), daemon=True).start()

    def stop(self) -> None:
        self._stop.set()
        if self._sock:
            try:
                self._sock.close()
            except OSError:
                pass
        if self._thread:
            self._thread.join(timeout=2.0)
