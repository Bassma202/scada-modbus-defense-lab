"""AETHER Process-Aware Zero-Trust Modbus Security Gateway (Remediated AETHER-01 through AETHER-05).

Security & concurrency architecture:
- AETHER-01: Dedicated non-overlapping locks (_rate_lock, _replay_lock, _decisions_lock, _policy_tx_lock);
  logging NEVER reacquires a held lock.
- AETHER-02: Explicit bounded TCP envelope stream framer handling byte-level fragmentation, coalesced
  messages, max frame lengths, timeouts, and truncated/malformed streams without hanging.
- AETHER-03: Authenticated 16-byte unique request nonce covered by HMAC-SHA256 + atomic bounded replay
  cache rejecting duplicate requests even within the clock-skew window.
- AETHER-04: Explicit default-deny RBAC and register-range authorization matrix for BOTH reads and writes;
  unknown roles, invalid addresses, and boundary-spanning ranges are rejected.
- AETHER-05: Serialized gateway policy-check + PLC forwarding failing closed when PLC state is unavailable,
  paired with authoritative synchronized PLC-boundary interlocks in ProcessState.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import socket
import struct
import threading
import time
from collections import OrderedDict, defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timezone

from aether.modbus import (
    EXC_ILLEGAL_DATA_ADDRESS,
    EXC_ILLEGAL_DATA_VALUE,
    EXC_ILLEGAL_FUNCTION,
    EXC_SERVER_DEVICE_FAILURE,
    ModbusFrame,
    ModbusStreamFramer,
    build_exception_frame,
)
from aether.process import PROFILES, OperatingMode

ENVELOPE_MAGIC = b"AETH"
NONCE_LEN = 16
MAX_CID_LEN = 64
MAX_MODBUS_FRAME_LEN = 260
MAX_ENVELOPE_BYTES = 4 + 8 + NONCE_LEN + 1 + MAX_CID_LEN + 32 + 2 + MAX_MODBUS_FRAME_LEN

VALID_ROLES = frozenset({"MONITOR", "OPERATOR", "MAINTENANCE"})

# Explicit register address spaces (start inclusive, end exclusive)
REGISTER_BOUNDS: dict[int, tuple[int, int]] = {
    0x01: (0, 2),  # Coils: 0=pump_power, 1=ventilation_open
    0x03: (0, 2),  # Holding Registers: 0=target_rpm, 1=operating_mode
    0x04: (0, 4),  # Input Registers: 0=pressure, 1=temp*10, 2=flow, 3=alarm
}

# Explicit default-deny role -> permitted function codes
ROLE_ALLOWED_FCS: dict[str, frozenset[int]] = {
    "MONITOR": frozenset({0x01, 0x03, 0x04}),
    "OPERATOR": frozenset({0x01, 0x03, 0x04, 0x05, 0x06}),
    "MAINTENANCE": frozenset({0x01, 0x03, 0x04, 0x05, 0x06}),
}


@dataclass
class ClientCredential:
    client_id: str
    role: str  # MONITOR | OPERATOR | MAINTENANCE
    secret_key: bytes


def build_auth_envelope(
    client_id: str,
    secret_key: bytes,
    modbus_frame: bytes,
    ts: int | None = None,
    nonce: bytes | None = None,
) -> bytes:
    """Wrap a raw Modbus TCP frame in an HMAC-SHA256 authenticated envelope with unique 16-byte nonce.

    Wire format:
      MAGIC(4='AETH') | ts(8 uint64) | nonce(16) | cid_len(1) | cid | mac(32) | frame_len(2) | frame
    """
    timestamp = int(time.time()) if ts is None else ts
    req_nonce = secrets.token_bytes(NONCE_LEN) if nonce is None else nonce
    if len(req_nonce) != NONCE_LEN:
        raise ValueError(f"Nonce must be exactly {NONCE_LEN} bytes.")
    cid_b = client_id.encode("utf-8")
    if not (1 <= len(cid_b) <= MAX_CID_LEN):
        raise ValueError(f"client_id length must be 1..{MAX_CID_LEN} bytes.")
    if len(modbus_frame) > MAX_MODBUS_FRAME_LEN:
        raise ValueError(f"Modbus frame exceeds maximum length {MAX_MODBUS_FRAME_LEN}.")

    signed_body = struct.pack(">Q", timestamp) + req_nonce + struct.pack(">B", len(cid_b)) + cid_b + struct.pack(">H", len(modbus_frame)) + modbus_frame
    mac = hmac.new(secret_key, signed_body, hashlib.sha256).digest()
    return ENVELOPE_MAGIC + struct.pack(">Q", timestamp) + req_nonce + struct.pack(">B", len(cid_b)) + cid_b + mac + struct.pack(">H", len(modbus_frame)) + modbus_frame


def parse_auth_envelope(data: bytes) -> tuple[int, bytes, str, bytes, bytes]:
    min_hdr = 4 + 8 + NONCE_LEN + 1
    if len(data) < min_hdr + 32 + 2 or not data.startswith(ENVELOPE_MAGIC):
        raise ValueError("Malformed AETHER authentication envelope.")
    ts = struct.unpack(">Q", data[4:12])[0]
    nonce = data[12 : 12 + NONCE_LEN]
    cid_len = data[12 + NONCE_LEN]
    if not (1 <= cid_len <= MAX_CID_LEN):
        raise ValueError(f"Invalid client_id length: {cid_len}")
    cid_start = 13 + NONCE_LEN
    cid_end = cid_start + cid_len
    if len(data) < cid_end + 32 + 2:
        raise ValueError("Truncated AETHER authentication envelope.")
    cid = data[cid_start:cid_end].decode("utf-8", errors="strict")
    mac = data[cid_end : cid_end + 32]
    frame_len = struct.unpack(">H", data[cid_end + 32 : cid_end + 34])[0]
    if frame_len == 0 or frame_len > MAX_MODBUS_FRAME_LEN:
        raise ValueError(f"Invalid embedded Modbus frame length: {frame_len}")
    total_expected = cid_end + 34 + frame_len
    if len(data) != total_expected:
        raise ValueError("Incomplete or trailing bytes in AETHER envelope.")
    frame = data[cid_end + 34 : total_expected]
    return ts, nonce, cid, mac, frame


class AuthEnvelopeStreamFramer:
    """Bounded TCP stream framer reassembling complete AETHER envelopes across partial or coalesced reads."""

    def __init__(self, max_buffer_bytes: int = 8192) -> None:
        self._buf = bytearray()
        self.max_buffer_bytes = max_buffer_bytes

    def feed(self, chunk: bytes) -> list[bytes]:
        if len(self._buf) + len(chunk) > self.max_buffer_bytes:
            self._buf.clear()
            raise ValueError("Envelope TCP buffer limit exceeded.")
        self._buf.extend(chunk)
        messages: list[bytes] = []

        while True:
            if len(self._buf) < 4:
                break
            if bytes(self._buf[:4]) != ENVELOPE_MAGIC:
                self._buf.clear()
                raise ValueError("Invalid AETHER envelope magic header.")
            min_hdr = 13 + NONCE_LEN
            if len(self._buf) < min_hdr:
                break
            cid_len = self._buf[12 + NONCE_LEN]
            if not (1 <= cid_len <= MAX_CID_LEN):
                self._buf.clear()
                raise ValueError(f"Invalid client_id length: {cid_len}")
            len_offset = min_hdr + cid_len + 32
            if len(self._buf) < len_offset + 2:
                break
            frame_len = struct.unpack(">H", self._buf[len_offset : len_offset + 2])[0]
            if frame_len == 0 or frame_len > MAX_MODBUS_FRAME_LEN:
                self._buf.clear()
                raise ValueError(f"Invalid Modbus frame length in envelope: {frame_len}")
            total_len = len_offset + 2 + frame_len
            if total_len > MAX_ENVELOPE_BYTES:
                self._buf.clear()
                raise ValueError("Envelope exceeds maximum allowed size.")
            if len(self._buf) < total_len:
                break
            messages.append(bytes(self._buf[:total_len]))
            del self._buf[:total_len]

        return messages

    @property
    def has_pending_bytes(self) -> bool:
        return len(self._buf) > 0


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
        max_replay_cache_entries: int = 10000,
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
        self.max_replay_cache_entries = max_replay_cache_entries

        self.decisions: deque[GatewayDecision] = deque(maxlen=5000)
        self._buckets: dict[str, deque[float]] = defaultdict(deque)
        self._seen_nonces: OrderedDict[tuple[str, bytes], float] = OrderedDict()

        # Separate non-overlapping locks to guarantee zero recursive lock acquisition (AETHER-01)
        self._rate_lock = threading.Lock()
        self._replay_lock = threading.Lock()
        self._decisions_lock = threading.Lock()
        self._policy_tx_lock = threading.Lock()

        self._stop = threading.Event()
        self._sock: socket.socket | None = None
        self._thread: threading.Thread | None = None

    def _record(self, client_id: str, role: str, fc: int, allowed: bool, reason: str, latency_ms: float) -> None:
        entry = GatewayDecision(
            timestamp=datetime.now(timezone.utc).isoformat(),
            client_id=client_id,
            role=role,
            function_code=fc,
            allowed=allowed,
            reason=reason,
            policy_mode=self.policy_mode,
            latency_ms=round(latency_ms, 3),
        )
        with self._decisions_lock:
            self.decisions.append(entry)

    def _check_and_record_replay(self, client_id: str, nonce: bytes, now_wall: float) -> bool:
        """Atomically verify (client_id, nonce) uniqueness with bounded retention (AETHER-03)."""
        key = (client_id, nonce)
        expiry = now_wall + self.replay_window_sec + 5.0
        with self._replay_lock:
            # Prune expired entries from oldest end
            while self._seen_nonces:
                oldest_key, oldest_exp = next(iter(self._seen_nonces.items()))
                if oldest_exp < now_wall:
                    self._seen_nonces.pop(oldest_key)
                else:
                    break
            if key in self._seen_nonces:
                return False
            while len(self._seen_nonces) >= self.max_replay_cache_entries:
                self._seen_nonces.popitem(last=False)
            self._seen_nonces[key] = expiry
            return True

    def _check_rate_limit(self, client_id: str) -> bool:
        """Atomically check sliding-window per-client rate limit without calling _record while locked (AETHER-01)."""
        now = time.monotonic()
        with self._rate_lock:
            q = self._buckets[client_id]
            while q and now - q[0] > 1.0:
                q.popleft()
            if len(q) >= self.rate_limit_per_sec:
                return False
            q.append(now)
            return True

    def _query_plc_mode(self) -> int:
        """Query Holding Register 1 (operating_mode) from the internal PLC; fail closed on communication error."""
        req = ModbusFrame(0xBEEF, 0, 1, struct.pack(">BHH", 0x03, 1, 1)).to_bytes()
        resp = self._forward_raw(req)
        if len(resp) >= 11 and resp[7] == 0x03:
            return int(struct.unpack(">H", resp[9:11])[0])
        raise OSError("Unexpected PLC response when querying operating_mode.")

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

    def evaluate_frame(self, client_id: str, role: str, frame: ModbusFrame, current_mode: int | None = None) -> tuple[bool, int, str]:
        """Default-deny authorization across role, function code, register range, and physical process state (AETHER-04)."""
        if role not in VALID_ROLES:
            return False, EXC_SERVER_DEVICE_FAILURE, f"Default-deny rejected unrecognized role '{role}'."

        spec = PROFILES.get(self.profile, PROFILES["observatory"])
        fc = frame.function_code
        pdu = frame.pdu

        allowed_fcs = ROLE_ALLOWED_FCS.get(role, frozenset())
        if fc not in allowed_fcs:
            if fc in (0x05, 0x06):
                return False, EXC_SERVER_DEVICE_FAILURE, f"Role {role} is not authorized for write FC 0x{fc:02X}."
            return False, EXC_ILLEGAL_FUNCTION, f"Default-deny blocked unsupported/unauthorized FC 0x{fc:02X}."

        if len(pdu) != 5:
            return False, EXC_ILLEGAL_DATA_VALUE, f"Malformed PDU length ({len(pdu)}) for FC 0x{fc:02X}."

        # Explicit read register-range validation (reads are NOT automatically permitted)
        if fc in (0x01, 0x03, 0x04):
            addr, qty = struct.unpack(">HH", pdu[1:5])
            min_addr, max_excl = REGISTER_BOUNDS[fc]
            if qty == 0 or addr < min_addr or addr + qty > max_excl:
                return (
                    False,
                    EXC_ILLEGAL_DATA_ADDRESS,
                    f"Unauthorized/out-of-bounds read range for FC 0x{fc:02X}: addr={addr}, qty={qty} (allowed {min_addr}..{max_excl - 1}).",
                )
            return True, 0, f"Authorized read telemetry (FC 0x{fc:02X}, addr={addr}, qty={qty})."

        addr, val = struct.unpack(">HH", pdu[1:5])

        # Basic protocol-only tier stops at static bounds
        if self.policy_mode == "protocol_only":
            if fc == 0x05 and addr not in (0, 1):
                return False, EXC_ILLEGAL_DATA_ADDRESS, f"Unauthorized coil address {addr}."
            if fc == 0x06 and addr not in (0, 1):
                return False, EXC_ILLEGAL_DATA_ADDRESS, f"Unauthorized holding register {addr}."
            if fc == 0x06 and addr == 0 and val > spec["max_rpm_physical"]:
                return False, EXC_ILLEGAL_DATA_VALUE, "Protocol limit exceeded."
            return True, 0, "Allowed by basic protocol filter."

        # Process-aware enforcement tier
        if current_mode is None:
            try:
                current_mode = self._query_plc_mode()
            except OSError as exc:
                return False, EXC_SERVER_DEVICE_FAILURE, f"FAIL_CLOSED: Unable to query PLC process state ({exc})."

        if fc == 0x05:
            if addr not in (0, 1):
                return False, EXC_ILLEGAL_DATA_ADDRESS, f"Unauthorized coil address {addr}."
            if val not in (0x0000, 0xFF00):
                return False, EXC_ILLEGAL_DATA_VALUE, f"Invalid Modbus coil value 0x{val:04X}."
            if addr == 0 and val == 0x0000 and current_mode == int(OperatingMode.OBSERVING):
                return (
                    False,
                    EXC_SERVER_DEVICE_FAILURE,
                    "PROCESS_SAFETY_BLOCK: Refused pump shutdown (Coil 0=OFF) while system is in OBSERVING mode.",
                )
            return True, 0, f"Authorized coil write (addr={addr}, val=0x{val:04X})."

        if fc == 0x06:
            if addr == 0:
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
            if addr == 1:
                if role != "MAINTENANCE" and val == int(OperatingMode.MAINTENANCE):
                    return False, EXC_SERVER_DEVICE_FAILURE, "Only MAINTENANCE role may transition to MAINTENANCE mode."
                if val not in (0, 1, 2, 3):
                    return False, EXC_ILLEGAL_DATA_VALUE, f"Invalid operating mode {val}."
                return True, 0, f"Authorized mode change to {OperatingMode(val).name}."
            return False, EXC_ILLEGAL_DATA_ADDRESS, f"Unauthorized holding register {addr}."

        return False, EXC_ILLEGAL_FUNCTION, "Default-deny fallback."

    def process_envelope(self, raw_envelope: bytes) -> bytes:
        t0 = time.perf_counter()
        try:
            ts, nonce, cid, mac, raw_modbus = parse_auth_envelope(raw_envelope)
        except ValueError as exc:
            self._record("unknown", "NONE", -1, False, f"AUTH_ENVELOPE_ERROR: {exc}", (time.perf_counter() - t0) * 1000)
            return build_exception_frame(0, 1, 0, EXC_SERVER_DEVICE_FAILURE)

        cred = self.credentials.get(cid)
        if not cred:
            self._record(cid, "UNKNOWN", -1, False, "AUTH_FAIL: Unknown client identity.", (time.perf_counter() - t0) * 1000)
            return build_exception_frame(0, 1, 0, EXC_SERVER_DEVICE_FAILURE)

        now_wall = time.time()
        if abs(int(now_wall) - ts) > self.replay_window_sec:
            self._record(cid, cred.role, -1, False, "AUTH_FAIL: Timestamp outside replay window.", (time.perf_counter() - t0) * 1000)
            return build_exception_frame(0, 1, 0, EXC_SERVER_DEVICE_FAILURE)

        cid_b = cid.encode("utf-8")
        signed_body = struct.pack(">Q", ts) + nonce + struct.pack(">B", len(cid_b)) + cid_b + struct.pack(">H", len(raw_modbus)) + raw_modbus
        expected_mac = hmac.new(cred.secret_key, signed_body, hashlib.sha256).digest()
        if not hmac.compare_digest(mac, expected_mac):
            self._record(cid, cred.role, -1, False, "AUTH_FAIL: Invalid HMAC-SHA256 signature.", (time.perf_counter() - t0) * 1000)
            return build_exception_frame(0, 1, 0, EXC_SERVER_DEVICE_FAILURE)

        # Atomic uniqueness check (AETHER-03)
        if not self._check_and_record_replay(cid, nonce, now_wall):
            self._record(cid, cred.role, -1, False, "AUTH_FAIL: Duplicate authenticated nonce replay rejected.", (time.perf_counter() - t0) * 1000)
            return build_exception_frame(0, 1, 0, EXC_SERVER_DEVICE_FAILURE)

        # Rate limit check — lock released BEFORE _record() (AETHER-01)
        if not self._check_rate_limit(cid):
            self._record(cid, cred.role, -1, False, "RATE_LIMIT: Exceeded client request rate.", (time.perf_counter() - t0) * 1000)
            return build_exception_frame(0, 1, 0, EXC_SERVER_DEVICE_FAILURE)

        framer = ModbusStreamFramer()
        try:
            frames = framer.feed(raw_modbus)
            if len(frames) != 1 or framer._buf:
                raise ValueError("Expected single complete Modbus ADU per authenticated envelope.")
            frame = frames[0]
        except ValueError as exc:
            self._record(cid, cred.role, -1, False, f"PROTOCOL_MALFORMED: {exc}", (time.perf_counter() - t0) * 1000)
            return build_exception_frame(0, 1, 0, EXC_ILLEGAL_DATA_VALUE)

        # Serialize state-query -> policy evaluation -> PLC write to eliminate gateway TOCTOU race (AETHER-05)
        with self._policy_tx_lock:
            allowed, exc_code, reason = self.evaluate_frame(cid, cred.role, frame)
            if not allowed:
                resp = build_exception_frame(frame.transaction_id, frame.unit_id, frame.function_code, exc_code)
            else:
                try:
                    resp = self._forward_raw(frame.to_bytes())
                except OSError as exc:
                    allowed = False
                    reason = f"PLC_COMM_ERROR: {exc}"
                    resp = build_exception_frame(frame.transaction_id, frame.unit_id, frame.function_code, EXC_SERVER_DEVICE_FAILURE)

        self._record(cid, cred.role, frame.function_code, allowed, reason, (time.perf_counter() - t0) * 1000)
        return resp

    def _handle_conn(self, conn: socket.socket) -> None:
        """Process full TCP stream with bounded framing, handling fragmentation and coalesced envelopes (AETHER-02)."""
        conn.settimeout(3.0)
        framer = AuthEnvelopeStreamFramer()
        try:
            while not self._stop.is_set():
                chunk = conn.recv(2048)
                if not chunk:
                    if framer.has_pending_bytes:
                        self._record("unknown", "NONE", -1, False, "TCP_TRUNCATED_ENVELOPE", 0.0)
                    break
                try:
                    envelopes = framer.feed(chunk)
                except ValueError as exc:
                    self._record("unknown", "NONE", -1, False, f"TCP_FRAMING_ERROR: {exc}", 0.0)
                    conn.sendall(build_exception_frame(0, 1, 0, EXC_ILLEGAL_DATA_VALUE))
                    break
                for env in envelopes:
                    resp = self.process_envelope(env)
                    conn.sendall(resp)
        except (TimeoutError, socket.timeout, OSError):
            pass
        finally:
            conn.close()

    def start(self) -> int:
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((self.listen_host, self.listen_port))
        self.listen_port = self._sock.getsockname()[1]
        self._sock.listen(64)
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
