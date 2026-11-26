"""Strict Modbus TCP MBAP framing, stream reassembly, and simulated PLC server."""

from __future__ import annotations

import socket
import struct
import threading
from dataclasses import dataclass

from aether.process import ProcessState

MODBUS_PROTOCOL_ID = 0
MIN_MBAP_LEN = 2
MAX_MBAP_LEN = 253

# Standard Modbus exception codes
EXC_ILLEGAL_FUNCTION = 0x01
EXC_ILLEGAL_DATA_ADDRESS = 0x02
EXC_ILLEGAL_DATA_VALUE = 0x03
EXC_SERVER_DEVICE_FAILURE = 0x04


@dataclass
class ModbusFrame:
    transaction_id: int
    protocol_id: int
    unit_id: int
    pdu: bytes

    def to_bytes(self) -> bytes:
        length = 1 + len(self.pdu)
        return struct.pack(">HHHB", self.transaction_id, self.protocol_id, length, self.unit_id) + self.pdu

    @property
    def function_code(self) -> int:
        return self.pdu[0] if self.pdu else -1


def build_exception_frame(tx_id: int, unit_id: int, fc: int, exc_code: int) -> bytes:
    pdu = struct.pack(">BB", (fc & 0x7F) | 0x80, exc_code)
    return ModbusFrame(tx_id, MODBUS_PROTOCOL_ID, unit_id, pdu).to_bytes()


class ModbusStreamFramer:
    """Reassembles complete Modbus TCP ADUs across fragmented or coalesced TCP reads."""

    def __init__(self, max_buffer_bytes: int = 8192) -> None:
        self._buf = bytearray()
        self.max_buffer_bytes = max_buffer_bytes

    def feed(self, chunk: bytes) -> list[ModbusFrame]:
        if len(self._buf) + len(chunk) > self.max_buffer_bytes:
            self._buf.clear()
            raise ValueError("TCP frame buffer limit exceeded.")
        self._buf.extend(chunk)
        frames: list[ModbusFrame] = []
        while len(self._buf) >= 7:
            tx_id, proto_id, length, unit_id = struct.unpack(">HHHB", self._buf[:7])
            if proto_id != MODBUS_PROTOCOL_ID:
                self._buf.clear()
                raise ValueError(f"Invalid Modbus protocol ID: {proto_id}")
            if length < MIN_MBAP_LEN or length > MAX_MBAP_LEN:
                self._buf.clear()
                raise ValueError(f"Invalid MBAP length field: {length}")
            total_len = 6 + length
            if len(self._buf) < total_len:
                break
            pdu = bytes(self._buf[7:total_len])
            del self._buf[:total_len]
            frames.append(ModbusFrame(tx_id, proto_id, unit_id, pdu))
        return frames


class ModbusPLCServer:
    """Simulated Modbus TCP PLC executing strictly against ProcessState (no native auth, matching real Modbus TCP)."""

    def __init__(self, state: ProcessState, host: str = "127.0.0.1", port: int = 0) -> None:
        self.state = state
        self.host = host
        self.port = port
        self._sock: socket.socket | None = None
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def handle_frame(self, frame: ModbusFrame) -> bytes:
        pdu = frame.pdu
        if not pdu:
            return build_exception_frame(frame.transaction_id, frame.unit_id, 0, EXC_ILLEGAL_FUNCTION)
        fc = pdu[0]

        # FC 0x01: Read Coils
        if fc == 0x01 and len(pdu) == 5:
            addr, qty = struct.unpack(">HH", pdu[1:5])
            coils = [self.state.pump_power, self.state.ventilation_open]
            if addr + qty > len(coils) or qty == 0:
                return build_exception_frame(frame.transaction_id, frame.unit_id, fc, EXC_ILLEGAL_DATA_ADDRESS)
            byte_val = 0
            for idx in range(qty):
                if coils[addr + idx]:
                    byte_val |= 1 << idx
            resp_pdu = struct.pack(">BBB", fc, 1, byte_val)
            return ModbusFrame(frame.transaction_id, 0, frame.unit_id, resp_pdu).to_bytes()

        # FC 0x03: Read Holding Registers (0=target_rpm, 1=operating_mode)
        if fc == 0x03 and len(pdu) == 5:
            addr, qty = struct.unpack(">HH", pdu[1:5])
            regs = [self.state.target_rpm, self.state.operating_mode]
            if addr + qty > len(regs) or qty == 0:
                return build_exception_frame(frame.transaction_id, frame.unit_id, fc, EXC_ILLEGAL_DATA_ADDRESS)
            slice_regs = regs[addr : addr + qty]
            resp_pdu = struct.pack(f">BB{qty}H", fc, qty * 2, *slice_regs)
            return ModbusFrame(frame.transaction_id, 0, frame.unit_id, resp_pdu).to_bytes()

        # FC 0x04: Read Input Registers (0=pressure, 1=temp*10, 2=flow, 3=alarm)
        if fc == 0x04 and len(pdu) == 5:
            self.state.step_physics()
            addr, qty = struct.unpack(">HH", pdu[1:5])
            regs = [self.state.pressure_psi, self.state.temperature_c_x10, self.state.flow_lpm, self.state.alarm_code]
            if addr + qty > len(regs) or qty == 0:
                return build_exception_frame(frame.transaction_id, frame.unit_id, fc, EXC_ILLEGAL_DATA_ADDRESS)
            slice_regs = regs[addr : addr + qty]
            resp_pdu = struct.pack(f">BB{qty}H", fc, qty * 2, *slice_regs)
            return ModbusFrame(frame.transaction_id, 0, frame.unit_id, resp_pdu).to_bytes()

        # FC 0x05: Write Single Coil (0=pump_power, 1=ventilation)
        if fc == 0x05 and len(pdu) == 5:
            addr, val = struct.unpack(">HH", pdu[1:5])
            if val not in (0x0000, 0xFF00):
                return build_exception_frame(frame.transaction_id, frame.unit_id, fc, EXC_ILLEGAL_DATA_VALUE)
            bit = 1 if val == 0xFF00 else 0
            if addr == 0:
                self.state.pump_power = bit
            elif addr == 1:
                self.state.ventilation_open = bit
            else:
                return build_exception_frame(frame.transaction_id, frame.unit_id, fc, EXC_ILLEGAL_DATA_ADDRESS)
            self.state.step_physics()
            return ModbusFrame(frame.transaction_id, 0, frame.unit_id, pdu).to_bytes()

        # FC 0x06: Write Single Register (0=target_rpm, 1=operating_mode)
        if fc == 0x06 and len(pdu) == 5:
            addr, val = struct.unpack(">HH", pdu[1:5])
            if addr == 0:
                if val > self.state.spec()["max_rpm_physical"]:
                    return build_exception_frame(frame.transaction_id, frame.unit_id, fc, EXC_ILLEGAL_DATA_VALUE)
                self.state.target_rpm = val
            elif addr == 1:
                if val > 3:
                    return build_exception_frame(frame.transaction_id, frame.unit_id, fc, EXC_ILLEGAL_DATA_VALUE)
                self.state.operating_mode = val
            else:
                return build_exception_frame(frame.transaction_id, frame.unit_id, fc, EXC_ILLEGAL_DATA_ADDRESS)
            self.state.step_physics()
            return ModbusFrame(frame.transaction_id, 0, frame.unit_id, pdu).to_bytes()

        return build_exception_frame(frame.transaction_id, frame.unit_id, fc, EXC_ILLEGAL_FUNCTION)

    def _serve_client(self, conn: socket.socket) -> None:
        conn.settimeout(5.0)
        framer = ModbusStreamFramer()
        try:
            while not self._stop.is_set():
                data = conn.recv(2048)
                if not data:
                    break
                try:
                    frames = framer.feed(data)
                except ValueError:
                    break
                for fr in frames:
                    conn.sendall(self.handle_frame(fr))
        except OSError:
            pass
        finally:
            conn.close()

    def start(self) -> int:
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((self.host, self.port))
        self.port = self._sock.getsockname()[1]
        self._sock.listen(16)
        self._sock.settimeout(0.5)
        self._thread = threading.Thread(target=self._accept_loop, daemon=True)
        self._thread.start()
        return self.port

    def _accept_loop(self) -> None:
        assert self._sock is not None
        while not self._stop.is_set():
            try:
                conn, _ = self._sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(target=self._serve_client, args=(conn,), daemon=True).start()

    def stop(self) -> None:
        self._stop.set()
        if self._sock:
            try:
                self._sock.close()
            except OSError:
                pass
        if self._thread:
            self._thread.join(timeout=2.0)
