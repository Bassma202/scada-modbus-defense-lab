"""
Unit & Integration Tests for SCADA Modbus Security Gateway & Pump Simulator
Compatible with pytest and standard python unittest.
"""

import struct
import unittest
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.pump_simulator import IndustrialPump
from src.security_gateway import ModbusSecurityGateway

class TestModbusSecurity(unittest.TestCase):
    def test_pump_initial_state(self):
        pump = IndustrialPump()
        self.assertEqual(pump.power_state, 1)
        self.assertEqual(pump.speed_rpm, 1450)
        self.assertEqual(pump.pressure_psi, 65)

    def test_modbus_pdu_read_holding_registers(self):
        pump = IndustrialPump()
        pdu = struct.pack(">B HH", 0x03, 0, 1)
        resp = pump.handle_modbus_pdu(pdu)
        self.assertEqual(resp[0], 0x03)
        self.assertEqual(resp[1], 2)
        speed = struct.unpack(">H", resp[2:4])[0]
        self.assertEqual(speed, 1450)

    def test_modbus_pdu_write_valid_speed(self):
        pump = IndustrialPump()
        pdu = struct.pack(">B HH", 0x06, 0, 2200)
        resp = pump.handle_modbus_pdu(pdu)
        self.assertEqual(resp[0], 0x06)
        self.assertEqual(pump.speed_rpm, 2200)

    def test_gateway_dpi_blocks_overspeed(self):
        gw = ModbusSecurityGateway()
        pdu = struct.pack(">B HH", 0x06, 0, 4500)
        allowed, reason = gw.inspect_and_filter(pdu, token="OPERATOR-SEC-TOKEN-42")
        self.assertFalse(allowed)
        self.assertIn("SAFETY_POLICY_VIOLATION", reason)

    def test_gateway_dpi_allows_safe_speed(self):
        gw = ModbusSecurityGateway()
        pdu = struct.pack(">B HH", 0x06, 0, 2500)
        allowed, reason = gw.inspect_and_filter(pdu, token="OPERATOR-SEC-TOKEN-42")
        self.assertTrue(allowed)
        self.assertEqual(reason, "ALLOWED")

    def test_gateway_blocks_read_only_token_writes(self):
        gw = ModbusSecurityGateway()
        pdu = struct.pack(">B HH", 0x06, 0, 1500)
        allowed, reason = gw.inspect_and_filter(pdu, token="MONITOR-SEC-TOKEN-99")
        self.assertFalse(allowed)
        self.assertIn("AUTHORIZATION_DENIED", reason)

if __name__ == "__main__":
    unittest.main()
