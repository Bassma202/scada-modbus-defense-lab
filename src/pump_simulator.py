"""
Industrial Pump Simulator (Modbus TCP Slave)
Simulates an industrial water pumping station with physical bounds:
- Coil 0: Pump Power State (0 = OFF, 1 = ON)
- Holding Register 0: Target Pump Speed (RPM, 0 - 3000)
- Input Register 0: Current System Pressure (PSI, 0 - 150)
- Input Register 1: Motor Core Temperature (°C, 20 - 120)
"""

import socket
import struct
import threading
import time
import logging

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("PumpSimulator")

class IndustrialPump:
    def __init__(self, host="0.0.0.0", port=5020):
        self.host = host
        self.port = port
        self.is_running = True
        
        # State registers
        self.power_state = 1        # Coil 0: 1 = ON
        self.speed_rpm = 1450       # Holding Reg 0: Normal operating speed (RPM)
        self.pressure_psi = 65      # Input Reg 0: Operating pressure (PSI)
        self.temperature_c = 45     # Input Reg 1: Motor temp (°C)
        self.lock = threading.Lock()

    def update_physics(self):
        """Background physics loop simulating physical pump feedback."""
        while self.is_running:
            with self.lock:
                if self.power_state == 1:
                    # Pressure correlates with RPM
                    target_pressure = int((self.speed_rpm / 3000.0) * 120.0)
                    self.pressure_psi = max(10, min(140, target_pressure))
                    
                    # High RPM causes overheating
                    if self.speed_rpm > 2800:
                        self.temperature_c = min(115, self.temperature_c + 1)
                    else:
                        self.temperature_c = max(35, self.temperature_c - 1)
                else:
                    self.speed_rpm = 0
                    self.pressure_psi = 5
                    self.temperature_c = max(22, self.temperature_c - 1)
            time.sleep(1.0)

    def handle_modbus_pdu(self, pdu):
        """
        Parses Modbus PDU and returns response PDU.
        Supports:
        - 0x01: Read Coils
        - 0x03: Read Holding Registers
        - 0x04: Read Input Registers
        - 0x05: Write Single Coil
        - 0x06: Write Single Register
        """
        if len(pdu) < 1:
            return b"\x80\x01" # Exception
            
        function_code = pdu[0]
        
        with self.lock:
            if function_code == 0x01: # Read Coils
                # Byte 1-2: starting addr, Byte 3-4: quantity
                return bytes([0x01, 0x01, self.power_state])
                
            elif function_code == 0x03: # Read Holding Registers (Speed)
                # Response: Function Code (1 byte), Byte count (1 byte), Value (2 bytes)
                return struct.pack(">BBH", 0x03, 2, self.speed_rpm)
                
            elif function_code == 0x04: # Read Input Registers (Pressure, Temp)
                return struct.pack(">BBHH", 0x04, 4, self.pressure_psi, self.temperature_c)
                
            elif function_code == 0x05: # Write Single Coil
                if len(pdu) >= 5:
                    addr, val = struct.unpack(">HH", pdu[1:5])
                    if addr == 0:
                        self.power_state = 1 if val == 0xFF00 else 0
                        logger.info(f"Coil 0 updated -> Power State: {'ON' if self.power_state else 'OFF'}")
                        return pdu # Echoes written command on success
                        
            elif function_code == 0x06: # Write Single Register (Speed)
                if len(pdu) >= 5:
                    addr, val = struct.unpack(">HH", pdu[1:5])
                    if addr == 0:
                        self.speed_rpm = val
                        logger.warning(f"[ALERT] Holding Register 0 modified! New Speed: {self.speed_rpm} RPM")
                        if self.speed_rpm > 3000:
                            logger.error(f"[DANGER] PUMP OVERSPEED: {self.speed_rpm} RPM exceeds safety threshold (3000 RPM)!")
                        return pdu # Echoes written command
                        
        # Default exception: Illegal Function
        return bytes([function_code | 0x80, 0x01])

    def start(self):
        physics_thread = threading.Thread(target=self.update_physics, daemon=True)
        physics_thread.start()
        
        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_sock.bind((self.host, self.port))
        server_sock.listen(5)
        logger.info(f"Industrial Pump Modbus TCP Server running on {self.host}:{self.port}")
        
        try:
            while self.is_running:
                client_sock, addr = server_sock.accept()
                logger.info(f"Connected to client: {addr}")
                client_handler = threading.Thread(target=self._handle_client, args=(client_sock,))
                client_handler.start()
        except KeyboardInterrupt:
            logger.info("Stopping pump simulator...")
        finally:
            self.is_running = False
            server_sock.close()

    def _handle_client(self, client_sock):
        try:
            while self.is_running:
                # Modbus TCP Header (MBAP): 7 bytes
                # Transaction ID (2B), Protocol ID (2B), Length (2B), Unit ID (1B)
                header = client_sock.recv(7)
                if not header or len(header) < 7:
                    break
                
                trans_id, proto_id, length, unit_id = struct.unpack(">HHHB", header)
                pdu_len = length - 1
                pdu = client_sock.recv(pdu_len)
                
                response_pdu = self.handle_modbus_pdu(pdu)
                resp_length = len(response_pdu) + 1
                resp_header = struct.pack(">HHHB", trans_id, proto_id, resp_length, unit_id)
                client_sock.sendall(resp_header + response_pdu)
        except Exception as e:
            logger.debug(f"Client disconnected: {e}")
        finally:
            client_sock.close()

if __name__ == "__main__":
    pump = IndustrialPump()
    pump.start()
