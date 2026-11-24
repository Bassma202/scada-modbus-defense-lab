"""
Authorized Operator Client
Demonstrates normal authorized control operations through the security gateway.
"""

import socket
import struct
import time
import logging

logging.basicConfig(level=logging.INFO, format="%(asctime)s [OPERATOR] %(message)s")
logger = logging.getLogger("OperatorClient")

def send_modbus_read_holding(sock, trans_id=1):
    # Function 0x03: Read holding register 0 (1 register)
    pdu = struct.pack(">B HH", 0x03, 0, 1)
    mbap = struct.pack(">HHHB", trans_id, 0, len(pdu) + 1, 1)
    sock.sendall(mbap + pdu)
    
    resp_mbap = sock.recv(7)
    if resp_mbap:
        _, _, r_len, _ = struct.unpack(">HHHB", resp_mbap)
        resp_pdu = sock.recv(r_len - 1)
        if len(resp_pdu) >= 4 and resp_pdu[0] == 0x03:
            speed = struct.unpack(">H", resp_pdu[2:4])[0]
            logger.info(f"Telemetry Read -> Current Pump Speed: {speed} RPM")
            return speed
    return None

def send_modbus_write_speed(sock, speed_rpm, trans_id=2):
    # Function 0x06: Write holding register 0
    pdu = struct.pack(">B HH", 0x06, 0, speed_rpm)
    mbap = struct.pack(">HHHB", trans_id, 0, len(pdu) + 1, 1)
    sock.sendall(mbap + pdu)
    
    resp_mbap = sock.recv(7)
    if resp_mbap:
        _, _, r_len, _ = struct.unpack(">HHHB", resp_mbap)
        resp_pdu = sock.recv(r_len - 1)
        if resp_pdu[0] == 0x06:
            logger.info(f"Command Acknowledged -> Pump Speed successfully set to {speed_rpm} RPM")
            return True
        elif resp_pdu[0] & 0x80:
            logger.error(f"Command Rejected -> Exception Code: 0x{resp_pdu[1]:02x}")
            return False
    return False

def run_operator_session(gateway_host="127.0.0.1", gateway_port=5021, token="OPERATOR-SEC-TOKEN-42"):
    logger.info(f"Connecting to Security Gateway at {gateway_host}:{gateway_port}...")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((gateway_host, gateway_port))
    
    # 1. Send auth token
    s.sendall(token.encode("utf-8") + b"\n")
    resp = s.recv(64).decode().strip()
    logger.info(f"Handshake Response: {resp}")
    
    if "OK" in resp:
        logger.info("Executing authorized routine maintenance operations...")
        send_modbus_read_holding(s, trans_id=1)
        time.sleep(1)
        
        logger.info("Adjusting operational setpoint to 1800 RPM (within safety limits)...")
        send_modbus_write_speed(s, 1800, trans_id=2)
        time.sleep(1)
        
        send_modbus_read_holding(s, trans_id=3)
        
    s.close()

if __name__ == "__main__":
    run_operator_session()
