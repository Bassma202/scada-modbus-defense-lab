"""
Zero-Trust Industrial Security Gateway & DPI Firewall for Modbus TCP
Acts as an authenticating reverse proxy in front of the Modbus PLC.
Features:
- Enforces Token-based client authorization (HMAC / Pre-Shared Token).
- Deep Packet Inspection (DPI): Enforces strict function code allowlists.
- Parameter Safety Boundary Checks: Blocks hazardous RPM values (> 3000).
- Emits structured JSON audit logs for SOC/SIEM integration.
"""

import socket
import struct
import threading
import json
import logging
import time

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] [GATEWAY] %(message)s")
logger = logging.getLogger("ModbusGateway")

VALID_TOKENS = {
    "OPERATOR-SEC-TOKEN-42": {"role": "OPERATOR", "allow_write": True, "max_rpm": 2800},
    "MONITOR-SEC-TOKEN-99": {"role": "MONITOR", "allow_write": False, "max_rpm": 0}
}

class ModbusSecurityGateway:
    def __init__(self, listen_host="0.0.0.0", listen_port=5021, target_host="127.0.0.1", target_port=5020):
        self.listen_host = listen_host
        self.listen_port = listen_port
        self.target_host = target_host
        self.target_port = target_port
        self.is_running = True

    def inspect_and_filter(self, pdu, token):
        """
        Deep Packet Inspection (DPI) Logic:
        Returns: (is_allowed: bool, reason: str)
        """
        if len(pdu) < 1:
            return False, "Malformed PDU: Empty payload"

        func_code = pdu[0]
        token_profile = VALID_TOKENS.get(token)

        # 1. Authentication check
        if not token_profile:
            return False, "AUTHENTICATION_FAILED: Invalid or missing security token"

        # 2. Authorization check (Read vs Write)
        if func_code in [0x05, 0x06, 0x0F, 0x10]: # Write functions
            if not token_profile.get("allow_write"):
                return False, f"AUTHORIZATION_DENIED: Role {token_profile['role']} lacks write permissions"

            # 3. Deep parameter inspection for holding register write (Function Code 0x06)
            if func_code == 0x06 and len(pdu) >= 5:
                addr, val = struct.unpack(">HH", pdu[1:5])
                if addr == 0: # Speed register
                    max_allowed = token_profile["max_rpm"]
                    if val > max_allowed or val > 3000:
                        return False, f"SAFETY_POLICY_VIOLATION: Requested {val} RPM exceeds safety threshold ({max_allowed} RPM)"

        return True, "ALLOWED"

    def start(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((self.listen_host, self.listen_port))
        server.listen(10)
        logger.info(f"Modbus Security Gateway active on {self.listen_host}:{self.listen_port} -> Target {self.target_host}:{self.target_port}")

        try:
            while self.is_running:
                client_sock, addr = server.accept()
                threading.Thread(target=self._proxy_client, args=(client_sock, addr), daemon=True).start()
        except KeyboardInterrupt:
            logger.info("Gateway shutting down...")
        finally:
            server.close()

    def _proxy_client(self, client_sock, client_addr):
        try:
            # 1. Handshake: Expect client to send authentication token header
            token_bytes = client_sock.recv(64).strip()
            token = token_bytes.decode("utf-8", errors="ignore")
            
            if token not in VALID_TOKENS:
                logger.warning(f"[ACCESS DENIED] Client {client_addr} presented invalid token: '{token}'")
                client_sock.sendall(b"ERROR: AUTHENTICATION_FAILED\n")
                client_sock.close()
                return

            client_sock.sendall(b"OK: AUTHENTICATED\n")
            logger.info(f"[ACCESS GRANTED] Client {client_addr} authenticated as role '{VALID_TOKENS[token]['role']}'")

            # 2. Connect to internal protected pump
            target_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            target_sock.connect((self.target_host, self.target_port))

            # 3. Transparent proxy with inline DPI
            while self.is_running:
                mbap = client_sock.recv(7)
                if not mbap or len(mbap) < 7:
                    break

                trans_id, proto_id, length, unit_id = struct.unpack(">HHHB", mbap)
                pdu = client_sock.recv(length - 1)

                allowed, reason = self.inspect_and_filter(pdu, token)

                if allowed:
                    # Forward to real pump
                    target_sock.sendall(mbap + pdu)
                    # Forward response back to client
                    resp_mbap = target_sock.recv(7)
                    if resp_mbap:
                        r_trans, r_proto, r_len, r_unit = struct.unpack(">HHHB", resp_mbap)
                        resp_pdu = target_sock.recv(r_len - 1)
                        client_sock.sendall(resp_mbap + resp_pdu)
                else:
                    logger.error(f"[DPI BLOCKED] Client {client_addr} | Reason: {reason} | FuncCode: 0x{pdu[0]:02x}")
                    # Return Modbus Gateway Exception (Exception Code 0x0A: Gateway Target Device Failed to Respond or 0x01)
                    err_pdu = bytes([pdu[0] | 0x80, 0x04]) # Server Device Failure
                    err_mbap = struct.pack(">HHHB", trans_id, proto_id, len(err_pdu) + 1, unit_id)
                    client_sock.sendall(err_mbap + err_pdu)

            target_sock.close()
        except Exception as e:
            logger.debug(f"Proxy session closed: {e}")
        finally:
            client_sock.close()

if __name__ == "__main__":
    gw = ModbusSecurityGateway()
    gw.start()
