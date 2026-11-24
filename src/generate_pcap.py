#!/usr/bin/env python3
"""
Industrial Modbus Traffic & PCAP Generator
Author: Bassma Alaoui Sossey
Generates synthetic Wireshark .pcap capture containing:
- Baseline telemetry polling (FC 0x03)
- Authorized operator setpoint adjustments (FC 0x06, 1800 RPM)
- Adversary unauthenticated command injection (FC 0x06, 4500 RPM)
- Gateway DPI security exception responses (FC 0x86, Code 0x04)
"""

import struct
import time
import os

def create_raw_pcap(output_path="pcap_samples/modbus_attack_defense.pcap"):
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    
    # Global PCAP Header: magic, v_major, v_minor, thiszone, sigfigs, snaplen, network (1 = Ethernet)
    global_header = struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)

    # Packets to inject
    # (timestamp_offset, src_ip, dst_ip, src_port, dst_port, payload_bytes)
    packets = [
        # 1. Normal polling: Client -> PLC (FC 0x03 Read Holding Reg 0)
        (0.1, "172.29.0.50", "172.28.0.10", 49152, 5020, 
         struct.pack(">HHHB BHH", 1, 0, 6, 1, 0x03, 0, 1)),
        # Response: PLC -> Client (1450 RPM)
        (0.12, "172.28.0.10", "172.29.0.50", 5020, 49152,
         struct.pack(">HHHB BBH", 1, 0, 5, 1, 0x03, 2, 1450)),

        # 2. Authorized Setpoint: Operator -> Gateway (FC 0x06 Write 1800 RPM)
        (1.5, "172.29.0.50", "172.28.0.20", 49153, 5021,
         struct.pack(">HHHB BHH", 2, 0, 6, 1, 0x06, 0, 1800)),
        # Gateway -> Client: Acknowledged
        (1.53, "172.28.0.20", "172.29.0.50", 5021, 49153,
         struct.pack(">HHHB BHH", 2, 0, 6, 1, 0x06, 0, 1800)),

        # 3. Rogue Attack: Adversary -> PLC directly (FC 0x06 Write 4500 RPM Overspeed)
        (3.0, "172.29.0.99", "172.28.0.10", 55555, 5020,
         struct.pack(">HHHB BHH", 999, 0, 6, 1, 0x06, 0, 4500)),
        # Unprotected PLC Accepts: Acknowledged (Hazardous condition)
        (3.02, "172.28.0.10", "172.29.0.99", 5020, 55555,
         struct.pack(">HHHB BHH", 999, 0, 6, 1, 0x06, 0, 4500)),

        # 4. Attacker through Gateway: Attempting 5000 RPM
        (4.2, "172.29.0.99", "172.28.0.20", 55556, 5021,
         struct.pack(">HHHB BHH", 1001, 0, 6, 1, 0x06, 0, 5000)),
        # Gateway DPI Intercepts: Returns Exception 0x04 (Device Failure / Blocked)
        (4.22, "172.28.0.20", "172.29.0.99", 5021, 55556,
         struct.pack(">HHHB BB", 1001, 0, 3, 1, 0x86, 0x04))
    ]

    def ip_to_bytes(ip_str):
        return bytes(map(int, ip_str.split(".")))

    with open(output_path, "wb") as f:
        f.write(global_header)
        base_time = int(time.time())

        for offset, src_ip, dst_ip, src_port, dst_port, payload in packets:
            # Ethernet header (14 bytes): Dst MAC, Src MAC, EtherType 0x0800 (IPv4)
            eth = b"\x00\x50\x56\x00\x00\x01\x00\x50\x56\x00\x00\x02\x08\x00"
            
            # IPv4 header (20 bytes)
            total_len = 20 + 20 + len(payload) # IP + TCP + Payload
            ip_hdr = struct.pack(">BBHHHBBH4s4s", 
                                0x45, 0, total_len, 0x1234, 0x4000, 64, 6, 0, 
                                ip_to_bytes(src_ip), ip_to_bytes(dst_ip))
            
            # TCP header (20 bytes)
            tcp_hdr = struct.pack(">HHIIBBHHH", 
                                  src_port, dst_port, 1000, 2000, 0x50, 0x18, 8192, 0, 0)
            
            frame = eth + ip_hdr + tcp_hdr + payload
            ts_sec = base_time + int(offset)
            ts_usec = int((offset % 1.0) * 1000000)
            
            pkt_hdr = struct.pack("<IIII", ts_sec, ts_usec, len(frame), len(frame))
            f.write(pkt_hdr + frame)

    print(f"[✓] Synthetic ICS Modbus PCAP generated successfully at: {output_path}")

if __name__ == "__main__":
    create_raw_pcap()
