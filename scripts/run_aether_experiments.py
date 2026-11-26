#!/usr/bin/env python3
"""AETHER 3-Tier Comparative Experiment & Measured Latency Benchmark.

Runs genuine localhost TCP connections across:
1. Tier 1: Unprotected Baseline PLC (direct Modbus TCP)
2. Tier 2: Basic Protocol Filter (valid syntax allowed; no physical state safety)
3. Tier 3: AETHER Process-Aware Zero-Trust Gateway (HMAC + state-aware enforcement)

Measures real p50, p95, p99 end-to-end TCP latency (ms) and throughput across N=200 requests.
"""

from __future__ import annotations

import json
import socket
import statistics
import struct
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from aether.gateway import AetherSecurityGateway, ClientCredential, build_auth_envelope
from aether.modbus import ModbusFrame, ModbusPLCServer
from aether.process import OperatingMode, ProcessState


def send_tcp(port: int, data: bytes) -> bytes:
    with socket.create_connection(("127.0.0.1", port), timeout=2.0) as s:
        s.settimeout(2.0)
        s.sendall(data)
        return s.recv(1024)


def run_tier(tier_name: str, policy_mode: str | None) -> dict:
    state = ProcessState(profile="observatory", operating_mode=int(OperatingMode.OBSERVING))
    plc = ModbusPLCServer(state)
    plc_port = plc.start()
    creds = {"op-1": ClientCredential("op-1", "OPERATOR", b"bench-ephemeral-key-2027")}
    gw = None
    target_port = plc_port
    if policy_mode:
        gw = AetherSecurityGateway("127.0.0.1", plc_port, creds, profile="observatory", policy_mode=policy_mode, rate_limit_per_sec=1000)
        target_port = gw.start()

    def wrap(frame: bytes) -> bytes:
        return build_auth_envelope("op-1", creds["op-1"].secret_key, frame) if gw else frame

    try:
        read_f = ModbusFrame(1, 0, 1, struct.pack(">BHH", 0x03, 0, 1)).to_bytes()
        r_read = send_tcp(target_port, wrap(read_f))
        telem_ok = r_read[7] == 0x03

        over_f = ModbusFrame(2, 0, 1, struct.pack(">BHH", 0x06, 0, 4500)).to_bytes()
        r_over = send_tcp(target_port, wrap(over_f))
        overspeed_blocked = bool(r_over[7] & 0x80)

        trip_f = ModbusFrame(3, 0, 1, struct.pack(">BHH", 0x05, 0, 0x0000)).to_bytes()
        r_trip = send_tcp(target_port, wrap(trip_f))
        trip_blocked = bool(r_trip[7] & 0x80)

        latencies_ms: list[float] = []
        if tier_name == "tier3_process_aware_gateway":
            t_start = time.perf_counter()
            for i in range(200):
                rf = ModbusFrame(100 + i, 0, 1, struct.pack(">BHH", 0x03, 0, 1)).to_bytes()
                t0 = time.perf_counter()
                res = send_tcp(target_port, wrap(rf))
                latencies_ms.append((time.perf_counter() - t0) * 1000.0)
                assert res[7] == 0x03
            total_s = time.perf_counter() - t_start
            latencies_ms.sort()
            bench = {
                "sample_size": len(latencies_ms),
                "measurement_boundary": "End-to-end localhost TCP client -> HMAC envelope -> AETHER Gateway -> PLC -> TCP response",
                "p50_ms": round(statistics.median(latencies_ms), 3),
                "p95_ms": round(latencies_ms[int(0.95 * len(latencies_ms))], 3),
                "p99_ms": round(latencies_ms[int(0.99 * len(latencies_ms))], 3),
                "throughput_req_per_sec": round(len(latencies_ms) / total_s, 1),
            }
        else:
            bench = {}

        return {
            "authorized_telemetry_ok": telem_ok,
            "overspeed_blocked": overspeed_blocked,
            "unsafe_pump_trip_blocked": trip_blocked,
            "final_rpm": state.target_rpm,
            "final_pump_power": state.pump_power,
            "benchmark": bench,
        }
    finally:
        if gw:
            gw.stop()
        plc.stop()


def main() -> None:
    t1 = run_tier("tier1_unprotected_plc", None)
    t2 = run_tier("tier2_protocol_filter_only", "protocol_only")
    t3 = run_tier("tier3_process_aware_gateway", "process_aware")
    bench = t3.pop("benchmark")
    t1.pop("benchmark", None)
    t2.pop("benchmark", None)

    out_path = ROOT / "evidence" / "aether_experiment_results.json"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    existing = json.loads(out_path.read_text(encoding="utf-8")) if out_path.exists() else {}
    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "evidence_classification": "Genuine laboratory execution (real localhost TCP sockets)",
        "three_tier_comparison": {
            "tier1_unprotected_plc": t1,
            "tier2_protocol_filter_only": t2,
            "tier3_process_aware_gateway": t3,
        },
        "latency_benchmark_ms": bench,
        "suricata_live_capture": existing.get("suricata_live_capture", {}),
    }
    out_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    print(json.dumps(payload, indent=2))


if __name__ == "__main__":
    main()
