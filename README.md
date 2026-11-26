# AETHER — Industrial & Cyber-Physical Systems Security Engineering

**Repository:** `https://github.com/Bassma202/scada-modbus-defense-lab`  
**Author:** Bassma Alaoui Sossey — Final-Year Cybersecurity Engineering Student (Université Euromed de Fès — EIDIA)

## 1. Purpose
AETHER is a process-aware industrial cybersecurity engineering laboratory demonstrating Modbus TCP protocol validation, TCP stream reassembly, HMAC-SHA256 client-to-gateway authentication, physical-state-aware command safety, passive Suricata 7 IDS detection on real captured traffic, and comparative 3-tier defense evaluation.

## 2. Dual-Profile Design
- **Observatory Profile (`observatory`)**: Fictional *Observatoire Méridien* primary-mirror thermal cooling loop (`800–2800 RPM` safe active range during `OBSERVING`, pump shutdown prohibited unless transitioned to `MAINTENANCE` by a `MAINTENANCE` operator).
- **Generic Industrial Profile (`generic_industrial`)**: Standard industrial water pumping station (`600–2600 RPM` active range), ensuring direct transferability to rail, utilities, water, and manufacturing OT environments.

## 3. Implemented Capabilities
- **Strict Modbus TCP Framing & Stream Reassembly (`src/aether/modbus.py`)**: `ModbusStreamFramer` reassembles fragmented TCP reads (down to 1-byte chunks) and coalesced multi-ADU streams, validating MBAP protocol ID, length bounds, unit ID, and function codes (`0x01`, `0x03`, `0x04`, `0x05`, `0x06`).
- **Process-Aware Zero-Trust Gateway (`src/aether/gateway.py`)**: Replaces static plaintext tokens with HMAC-SHA256 timestamped client envelopes (`±30s` replay window), default-deny function-code/register allowlists, role separation (`MONITOR` read-only, `OPERATOR` safe control, `MAINTENANCE` mode transitions), sliding-window rate limits, redacted audit logs, and live PLC state queries prior to forwarding writes.
- **3-Tier Comparative Experiment & Measured Latency (`scripts/run_aether_experiments.py`)**:
  - **Tier 1 (Unprotected PLC)**: Overspeed `4500 RPM` and pump trip succeed (`final_rpm=4500, pump=0`).
  - **Tier 2 (Protocol-Only Filter)**: Valid syntax still permits unsafe overspeed and pump trip (`final_rpm=4500, pump=0`).
  - **Tier 3 (AETHER Process-Aware Gateway)**: Blocks both overspeed and unsafe pump shutdown during `OBSERVING` (`final_rpm=1450, pump=1`) while maintaining `100%` authorized telemetry.
  - **Measured Latency (`N=200` real localhost TCP transactions)**: `p50 = 0.287 ms`, `p95 = 0.499 ms`, `p99 = 0.668 ms`, `3,131.2 req/s`.
- **Suricata 7 OT Detection (`rules/suricata_modbus.rules`)**: Validated Modbus TCP rules mapped to MITRE ATT&CK for ICS (`T0888`, `T0855`) executed against genuine laboratory PCAP captures.
- **Operations Web Dashboard (`src/aether/web.py`)**: Live simulated telemetry, profile switcher, and measured experiment results.

## 4. Quick Start & Reproduction
```bash
make setup
make test
make security
make demo
make up   # Opens AETHER dashboard on http://127.0.0.1:8001
```

## 5. Known Limitations
- The physical cooling/pumping process model is an educational deterministic simulation, not safety-certified PLC firmware.
- Native Modbus TCP carries no built-in cryptographic authentication; AETHER provides HMAC-SHA256 authentication at the client-to-gateway DMZ boundary while isolating raw Modbus TCP on the internal OT segment.

## 6. License
MIT License.
