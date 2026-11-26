# AETHER — Industrial & Cyber-Physical Systems Security Engineering

**Repository:** `https://github.com/Bassma202/scada-modbus-defense-lab`  
**Author:** Bassma Alaoui Sossey — Final-Year Cybersecurity Engineering Student (Université Euromed de Fès — EIDIA)

## 1. Purpose
AETHER is a process-aware industrial cybersecurity engineering laboratory demonstrating Modbus TCP protocol validation, bounded authenticated TCP stream reassembly, replay-resistant HMAC-SHA256 client-to-gateway authentication, race-safe physical-state command safety interlocks at both gateway and PLC boundaries, passive Suricata 7 IDS detection on real captured traffic, and comparative 3-tier defense evaluation.

## 2. Dual-Profile Design
- **Observatory Profile (`observatory`):** Fictional *Observatoire Méridien* primary-mirror thermal cooling loop (`800–2800 RPM` safe active range during `OBSERVING`, pump shutdown prohibited unless transitioned to `MAINTENANCE` by a `MAINTENANCE` operator).
- **Generic Industrial Profile (`generic_industrial`):** Standard industrial water pumping station (`600–2600 RPM` active range), ensuring direct transferability to rail, utilities, water, and manufacturing OT environments.

## 3. Implemented Capabilities
- **Strict Modbus TCP & Bounded Auth Envelope Stream Framing (`src/aether/modbus.py`, `src/aether/gateway.py`):** `ModbusStreamFramer` and `AuthEnvelopeStreamFramer` reassemble fragmented TCP streams (down to 1-byte chunks) and coalesced multi-frame bursts while enforcing strict size bounds, read timeouts, MBAP headers, and explicit function-code allowlists (`0x01`, `0x03`, `0x04`, `0x05`, `0x06`; multi-register `0x10` explicitly denied).
- **Replay-Resistant, Deadlock-Free Process-Aware Gateway (`src/aether/gateway.py`):**
  - Cryptographic HMAC-SHA256 client envelopes covering client ID, timestamp (`±30s`), unique 16-byte cryptographic `nonce`, and Modbus payload, enforced by an atomic bounded `OrderedDict` replay cache (`max_replay_cache_entries=10000`).
  - Default-deny RBAC and strict register-range bounds on BOTH reads and writes (`MONITOR`, `OPERATOR`, `MAINTENANCE`).
  - Deadlock-free separated lock hierarchy (`_rate_lock`, `_replay_lock`, `_decisions_lock`, `_policy_tx_lock`)—verified under rate-limit exhaustion and high concurrency.
  - Serialized state-query -> policy evaluation -> PLC forward under `_policy_tx_lock` failing closed on PLC communication errors.
- **Authoritative PLC-Boundary Safety Interlocks (`src/aether/plc.py`):** Synchronized `ProcessState` enforces independent local safety interlocks (`enforce_local_safety_interlocks=True`) atomically at write time so concurrent mode/pump races never violate `state.is_safe_state()`.
- **3-Tier Comparative Experiment & Measured Latency (`scripts/run_aether_experiments.py`):**
  - **Tier 1 (Unprotected PLC):** Overspeed `4500 RPM` and pump trip succeed (`final_rpm=4500, pump=0`).
  - **Tier 2 (Protocol-Only Filter):** Valid syntax still permits unsafe overspeed and pump trip (`final_rpm=4500, pump=0`).
  - **Tier 3 (AETHER Process-Aware Gateway + PLC Interlocks):** Blocks both overspeed and unsafe pump shutdown during `OBSERVING` (`final_rpm=1450, pump=1`) while maintaining `100%` authorized telemetry.
  - **Measured Latency (`N=200` real localhost TCP transactions):** `p50 = 0.292 ms`, `p95 = 0.523 ms`, `p99 = 0.739 ms`, `3,040.3 req/s`.
- **Suricata 7 OT Detection (`rules/suricata_modbus.rules`):** Validated Modbus TCP rules mapped to MITRE ATT&CK for ICS (`T0888`, `T0855`) executed against genuine laboratory port-502 PCAP captures (`50` packets -> `4/4` Suricata `7.0.8` alerts, `0` false alerts on FC 03 telemetry).

## 4. Quick Start & Reproduction
```bash
make setup
make test
make security
make demo
make up   # Opens AETHER dashboard on http://127.0.0.1:8001
```

## 5. Known Limitations
- The physical cooling/pumping process model is an educational deterministic simulation, not safety-certified PLC firmware (IEC 61508 SIL).
- Native Modbus TCP carries no built-in cryptographic authentication; AETHER provides HMAC-SHA256 + nonce replay protection at the client-to-gateway DMZ boundary while isolating raw Modbus TCP on the internal OT segment.

## 6. License
MIT License.
