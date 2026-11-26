# Threat Model & Zone Architecture — AETHER

## Zone & Conduit Topology
- **Zone 1 (OT Control / Level 1)**: Isolated simulated Modbus TCP PLC (`ModbusPLCServer`) controlling physical cooling/pumping state (`ProcessState`). Bound strictly to internal OT network (`127.0.0.1` / `ics_internal`), never exposed directly to host external interfaces.
- **Zone 2 (Industrial DMZ / Level 2–3)**: `AetherSecurityGateway` terminating HMAC-SHA256 timestamped client envelopes, enforcing default-deny function-code/register allowlists, querying live process operating state before forwarding writes, and emitting redacted audit events.
- **Passive Detection Sensor**: Suricata 7 inspecting real Modbus TCP traffic (`rules/suricata_modbus.rules`) for ATT&CK for ICS `T0888` (recon) and `T0855` (unauthorized commands).

## Network Detection vs. Process-Aware Enforcement
Suricata detects protocol-level Modbus writes (`FC 0x05`, `FC 0x06`, `FC 0x10`) and diagnostic probes (`FC 0x08`, `FC 0x2B`) on the wire, whereas only the stateful gateway knows whether turning off `Coil 0` is safe (`MAINTENANCE` mode) or physically hazardous (`OBSERVING` mode). Combining both layers provides defense-in-depth.
