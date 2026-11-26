"""Physical process simulation for AETHER (Observatory Thermal Control & Generic Industrial Pump).

Strictly separated from Modbus TCP framing. Provides thread-safe atomic state transitions and optional
authoritative local safety interlocks at the simulated PLC boundary (AETHER-05).
NOTE: This is an educational/cybersecurity laboratory simulation — NOT certified functional-safety software (IEC 61508/SIL).
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any


class OperatingMode(IntEnum):
    IDLE = 0
    OBSERVING = 1      # Active telescope observation (or critical industrial run): cooling MUST stay active >= min_rpm_active
    MAINTENANCE = 2    # Safe maintenance mode: pump may be stopped (0 RPM)
    EMERGENCY_SAFE = 3


PROFILES: dict[str, dict[str, Any]] = {
    "observatory": {
        "name": "Observatoire Méridien — Primary Mirror Thermal Cooling Loop",
        "min_rpm_active": 800,
        "max_rpm_safe": 2800,
        "max_rpm_physical": 5000,
        "max_pressure_psi": 120,
        "max_temp_c": 45,
        "default_rpm": 1450,
    },
    "generic_industrial": {
        "name": "Generic Industrial Water Pumping Station",
        "min_rpm_active": 600,
        "max_rpm_safe": 2600,
        "max_rpm_physical": 5000,
        "max_pressure_psi": 130,
        "max_temp_c": 85,
        "default_rpm": 1400,
    },
}


@dataclass
class ProcessState:
    profile: str = "observatory"
    pump_power: int = 1                     # Coil 0 (0=OFF, 1=ON)
    ventilation_open: int = 1               # Coil 1 (0=CLOSED, 1=OPEN)
    target_rpm: int = 1450                  # Holding Register 0 (RPM)
    operating_mode: int = int(OperatingMode.OBSERVING)  # Holding Register 1
    pressure_psi: int = 62                  # Input Register 0 (PSI)
    temperature_c_x10: int = 185            # Input Register 1 (18.5 °C scaled x10)
    flow_lpm: int = 48                      # Input Register 2 (L/min)
    alarm_code: int = 0                     # Input Register 3 (0=OK, 1=WARN, 2=CRITICAL)
    enforce_local_safety_interlocks: bool = False  # True for hardened PLC boundary; False for Tier 1/2 baseline comparison
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def spec(self) -> dict[str, Any]:
        return PROFILES.get(self.profile, PROFILES["observatory"])

    def _step_physics_unlocked(self) -> None:
        spec = self.spec()
        eff_rpm = self.target_rpm if self.pump_power == 1 else 0
        self.pressure_psi = min(200, max(0, int(round(eff_rpm * 0.043))))
        self.flow_lpm = min(150, max(0, int(round(eff_rpm * 0.033))))
        if self.pump_power == 0 and self.operating_mode == int(OperatingMode.OBSERVING):
            self.temperature_c_x10 = min(1200, self.temperature_c_x10 + 95)
        elif eff_rpm > spec["max_rpm_safe"]:
            self.temperature_c_x10 = min(1200, int(220 + (eff_rpm - spec["max_rpm_safe"]) * 0.18))
        else:
            target_t = 180 if self.profile == "observatory" else 420
            if self.ventilation_open == 0:
                target_t += 60
            self.temperature_c_x10 = int(round(0.5 * self.temperature_c_x10 + 0.5 * target_t))

        if self.pressure_psi > spec["max_pressure_psi"] or (self.temperature_c_x10 / 10.0) > spec["max_temp_c"]:
            self.alarm_code = 2
        elif eff_rpm > int(spec["max_rpm_safe"] * 0.92) or (self.pump_power == 0 and self.operating_mode == int(OperatingMode.OBSERVING)):
            self.alarm_code = 1
        else:
            self.alarm_code = 0

    def step_physics(self) -> None:
        with self._lock:
            self._step_physics_unlocked()

    def apply_coil_write(self, addr: int, bit: int) -> tuple[bool, str]:
        """Atomically apply a coil write with synchronized local safety invariant enforcement."""
        with self._lock:
            if addr == 0:
                if self.enforce_local_safety_interlocks and bit == 0 and self.operating_mode == int(OperatingMode.OBSERVING):
                    return False, "PLC_INTERLOCK: Cannot cut pump power while in OBSERVING mode."
                self.pump_power = bit
            elif addr == 1:
                self.ventilation_open = bit
            else:
                return False, f"Invalid coil address {addr}"
            self._step_physics_unlocked()
            return True, "OK"

    def apply_register_write(self, addr: int, val: int) -> tuple[bool, str]:
        """Atomically apply a holding register write with synchronized local safety invariant enforcement."""
        with self._lock:
            spec = self.spec()
            if addr == 0:
                if val > spec["max_rpm_physical"]:
                    return False, f"RPM {val} exceeds physical ceiling {spec['max_rpm_physical']}"
                if self.enforce_local_safety_interlocks:
                    if val > spec["max_rpm_safe"]:
                        return False, f"PLC_INTERLOCK: RPM {val} exceeds safe ceiling {spec['max_rpm_safe']}."
                    if self.operating_mode == int(OperatingMode.OBSERVING) and val < spec["min_rpm_active"]:
                        return False, f"PLC_INTERLOCK: RPM {val} below minimum cooling {spec['min_rpm_active']} during OBSERVING."
                self.target_rpm = val
            elif addr == 1:
                if val not in (0, 1, 2, 3):
                    return False, f"Invalid operating mode {val}"
                if self.enforce_local_safety_interlocks and val == int(OperatingMode.OBSERVING):
                    if self.pump_power == 0 or self.target_rpm < spec["min_rpm_active"]:
                        return False, "PLC_INTERLOCK: Cannot enter OBSERVING mode while pump is OFF or RPM below safe minimum."
                self.operating_mode = val
            else:
                return False, f"Invalid holding register address {addr}"
            self._step_physics_unlocked()
            return True, "OK"

    def read_coils_atomic(self) -> list[int]:
        with self._lock:
            return [self.pump_power, self.ventilation_open]

    def read_holding_atomic(self) -> list[int]:
        with self._lock:
            return [self.target_rpm, self.operating_mode]

    def read_inputs_atomic(self) -> list[int]:
        with self._lock:
            self._step_physics_unlocked()
            return [self.pressure_psi, self.temperature_c_x10, self.flow_lpm, self.alarm_code]

    def is_safe_state(self) -> bool:
        """Verify simulated physical safety invariant (OBSERVING mode requires active cooling within safe RPM bounds)."""
        with self._lock:
            spec = self.spec()
            if self.target_rpm > spec["max_rpm_safe"]:
                return False
            if self.operating_mode == int(OperatingMode.OBSERVING):
                return self.pump_power == 1 and self.target_rpm >= spec["min_rpm_active"]
            return True

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            return {
                "profile": self.profile,
                "profile_name": self.spec()["name"],
                "pump_power": self.pump_power,
                "ventilation_open": self.ventilation_open,
                "target_rpm": self.target_rpm,
                "operating_mode": OperatingMode(self.operating_mode).name if self.operating_mode in OperatingMode._value2member_map_ else str(self.operating_mode),
                "operating_mode_code": self.operating_mode,
                "pressure_psi": self.pressure_psi,
                "temperature_c": round(self.temperature_c_x10 / 10.0, 1),
                "flow_lpm": self.flow_lpm,
                "alarm_code": self.alarm_code,
            }
