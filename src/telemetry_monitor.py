#!/usr/bin/env python3
"""
Industrial Process & Security Operations Console
Author: Bassma Alaoui Sossey
Live monitoring console rendering physical pump parameters and DPI firewall status.
"""

import sys
import time

def render_dashboard(rpm=1450, pressure=65, temp=45, gateway_status="ACTIVE", alerts=None):
    if alerts is None:
        alerts = []
    
    # ANSI escape sequences
    CYAN = "\033[96m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    RED = "\033[91m"
    BOLD = "\033[1m"
    RESET = "\033[0m"

    print("\033[H\033[J", end="") # Clear screen
    print(f"{CYAN}{BOLD}================================================================================{RESET}")
    print(f"{CYAN}{BOLD}         ICS / SCADA CRITICAL INFRASTRUCTURE DEFENSE CONSOLE                   {RESET}")
    print(f"{CYAN}{BOLD}         Asset: PUMP_STATION_ALPHA | Protocol: Modbus/TCP (Port 5020/5021)     {RESET}")
    print(f"{CYAN}{BOLD}================================================================================{RESET}\n")

    # Status indicators
    status_color = GREEN if rpm <= 2800 else RED
    print(f"  [SYSTEM STATUS]  Power: {GREEN}ONLINE{RESET}  |  Gateway DPI: {GREEN}{gateway_status}{RESET}  |  Zone: {BOLD}IEC 62443 SL-3{RESET}\n")

    # Telemetry Bars
    rpm_pct = min(100, int((rpm / 3500) * 100))
    rpm_bar = "█" * (rpm_pct // 4) + "░" * (25 - (rpm_pct // 4))
    print(f"  • {BOLD}Pump Speed (Holding Reg 0):{RESET}  [{status_color}{rpm_bar}{RESET}]  {status_color}{rpm} RPM{RESET} (Nominal: 1450, Max Safe: 3000)")

    press_pct = min(100, int((pressure / 150) * 100))
    press_bar = "█" * (press_pct // 4) + "░" * (25 - (press_pct // 4))
    print(f"  • {BOLD}Hydraulic Pressure (Input 0):{RESET} [{CYAN}{press_bar}{RESET}]  {CYAN}{pressure} PSI{RESET} (Max: 120 PSI)")

    temp_color = GREEN if temp < 75 else RED
    temp_pct = min(100, int((temp / 120) * 100))
    temp_bar = "█" * (temp_pct // 4) + "░" * (25 - (temp_pct // 4))
    print(f"  • {BOLD}Motor Core Temp (Input 1):{RESET}   [{temp_color}{temp_bar}{RESET}]  {temp_color}{temp} °C{RESET} (Critical Threshold: 85 °C)\n")

    print(f"{BOLD}--- Security Gateway & Suricata OT Detection Log ---{RESET}")
    if not alerts:
        print(f"  {GREEN}[✓] No anomalous function codes or parameter setpoint violations detected.{RESET}")
    else:
        for alert in alerts[-4:]:
            print(f"  {RED}[ALERT] {alert}{RESET}")
    print(f"\n{CYAN}================================================================================{RESET}")

if __name__ == "__main__":
    sample_alerts = [
        "17:31:02 - [SID 1000004] Modbus Write FC 06 to Address 0x0000 (RPM) detected",
        "17:31:05 - [DPI BLOCKED] Requested 4500 RPM exceeds physical safety threshold",
        "17:31:06 - [GATEWAY] Returning Modbus Exception 0x04 (Slave Device Failure)"
    ]
    render_dashboard(rpm=1800, pressure=78, temp=52, alerts=sample_alerts)
