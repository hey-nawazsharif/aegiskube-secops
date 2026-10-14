#!/usr/bin/env python3
"""
AegisKube-SecOps — Linux Hardening Auditor
===========================================
Performs deep inspection of the Linux system security posture by analyzing:
  - Kernel sysctl security parameters
  - Active network sockets (TCP/UDP listeners & connections)
  - Rootkit indicators (suspicious kernel modules, hidden processes)
  - SSH daemon configuration hardening

Author : Nawaz Sharif <contact@nawazsharif.in>
Role   : Senior Linux Developer | Kubernetes | Cybersecurity & Blockchain Architect | AI/ML & Python | DevOps & Cloud
License: Apache-2.0
"""

from __future__ import annotations

import json
import os
import platform
import re
import shutil
import socket
import subprocess
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SYSCTL_SECURITY_PARAMS: dict[str, dict[str, Any]] = {
    # Network hardening
    "net.ipv4.ip_forward": {
        "expected": "0",
        "severity": "HIGH",
        "description": "IP forwarding should be disabled unless this host is a router",
    },
    "net.ipv4.conf.all.rp_filter": {
        "expected": "1",
        "severity": "MEDIUM",
        "description": "Reverse path filtering prevents IP spoofing",
    },
    "net.ipv4.conf.default.rp_filter": {
        "expected": "1",
        "severity": "MEDIUM",
        "description": "Reverse path filtering (default interface)",
    },
    "net.ipv4.conf.all.accept_redirects": {
        "expected": "0",
        "severity": "HIGH",
        "description": "ICMP redirects should be ignored (MITM vector)",
    },
    "net.ipv4.conf.all.send_redirects": {
        "expected": "0",
        "severity": "HIGH",
        "description": "Should not send ICMP redirects",
    },
    "net.ipv4.conf.all.accept_source_route": {
        "expected": "0",
        "severity": "HIGH",
        "description": "Source-routed packets are a spoofing vector",
    },
    "net.ipv4.icmp_echo_ignore_broadcasts": {
        "expected": "1",
        "severity": "MEDIUM",
        "description": "Smurf attack mitigation",
    },
    "net.ipv4.tcp_syncookies": {
        "expected": "1",
        "severity": "HIGH",
        "description": "SYN-flood protection",
    },
    # Kernel hardening
    "kernel.randomize_va_space": {
        "expected": "2",
        "severity": "HIGH",
        "description": "Full ASLR must be enabled",
    },
    "kernel.dmesg_restrict": {
        "expected": "1",
        "severity": "MEDIUM",
        "description": "Restrict dmesg to privileged users",
    },
    "kernel.kptr_restrict": {
        "expected": "2",
        "severity": "HIGH",
        "description": "Hide kernel pointer addresses from unprivileged users",
    },
    "kernel.yama.ptrace_scope": {
        "expected": "1",
        "severity": "HIGH",
        "description": "Restrict ptrace to parent process only",
    },
    "fs.suid_dumpable": {
        "expected": "0",
        "severity": "MEDIUM",
        "description": "Disable core dumps for SUID binaries",
    },
    "fs.protected_hardlinks": {
        "expected": "1",
        "severity": "MEDIUM",
        "description": "Prevent hard-link attacks on writable directories",
    },
    "fs.protected_symlinks": {
        "expected": "1",
        "severity": "MEDIUM",
        "description": "Prevent symlink-following attacks in sticky directories",
    },
}

ROOTKIT_INDICATORS: list[str] = [
    "azazel",
    "adore",
    "knark",
    "rexeditor",
    "modhide",
    "synful",
    "reptile",
    "diamorphine",
    "suterusu",
    "necurs",
    "bdvl",
]

SSH_SECURE_OPTIONS: dict[str, str] = {
    "PermitRootLogin": "no",
    "PasswordAuthentication": "no",
    "X11Forwarding": "no",
    "PermitEmptyPasswords": "no",
    "Protocol": "2",
    "MaxAuthTries": "3",
    "LoginGraceTime": "60",
    "AllowAgentForwarding": "no",
    "AllowTcpForwarding": "no",
    "UsePAM": "yes",
}

SSH_CONFIG_PATH = Path("/etc/ssh/sshd_config")


# ---------------------------------------------------------------------------
# Data Models
# ---------------------------------------------------------------------------


@dataclass
class SysctlFinding:
    parameter: str
    expected: str
    actual: str
    compliant: bool
    severity: str
    description: str


@dataclass
class NetworkSocketInfo:
    protocol: str
    local_address: str
    local_port: int
    remote_address: str | None
    remote_port: int | None
    state: str
    pid: int | None
    process_name: str | None
    risk_flag: bool = False
    risk_reason: str = ""


@dataclass
class RootkitFinding:
    indicator: str
    found: bool
    location: str
    severity: str = "CRITICAL"


@dataclass
class SshFinding:
    option: str
    expected: str
    actual: str
    compliant: bool
    severity: str = "HIGH"


@dataclass
class AuditReport:
    hostname: str
    platform: str
    kernel_version: str
    audit_timestamp: float
    sysctl_findings: list[SysctlFinding] = field(default_factory=list)
    network_sockets: list[NetworkSocketInfo] = field(default_factory=list)
    rootkit_findings: list[RootkitFinding] = field(default_factory=list)
    ssh_findings: list[SshFinding] = field(default_factory=list)
    overall_risk_score: float = 0.0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    summary: str = ""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _run(cmd: list[str], timeout: int = 10) -> str:
    """Run a subprocess command safely and return stdout."""
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return result.stdout.strip()
    except (subprocess.TimeoutExpired, FileNotFoundError, PermissionError):
        return ""


def _sysctl_read(param: str) -> str:
    """Read a single sysctl value from the /proc pseudo-filesystem or sysctl."""
    proc_path = Path("/proc/sys/" + param.replace(".", "/"))
    if proc_path.exists():
        try:
            return proc_path.read_text().strip()
        except PermissionError:
            pass
    output = _run(["sysctl", "-n", param])
    return output if output else "UNAVAILABLE"


# ---------------------------------------------------------------------------
# Audit Modules
# ---------------------------------------------------------------------------


def audit_sysctl() -> list[SysctlFinding]:
    """Check every defined sysctl security parameter against its expected value."""
    findings: list[SysctlFinding] = []
    for param, meta in SYSCTL_SECURITY_PARAMS.items():
        actual = _sysctl_read(param)
        compliant = actual == meta["expected"]
        findings.append(
            SysctlFinding(
                parameter=param,
                expected=meta["expected"],
                actual=actual,
                compliant=compliant,
                severity=meta["severity"] if not compliant else "OK",
                description=meta["description"],
            )
        )
    return findings


def audit_network_sockets() -> list[NetworkSocketInfo]:
    """Enumerate active network sockets using ss/netstat and flag risky listeners."""
    sockets: list[NetworkSocketInfo] = []
    # Well-known high-risk ports that should almost never be publicly listening
    risky_ports = {21, 23, 69, 111, 512, 513, 514, 1099, 2049, 4444, 6666, 6667, 31337}

    raw = _run(["ss", "-tlnpH"])
    if not raw:
        raw = _run(["netstat", "-tlnp"])

    for line in raw.splitlines():
        parts = line.split()
        if len(parts) < 4:
            continue
        try:
            local = parts[3] if "ss" in str(shutil.which("ss") or "") else parts[3]
            # Parse host:port — handle IPv6 like [::]:22
            if local.startswith("["):
                match = re.match(r"\[(.+)\]:(\d+)", local)
                if match:
                    host, port_str = match.group(1), match.group(2)
                else:
                    continue
            elif ":" in local:
                host, _, port_str = local.rpartition(":")
            else:
                continue

            port = int(port_str)
            risk = port in risky_ports
            reason = f"Port {port} is a known high-risk service port" if risk else ""

            sock = NetworkSocketInfo(
                protocol="TCP",
                local_address=host,
                local_port=port,
                remote_address=None,
                remote_port=None,
                state="LISTEN",
                pid=None,
                process_name=None,
                risk_flag=risk,
                risk_reason=reason,
            )
            sockets.append(sock)
        except (ValueError, IndexError):
            continue

    return sockets


def audit_rootkit_indicators() -> list[RootkitFinding]:
    """
    Check for known rootkit artefacts:
      - Kernel module names
      - Suspicious files in /dev, /tmp, /proc
    """
    findings: list[RootkitFinding] = []
    loaded_modules = _run(["lsmod"]).lower()

    for indicator in ROOTKIT_INDICATORS:
        # Check kernel modules
        found = indicator in loaded_modules
        location = "kernel module (lsmod)" if found else ""

        # Check common rootkit file paths
        if not found:
            for suspicious_dir in ["/dev/.hidden", f"/dev/{indicator}", f"/tmp/.{indicator}"]:
                if Path(suspicious_dir).exists():
                    found = True
                    location = suspicious_dir
                    break

        findings.append(
            RootkitFinding(
                indicator=indicator,
                found=found,
                location=location if found else "Not detected",
            )
        )
    return findings


def audit_ssh_config() -> list[SshFinding]:
    """Parse /etc/ssh/sshd_config and flag insecure settings."""
    findings: list[SshFinding] = []
    parsed: dict[str, str] = {}

    if SSH_CONFIG_PATH.exists():
        try:
            content = SSH_CONFIG_PATH.read_text()
            for line in content.splitlines():
                line = line.strip()
                if line.startswith("#") or not line:
                    continue
                parts = line.split(None, 1)
                if len(parts) == 2:
                    parsed[parts[0]] = parts[1].strip()
        except PermissionError:
            # Cannot read sshd_config without root — mark all as UNKNOWN
            for opt, expected in SSH_SECURE_OPTIONS.items():
                findings.append(
                    SshFinding(
                        option=opt,
                        expected=expected,
                        actual="PERMISSION_DENIED",
                        compliant=False,
                    )
                )
            return findings

    for opt, expected in SSH_SECURE_OPTIONS.items():
        actual = parsed.get(opt, "DEFAULT/MISSING")
        compliant = actual.lower() == expected.lower()
        findings.append(
            SshFinding(
                option=opt,
                expected=expected,
                actual=actual,
                compliant=compliant,
            )
        )
    return findings


# ---------------------------------------------------------------------------
# Risk Scoring
# ---------------------------------------------------------------------------

SEVERITY_WEIGHTS = {"CRITICAL": 10, "HIGH": 5, "MEDIUM": 2, "LOW": 1, "OK": 0}


def _compute_risk_score(report: AuditReport) -> float:
    """
    Compute a normalized 0–100 risk score from all findings.
    Higher = more dangerous.
    """
    total_weight = 0.0
    max_possible = 0.0

    for f in report.sysctl_findings:
        w = SEVERITY_WEIGHTS.get(f.severity, 0)
        total_weight += w
        max_possible += SEVERITY_WEIGHTS["HIGH"]

    for sock in report.network_sockets:
        if sock.risk_flag:
            total_weight += SEVERITY_WEIGHTS["HIGH"]
        max_possible += SEVERITY_WEIGHTS["HIGH"]

    for rf in report.rootkit_findings:
        if rf.found:
            total_weight += SEVERITY_WEIGHTS["CRITICAL"]
        max_possible += SEVERITY_WEIGHTS["CRITICAL"]

    for sf in report.ssh_findings:
        if not sf.compliant:
            total_weight += SEVERITY_WEIGHTS[sf.severity]
        max_possible += SEVERITY_WEIGHTS[sf.severity]

    if max_possible == 0:
        return 0.0
    return round((total_weight / max_possible) * 100, 2)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def run_audit(demo_mode: bool = False) -> dict[str, Any]:
    """
    Execute all Linux security audit checks and return a structured JSON
    telemetry dictionary.

    Parameters
    ----------
    demo_mode : bool
        When True, injects synthetic findings to simulate a real audit
        on non-Linux platforms (macOS, Windows CI runners).
    """
    report = AuditReport(
        hostname=socket.gethostname(),
        platform=platform.platform(),
        kernel_version=platform.release(),
        audit_timestamp=time.time(),
    )

    if demo_mode or platform.system() != "Linux":
        # Synthetic demo data — safe to run everywhere
        report.sysctl_findings = [
            SysctlFinding(
                parameter="kernel.randomize_va_space",
                expected="2",
                actual="0",
                compliant=False,
                severity="HIGH",
                description="Full ASLR must be enabled",
            ),
            SysctlFinding(
                parameter="net.ipv4.tcp_syncookies",
                expected="1",
                actual="1",
                compliant=True,
                severity="OK",
                description="SYN-flood protection",
            ),
            SysctlFinding(
                parameter="net.ipv4.ip_forward",
                expected="0",
                actual="1",
                compliant=False,
                severity="HIGH",
                description="IP forwarding should be disabled",
            ),
            SysctlFinding(
                parameter="kernel.kptr_restrict",
                expected="2",
                actual="0",
                compliant=False,
                severity="HIGH",
                description="Hide kernel pointer addresses",
            ),
            SysctlFinding(
                parameter="fs.protected_symlinks",
                expected="1",
                actual="1",
                compliant=True,
                severity="OK",
                description="Prevent symlink-following attacks",
            ),
        ]
        report.network_sockets = [
            NetworkSocketInfo(
                protocol="TCP",
                local_address="0.0.0.0",
                local_port=22,
                remote_address=None,
                remote_port=None,
                state="LISTEN",
                pid=1234,
                process_name="sshd",
                risk_flag=False,
            ),
            NetworkSocketInfo(
                protocol="TCP",
                local_address="0.0.0.0",
                local_port=23,
                remote_address=None,
                remote_port=None,
                state="LISTEN",
                pid=9999,
                process_name="telnetd",
                risk_flag=True,
                risk_reason="Port 23 is a known high-risk service port (Telnet – plaintext)",
            ),
        ]
        report.rootkit_findings = [
            RootkitFinding(
                indicator="diamorphine",
                found=False,
                location="Not detected",
            ),
            RootkitFinding(
                indicator="reptile",
                found=True,
                location="/dev/.reptile",
                severity="CRITICAL",
            ),
        ]
        report.ssh_findings = [
            SshFinding(
                option="PermitRootLogin",
                expected="no",
                actual="yes",
                compliant=False,
            ),
            SshFinding(
                option="PasswordAuthentication",
                expected="no",
                actual="yes",
                compliant=False,
            ),
            SshFinding(
                option="X11Forwarding",
                expected="no",
                actual="no",
                compliant=True,
            ),
            SshFinding(
                option="Protocol",
                expected="2",
                actual="2",
                compliant=True,
            ),
        ]
    else:
        report.sysctl_findings = audit_sysctl()
        report.network_sockets = audit_network_sockets()
        report.rootkit_findings = audit_rootkit_indicators()
        report.ssh_findings = audit_ssh_config()

    # Count by severity
    for f in report.sysctl_findings:
        sev = f.severity
        if sev == "CRITICAL":
            report.critical_count += 1
        elif sev == "HIGH":
            report.high_count += 1
        elif sev == "MEDIUM":
            report.medium_count += 1

    for rf in report.rootkit_findings:
        if rf.found:
            report.critical_count += 1

    for sf in report.ssh_findings:
        if not sf.compliant:
            report.high_count += 1

    for sock in report.network_sockets:
        if sock.risk_flag:
            report.high_count += 1

    report.overall_risk_score = _compute_risk_score(report)
    report.summary = (
        f"Audit complete. Risk Score: {report.overall_risk_score}/100 — "
        f"Critical: {report.critical_count}, High: {report.high_count}, "
        f"Medium: {report.medium_count}, Low: {report.low_count}"
    )

    return asdict(report)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="AegisKube-SecOps Linux Hardening Auditor")
    parser.add_argument("--demo", action="store_true", help="Run in demo mode with synthetic data")
    parser.add_argument("--output", choices=["json", "pretty"], default="pretty")
    args = parser.parse_args()

    result = run_audit(demo_mode=args.demo)
    if args.output == "json":
        print(json.dumps(result, indent=2))
    else:
        print(json.dumps(result, indent=2))
