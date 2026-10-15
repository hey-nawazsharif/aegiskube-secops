#!/usr/bin/env python3
"""
AegisKube-SecOps — Linux Hardening Auditor
===========================================
Read-only inspection of the Linux security posture. It reports on:
  - Kernel sysctl security parameters
  - Active network sockets (TCP listeners)
  - Rootkit indicators (suspicious kernel modules, known artefact paths)
  - SSH daemon configuration hardening

It does NOT change any system setting; it only reports findings.
On non-Linux hosts it refuses to run (use --demo for clearly-labelled
sample data).

Author : Nawaz Sharif <contact@nawazsharif.in>
License: Apache-2.0
"""

from __future__ import annotations

import json
import platform
import re
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

# ("Protocol" was removed: modern OpenSSH only speaks protocol 2 and no
#  longer accepts the option, so it always showed up as a false failure.)
SSH_SECURE_OPTIONS: dict[str, str] = {
    "PermitRootLogin": "no",
    "PasswordAuthentication": "no",
    "X11Forwarding": "no",
    "PermitEmptyPasswords": "no",
    "MaxAuthTries": "3",
    "LoginGraceTime": "60",
    "AllowAgentForwarding": "no",
    "AllowTcpForwarding": "no",
    "UsePAM": "yes",
}

# For these options "expected" is a maximum, not an exact value.
SSH_NUMERIC_MAX = {"MaxAuthTries", "LoginGraceTime"}

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
    sample_data: bool = False    # True when findings are synthetic demo data


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
    """Enumerate listening TCP sockets using ss/netstat and flag risky ports."""
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
            local = parts[3]
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

            sockets.append(
                NetworkSocketInfo(
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
            )
        except (ValueError, IndexError):
            continue

    return sockets


def audit_rootkit_indicators() -> list[RootkitFinding]:
    """
    Check for known rootkit artefacts:
      - Kernel module names
      - Suspicious files in /dev and /tmp
    """
    findings: list[RootkitFinding] = []
    loaded_modules = _run(["lsmod"]).lower()

    for indicator in ROOTKIT_INDICATORS:
        found = indicator in loaded_modules
        location = "kernel module (lsmod)" if found else ""

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


def _ssh_effective_config() -> dict[str, str]:
    """
    Return the SSH daemon's effective settings (lower-cased keys).

    Preferred source is `sshd -T` (resolves defaults, Include files and
    sshd_config.d/, but usually needs root). Falls back to parsing
    /etc/ssh/sshd_config directly. Returns {} if neither is readable.
    """
    parsed: dict[str, str] = {}

    for line in _run(["sshd", "-T"]).splitlines():
        parts = line.split(None, 1)
        if len(parts) == 2:
            parsed[parts[0].lower()] = parts[1].strip()
    if parsed:
        return parsed

    if SSH_CONFIG_PATH.exists():
        try:
            for line in SSH_CONFIG_PATH.read_text().splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split(None, 1)
                if len(parts) == 2:
                    parsed.setdefault(parts[0].lower(), parts[1].strip())
        except PermissionError:
            return {}
    return parsed


def _ssh_option_ok(option: str, expected: str, actual: str) -> bool:
    if option in SSH_NUMERIC_MAX:
        try:
            return int(actual) <= int(expected)
        except ValueError:
            return False
    return actual.lower() == expected.lower()


def audit_ssh_config() -> list[SshFinding]:
    """Check the SSH daemon configuration against hardening recommendations."""
    findings: list[SshFinding] = []
    effective = _ssh_effective_config()

    if not effective:
        # Cannot read config (not root / sshd not installed): say so plainly.
        for opt, expected in SSH_SECURE_OPTIONS.items():
            findings.append(
                SshFinding(option=opt, expected=expected, actual="UNREADABLE (run as root)", compliant=False)
            )
        return findings

    for opt, expected in SSH_SECURE_OPTIONS.items():
        actual = effective.get(opt.lower(), "DEFAULT/MISSING")
        findings.append(
            SshFinding(
                option=opt,
                expected=expected,
                actual=actual,
                compliant=_ssh_option_ok(opt, expected, actual),
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
        total_weight += SEVERITY_WEIGHTS.get(f.severity, 0)
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
# Synthetic demo data (clearly labelled, never used for real audits)
# ---------------------------------------------------------------------------


def _fill_sample_data(report: AuditReport) -> None:
    report.sysctl_findings = [
        SysctlFinding("kernel.randomize_va_space", "2", "0", False, "HIGH", "Full ASLR must be enabled"),
        SysctlFinding("net.ipv4.tcp_syncookies", "1", "1", True, "OK", "SYN-flood protection"),
        SysctlFinding("net.ipv4.ip_forward", "0", "1", False, "HIGH", "IP forwarding should be disabled"),
        SysctlFinding("kernel.kptr_restrict", "2", "0", False, "HIGH", "Hide kernel pointer addresses"),
        SysctlFinding("fs.protected_symlinks", "1", "1", True, "OK", "Prevent symlink-following attacks"),
    ]
    report.network_sockets = [
        NetworkSocketInfo("TCP", "0.0.0.0", 22, None, None, "LISTEN", 1234, "sshd", False),
        NetworkSocketInfo(
            "TCP", "0.0.0.0", 23, None, None, "LISTEN", 9999, "telnetd", True,
            "Port 23 is a known high-risk service port (Telnet – plaintext)",
        ),
    ]
    report.rootkit_findings = [
        RootkitFinding("diamorphine", False, "Not detected"),
        RootkitFinding("reptile", True, "/dev/.reptile", "CRITICAL"),
    ]
    report.ssh_findings = [
        SshFinding("PermitRootLogin", "no", "yes", False),
        SshFinding("PasswordAuthentication", "no", "yes", False),
        SshFinding("X11Forwarding", "no", "no", True),
        SshFinding("MaxAuthTries", "3", "3", True),
    ]


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def run_audit(demo_mode: bool = False) -> dict[str, Any]:
    """
    Execute all Linux security audit checks and return a structured dict.

    Parameters
    ----------
    demo_mode : bool
        When True, returns synthetic findings (marked sample_data=True and
        given a placeholder hostname) so it can run on any OS.
        When False the audit only runs on Linux; on other systems it exits
        with a clear message instead of returning fake results.
    """
    if not demo_mode and platform.system() != "Linux":
        raise SystemExit(
            f"Linux hardening audit needs a Linux host (detected: {platform.system()}). "
            "Use --demo to see clearly-labelled sample data."
        )

    if demo_mode:
        report = AuditReport(
            hostname="demo-host",
            platform="SAMPLE DATA (not a real system)",
            kernel_version="n/a",
            audit_timestamp=time.time(),
            sample_data=True,
        )
        _fill_sample_data(report)
    else:
        report = AuditReport(
            hostname=socket.gethostname(),
            platform=platform.platform(),
            kernel_version=platform.release(),
            audit_timestamp=time.time(),
        )
        report.sysctl_findings = audit_sysctl()
        report.network_sockets = audit_network_sockets()
        report.rootkit_findings = audit_rootkit_indicators()
        report.ssh_findings = audit_ssh_config()

    # Count by severity
    for f in report.sysctl_findings:
        if f.severity == "CRITICAL":
            report.critical_count += 1
        elif f.severity == "HIGH":
            report.high_count += 1
        elif f.severity == "MEDIUM":
            report.medium_count += 1
        elif f.severity == "LOW":
            report.low_count += 1

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
        f"{'[SAMPLE DATA] ' if demo_mode else ''}"
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

    parser = argparse.ArgumentParser(description="AegisKube-SecOps Linux Hardening Auditor (read-only)")
    parser.add_argument("--demo", action="store_true", help="Show clearly-labelled sample data")
    parser.add_argument("--output", choices=["json", "pretty"], default="pretty")
    args = parser.parse_args()

    result = run_audit(demo_mode=args.demo)
    if args.output == "pretty":
        print(result["summary"])
    print(json.dumps(result, indent=2))
