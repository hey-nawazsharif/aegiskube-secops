#!/usr/bin/env python3
"""
AegisKube-SecOps — AI Threat Detection Engine
==============================================
Heuristic & statistical anomaly detection engine that:
  - Parses Linux auth and syslog entries for attack patterns
  - Analyzes network traffic metrics for anomalies
  - Applies Zero-Trust scoring with multi-dimensional risk factors
  - Produces structured threat intelligence reports

Methodology:
  - Sliding-window frequency analysis (brute-force detection)
  - Statistical Z-score deviation (traffic volume anomalies)
  - Regex-based pattern matching (CVE/exploit signatures)
  - Weighted scoring model (Zero-Trust framework)

Author : Nawaz Sharif <contact@nawazsharif.in>
Role   : Senior Linux Developer | Kubernetes | Cybersecurity & Blockchain Architect | AI/ML & Python | DevOps & Cloud
License: Apache-2.0
"""

from __future__ import annotations

import math
import random
import re
import time
from dataclasses import asdict, dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------


class ThreatLevel(str, Enum):
    CRITICAL = "CRITICAL"   # Immediate incident response required
    HIGH = "HIGH"           # Likely attack in progress
    MEDIUM = "MEDIUM"       # Suspicious activity — investigate
    LOW = "LOW"             # Weak signal — log and monitor
    NOMINAL = "NOMINAL"     # Within expected baseline — no action


class ThreatCategory(str, Enum):
    BRUTE_FORCE = "Brute Force Attack"
    PRIVILEGE_ESCALATION = "Privilege Escalation Attempt"
    LATERAL_MOVEMENT = "Lateral Movement"
    DATA_EXFILTRATION = "Data Exfiltration"
    ROOTKIT = "Rootkit / Persistence"
    NETWORK_SCAN = "Network Port Scan"
    ANOMALOUS_TRAFFIC = "Anomalous Network Traffic"
    EXPLOIT = "Exploit Attempt"
    INSIDER_THREAT = "Insider Threat Indicator"
    UNKNOWN = "Unknown Threat Vector"


# ---------------------------------------------------------------------------
# Regex Signatures
# ---------------------------------------------------------------------------

AUTH_LOG_PATTERNS: list[dict[str, Any]] = [
    {
        "name": "SSH Brute Force",
        "pattern": re.compile(
            r"(Failed password|Invalid user|authentication failure).*from\s+(\d+\.\d+\.\d+\.\d+)",
            re.IGNORECASE,
        ),
        "category": ThreatCategory.BRUTE_FORCE,
        "base_score": 7.0,
        "extract_ip": True,
    },
    {
        "name": "Root Login Attempt",
        "pattern": re.compile(r"(Failed|Invalid).*root.*from\s+(\d+\.\d+\.\d+\.\d+)", re.IGNORECASE),
        "category": ThreatCategory.PRIVILEGE_ESCALATION,
        "base_score": 9.0,
        "extract_ip": True,
    },
    {
        "name": "Sudo Privilege Escalation",
        "pattern": re.compile(r"sudo.*COMMAND.*(/bin/su|/usr/bin/passwd|/bin/bash|/bin/sh)", re.IGNORECASE),
        "category": ThreatCategory.PRIVILEGE_ESCALATION,
        "base_score": 8.5,
        "extract_ip": False,
    },
    {
        "name": "New User Creation",
        "pattern": re.compile(r"(useradd|adduser).*new user", re.IGNORECASE),
        "category": ThreatCategory.INSIDER_THREAT,
        "base_score": 6.0,
        "extract_ip": False,
    },
    {
        "name": "SSH Key Added",
        "pattern": re.compile(r"Accepted publickey.*from\s+(\d+\.\d+\.\d+\.\d+)", re.IGNORECASE),
        "category": ThreatCategory.LATERAL_MOVEMENT,
        "base_score": 5.0,
        "extract_ip": True,
    },
    {
        "name": "PAM Auth Failure",
        "pattern": re.compile(r"pam_unix.*authentication failure.*rhost=(\S+)", re.IGNORECASE),
        "category": ThreatCategory.BRUTE_FORCE,
        "base_score": 6.5,
        "extract_ip": True,
    },
    {
        "name": "Exploit String Detected",
        "pattern": re.compile(r"(\.\.\/|%00|%2e%2e|;cmd=|union.*select|<script>|eval\(base64)", re.IGNORECASE),
        "category": ThreatCategory.EXPLOIT,
        "base_score": 9.5,
        "extract_ip": False,
    },
    {
        "name": "Mass Connection Scan",
        "pattern": re.compile(r"Connection closed by.*(\d+\.\d+\.\d+\.\d+).*\[preauth\]", re.IGNORECASE),
        "category": ThreatCategory.NETWORK_SCAN,
        "base_score": 7.5,
        "extract_ip": True,
    },
]

# ---------------------------------------------------------------------------
# Data Models
# ---------------------------------------------------------------------------


@dataclass
class ThreatEvent:
    """Represents a single detected threat event."""
    event_id: str
    timestamp: float
    category: str
    name: str
    description: str
    source_ip: str | None
    log_line: str
    raw_score: float             # 0–10 base severity
    confidence: float            # 0–1 confidence coefficient
    threat_level: str
    zero_trust_score: float      # 0–100 Zero-Trust composite score


@dataclass
class NetworkMetrics:
    """Snapshot of network traffic statistics."""
    timestamp: float
    bytes_in: int
    bytes_out: int
    connections_per_second: float
    unique_src_ips: int
    failed_auth_rate: float      # failures per minute
    avg_packet_size: float


@dataclass
class ThreatDetectionReport:
    """Full threat detection output."""
    scan_id: str
    hostname: str
    analysis_timestamp: float
    log_lines_analyzed: int
    events_detected: list[ThreatEvent] = field(default_factory=list)
    network_anomalies: list[dict[str, Any]] = field(default_factory=list)
    ip_reputation: dict[str, dict[str, Any]] = field(default_factory=dict)
    composite_threat_score: float = 0.0
    overall_threat_level: str = ThreatLevel.NOMINAL
    top_attacker_ip: str | None = None
    attack_timeline: list[dict[str, Any]] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)
    ai_summary: str = ""


# ---------------------------------------------------------------------------
# Statistical Helpers
# ---------------------------------------------------------------------------


def _mean(values: list[float]) -> float:
    return sum(values) / len(values) if values else 0.0


def _std_dev(values: list[float]) -> float:
    if len(values) < 2:
        return 0.0
    m = _mean(values)
    variance = sum((v - m) ** 2 for v in values) / (len(values) - 1)
    return math.sqrt(variance)


def _z_score(value: float, mean: float, std: float) -> float:
    if std == 0:
        return 0.0
    return (value - mean) / std


def _score_to_level(score: float) -> ThreatLevel:
    """Map a 0–100 composite score to a named threat level."""
    if score >= 85:
        return ThreatLevel.CRITICAL
    elif score >= 65:
        return ThreatLevel.HIGH
    elif score >= 40:
        return ThreatLevel.MEDIUM
    elif score >= 20:
        return ThreatLevel.LOW
    return ThreatLevel.NOMINAL


# ---------------------------------------------------------------------------
# IP Reputation Tracker
# ---------------------------------------------------------------------------


class IpReputationTracker:
    """
    Lightweight in-memory IP reputation system based on:
    - Hit frequency
    - Attack category diversity
    - Temporal clustering
    """

    def __init__(self) -> None:
        self._registry: dict[str, dict[str, Any]] = {}

    def record_hit(
        self,
        ip: str,
        category: str,
        score: float,
        timestamp: float,
    ) -> None:
        if ip not in self._registry:
            self._registry[ip] = {
                "hit_count": 0,
                "categories": set(),
                "total_score": 0.0,
                "first_seen": timestamp,
                "last_seen": timestamp,
                "reputation_score": 0.0,
            }
        entry = self._registry[ip]
        entry["hit_count"] += 1
        entry["categories"].add(category)
        entry["total_score"] += score
        entry["last_seen"] = timestamp
        # Reputation grows with frequency and category diversity
        diversity_bonus = len(entry["categories"]) * 5
        entry["reputation_score"] = min(
            100.0,
            (entry["total_score"] / entry["hit_count"]) * 10 + diversity_bonus,
        )

    def get_report(self) -> dict[str, dict[str, Any]]:
        result = {}
        for ip, data in self._registry.items():
            result[ip] = {
                **data,
                "categories": list(data["categories"]),
            }
        return result

    def top_attacker(self) -> str | None:
        if not self._registry:
            return None
        return max(
            self._registry,
            key=lambda ip: self._registry[ip]["reputation_score"],
        )


# ---------------------------------------------------------------------------
# Log Analyzer
# ---------------------------------------------------------------------------


class LogAnalyzer:
    """
    Parses log lines with regex signatures and applies frequency-window
    analysis to amplify recurring attack patterns.
    """

    def __init__(self) -> None:
        self._ip_tracker = IpReputationTracker()
        self._window: dict[str, list[float]] = {}   # ip -> [timestamps]
        self._events: list[ThreatEvent] = []
        self._event_counter = 0

    def _next_event_id(self) -> str:
        self._event_counter += 1
        return f"EVT-{self._event_counter:05d}"

    def _brute_force_amplifier(self, ip: str, now: float) -> float:
        """
        Sliding 5-minute window frequency amplifier.
        Returns a multiplier 1.0–3.0 based on repetition.
        """
        window_seconds = 300
        if ip not in self._window:
            self._window[ip] = []
        self._window[ip].append(now)
        # Prune old timestamps
        self._window[ip] = [t for t in self._window[ip] if now - t <= window_seconds]
        count = len(self._window[ip])
        # Logarithmic amplification
        return min(3.0, 1.0 + math.log1p(count) * 0.5)

    def analyze_line(self, line: str, timestamp: float | None = None) -> ThreatEvent | None:
        """Attempt to match a log line against all signatures."""
        now = timestamp or time.time()
        for sig in AUTH_LOG_PATTERNS:
            match = sig["pattern"].search(line)
            if not match:
                continue

            src_ip: str | None = None
            if sig["extract_ip"] and match.lastindex and match.lastindex >= 1:
                # Last capture group is usually the IP
                src_ip = match.group(match.lastindex)
                # Basic IP validation
                parts = src_ip.split(".")
                if len(parts) != 4:
                    src_ip = None

            # Compute confidence from pattern specificity and context
            confidence = 0.75
            if src_ip:
                confidence = min(1.0, confidence + 0.15)

            # Frequency amplification for IPs
            freq_mult = 1.0
            if src_ip:
                freq_mult = self._brute_force_amplifier(src_ip, now)

            raw_score = min(10.0, sig["base_score"] * freq_mult)
            zt_score = round(raw_score * confidence * 10, 2)  # Zero-Trust: 0–100
            level = _score_to_level(zt_score)

            if src_ip:
                self._ip_tracker.record_hit(src_ip, sig["category"].value, raw_score, now)

            event = ThreatEvent(
                event_id=self._next_event_id(),
                timestamp=now,
                category=sig["category"].value,
                name=sig["name"],
                description=f"Detected via pattern: {sig['name']}",
                source_ip=src_ip,
                log_line=line[:200],
                raw_score=round(raw_score, 2),
                confidence=confidence,
                threat_level=level.value,
                zero_trust_score=zt_score,
            )
            self._events.append(event)
            return event

        return None

    def get_ip_report(self) -> dict[str, dict[str, Any]]:
        return self._ip_tracker.get_report()

    def top_attacker(self) -> str | None:
        return self._ip_tracker.top_attacker()


# ---------------------------------------------------------------------------
# Network Anomaly Detector
# ---------------------------------------------------------------------------


def analyze_network_metrics(
    metrics_series: list[NetworkMetrics],
) -> list[dict[str, Any]]:
    """
    Applies Z-score analysis to a time-series of network metrics.
    Returns a list of anomaly records for metrics that deviate
    more than 2 standard deviations from the rolling mean.
    """
    if len(metrics_series) < 3:
        return []

    anomalies: list[dict[str, Any]] = []
    fields_to_analyze = [
        ("connections_per_second", "Connections per second spike", 2.0),
        ("bytes_in", "Inbound traffic volume spike", 2.5),
        ("bytes_out", "Outbound traffic spike (possible exfiltration)", 2.0),
        ("failed_auth_rate", "Authentication failure rate spike", 1.8),
        ("unique_src_ips", "Unusual diversity of source IPs (scan/botnet)", 2.0),
    ]

    for field_name, label, threshold in fields_to_analyze:
        values = [getattr(m, field_name) for m in metrics_series]
        mean = _mean(values)
        std = _std_dev(values)

        for i, (m, v) in enumerate(zip(metrics_series, values)):
            z = abs(_z_score(v, mean, std))
            if z > threshold:
                anomalies.append(
                    {
                        "metric": field_name,
                        "label": label,
                        "timestamp": m.timestamp,
                        "observed_value": v,
                        "baseline_mean": round(mean, 4),
                        "z_score": round(z, 3),
                        "threshold": threshold,
                        "severity": "HIGH" if z > threshold * 1.5 else "MEDIUM",
                    }
                )

    return anomalies


# ---------------------------------------------------------------------------
# Main Detection Engine
# ---------------------------------------------------------------------------


class AiThreatDetector:
    """
    Orchestrates log analysis, network anomaly detection, and
    IP reputation tracking into a unified Zero-Trust threat score.
    """

    def __init__(self) -> None:
        self._log_analyzer = LogAnalyzer()

    def analyze_logs(self, log_lines: list[str]) -> list[ThreatEvent]:
        """Analyze a batch of log lines and return all detected events."""
        events: list[ThreatEvent] = []
        for line in log_lines:
            event = self._log_analyzer.analyze_line(line)
            if event:
                events.append(event)
        return events

    def analyze_network(
        self, metrics_series: list[NetworkMetrics]
    ) -> list[dict[str, Any]]:
        return analyze_network_metrics(metrics_series)

    def compute_composite_score(
        self,
        events: list[ThreatEvent],
        network_anomalies: list[dict[str, Any]],
    ) -> float:
        """
        Zero-Trust composite score (0–100):
          - Weighted average of event ZT scores (70% weight)
          - Network anomaly contribution (30% weight)
        """
        event_score = 0.0
        if events:
            top_events = sorted(events, key=lambda e: e.zero_trust_score, reverse=True)[:5]
            event_score = _mean([e.zero_trust_score for e in top_events])

        net_score = 0.0
        if network_anomalies:
            severity_map = {"HIGH": 80, "MEDIUM": 50, "LOW": 20}
            scores = [severity_map.get(a.get("severity", "LOW"), 20) for a in network_anomalies]
            net_score = min(100.0, _mean(scores))

        composite = (event_score * 0.70) + (net_score * 0.30)
        return round(min(100.0, composite), 2)

    def generate_recommendations(
        self,
        events: list[ThreatEvent],
        anomalies: list[dict[str, Any]],
    ) -> list[str]:
        """Generate actionable security recommendations based on detected threats."""
        recs: list[str] = []
        categories_seen = {e.category for e in events}

        if ThreatCategory.BRUTE_FORCE.value in categories_seen:
            recs.append("🔒 Immediately deploy IP blocklist via iptables/nftables for top attacking IPs")
            recs.append("🔑 Enforce SSH key-only authentication — disable password auth")
            recs.append("🛡️ Install fail2ban with aggressive SSH jail configuration")

        if ThreatCategory.PRIVILEGE_ESCALATION.value in categories_seen:
            recs.append("⚠️  Review /etc/sudoers and remove unnecessary sudo grants")
            recs.append("🔍 Audit SUID/SGID binaries: find / -perm -4000 -type f")

        if ThreatCategory.EXPLOIT.value in categories_seen:
            recs.append("🚨 Exploit signatures detected — engage incident response immediately")
            recs.append("📋 Capture memory dump and preserve forensic evidence")

        if ThreatCategory.ROOTKIT.value in categories_seen:
            recs.append("☣️  Rootkit indicators found — system may be fully compromised")
            recs.append("💾 Boot from trusted media and perform offline forensic analysis")

        if any(a.get("metric") == "bytes_out" for a in anomalies):
            recs.append("📤 Outbound traffic anomaly — check for data exfiltration: tcpdump/wireshark")

        if not recs:
            recs.append("✅ No critical threats detected — continue routine monitoring")

        return recs


# ---------------------------------------------------------------------------
# Demo Data Generator
# ---------------------------------------------------------------------------

_DEMO_LOG_LINES = [
    "Oct 14 09:01:22 node01 sshd[1234]: Failed password for root from 185.224.128.67 port 49512 ssh2",
    "Oct 14 09:01:23 node01 sshd[1234]: Failed password for root from 185.224.128.67 port 49513 ssh2",
    "Oct 14 09:01:24 node01 sshd[1234]: Failed password for invalid user admin from 185.224.128.67 port 49514 ssh2",
    "Oct 14 09:01:25 node01 sshd[1235]: Failed password for root from 45.33.32.156 port 22001 ssh2",
    "Oct 14 09:01:30 node01 sshd[1236]: Failed password for invalid user ubuntu from 185.224.128.67 port 49520 ssh2",
    "Oct 14 09:02:01 node01 sudo: www-data : COMMAND=/bin/bash",
    "Oct 14 09:03:10 node01 sshd[1237]: Accepted publickey for deploy from 203.0.113.42 port 51234 ssh2",
    "Oct 14 09:05:00 node01 useradd[9999]: new user: name=backdoor, UID=0",
    "Oct 14 09:06:44 node01 kernel: EXT4-fs error: GET ../../../etc/passwd",
    "Oct 14 09:07:12 node01 sshd[1240]: Connection closed by 192.168.1.200 port 4590 [preauth]",
    "Oct 14 09:07:13 node01 sshd[1241]: Connection closed by 192.168.1.200 port 4591 [preauth]",
    "Oct 14 09:07:14 node01 sshd[1242]: Connection closed by 192.168.1.200 port 4592 [preauth]",
    "Oct 14 09:08:00 node01 sshd[1243]: pam_unix(sshd:auth): authentication failure; logname= uid=0 rhost=45.33.32.156",
    "Oct 14 09:09:15 node01 nginx: 185.220.101.34 GET /?id=1+UNION+SELECT+1,2,3-- HTTP/1.1",
    "Oct 14 09:10:00 node01 sshd[1250]: Failed password for root from 185.224.128.67 port 49550 ssh2",
]


def generate_demo_metrics() -> list[NetworkMetrics]:
    """Generates a synthetic time-series of network metrics with injected anomalies."""
    random.seed(42)
    baseline_cps = 120.0
    metrics = []
    for i in range(20):
        ts = time.time() - (20 - i) * 60
        # Inject anomalies at indices 10, 15
        cps = baseline_cps + random.gauss(0, 15)
        bytes_out = random.randint(50_000, 200_000)
        if i == 10:
            cps = baseline_cps * 8        # Port scan spike
        if i == 15:
            bytes_out = 12_000_000        # Data exfiltration spike
        metrics.append(
            NetworkMetrics(
                timestamp=ts,
                bytes_in=random.randint(100_000, 500_000),
                bytes_out=bytes_out,
                connections_per_second=max(0, cps),
                unique_src_ips=random.randint(5, 30) if i != 10 else 320,
                failed_auth_rate=random.uniform(0.1, 2.5),
                avg_packet_size=random.uniform(400, 1500),
            )
        )
    return metrics


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def run_detection(
    log_lines: list[str] | None = None,
    metrics_series: list[NetworkMetrics] | None = None,
    demo_mode: bool = False,
    hostname: str = "localhost",
) -> dict[str, Any]:
    """
    Execute the full AI threat detection pipeline.

    Parameters
    ----------
    log_lines      : Raw log lines to analyze (use demo_mode to auto-generate)
    metrics_series : Network metric snapshots for anomaly detection
    demo_mode      : Use synthetic data for demonstration
    hostname       : Node hostname for the report header

    Returns
    -------
    dict : Full threat detection report as a JSON-serializable dict
    """
    if demo_mode:
        log_lines = _DEMO_LOG_LINES
        metrics_series = generate_demo_metrics()
    else:
        log_lines = log_lines or _read_system_logs()
        metrics_series = metrics_series or []

    detector = AiThreatDetector()

    events = detector.analyze_logs(log_lines)
    anomalies = detector.analyze_network(metrics_series or [])
    composite_score = detector.compute_composite_score(events, anomalies)
    recommendations = detector.generate_recommendations(events, anomalies)
    overall_level = _score_to_level(composite_score)

    ip_report = detector._log_analyzer.get_ip_report()
    top_ip = detector._log_analyzer.top_attacker()

    # Build attack timeline
    timeline = sorted(
        [{"timestamp": e.timestamp, "event": e.name, "ip": e.source_ip, "level": e.threat_level}
         for e in events],
        key=lambda x: x["timestamp"],
    )

    # AI summary
    event_count = len(events)
    anomaly_count = len(anomalies)
    summary = (
        f"AI Sentinel analyzed {len(log_lines)} log entries and {len(metrics_series)} "
        f"network metric snapshots. Detected {event_count} threat event(s) and "
        f"{anomaly_count} network anomalie(s). Composite Zero-Trust Score: "
        f"{composite_score}/100 [{overall_level.value}]."
    )
    if top_ip:
        summary += f" Primary threat actor: {top_ip}."

    report = ThreatDetectionReport(
        scan_id=f"SCAN-{int(time.time())}",
        hostname=hostname,
        analysis_timestamp=time.time(),
        log_lines_analyzed=len(log_lines),
        events_detected=events,
        network_anomalies=anomalies,
        ip_reputation=ip_report,
        composite_threat_score=composite_score,
        overall_threat_level=overall_level.value,
        top_attacker_ip=top_ip,
        attack_timeline=timeline,
        recommendations=recommendations,
        ai_summary=summary,
    )

    return asdict(report)


def _read_system_logs(max_lines: int = 500) -> list[str]:
    """Read system log lines from common Linux log paths."""
    log_paths = [
        Path("/var/log/auth.log"),
        Path("/var/log/secure"),
        Path("/var/log/syslog"),
    ]
    lines: list[str] = []
    for path in log_paths:
        if path.exists():
            try:
                content = path.read_text(errors="replace")
                lines.extend(content.splitlines()[-max_lines:])
            except PermissionError:
                continue
    return lines[:max_lines]


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import argparse
    import json

    parser = argparse.ArgumentParser(description="AegisKube-SecOps AI Threat Detector")
    parser.add_argument("--demo", action="store_true", help="Run in demo mode with synthetic data")
    args = parser.parse_args()

    result = run_detection(demo_mode=args.demo)
    print(json.dumps(result, indent=2, default=str))
