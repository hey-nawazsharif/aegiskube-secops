#!/usr/bin/env python3
"""
AegisKube-SecOps — Main CLI Entry Point & Live Dashboard
=========================================================
Ties together the Linux Hardening Auditor, AI Threat Detector, and
Blockchain Audit Ledger into a unified security sentinel with a
rich terminal dashboard.

Usage
-----
  python3 src/main.py --demo                  # Simulated demo mode
  python3 src/main.py --audit                 # Linux hardening audit only
  python3 src/main.py --detect --log /var/log/auth.log
  python3 src/main.py --full --demo           # Full pipeline demo
  python3 src/main.py --verify-ledger ledger.json

Author : Nawaz Sharif <contact@nawazsharif.in>
Role   : Senior Linux Developer | Kubernetes | Cybersecurity & Blockchain Architect | AI/ML & Python | DevOps & Cloud
License: Apache-2.0
"""

from __future__ import annotations

import argparse
import json
import math
import os
import socket
import sys
import time
from pathlib import Path
from typing import Any

# Ensure src/ is on PYTHONPATH when invoked directly
sys.path.insert(0, str(Path(__file__).parent))

from linux_hardening_audit import run_audit
from ai_threat_detector import run_detection, NetworkMetrics, generate_demo_metrics
from blockchain_audit_ledger import BlockchainAuditLedger

# ---------------------------------------------------------------------------
# Version & Branding
# ---------------------------------------------------------------------------

VERSION = "1.0.0"
BANNER = r"""
  ___          _    _      _  __     _          ____            ___
 / _ \   ___  (_)  | | __ | |/ /   _  | |__   ___/ ___|  ___  ___ / _ \  _ __  ___
| | | | / _ \ | |  | |/ / | ' /   | | | '_ \ / _ \___ \ / _ \/ __| | | || '_ \/ __|
| |_| ||  __/ | |  |   <  | . \   | | | |_) |  __/___) |  __/ (__| |_| || |_) \__ \
 \__\_\ \___| |_|  |_|\_\ |_|\_\  |_| |_.__/ \___|____/ \___|\___|\___/ | .__/|___/
                                                                           |_|
"""

SEPARATOR = "═" * 78

# ANSI colours (fallback to empty strings on non-TTY)
_IS_TTY = hasattr(sys.stdout, "isatty") and sys.stdout.isatty()


def _c(code: str) -> str:
    return code if _IS_TTY else ""


RED     = _c("\033[0;31m")
GREEN   = _c("\033[0;32m")
YELLOW  = _c("\033[1;33m")
CYAN    = _c("\033[0;36m")
MAGENTA = _c("\033[0;35m")
BLUE    = _c("\033[0;34m")
BOLD    = _c("\033[1m")
DIM     = _c("\033[2m")
RESET   = _c("\033[0m")

# ---------------------------------------------------------------------------
# Terminal Helpers
# ---------------------------------------------------------------------------


def _print_banner() -> None:
    print(f"{CYAN}{BANNER}{RESET}")
    print(f"{BOLD}{SEPARATOR}{RESET}")
    print(f"  {BOLD}AegisKube-SecOps v{VERSION}{RESET} — High-Performance Linux & Kubernetes Cybersecurity Sentinel")
    print(f"  {DIM}Author: Nawaz Sharif <contact@nawazsharif.in>{RESET}")
    print(f"  {DIM}AI-Driven Anomaly Detection │ Blockchain Audit Ledger │ Zero-Trust Scoring{RESET}")
    print(f"{BOLD}{SEPARATOR}{RESET}\n")


def _section(title: str) -> None:
    print(f"\n{BOLD}{CYAN}{'─' * 78}{RESET}")
    print(f"{BOLD}{CYAN}  {title}{RESET}")
    print(f"{BOLD}{CYAN}{'─' * 78}{RESET}")


def _severity_color(severity: str) -> str:
    mapping = {
        "CRITICAL": RED,
        "HIGH": MAGENTA,
        "MEDIUM": YELLOW,
        "LOW": CYAN,
        "OK": GREEN,
        "INFO": BLUE,
        "NOMINAL": GREEN,
    }
    return mapping.get(severity.upper(), RESET)


def _severity_icon(severity: str) -> str:
    mapping = {
        "CRITICAL": "☣ ",
        "HIGH":     "🔴",
        "MEDIUM":   "🟠",
        "LOW":      "🟡",
        "OK":       "✅",
        "INFO":     "ℹ️ ",
        "NOMINAL":  "✅",
    }
    return mapping.get(severity.upper(), "⚪")


def _risk_bar(score: float, width: int = 30) -> str:
    """Render a visual ASCII risk bar."""
    filled = math.ceil((score / 100) * width)
    empty = width - filled
    if score >= 85:
        colour = RED
    elif score >= 65:
        colour = MAGENTA
    elif score >= 40:
        colour = YELLOW
    elif score >= 20:
        colour = CYAN
    else:
        colour = GREEN
    return f"{colour}{'█' * filled}{'░' * empty}{RESET} {score:.1f}/100"


def _timestamp_str(ts: float) -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(ts))


# ---------------------------------------------------------------------------
# Report Renderers
# ---------------------------------------------------------------------------


def render_audit_report(audit: dict[str, Any]) -> None:
    _section("🛡️  LINUX HARDENING AUDIT REPORT")

    print(f"\n  Host     : {BOLD}{audit['hostname']}{RESET}")
    print(f"  OS       : {audit['platform'][:60]}")
    print(f"  Kernel   : {audit['kernel_version']}")
    print(f"  Audited  : {_timestamp_str(audit['audit_timestamp'])}")
    print(f"\n  Risk Score : {_risk_bar(audit['overall_risk_score'])}")
    print(f"  Critical   : {RED}{audit['critical_count']}{RESET}  "
          f"High: {MAGENTA}{audit['high_count']}{RESET}  "
          f"Medium: {YELLOW}{audit['medium_count']}{RESET}  "
          f"Low: {CYAN}{audit['low_count']}{RESET}")

    # Sysctl findings
    print(f"\n  {BOLD}Kernel Parameter Audit (sysctl):{RESET}")
    print(f"  {'Parameter':<42} {'Expected':<8} {'Actual':<8} {'Status'}")
    print(f"  {'─' * 75}")
    for f in audit["sysctl_findings"]:
        icon = _severity_icon(f["severity"])
        col  = _severity_color(f["severity"])
        status_label = f"{col}{f['severity']:8s}{RESET}"
        print(f"  {f['parameter']:<42} {f['expected']:<8} {f['actual']:<8} {icon} {status_label}")

    # Network sockets
    print(f"\n  {BOLD}Active Network Listeners:{RESET}")
    sockets = audit.get("network_sockets", [])
    if sockets:
        for s in sockets:
            flag = f"{RED} ⚠  {s['risk_reason']}{RESET}" if s["risk_flag"] else f"{GREEN}  OK{RESET}"
            print(f"  {s['protocol']:<5} {s['local_address']:<20} :{s['local_port']:<6}{flag}")
    else:
        print(f"  {DIM}  No listeners detected (or insufficient privileges){RESET}")

    # Rootkit findings
    print(f"\n  {BOLD}Rootkit Indicators:{RESET}")
    for r in audit["rootkit_findings"]:
        icon = f"{RED}☣  DETECTED{RESET}" if r["found"] else f"{GREEN}✓  Clean{RESET}"
        print(f"  {r['indicator']:<20} → {icon}  {DIM}{r['location']}{RESET}")

    # SSH findings
    print(f"\n  {BOLD}SSH Configuration Audit:{RESET}")
    for s in audit["ssh_findings"]:
        icon = _severity_icon("OK" if s["compliant"] else "HIGH")
        col  = GREEN if s["compliant"] else RED
        status = f"{col}{'PASS' if s['compliant'] else 'FAIL'}{RESET}"
        print(f"  {s['option']:<30} Expected: {s['expected']:<8} Actual: {s['actual']:<20} {icon} {status}")

    print(f"\n  {BOLD}Summary:{RESET} {audit['summary']}")


def render_ai_report(detection: dict[str, Any]) -> None:
    _section("🤖  AI THREAT DETECTION — ZERO-TRUST ANALYSIS")

    level = detection["overall_threat_level"]
    score = detection["composite_threat_score"]
    col   = _severity_color(level)

    print(f"\n  Scan ID  : {BOLD}{detection['scan_id']}{RESET}")
    print(f"  Analyzed : {detection['log_lines_analyzed']} log lines")
    print(f"  Timestamp: {_timestamp_str(detection['analysis_timestamp'])}")
    print(f"\n  {BOLD}Composite Zero-Trust Score:{RESET} {_risk_bar(score)}")
    print(f"  {BOLD}Overall Threat Level:{RESET}       {col}{_severity_icon(level)} {level}{RESET}")

    if detection.get("top_attacker_ip"):
        print(f"  {BOLD}Primary Threat Actor:{RESET}      {RED}{detection['top_attacker_ip']}{RESET}")

    # Threat events
    events = detection.get("events_detected", [])
    print(f"\n  {BOLD}Detected Threat Events ({len(events)}):{RESET}")
    if events:
        print(f"  {'Event ID':<12} {'Level':<10} {'Category':<35} {'ZT Score':<10} {'Source IP'}")
        print(f"  {'─' * 75}")
        for e in events:
            col = _severity_color(e["threat_level"])
            ip_str = e.get("source_ip") or "N/A"
            print(
                f"  {e['event_id']:<12} "
                f"{col}{e['threat_level']:<10}{RESET} "
                f"{e['category']:<35} "
                f"{e['zero_trust_score']:<10.1f} "
                f"{ip_str}"
            )
    else:
        print(f"  {GREEN}  No threats detected.{RESET}")

    # Network anomalies
    anomalies = detection.get("network_anomalies", [])
    print(f"\n  {BOLD}Network Anomalies ({len(anomalies)}):{RESET}")
    if anomalies:
        for a in anomalies:
            col = _severity_color(a.get("severity", "LOW"))
            print(
                f"  {col}{_severity_icon(a['severity'])}{RESET}  "
                f"{a['label']:<45} Z={a['z_score']:.2f}  "
                f"(baseline={a['baseline_mean']:.1f}, observed={a['observed_value']:.1f})"
            )
    else:
        print(f"  {GREEN}  No network anomalies detected.{RESET}")

    # IP reputation
    ip_rep = detection.get("ip_reputation", {})
    if ip_rep:
        print(f"\n  {BOLD}IP Reputation Report:{RESET}")
        print(f"  {'IP Address':<20} {'Hits':<6} {'Rep.Score':<10} {'Categories'}")
        print(f"  {'─' * 70}")
        for ip, data in sorted(ip_rep.items(), key=lambda x: -x[1]["reputation_score"]):
            cats = ", ".join(data.get("categories", []))
            print(
                f"  {RED}{ip:<20}{RESET} "
                f"{data['hit_count']:<6} "
                f"{data['reputation_score']:<10.1f} "
                f"{cats}"
            )

    # Recommendations
    print(f"\n  {BOLD}Security Recommendations:{RESET}")
    for rec in detection.get("recommendations", []):
        print(f"    {rec}")

    print(f"\n  {BOLD}AI Summary:{RESET}")
    print(f"  {DIM}{detection['ai_summary']}{RESET}")


def render_blockchain_report(ledger: BlockchainAuditLedger) -> None:
    _section("⛓️  BLOCKCHAIN AUDIT LEDGER")

    valid, errors = ledger.verify_integrity()
    status_str = f"{GREEN}✅ VERIFIED — Chain Integrity INTACT{RESET}" if valid else \
                 f"{RED}❌ TAMPERED — Chain Integrity FAILED{RESET}"

    print(f"\n  Chain Length : {BOLD}{ledger.chain_length}{RESET} blocks")
    print(f"  Difficulty   : {ledger.difficulty} leading zeros (proof-of-work)")
    print(f"  Genesis Hash : {DIM}{ledger._chain[0].hash[:32]}…{RESET}")
    print(f"  Latest Hash  : {DIM}{ledger.latest_block.hash[:32]}…{RESET}")
    print(f"  Integrity    : {status_str}")

    if errors:
        for err in errors:
            print(f"  {RED}  ✗ {err}{RESET}")

    print(f"\n  {BOLD}Recent Blocks:{RESET}")
    print(f"  {'#':<6} {'Timestamp':<22} {'Severity':<10} {'Alert Type':<35} {'Hash (prefix)'}")
    print(f"  {'─' * 95}")
    for block in ledger._chain[-8:]:
        ts  = _timestamp_str(block.timestamp)
        col = _severity_color(block.severity)
        print(
            f"  {block.index:<6} "
            f"{ts:<22} "
            f"{col}{block.severity:<10}{RESET} "
            f"{block.alert_type:<35} "
            f"{DIM}{block.hash[:16]}…{RESET}"
        )


# ---------------------------------------------------------------------------
# Pipeline
# ---------------------------------------------------------------------------


def run_full_pipeline(
    demo_mode: bool = True,
    log_file: str | None = None,
    ledger_path: str | None = None,
    save_json: str | None = None,
) -> dict[str, Any]:
    """
    Execute the complete AegisKube-SecOps pipeline:
      1. Linux Hardening Audit
      2. AI Threat Detection
      3. Blockchain Ledger ingestion
      4. Terminal Dashboard Render
    """
    hostname = socket.gethostname()
    pipeline_start = time.time()

    _print_banner()
    print(f"  {BOLD}Starting AegisKube-SecOps Security Sentinel{RESET}")
    print(f"  Mode: {BOLD}{'DEMO' if demo_mode else 'LIVE'}{RESET}  |  Host: {hostname}  |  Time: {_timestamp_str(pipeline_start)}\n")

    # ── Step 1: Linux Hardening Audit ─────────────────────────────────────
    print(f"  {CYAN}[1/3]{RESET} Running Linux Hardening Audit…", end="", flush=True)
    audit_result = run_audit(demo_mode=demo_mode)
    print(f" {GREEN}Done{RESET}")

    # ── Step 2: AI Threat Detection ───────────────────────────────────────
    print(f"  {CYAN}[2/3]{RESET} Running AI Threat Detection Engine…", end="", flush=True)
    log_lines: list[str] | None = None
    if log_file and not demo_mode:
        lp = Path(log_file)
        if lp.exists():
            log_lines = lp.read_text(errors="replace").splitlines()[-500:]
    detection_result = run_detection(
        log_lines=log_lines,
        demo_mode=demo_mode,
        hostname=hostname,
    )
    print(f" {GREEN}Done{RESET}")

    # ── Step 3: Blockchain Ledger ─────────────────────────────────────────
    print(f"  {CYAN}[3/3]{RESET} Committing alerts to Blockchain Ledger…", end="", flush=True)
    ledger = BlockchainAuditLedger(difficulty=2, ledger_path=ledger_path)

    # Ingest high-severity threat events into the ledger
    events = detection_result.get("events_detected", [])
    for event in events:
        if event.get("zero_trust_score", 0) >= 30:
            ledger.add_alert(
                alert_type=event["category"].replace(" ", "_").upper(),
                payload={
                    "event_id": event["event_id"],
                    "name": event["name"],
                    "source_ip": event.get("source_ip"),
                    "zero_trust_score": event["zero_trust_score"],
                    "log_line": event["log_line"][:120],
                },
                severity=event["threat_level"],
                node_id=hostname,
            )

    # Ingest audit-level findings
    if audit_result.get("critical_count", 0) > 0 or audit_result.get("overall_risk_score", 0) > 50:
        ledger.add_alert(
            alert_type="LINUX_HARDENING_VIOLATION",
            payload={
                "risk_score": audit_result["overall_risk_score"],
                "critical": audit_result["critical_count"],
                "high": audit_result["high_count"],
                "summary": audit_result["summary"],
            },
            severity="HIGH" if audit_result["overall_risk_score"] >= 50 else "MEDIUM",
            node_id=hostname,
        )

    for anomaly in detection_result.get("network_anomalies", []):
        ledger.add_alert(
            alert_type="NETWORK_ANOMALY",
            payload=anomaly,
            severity=anomaly.get("severity", "MEDIUM"),
            node_id=hostname,
        )
    print(f" {GREEN}Done ({ledger.chain_length} blocks){RESET}")

    # ── Render Dashboard ──────────────────────────────────────────────────
    render_audit_report(audit_result)
    render_ai_report(detection_result)
    render_blockchain_report(ledger)

    # ── Save outputs ──────────────────────────────────────────────────────
    if ledger_path:
        saved = ledger.save()
        print(f"\n  {GREEN}💾 Ledger saved → {saved}{RESET}")

    if save_json:
        output = {
            "aegiskube_version": VERSION,
            "pipeline_timestamp": pipeline_start,
            "audit": audit_result,
            "detection": detection_result,
            "ledger": ledger.to_dict(),
        }
        Path(save_json).write_text(json.dumps(output, indent=2, default=str))
        print(f"  {GREEN}📄 JSON report saved → {save_json}{RESET}")

    duration = time.time() - pipeline_start
    print(f"\n{BOLD}{SEPARATOR}{RESET}")
    print(f"  {GREEN}✅ AegisKube-SecOps scan complete in {duration:.2f}s{RESET}")
    print(f"  {DIM}Author: Nawaz Sharif | contact@nawazsharif.in | Dubai, UAE{RESET}")
    print(f"{BOLD}{SEPARATOR}{RESET}\n")

    return {
        "audit": audit_result,
        "detection": detection_result,
        "ledger_blocks": ledger.chain_length,
        "ledger_valid": ledger.verify_integrity()[0],
    }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="aegiskube",
        description=(
            "AegisKube-SecOps — High-Performance Linux & Kubernetes Cybersecurity Sentinel\n"
            "Author: Nawaz Sharif <contact@nawazsharif.in>"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 src/main.py --demo                  # Full pipeline demo (safe on any OS)
  python3 src/main.py --audit                 # Linux hardening audit only
  python3 src/main.py --detect                # AI threat scan (reads /var/log/auth.log)
  python3 src/main.py --full                  # Full pipeline on live system
  python3 src/main.py --demo --save-json out.json
  python3 src/main.py --verify-ledger ledger.json
        """,
    )
    parser.add_argument("--version", action="version", version=f"AegisKube-SecOps {VERSION}")

    mode_group = parser.add_mutually_exclusive_group()
    mode_group.add_argument(
        "--demo", action="store_true",
        help="Run full pipeline with synthetic demo data (no root required)",
    )
    mode_group.add_argument(
        "--audit", action="store_true",
        help="Run only the Linux hardening audit on the live system",
    )
    mode_group.add_argument(
        "--detect", action="store_true",
        help="Run only the AI threat detection engine on live logs",
    )
    mode_group.add_argument(
        "--full", action="store_true",
        help="Run full pipeline on the live system (requires root for full access)",
    )
    mode_group.add_argument(
        "--verify-ledger", metavar="FILE",
        help="Load and cryptographically verify a saved blockchain ledger JSON",
    )

    parser.add_argument(
        "--log", metavar="FILE",
        help="Path to a log file to analyze (default: /var/log/auth.log)",
    )
    parser.add_argument(
        "--ledger", metavar="FILE",
        help="Path to save/load the blockchain ledger JSON",
        default="aegiskube_ledger.json",
    )
    parser.add_argument(
        "--save-json", metavar="FILE",
        help="Save complete JSON pipeline report to a file",
    )
    parser.add_argument(
        "--quiet", action="store_true",
        help="Suppress dashboard output, only print JSON result",
    )

    return parser


def main() -> int:
    parser = _build_parser()

    # Handle case where no args given
    if len(sys.argv) == 1:
        parser.print_help()
        print(f"\n{YELLOW}💡 Tip: Run with --demo to see a live simulation!{RESET}")
        return 0

    args = parser.parse_args()

    # ── Verify ledger mode ─────────────────────────────────────────────────
    if args.verify_ledger:
        try:
            ledger = BlockchainAuditLedger.load(args.verify_ledger)
            valid, errors = ledger.verify_integrity()
            if valid:
                print(f"\n{GREEN}✅ Ledger VALID — {ledger.chain_length} blocks, chain integrity INTACT{RESET}\n")
                ledger.print_chain()
                return 0
            else:
                print(f"\n{RED}❌ Ledger TAMPERED!{RESET}")
                for err in errors:
                    print(f"  {RED}✗ {err}{RESET}")
                return 1
        except Exception as exc:
            print(f"{RED}Error: {exc}{RESET}", file=sys.stderr)
            return 2

    # ── Audit only ─────────────────────────────────────────────────────────
    if args.audit:
        _print_banner()
        result = run_audit(demo_mode=False)
        render_audit_report(result)
        if args.save_json:
            Path(args.save_json).write_text(json.dumps(result, indent=2, default=str))
        return 0

    # ── Detect only ────────────────────────────────────────────────────────
    if args.detect:
        _print_banner()
        log_lines = None
        if args.log:
            lp = Path(args.log)
            if lp.exists():
                log_lines = lp.read_text(errors="replace").splitlines()[-500:]
        result = run_detection(log_lines=log_lines, demo_mode=False)
        render_ai_report(result)
        if args.save_json:
            Path(args.save_json).write_text(json.dumps(result, indent=2, default=str))
        return 0

    # ── Full / Demo pipeline ───────────────────────────────────────────────
    demo = args.demo or not args.full
    result = run_full_pipeline(
        demo_mode=demo,
        log_file=args.log,
        ledger_path=args.ledger if args.ledger else None,
        save_json=args.save_json,
    )

    if args.quiet:
        print(json.dumps(result, indent=2, default=str))

    return 0


if __name__ == "__main__":
    sys.exit(main())
