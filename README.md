# AegisKube-SecOps

[![CI Status](https://github.com/hey-nawazsharif/aegiskube-secops/actions/workflows/secops-ci.yml/badge.svg)](https://github.com/hey-nawazsharif/aegiskube-secops/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/downloads/)

A zero-trust security sentinel for Linux and Kubernetes combining host hardening, anomaly detection, and a tamper-evident audit ledger.

---

## Quick Start

```bash
git clone https://github.com/hey-nawazsharif/aegiskube-secops.git
cd aegiskube-secops
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python3 tests/test_sentinel.py
```

---

## Roadmap & Implementation Status

- [x] **Project Scaffolding**: Repo structure, tests, CI workflow, Dockerfile.
- [ ] **Core Linux Hardening**: Host configuration hardening, kernel module restrictions, file permission enforcement.
- [x] **Hash-Chain Audit Ledger**: Block chaining, previous-hash verification, tamper detection.
- [ ] **File Integrity Monitor (FIM)**: Baseline hashes for critical paths (`/etc/passwd`, `/etc/shadow`).
- [ ] **Privilege Escalation Parser**: SUID binary scanning and `auth.log` sudo event parsing.
- [ ] **AI Anomaly Detection**: scikit-learn `IsolationForest` on process and syscall frequency.
- [ ] **K8s DaemonSet Deployment**: Cluster-wide deployment manifests.

---

## Demo Output

```bash
$ python3 src/blockchain_audit_ledger.py --demo
```

```text
══════════════════════════════════════════════════════════════════════
  ⛓  AegisKube-SecOps Blockchain Audit Ledger  (length=5)
══════════════════════════════════════════════════════════════════════
  Block #0000 | 2026-10-15 14:03:15 | 🟢 INFO     | GENESIS                        | Hash: 00b287c50e83…
  Block #0001 | 2026-10-15 14:03:15 | 🔴 HIGH     | SSH_BRUTE_FORCE                | Hash: 005ca4529629…
  Block #0002 | 2026-10-15 14:03:15 | ☣ CRITICAL | ROOTKIT_DETECTED               | Hash: 00132474259e…
  Block #0003 | 2026-10-15 14:03:15 | 🔴 HIGH     | PRIVILEGE_ESCALATION           | Hash: 00468d262777…
  Block #0004 | 2026-10-15 14:03:15 | 🟠 MEDIUM   | SYSCTL_VIOLATION               | Hash: 0047e7ece283…
══════════════════════════════════════════════════════════════════════

Chain Integrity: ✅ VALID
```

---

## License

MIT
