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
- [ ] **Hash-Chain Audit Ledger**: Block chaining, previous-hash verification, tamper detection.
- [ ] **File Integrity Monitor (FIM)**: Baseline hashes for critical paths (`/etc/passwd`, `/etc/shadow`).
- [ ] **Privilege Escalation Parser**: SUID binary scanning and `auth.log` sudo event parsing.
- [ ] **AI Anomaly Detection**: scikit-learn `IsolationForest` on process and syscall frequency.
- [ ] **K8s DaemonSet Deployment**: Cluster-wide deployment manifests.

---

## Sample CLI Output (Target Design)

```bash
$ python3 -m aegiskube.sentinel --scan
[INFO] Initializing AegisKube-SecOps Sentinel...
[INFO] Loading File Integrity Baseline... [OK]
[WARN] [FIM] Unauthorized modification detected on /etc/passwd!
[ALERT] Privilege escalation vector identified via sudo log!
[SUCCESS] Audit block appended to ledger.
```

---

## License

MIT
