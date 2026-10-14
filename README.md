# AegisKube SecOps

AegisKube SecOps is an enterprise-grade Kubernetes security monitoring, Linux hardening audit, and AI-driven threat detection framework featuring immutable blockchain-based audit logging.

## Architecture

```mermaid
graph TD
    A[Linux Hardening Audit] --> B[Blockchain Audit Ledger]
    C[AI Threat Detector] --> B
    B --> D[Kubernetes Security DaemonSet]
    D --> E[Security Monitoring Namespace]
```

## Clone Repository

```bash
git clone [https://github.com/hey-nawazsharif/aegiskube-secops.git](https://github.com/hey-nawazsharif/aegiskube-secops.git)
cd aegiskube-secops
```

## Quick Start

To set up the environment and run the core verification script:
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python3 src/test_sentinel.py
```
