#!/usr/bin/env python3
"""
AegisKube-SecOps — Blockchain Audit Ledger
==========================================
Implements a lightweight, immutable SHA-256 hash-chain (blockchain) to store
security alerts so that audit logs cannot be tampered with after the fact.

Architecture
------------
  Block structure:
    ┌─────────────────────────────────────────┐
    │  index          : int                   │
    │  timestamp      : float (Unix epoch)    │
    │  alert_type     : str                   │
    │  payload        : dict                  │
    │  severity       : str                   │
    │  previous_hash  : str  (SHA-256 hex)    │
    │  nonce          : int  (proof-of-work)  │
    │  hash           : str  (SHA-256 hex)    │
    └─────────────────────────────────────────┘

  Each block's hash is computed over all fields including previous_hash,
  creating an unbreakable chain. Any tampering with any historical block
  immediately invalidates all subsequent block hashes.

  Optional proof-of-work (configurable difficulty) makes retroactive
  chain rewriting computationally prohibitive.

Author : Nawaz Sharif <contact@nawazsharif.in>
Role   : Senior Linux Developer | Kubernetes | Cybersecurity & Blockchain Architect | AI/ML & Python | DevOps & Cloud
License: Apache-2.0
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

GENESIS_HASH = "0" * 64          # Genesis block predecessor hash
DEFAULT_DIFFICULTY = 2            # Proof-of-work difficulty (leading zeros required)
LEDGER_VERSION = "1.0.0"


# ---------------------------------------------------------------------------
# Block
# ---------------------------------------------------------------------------


@dataclass
class Block:
    """
    Immutable unit of the audit ledger chain.

    Attributes
    ----------
    index          : Sequential block number (0 = genesis)
    timestamp      : Unix epoch float of block creation
    alert_type     : Category label for the security alert
    payload        : Arbitrary JSON-serializable alert data
    severity       : Alert severity level string
    previous_hash  : SHA-256 hash of the preceding block
    nonce          : Proof-of-work counter
    hash           : SHA-256 hash of this block (computed on mint)
    node_id        : Identifier of the node that generated the alert
    """

    index: int
    timestamp: float
    alert_type: str
    payload: dict[str, Any]
    severity: str
    previous_hash: str
    nonce: int = 0
    hash: str = field(default="", init=False)
    node_id: str = field(default_factory=lambda: os.environ.get("HOSTNAME", "aegiskube-node"))

    def __post_init__(self) -> None:
        """Compute initial hash immediately after construction."""
        self.hash = self.compute_hash()

    def _canonical_data(self, nonce: int | None = None) -> bytes:
        """
        Produce a deterministic, canonical byte representation
        of the block for hashing. Excludes the `hash` field itself.
        """
        data = {
            "index": self.index,
            "timestamp": self.timestamp,
            "alert_type": self.alert_type,
            "payload": self.payload,
            "severity": self.severity,
            "previous_hash": self.previous_hash,
            "nonce": nonce if nonce is not None else self.nonce,
            "node_id": self.node_id,
        }
        return json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def compute_hash(self, nonce: int | None = None) -> str:
        """Return SHA-256 hex digest of canonical block data."""
        return hashlib.sha256(self._canonical_data(nonce=nonce)).hexdigest()

    def mine(self, difficulty: int) -> None:
        """
        Perform proof-of-work mining: increment nonce until the block hash
        has the required number of leading zeros.

        Parameters
        ----------
        difficulty : Number of leading zero hex characters required
        """
        prefix = "0" * difficulty
        self.nonce = 0
        candidate = self.compute_hash(nonce=0)
        while not candidate.startswith(prefix):
            self.nonce += 1
            candidate = self.compute_hash(nonce=self.nonce)
        self.hash = candidate

    def is_valid_pow(self, difficulty: int) -> bool:
        """Verify this block satisfies the proof-of-work constraint."""
        return self.hash.startswith("0" * difficulty)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        # payload is already a dict
        return d


# ---------------------------------------------------------------------------
# Blockchain Ledger
# ---------------------------------------------------------------------------


class BlockchainAuditLedger:
    """
    Append-only, tamper-evident blockchain ledger for security alerts.

    Usage
    -----
    >>> ledger = BlockchainAuditLedger(difficulty=2)
    >>> ledger.add_alert("SSH_BRUTE_FORCE", {"source_ip": "1.2.3.4"}, severity="HIGH")
    >>> assert ledger.verify_integrity()
    >>> ledger.save("audit_ledger.json")
    """

    def __init__(
        self,
        difficulty: int = DEFAULT_DIFFICULTY,
        ledger_path: Path | str | None = None,
    ) -> None:
        """
        Parameters
        ----------
        difficulty   : Proof-of-work leading-zero requirement (0 = no PoW)
        ledger_path  : Optional file path to persist the ledger
        """
        self.difficulty = difficulty
        self.ledger_path = Path(ledger_path) if ledger_path else None
        self._chain: list[Block] = []
        self._create_genesis_block()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _create_genesis_block(self) -> None:
        """Create and append the immutable genesis block."""
        genesis = Block(
            index=0,
            timestamp=time.time(),
            alert_type="GENESIS",
            payload={
                "message": "AegisKube-SecOps Blockchain Audit Ledger — Genesis Block",
                "version": LEDGER_VERSION,
                "author": "Nawaz Sharif <contact@nawazsharif.in>",
            },
            severity="INFO",
            previous_hash=GENESIS_HASH,
        )
        if self.difficulty > 0:
            genesis.mine(self.difficulty)
        self._chain.append(genesis)

    @property
    def latest_block(self) -> Block:
        """Return the most recently added block."""
        return self._chain[-1]

    @property
    def chain_length(self) -> int:
        return len(self._chain)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def add_alert(
        self,
        alert_type: str,
        payload: dict[str, Any],
        severity: str = "INFO",
        node_id: str | None = None,
    ) -> Block:
        """
        Append a new security alert block to the chain.

        Parameters
        ----------
        alert_type : Category label (e.g. "SSH_BRUTE_FORCE", "ROOTKIT_DETECTED")
        payload    : JSON-serializable dict containing alert details
        severity   : One of INFO / LOW / MEDIUM / HIGH / CRITICAL
        node_id    : Override the originating node identifier

        Returns
        -------
        Block : The newly minted and appended block
        """
        block = Block(
            index=len(self._chain),
            timestamp=time.time(),
            alert_type=alert_type,
            payload=payload,
            severity=severity,
            previous_hash=self.latest_block.hash,
        )
        if node_id:
            block.node_id = node_id
        if self.difficulty > 0:
            block.mine(self.difficulty)
        self._chain.append(block)
        return block

    def verify_integrity(self) -> tuple[bool, list[str]]:
        """
        Verify the entire chain's cryptographic integrity.

        Checks:
          1. Each block's stored hash matches its recomputed hash
          2. Each block's previous_hash matches the actual hash of the prior block
          3. Proof-of-work constraint (if difficulty > 0)

        Returns
        -------
        (valid: bool, errors: list[str])
        """
        errors: list[str] = []

        for i, block in enumerate(self._chain):
            # Re-compute hash from block data
            recomputed = block.compute_hash()
            if recomputed != block.hash:
                errors.append(
                    f"Block #{i} hash mismatch: stored={block.hash[:16]}… "
                    f"recomputed={recomputed[:16]}…"
                )

            # Verify linkage (skip genesis)
            if i > 0:
                expected_prev = self._chain[i - 1].hash
                if block.previous_hash != expected_prev:
                    errors.append(
                        f"Block #{i} chain break: previous_hash={block.previous_hash[:16]}… "
                        f"expected={expected_prev[:16]}…"
                    )

            # Verify proof-of-work
            if self.difficulty > 0 and not block.is_valid_pow(self.difficulty):
                errors.append(f"Block #{i} fails proof-of-work check")

        return len(errors) == 0, errors

    def get_blocks_by_severity(self, severity: str) -> list[Block]:
        """Return all blocks matching a given severity level."""
        return [b for b in self._chain if b.severity == severity.upper()]

    def get_blocks_by_type(self, alert_type: str) -> list[Block]:
        """Return all blocks of a given alert type."""
        return [b for b in self._chain if b.alert_type == alert_type.upper()]

    def to_dict(self) -> dict[str, Any]:
        """Serialize the full chain to a JSON-compatible dictionary."""
        return {
            "ledger_version": LEDGER_VERSION,
            "chain_length": self.chain_length,
            "difficulty": self.difficulty,
            "chain_valid": self.verify_integrity()[0],
            "blocks": [b.to_dict() for b in self._chain],
        }

    def save(self, path: Path | str | None = None) -> Path:
        """
        Persist the ledger to a JSON file.

        Parameters
        ----------
        path : Override the default ledger_path

        Returns
        -------
        Path : The file that was written
        """
        target = Path(path) if path else self.ledger_path
        if not target:
            raise ValueError("No ledger file path configured")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(self.to_dict(), indent=2, default=str))
        return target

    @classmethod
    def load(cls, path: Path | str) -> "BlockchainAuditLedger":
        """
        Load a previously saved ledger from disk and validate integrity.

        Raises
        ------
        ValueError   : If the chain fails integrity verification after loading
        FileNotFoundError : If the ledger file does not exist
        """
        path = Path(path)
        if not path.exists():
            raise FileNotFoundError(f"Ledger file not found: {path}")

        raw = json.loads(path.read_text())
        ledger = cls(difficulty=raw.get("difficulty", DEFAULT_DIFFICULTY), ledger_path=path)
        # Replace genesis block with loaded chain
        ledger._chain = []
        for block_data in raw["blocks"]:
            b = Block(
                index=block_data["index"],
                timestamp=block_data["timestamp"],
                alert_type=block_data["alert_type"],
                payload=block_data["payload"],
                severity=block_data["severity"],
                previous_hash=block_data["previous_hash"],
            )
            b.nonce = block_data["nonce"]
            b.hash = block_data["hash"]
            b.node_id = block_data.get("node_id", "unknown")
            ledger._chain.append(b)

        valid, errors = ledger.verify_integrity()
        if not valid:
            raise ValueError(f"Ledger integrity check FAILED:\n" + "\n".join(errors))
        return ledger

    def print_chain(self, max_blocks: int = 10) -> None:
        """Pretty-print a summary of the chain (useful for CLI inspection)."""
        print(f"\n{'═' * 70}")
        print(f"  ⛓  AegisKube-SecOps Blockchain Audit Ledger  (length={self.chain_length})")
        print(f"{'═' * 70}")
        for block in self._chain[-max_blocks:]:
            ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(block.timestamp))
            sev_icon = {"CRITICAL": "☣", "HIGH": "🔴", "MEDIUM": "🟠", "LOW": "🟡", "INFO": "🟢"}.get(
                block.severity, "⚪"
            )
            print(
                f"  Block #{block.index:04d} | {ts} | {sev_icon} {block.severity:8s} | "
                f"{block.alert_type:30s} | Hash: {block.hash[:12]}…"
            )
        print(f"{'═' * 70}\n")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="AegisKube Blockchain Audit Ledger")
    parser.add_argument("--demo", action="store_true", help="Run demo: add sample alerts and verify")
    parser.add_argument("--verify", metavar="FILE", help="Load and verify a saved ledger JSON file")
    args = parser.parse_args()

    if args.verify:
        try:
            ledger = BlockchainAuditLedger.load(args.verify)
            valid, errors = ledger.verify_integrity()
            if valid:
                print(f"✅ Ledger {args.verify} is VALID ({ledger.chain_length} blocks)")
            else:
                print(f"❌ Ledger TAMPERED! Errors:\n" + "\n".join(errors))
        except Exception as e:
            print(f"Error: {e}")
    else:
        # Demo mode
        ledger = BlockchainAuditLedger(difficulty=2)
        ledger.add_alert("SSH_BRUTE_FORCE", {"source_ip": "185.224.128.67", "attempts": 342}, "HIGH")
        ledger.add_alert("ROOTKIT_DETECTED", {"path": "/dev/.reptile", "module": "reptile"}, "CRITICAL")
        ledger.add_alert("PRIVILEGE_ESCALATION", {"user": "www-data", "command": "/bin/bash"}, "HIGH")
        ledger.add_alert("SYSCTL_VIOLATION", {"param": "kernel.randomize_va_space", "actual": "0"}, "MEDIUM")
        ledger.print_chain()
        valid, errors = ledger.verify_integrity()
        status = "✅ VALID" if valid else f"❌ TAMPERED: {errors}"
        print(f"Chain Integrity: {status}")
        print(json.dumps(ledger.to_dict(), indent=2, default=str))
