"""Unit tests for AegisKube SecOps security sentinel and ledger integrity."""

import hashlib
import unittest
from typing import Any, Dict, List


class BlockchainLedger:
    """Simulates a secure blockchain-backed audit ledger."""

    chain: List[Dict[str, Any]]

    def __init__(self) -> None:
        self.chain = []
        self.create_block("Genesis Block", "0")

    def create_block(self, data: str, prev_hash: str) -> Dict[str, Any]:
        block_data = str(data) + str(prev_hash)
        block_hash = hashlib.sha256(block_data.encode()).hexdigest()
        block: Dict[str, Any] = {
            "index": len(self.chain) + 1,
            "data": data,
            "prev_hash": prev_hash,
            "hash": block_hash,
        }
        self.chain.append(block)
        return block

    def verify_integrity(self) -> bool:
        """Verifies cryptographic integrity of the blockchain ledger."""
        for i in range(1, len(self.chain)):
            current = self.chain[i]
            prev = self.chain[i - 1]
            if current["prev_hash"] != prev["hash"]:
                return False
            raw_data = str(current["data"]) + str(current["prev_hash"])
            recomputed_hash = hashlib.sha256(raw_data.encode()).hexdigest()
            if current["hash"] != recomputed_hash:
                return False
        return True


class ThreatDetector:
    """Detects known security threat signatures in system logs."""

    known_signatures: List[str]

    def __init__(self) -> None:
        self.known_signatures = [
            "sql_injection",
            "privilege_escalation",
            "unauthorized_root_access",
        ]

    def analyze(self, log_entry: str) -> str:
        """Analyzes log entry for threat patterns."""
        for sig in self.known_signatures:
            if sig in log_entry.lower():
                return f"ALERT: Threat detected - {sig}"
        return "SECURE"


class TestAegisKubeSecurity(unittest.TestCase):
    """Test cases for ledger integrity and threat detection."""

    def test_ledger_integrity_valid(self) -> None:
        ledger = BlockchainLedger()
        ledger.create_block("Audit Log A", ledger.chain[-1]["hash"])
        ledger.create_block("Audit Log B", ledger.chain[-1]["hash"])
        self.assertTrue(ledger.verify_integrity())

    def test_ledger_tampering_detection(self) -> None:
        ledger = BlockchainLedger()
        ledger.create_block("Audit Log A", ledger.chain[-1]["hash"])
        ledger.chain[1]["data"] = "Tampered Malicious Data"
        self.assertFalse(ledger.verify_integrity())

    def test_threat_detector_patterns(self) -> None:
        detector = ThreatDetector()
        self.assertEqual(
            detector.analyze("Normal system heartbeat"), "SECURE"
        )
        log_msg = "Detected privilege_escalation attempt"
        self.assertIn("ALERT", detector.analyze(log_msg))


if __name__ == "__main__":
    unittest.main()
