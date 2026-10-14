import unittest
import hashlib

class BlockchainLedger:
    def __init__(self):
        self.chain = []
        self.create_block("Genesis Block", "0")

    def create_block(self, data, prev_hash):
        block = {
            "index": len(self.chain) + 1,
            "data": data,
            "prev_hash": prev_hash,
            "hash": hashlib.sha256((str(data) + str(prev_hash)).encode()).hexdigest()
        }
        self.chain.append(block)
        return block

    def verify_integrity(self):
        for i in range(1, len(self.chain)):
            current = self.chain[i]
            prev = self.chain[i-1]
            if current["prev_hash"] != prev["hash"]:
                return False
            recomputed_hash = hashlib.sha256((str(current["data"]) + str(current["prev_hash"])).encode()).hexdigest()
            if current["hash"] != recomputed_hash:
                return False
        return True

class ThreatDetector:
    def __init__(self):
        self.known_signatures = ["sql_injection", "privilege_escalation", "unauthorized_root_access"]

    def analyze(self, log_entry):
        for sig in self.known_signatures:
            if sig in log_entry.lower():
                return f"ALERT: Threat detected - {sig}"
        return "SECURE"

class TestAegisKubeSecurity(unittest.TestCase):
    def test_ledger_integrity_valid(self):
        ledger = BlockchainLedger()
        ledger.create_block("Audit Log A", ledger.chain[-1]["hash"])
        ledger.create_block("Audit Log B", ledger.chain[-1]["hash"])
        self.assertTrue(ledger.verify_integrity())

    def test_ledger_tampering_detection(self):
        ledger = BlockchainLedger()
        ledger.create_block("Audit Log A", ledger.chain[-1]["hash"])
        ledger.chain[1]["data"] = "Tampered Malicious Data"
        self.assertFalse(ledger.verify_integrity())

    def test_threat_detector_patterns(self):
        detector = ThreatDetector()
        self.assertEqual(detector.analyze("Normal system heartbeat"), "SECURE")
        self.assertIn("ALERT", detector.analyze("Detected privilege_escalation attempt in namespace"))

if __name__ == "__main__":
    unittest.main()
