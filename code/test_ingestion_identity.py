"""
test_ingestion_identity.py - Unit tests for ingestion and identity modules.
"""

import unittest
from pathlib import Path

from ingestion import DataIngestor, EvidenceFile, EvidenceManifest, resolve_dataset_dir
from identity import (
    IdentityResolver,
    UserIdentity,
    compute_sha256,
    normalize_email,
    resolve_identity_for_request,
)


class TestIngestion(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ingestor = DataIngestor()

    def test_dataset_dir_exists(self):
        dataset_dir = resolve_dataset_dir()
        self.assertTrue(dataset_dir.is_dir())
        self.assertTrue((dataset_dir / "deletion_requests.csv").exists())

    def test_load_all_csvs(self):
        datasets = self.ingestor.load_all()
        expected_keys = [
            "user_identities",
            "user_audit_log",
            "deletion_requests",
            "sample_deletion_requests",
            "sample_output",
            "system_activity",
            "deletion_rules",
            "evidence_files",
        ]
        for key in expected_keys:
            self.assertIn(key, datasets)
            self.assertFalse(datasets[key].empty, f"Dataset {key} should not be empty")

    def test_row_counts(self):
        self.assertEqual(len(self.ingestor.user_identities), 850)
        self.assertEqual(len(self.ingestor.user_audit_log), 306)
        self.assertEqual(len(self.ingestor.deletion_requests), 518)
        self.assertEqual(len(self.ingestor.sample_requests), 32)
        self.assertEqual(len(self.ingestor.sample_output), 32)
        self.assertEqual(len(self.ingestor.system_activity), 4011)
        self.assertEqual(len(self.ingestor.deletion_rules), 15)
        self.assertEqual(len(self.ingestor.evidence_files), 94)

    def test_evidence_manifest(self):
        manifest = self.ingestor.evidence_manifest
        self.assertEqual(len(manifest), 94)

        ev1 = manifest.get("evidence_01")
        self.assertIsNotNone(ev1)
        self.assertTrue(ev1.exists)
        self.assertEqual(ev1.file_type, "log")

        # Test safe read
        text = ev1.read_text()
        self.assertGreater(len(text), 0)


class TestIdentityResolution(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.resolver = IdentityResolver()

    def test_resolve_current_email(self):
        user = self.resolver.resolve_user("amina.elmasri@gmail.com")
        self.assertIsNotNone(user)
        self.assertEqual(user.user_id, "user_01")
        self.assertEqual(user.current_email, "amina.elmasri@gmail.com")

    def test_resolve_historical_email(self):
        # nadia.ionescu@yahoo.com was the oldest email of user_10
        user = self.resolver.resolve_user("nadia.ionescu@yahoo.com")
        self.assertIsNotNone(user)
        self.assertEqual(user.user_id, "user_10")
        self.assertEqual(user.current_email, "n.petrescu@yahoo.com")
        self.assertIn("nadia.ionescu@yahoo.com", user.historical_emails)
        self.assertTrue(user.is_historical_email("nadia.ionescu@yahoo.com"))
        self.assertFalse(user.is_historical_email("n.petrescu@yahoo.com"))

    def test_resolve_by_case_id(self):
        user = self.resolver.resolve_user("case_01")
        self.assertIsNotNone(user)
        self.assertEqual(user.user_id, "user_01")

        user_hist = self.resolver.resolve_user("case_10")
        self.assertIsNotNone(user_hist)
        self.assertEqual(user_hist.user_id, "user_10")

    def test_resolve_by_hash(self):
        email = "amina.elmasri@gmail.com"
        h = compute_sha256(email)
        user = self.resolver.get_user_by_hash(h)
        self.assertIsNotNone(user)
        self.assertEqual(user.user_id, "user_01")

    def test_resolve_by_phone(self):
        user = self.resolver.get_user_by_id("user_01")
        self.assertIsNotNone(user)
        by_phone = self.resolver.get_user_by_phone(user.current_phone)
        self.assertIsNotNone(by_phone)
        self.assertEqual(by_phone.user_id, "user_01")

    def test_100_percent_coverage(self):
        stats = self.resolver.get_stats()
        self.assertEqual(stats["sample_requests"]["resolved"], 32)
        self.assertEqual(stats["sample_requests"]["total"], 32)
        self.assertEqual(stats["eval_requests"]["resolved"], 518)
        self.assertEqual(stats["eval_requests"]["total"], 518)

    def test_deliverable_function(self):
        user = resolve_identity_for_request("case_03")
        self.assertIsNotNone(user)
        self.assertEqual(user.user_id, "user_43")
        self.assertIn("l.fontaine46@yahoo.com", user.all_emails)


if __name__ == "__main__":
    unittest.main()

