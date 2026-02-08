import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

import guardflow_app as app


class GuardFlowTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        app.DB_PATH = Path(self.tmp.name) / "test_logs.db"
        app.ensure_database()
        self.api = app.GuardFlowAPI()

    def tearDown(self):
        self.api.close()
        self.tmp.cleanup()

    def test_scan_file_hash_only_path_and_logging(self):
        sample = Path(self.tmp.name) / "sample.bin"
        sample.write_bytes(b"abc123")

        self.api.requests = SimpleNamespace(
            post=lambda *args, **kwargs: SimpleNamespace(status_code=200, content=b"1", json=lambda: {"verdict": "safe", "detail": "ok"}),
            get=lambda *args, **kwargs: SimpleNamespace(status_code=200),
            options=lambda *args, **kwargs: SimpleNamespace(status_code=200),
        )
        self.api.compatibility["hashPath"] = app.HASH_PATH_CANDIDATES[0]

        res = self.api.scan_file(str(sample))
        self.assertTrue(res["ok"])
        self.assertEqual(res["status"], "SAFE")

        reports = self.api.get_reports()
        self.assertEqual(reports["summary"]["totalScanned"], 1)

    def test_pause_and_resume(self):
        self.assertFalse(self.api.pause_event.is_set())
        self.api.pause_all_scans()
        self.assertTrue(self.api.pause_event.is_set())
        self.api.resume_all_scans()
        self.assertFalse(self.api.pause_event.is_set())

    def test_schedule_validation(self):
        bad = self.api.schedule_scan("file", "/nope/file", "daily", 6)
        self.assertFalse(bad["ok"])

    def test_deep_scan_error_when_missing_file(self):
        res = self.api.upload_for_deep_scan("/missing/no.file")
        self.assertFalse(res["ok"])


if __name__ == "__main__":
    unittest.main()
