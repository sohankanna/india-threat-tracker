"""scripts/ransomware_counts.py: counts only, never names, never breaks the job."""
import contextlib
import io
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))
import ransomware_counts as rc  # noqa: E402

SECRET = "Example Victim Pvt Ltd"


def rec(day, group="akira", **extra):
    return {"victim": SECRET, "post_title": SECRET, "website": "victim.example", "country": "IN",
            "attackdate": day, "group": group, **extra}


class RansomwareCounts(unittest.TestCase):
    def run_main(self, payload, date="2026-11-04"):
        with tempfile.TemporaryDirectory() as tmp:
            src = os.path.join(tmp, "in.json")
            out = os.path.join(tmp, "out.md")
            with open(src, "w") as f:
                f.write(payload if isinstance(payload, str) else json.dumps(payload))
            stdout, stderr = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                code = rc.main(["--from-file", src, "--date", date, "--out", out])
            written = ""
            if os.path.exists(out):
                with open(out) as f:
                    written = f.read()
        return code, stdout.getvalue(), stderr.getvalue(), written

    def test_counts_full_months_only(self):
        payload = [rec("2026-10-03"), rec("2026-10-30 12:00:00", "qilin"), rec("2026-09-15"),
                   rec("2026-11-02"),          # current month: not counted yet
                   rec("2025-10-31")]          # older than 12 full months
        code, out, _, written = self.run_main(payload)
        self.assertEqual(code, 0)
        self.assertIn("| Oct 2026 | 2 |", out)
        self.assertIn("| Sep 2026 | 1 |", out)
        self.assertIn("| Nov 2025 | 0 |", out)
        self.assertIn("**Last 12 full months:** 3 claims", out)
        self.assertEqual(out.strip(), written.strip())

    def test_never_prints_victim_names(self):
        _, out, _, _ = self.run_main([rec("2026-10-03")])
        self.assertNotIn(SECRET, out)
        self.assertNotIn("victim.example", out)

    def test_accepts_other_field_names_and_wrappers(self):
        payload = {"victims": [{"discovered": "2026-10-05T01:02:03", "group_name": "lockbit5"},
                               {"published": "2026-10-06", "group": "akira"}]}
        _, out, _, _ = self.run_main(payload)
        self.assertIn("| Oct 2026 | 2 |", out)
        self.assertIn("lockbit5 (1)", out)

    def test_fails_soft(self):
        for label, payload in {"bad json": "<html>blocked</html>", "unknown shape": {"error": "rate limited"},
                               "no dates": [{"victim": SECRET}]}.items():
            with self.subTest(label):
                code, out, err, _ = self.run_main(payload)
                self.assertEqual(code, 0)
                self.assertEqual(out, "")
                self.assertIn("::warning::", err)
                self.assertNotIn(SECRET, err)


if __name__ == "__main__":
    unittest.main()
