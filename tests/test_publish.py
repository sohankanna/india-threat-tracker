"""Simulates the update job racing a human push (scripts/publish_update.sh).

Setup: a bare "GitHub" repo, a bot checkout and a human checkout of the same
commit. The human pushes a campaign edit and a relevance override; the bot,
still on the old commit, generates its outputs and tries to push.

Expected: the bot's push is rejected, it rebuilds on top of the human commit,
and main ends up with the human edit intact and every derived file (IOC
exports, KEV feeds) rebuilt against it. No network: upstream KEV/EPSS data
comes from a cache, the same path the job uses on a retry.
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
SCRIPT = "scripts/publish_update.sh"
HUMAN_DOMAIN = "human-edit-check[.]example"

KEV = [
    {"cveID": "CVE-2026-1111", "vendorProject": "Fortinet", "product": "FortiOS",
     "vulnerabilityName": "test", "shortDescription": "test", "dateAdded": "2026-10-01",
     "dueDate": "2026-10-22", "requiredAction": "Patch.", "knownRansomwareCampaignUse": "Unknown", "cwes": []},
    {"cveID": "CVE-2020-2222", "vendorProject": "Acme", "product": "Widget Server",
     "vulnerabilityName": "test", "shortDescription": "test", "dateAdded": "2020-01-15",
     "dueDate": "2020-02-05", "requiredAction": "Patch.", "knownRansomwareCampaignUse": "Unknown", "cwes": []},
]
EPSS = {"CVE-2026-1111": [0.9, 0.99, "2026-10-19"]}


def sh(*args, cwd, env=None, check=True):
    r = subprocess.run(args, cwd=cwd, env=env, capture_output=True, text=True)
    if check and r.returncode != 0:
        raise AssertionError(f"{' '.join(args)} failed ({r.returncode}):\n{r.stdout}\n{r.stderr}")
    return r


def git(cwd, *args, check=True):
    return sh("git", "-c", "user.name=t", "-c", "user.email=t@example.com",
              "-c", "init.defaultBranch=main", *args, cwd=cwd, check=check)


@unittest.skipUnless(shutil.which("git") and shutil.which("bash"), "needs git and bash")
class UpdateJobRace(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.tmp = tmp.name
        self.origin = os.path.join(self.tmp, "origin.git")
        seed = os.path.join(self.tmp, "seed")
        shutil.copytree(ROOT, seed, ignore=shutil.ignore_patterns(".git", "__pycache__", ".workflow-update"))
        os.makedirs(os.path.join(seed, "drafts"), exist_ok=True)
        open(os.path.join(seed, "drafts", ".gitkeep"), "a").close()
        git(self.tmp, "init", "--bare", "-q", self.origin)
        git(seed, "init", "-q")
        git(seed, "add", "-A")
        git(seed, "commit", "-qm", "seed")
        git(seed, "push", "-q", self.origin, "HEAD:main")
        self.bot = os.path.join(self.tmp, "bot")
        self.human = os.path.join(self.tmp, "human")
        git(self.tmp, "clone", "-q", self.origin, self.bot)
        git(self.tmp, "clone", "-q", self.origin, self.human)
        self.cache = os.path.join(self.tmp, "cache")
        os.makedirs(self.cache)
        with open(os.path.join(self.cache, "upstream.json"), "w") as f:
            json.dump({"kev": KEV, "epss": EPSS, "epss_failed_requests": 0}, f)

    def run_bot(self):
        env = dict(os.environ, UPDATE_FROM_CACHE=self.cache, UPDATE_BACKOFF="0", PYTHON=sys.executable,
                   GIT_AUTHOR_NAME="bot", GIT_AUTHOR_EMAIL="bot@example.com",
                   GIT_COMMITTER_NAME="bot", GIT_COMMITTER_EMAIL="bot@example.com")
        return sh("bash", SCRIPT, cwd=self.bot, env=env)

    def read_main(self, path):
        return git(self.tmp, "--git-dir", self.origin, "show", f"main:{path}").stdout

    def test_concurrent_human_edit_survives_and_outputs_are_rebuilt_on_it(self):
        # The human edits curated data and pushes while the bot is on the old commit.
        path = os.path.join(self.human, "data", "smishing-apk.json")
        with open(path) as f:
            camp = json.load(f)
        target = camp["items"][0]
        target.setdefault("iocs", {}).setdefault("domains", []).append(HUMAN_DOMAIN)
        with open(path, "w") as f:
            json.dump(camp, f, indent=2)
            f.write("\n")
        ovr_path = os.path.join(self.human, "data", "relevance-overrides.json")
        with open(ovr_path) as f:
            ovr = json.load(f)
        ovr["overrides"]["CVE-2020-2222"] = {"tier": "high", "reason": "Reviewed: common in Indian banks", "reviewed": "2026-10-20"}
        with open(ovr_path, "w") as f:
            json.dump(ovr, f, indent=2)
            f.write("\n")
        git(self.human, "commit", "-qam", "human: add indicator and override")
        git(self.human, "push", "-q", "origin", "HEAD:main")
        human_sha = git(self.human, "rev-parse", "HEAD").stdout.strip()

        out = self.run_bot()
        self.assertIn("Rebuilding on top of it", out.stdout)
        self.assertIn("Pushed on attempt 2", out.stdout)

        # History: the bot commit sits directly on the human commit.
        parent = git(self.tmp, "--git-dir", self.origin, "rev-parse", "main^").stdout.strip()
        self.assertEqual(parent, human_sha)

        # The human edit is untouched...
        main_camp = json.loads(self.read_main("data/smishing-apk.json"))
        self.assertIn(HUMAN_DOMAIN, main_camp["items"][0]["iocs"]["domains"])
        self.assertEqual(self.read_main("data/relevance-overrides.json"), open(ovr_path).read())
        # ...and the derived files were rebuilt against it.
        self.assertIn(HUMAN_DOMAIN, self.read_main("data/iocs.csv"))
        self.assertIn(HUMAN_DOMAIN, self.read_main("data/iocs.txt"))
        feed = json.loads(self.read_main("data/exploited-cve.json"))
        b = next(i for i in feed["items"] if i["cve"] == "CVE-2020-2222")
        self.assertEqual((b["india_relevance"], b.get("_manual_relevance")), ("high", True))

    def test_no_race_pushes_once(self):
        out = self.run_bot()
        self.assertIn("Pushed on attempt 1", out.stdout)
        self.assertNotIn("Rebuilding on top of it", out.stdout)

    def test_human_edit_that_breaks_validation_stops_the_job(self):
        """A rebuild that fails against the new main must fail loudly, not push."""
        path = os.path.join(self.human, "data", "relevance-overrides.json")
        with open(path) as f:
            ovr = json.load(f)
        ovr["overrides"]["CVE-2020-2222"] = {"tier": "critical", "reason": "not a valid tier", "reviewed": "2026-10-20"}
        with open(path, "w") as f:
            json.dump(ovr, f)
        git(self.human, "commit", "-qam", "human: bad override")
        git(self.human, "push", "-q", "origin", "HEAD:main")
        human_sha = git(self.human, "rev-parse", "HEAD").stdout.strip()

        env = dict(os.environ, UPDATE_FROM_CACHE=self.cache, UPDATE_BACKOFF="0", PYTHON=sys.executable,
                   GIT_AUTHOR_NAME="bot", GIT_AUTHOR_EMAIL="bot@example.com",
                   GIT_COMMITTER_NAME="bot", GIT_COMMITTER_EMAIL="bot@example.com")
        r = sh("bash", SCRIPT, cwd=self.bot, env=env, check=False)
        self.assertNotEqual(r.returncode, 0)
        head = git(self.tmp, "--git-dir", self.origin, "rev-parse", "main").stdout.strip()
        self.assertEqual(head, human_sha, "nothing may be pushed when the rebuild fails")


if __name__ == "__main__":
    unittest.main()
