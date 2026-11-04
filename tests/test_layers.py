"""ATT&CK: every technique id the tracker uses is real, and the layers match the data."""
import json
import os
import sys
import unittest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(ROOT, "scripts"))
import build_layers as bl  # noqa: E402


def load(rel):
    with open(os.path.join(ROOT, rel), encoding="utf-8") as f:
        return json.load(f)


class Layers(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.files = {k: json.loads(v) for k, v in bl.build().items()}
        cls.ref = load("config/attack-techniques.json")["domains"]

    def test_committed_layers_are_current(self):
        self.assertEqual(bl.main(["--check"]), 0)

    def test_every_mapping_uses_a_current_technique_with_its_current_name(self):
        for path, domain in (("data/apt-campaigns.json", "enterprise"), ("data/ransomware.json", "enterprise"),
                             ("data/hacktivist.json", "enterprise"), ("data/smishing-apk.json", "mobile")):
            techs = self.ref[domain]["techniques"]
            for it in load(path)["items"]:
                for a in it.get("attack") or []:
                    self.assertIn(a["id"], techs, f"{path} {it['id']}: {a['id']} is not in {domain} ATT&CK")
                    name = techs[a["id"]]["name"]
                    if "." in a["id"]:
                        name = f"{techs[a['id'].split('.')[0]]['name']}: {name}"
                    self.assertEqual(a["name"], name, f"{path} {it['id']} {a['id']}")

    def test_every_sigma_tag_is_a_current_enterprise_technique(self):
        for tid, rules in bl.rule_tags().items():
            self.assertIn(tid, self.ref["enterprise"]["techniques"], rules)

    def test_unknown_ids_fail_the_build(self):
        bad = bl.unknown_ids({"T1496", "T9999"}, self.ref["mobile"])
        self.assertEqual(len(bad), 2)

    def test_coverage_rules(self):
        rules = {"T1059": ["parent_rule"], "T1204.002": ["exact_rule"], "T1567.002": ["sub_rule"]}
        self.assertEqual(bl.coverage_for("T1204.002", rules), ("exact", ["exact_rule"]))
        self.assertEqual(bl.coverage_for("T1059.001", rules), ("related", ["parent_rule"]))   # parent tagged
        self.assertEqual(bl.coverage_for("T1567", rules), ("related", ["sub_rule"]))           # sub tagged
        self.assertEqual(bl.coverage_for("T1204.001", rules), ("none", []))                    # sibling: no
        self.assertEqual(bl.coverage_for("T1486", rules), ("none", []))

    def test_layers_are_navigator_shaped(self):
        for rel in ("layers/india-actors.json", "layers/detection-coverage.json", "layers/india-fraud-mobile.json"):
            lay = self.files[rel]
            domain = "mobile" if "mobile" in rel else "enterprise"
            self.assertEqual(lay["domain"], f"{domain}-attack")
            self.assertEqual(lay["versions"]["attack"], self.ref[domain]["version"].split(".")[0])
            self.assertEqual(lay["versions"]["layer"], bl.LAYER_FORMAT)
            self.assertTrue(lay["techniques"], rel)
            for t in lay["techniques"]:
                self.assertIn(t["techniqueID"], self.ref[domain]["techniques"], rel)

    def test_coverage_counts_add_up_and_match_the_layer(self):
        cov = self.files["data/attack-coverage.json"]
        s = cov["summary"]
        self.assertEqual(s["exact"] + s["related"] + s["none"], s["actor_techniques"])
        self.assertEqual(s["actor_techniques"], len(cov["items"]))
        colours = {t["techniqueID"]: t["color"] for t in self.files["layers/detection-coverage.json"]["techniques"]}
        for r in cov["items"]:
            self.assertEqual(colours[r["id"]], {"exact": bl.GREEN, "related": bl.AMBER, "none": bl.RED}[r["coverage"]])
        for g in cov["top_gaps"]:
            self.assertEqual(next(r for r in cov["items"] if r["id"] == g["id"])["coverage"], "none")

    def test_every_rule_appears_in_coverage(self):
        stems = {f[:-4] for f in os.listdir(os.path.join(ROOT, "detections", "sigma")) if f.endswith(".yml")}
        tagged = {r for rs in bl.rule_tags().values() for r in rs}
        self.assertEqual(tagged, stems)


if __name__ == "__main__":
    unittest.main()
