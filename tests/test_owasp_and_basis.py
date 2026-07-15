import unittest

from monna_adip import analyze_inventory
from monna_adip.renderers import OWASP_ASI_2026, RULE_DESCRIPTIONS, build_sarif


class BasisLabelTests(unittest.TestCase):
    def test_every_finding_carries_a_basis(self):
        inventory = {
            "data_objects": [
                {
                    "id": "message",
                    "format": "json",
                    "fields": [
                        {"name": "id", "trust": "untrusted", "security_role": "identifier"},
                        {"name": "note", "trust": "mostly-fine", "security_role": "content"},
                    ],
                }
            ],
            "actions": [],
        }
        findings = analyze_inventory(inventory)["findings"]
        bases = {finding["id"]: finding["basis"] for finding in findings}
        self.assertEqual(bases["ADIP-01"], "structural")
        self.assertEqual(bases["ADIP-02"], "declared")

    def test_missing_arrays_is_structural(self):
        finding = analyze_inventory({"system": {}})["findings"][0]
        self.assertEqual(finding["basis"], "structural")

    def test_declared_control_claims_are_declared_basis(self):
        inventory = {
            "data_objects": [
                {
                    "id": "record",
                    "format": "json",
                    "structural_isolation": True,
                    "fields": [
                        {"name": "id", "trust": "trusted", "security_role": "identifier"}
                    ],
                }
            ],
            "actions": [],
        }
        finding = analyze_inventory(inventory)["findings"][0]
        self.assertEqual(finding["id"], "ADIP-07")
        self.assertEqual(finding["basis"], "declared")


class OwaspMappingTests(unittest.TestCase):
    def test_every_rule_has_a_mapping_entry(self):
        self.assertEqual(set(OWASP_ASI_2026), set(RULE_DESCRIPTIONS))

    def test_sarif_rules_carry_asi_tags(self):
        report = {
            "version": "0.2.0",
            "status": "EXPOSED",
            "inventory_count": 1,
            "finding_counts": {"critical": 1, "medium": 1},
            "findings": [
                {
                    "source": "one.json",
                    "id": "ADIP-02",
                    "severity": "critical",
                    "location": "x",
                    "message": "m",
                    "recommendation": "r",
                    "basis": "declared",
                },
                {
                    "source": "one.json",
                    "id": "ADIP-07",
                    "severity": "medium",
                    "location": "y",
                    "message": "m",
                    "recommendation": "r",
                    "basis": "declared",
                },
            ],
        }
        sarif = build_sarif(report)
        rules = {rule["id"]: rule for rule in sarif["runs"][0]["tool"]["driver"]["rules"]}
        self.assertIn("external/owasp-asi/ASI03", rules["ADIP-02"]["properties"]["tags"])
        self.assertEqual(rules["ADIP-02"]["properties"]["owaspAsi2026"], ["ASI03"])
        self.assertEqual(rules["ADIP-07"]["properties"]["tags"], ["security"])
        self.assertEqual(rules["ADIP-07"]["properties"]["owaspAsi2026"], [])
        self.assertEqual(
            sarif["runs"][0]["results"][0]["properties"]["basis"], "declared"
        )


if __name__ == "__main__":
    unittest.main()
