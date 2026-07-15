import unittest

from monna_adip import analyze_inventory


class AnalyzerTests(unittest.TestCase):
    def test_missing_arrays_is_incomplete(self):
        result = analyze_inventory({"system": {"name": "x"}})
        self.assertEqual(result["status"], "INCOMPLETE")
        self.assertEqual(result["findings"][0]["id"], "ADIP-01")

    def test_mixed_trust_and_unverified_action_are_exposed(self):
        inventory = {
            "data_objects": [
                {
                    "id": "message",
                    "format": "json",
                    "structural_isolation": False,
                    "fields": [
                        {
                            "name": "id",
                            "trust": "trusted",
                            "security_role": "identifier",
                        },
                        {
                            "name": "body",
                            "trust": "untrusted",
                            "security_role": "content",
                        },
                    ],
                }
            ],
            "actions": [
                {
                    "id": "send",
                    "impact": "critical",
                    "parameters": [
                        {
                            "name": "id",
                            "source": {"object": "message", "field": "id"},
                            "deterministic_validation": True,
                            "provenance_check": False,
                        }
                    ],
                }
            ],
        }
        result = analyze_inventory(inventory)
        ids = {finding["id"] for finding in result["findings"]}
        self.assertEqual(result["status"], "EXPOSED")
        self.assertIn("ADIP-03", ids)
        self.assertIn("ADIP-04", ids)

    def test_controlled_inventory_is_review_ready(self):
        inventory = {
            "data_objects": [
                {
                    "id": "record",
                    "format": "json",
                    "structural_isolation": True,
                    "fields": [
                        {
                            "name": "id",
                            "trust": "trusted",
                            "security_role": "identifier",
                        }
                    ],
                }
            ],
            "actions": [
                {
                    "id": "read",
                    "impact": "high",
                    "parameters": [
                        {
                            "name": "id",
                            "source": {"object": "record", "field": "id"},
                            "deterministic_validation": True,
                            "provenance_check": True,
                        }
                    ],
                }
            ],
        }
        result = analyze_inventory(inventory)
        self.assertEqual(result["status"], "REVIEW_READY")
        self.assertEqual(result["findings"], [])


if __name__ == "__main__":
    unittest.main()

