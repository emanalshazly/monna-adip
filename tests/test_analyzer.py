import unittest

from monna_adip import analyze_inventory


def controlled_inventory():
    return {
        "system": {"name": "test", "description": "test inventory"},
        "data_objects": [
            {
                "id": "record",
                "format": "json",
                "structural_isolation": True,
                "structural_isolation_evidence": "serializer-test-17",
                "fields": [
                    {
                        "name": "id",
                        "trust": "trusted",
                        "origin": "backend",
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
                        "validation_evidence": "schema-test-4",
                        "provenance_check": True,
                        "provenance_evidence": "backend-signature-test-2",
                    }
                ],
            }
        ],
        "mitigations": [
            {
                "id": "M-1",
                "control": "server-side lookup",
                "scope": "record.id",
                "verification_status": "verified",
                "verification_evidence": "integration-test-8",
            }
        ],
    }


class AnalyzerTests(unittest.TestCase):
    def test_missing_arrays_is_incomplete(self):
        result = analyze_inventory({"system": {"name": "x"}})
        self.assertEqual(result["status"], "INCOMPLETE")
        self.assertEqual(result["findings"][0]["id"], "ADIP-01")

    def test_controlled_inventory_is_review_ready(self):
        result = analyze_inventory(controlled_inventory())
        self.assertEqual(result["status"], "REVIEW_READY")
        self.assertEqual(result["findings"], [])

    def test_unsupported_trust_class_is_adip01(self):
        inventory = controlled_inventory()
        inventory["data_objects"][0]["fields"][0]["trust"] = "mostly-trusted"
        ids = {item["id"] for item in analyze_inventory(inventory)["findings"]}
        self.assertIn("ADIP-01", ids)

    def test_untrusted_security_role_is_adip02(self):
        inventory = controlled_inventory()
        inventory["data_objects"][0]["fields"][0]["trust"] = "untrusted"
        ids = {item["id"] for item in analyze_inventory(inventory)["findings"]}
        self.assertIn("ADIP-02", ids)

    def test_unverified_critical_parameter_is_adip03(self):
        inventory = controlled_inventory()
        parameter = inventory["actions"][0]["parameters"][0]
        parameter["provenance_check"] = False
        inventory["actions"][0]["impact"] = "critical"
        findings = analyze_inventory(inventory)["findings"]
        adip03 = next(item for item in findings if item["id"] == "ADIP-03")
        self.assertEqual(adip03["severity"], "critical")

    def test_mixed_trust_without_isolation_is_adip04(self):
        inventory = controlled_inventory()
        obj = inventory["data_objects"][0]
        obj["structural_isolation"] = False
        obj["fields"].append(
            {"name": "body", "trust": "untrusted", "origin": "user", "security_role": "content"}
        )
        ids = {item["id"] for item in analyze_inventory(inventory)["findings"]}
        self.assertIn("ADIP-04", ids)

    def test_same_context_confirmation_is_adip05(self):
        inventory = controlled_inventory()
        action = inventory["actions"][0]
        action["user_confirmation"] = True
        action["independent_confirmation_evidence"] = False
        ids = {item["id"] for item in analyze_inventory(inventory)["findings"]}
        self.assertIn("ADIP-05", ids)

    def test_derived_value_without_provenance_is_adip06(self):
        inventory = controlled_inventory()
        field = inventory["data_objects"][0]["fields"][0]
        field["trust"] = "derived"
        field["provenance_preserved"] = False
        ids = {item["id"] for item in analyze_inventory(inventory)["findings"]}
        self.assertIn("ADIP-06", ids)

    def test_claimed_controls_without_evidence_are_adip07(self):
        inventory = controlled_inventory()
        obj = inventory["data_objects"][0]
        obj.pop("structural_isolation_evidence")
        parameter = inventory["actions"][0]["parameters"][0]
        parameter.pop("validation_evidence")
        inventory["mitigations"][0]["verification_status"] = "planned"
        findings = analyze_inventory(inventory)["findings"]
        adip07 = [item for item in findings if item["id"] == "ADIP-07"]
        self.assertEqual(len(adip07), 3)

    def test_unresolvable_parameter_source_is_adip01(self):
        inventory = controlled_inventory()
        inventory["actions"][0]["parameters"][0]["source"]["field"] = "missing"
        ids = {item["id"] for item in analyze_inventory(inventory)["findings"]}
        self.assertIn("ADIP-01", ids)

    def test_malformed_nested_values_do_not_crash(self):
        inventory = controlled_inventory()
        inventory["data_objects"].append("not-an-object")
        inventory["actions"].append("not-an-action")
        result = analyze_inventory(inventory)
        self.assertEqual(result["status"], "EXPOSED")
        self.assertGreaterEqual(result["finding_counts"]["high"], 2)


if __name__ == "__main__":
    unittest.main()
