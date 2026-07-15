import importlib.util
import unittest

from monna_adip.validation import load_schema, validate_inventory

JSONSCHEMA_AVAILABLE = importlib.util.find_spec("jsonschema") is not None


class ValidationTests(unittest.TestCase):
    def test_packaged_schema_loads(self):
        schema = load_schema()
        self.assertEqual(schema["title"], "MONNA ADIP Inventory")
        self.assertIn("mitigations", schema["properties"])

    @unittest.skipUnless(JSONSCHEMA_AVAILABLE, "jsonschema optional extra not installed")
    def test_schema_reports_missing_required_fields(self):
        errors = validate_inventory({"system": {"name": "x"}})
        self.assertTrue(any("description" in error for error in errors))
        self.assertTrue(any("data_objects" in error for error in errors))

    @unittest.skipUnless(JSONSCHEMA_AVAILABLE, "jsonschema optional extra not installed")
    def test_schema_rejects_unsupported_trust_class(self):
        inventory = {
            "system": {"name": "x", "description": "x"},
            "data_objects": [
                {
                    "id": "x",
                    "format": "json",
                    "fields": [
                        {"name": "x", "trust": "maybe", "origin": "x", "security_role": "content"}
                    ],
                }
            ],
            "actions": [],
        }
        errors = validate_inventory(inventory)
        self.assertTrue(any("maybe" in error for error in errors))


if __name__ == "__main__":
    unittest.main()
