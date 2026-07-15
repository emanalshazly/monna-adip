import importlib.util
import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr
from pathlib import Path

from monna_adip.cli import main
from monna_adip.validation import load_schema

JSONSCHEMA_AVAILABLE = importlib.util.find_spec("jsonschema") is not None


class SchemaContractTests(unittest.TestCase):
    def test_public_and_packaged_schemas_match(self):
        public_schema = json.loads(
            Path("schemas/inventory.schema.json").read_text(encoding="utf-8")
        )
        self.assertEqual(public_schema, load_schema())

    @unittest.skipUnless(JSONSCHEMA_AVAILABLE, "jsonschema optional extra not installed")
    def test_cli_validate_rejects_malformed_inventory(self):
        malformed = {
            "system": {"name": "missing-description"},
            "data_objects": [],
            "actions": [],
        }
        with tempfile.TemporaryDirectory() as directory_name:
            path = Path(directory_name) / "invalid.json"
            path.write_text(json.dumps(malformed), encoding="utf-8")
            stderr = io.StringIO()
            with redirect_stderr(stderr):
                code = main([str(path), "--validate"])
        self.assertEqual(code, 3)
        self.assertIn("Schema validation failed", stderr.getvalue())
        self.assertIn("description", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
