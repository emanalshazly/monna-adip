import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

from monna_adip.cli import main


def exposed_inventory():
    return {
        "system": {"name": "test", "description": "CLI fixture"},
        "data_objects": [
            {
                "id": "message",
                "format": "json",
                "structural_isolation": False,
                "fields": [
                    {"name": "id", "trust": "trusted", "origin": "backend", "security_role": "identifier"},
                    {"name": "body", "trust": "untrusted", "origin": "user", "security_role": "content"},
                ],
            }
        ],
        "actions": [],
    }


class CliTests(unittest.TestCase):
    def write_inventory(self, directory: Path, name: str = "inventory.json") -> Path:
        path = directory / name
        path.write_text(json.dumps(exposed_inventory()), encoding="utf-8")
        return path

    def test_version(self):
        stdout = io.StringIO()
        with self.assertRaises(SystemExit) as raised, redirect_stdout(stdout):
            main(["--version"])
        self.assertEqual(raised.exception.code, 0)
        self.assertIn("0.2.0", stdout.getvalue())

    def test_text_report(self):
        with tempfile.TemporaryDirectory() as directory_name:
            path = self.write_inventory(Path(directory_name))
            stdout = io.StringIO()
            with redirect_stdout(stdout):
                code = main([str(path), "--format", "text"])
        self.assertEqual(code, 2)
        self.assertIn("Status: EXPOSED", stdout.getvalue())
        self.assertIn("ADIP-04", stdout.getvalue())

    def test_markdown_report(self):
        with tempfile.TemporaryDirectory() as directory_name:
            path = self.write_inventory(Path(directory_name))
            stdout = io.StringIO()
            with redirect_stdout(stdout):
                code = main([str(path), "--format", "markdown"])
        self.assertEqual(code, 2)
        self.assertIn("# MONNA ADIP Lite Report", stdout.getvalue())
        self.assertIn("| Severity | Rule |", stdout.getvalue())

    def test_sarif_report(self):
        with tempfile.TemporaryDirectory() as directory_name:
            path = self.write_inventory(Path(directory_name))
            stdout = io.StringIO()
            with redirect_stdout(stdout):
                code = main([str(path), "--format", "sarif"])
        sarif = json.loads(stdout.getvalue())
        self.assertEqual(code, 2)
        self.assertEqual(sarif["version"], "2.1.0")
        self.assertEqual(sarif["runs"][0]["results"][0]["ruleId"], "ADIP-04")

    def test_output_file(self):
        with tempfile.TemporaryDirectory() as directory_name:
            directory = Path(directory_name)
            path = self.write_inventory(directory)
            output = directory / "report.md"
            stdout = io.StringIO()
            with redirect_stdout(stdout):
                code = main([str(path), "--format", "markdown", "--output", str(output)])
            contents = output.read_text(encoding="utf-8")
        self.assertEqual(code, 2)
        self.assertEqual(stdout.getvalue(), "")
        self.assertIn("ADIP-04", contents)

    def test_directory_scanning_aggregates_inventories(self):
        with tempfile.TemporaryDirectory() as directory_name:
            directory = Path(directory_name)
            self.write_inventory(directory, "one.json")
            self.write_inventory(directory, "two.json")
            stdout = io.StringIO()
            with redirect_stdout(stdout):
                code = main([str(directory)])
        report = json.loads(stdout.getvalue())
        self.assertEqual(code, 2)
        self.assertEqual(report["inventory_count"], 2)
        self.assertEqual(len(report["findings"]), 2)

    def test_recursive_directory_scanning(self):
        with tempfile.TemporaryDirectory() as directory_name:
            directory = Path(directory_name)
            nested = directory / "nested"
            nested.mkdir()
            self.write_inventory(nested)
            stderr = io.StringIO()
            with redirect_stderr(stderr):
                no_recursive = main([str(directory)])
            stdout = io.StringIO()
            with redirect_stdout(stdout):
                recursive = main([str(directory), "--recursive"])
        self.assertEqual(no_recursive, 3)
        self.assertEqual(recursive, 2)
        self.assertEqual(json.loads(stdout.getvalue())["inventory_count"], 1)

    def test_invalid_json_returns_data_error(self):
        with tempfile.TemporaryDirectory() as directory_name:
            path = Path(directory_name) / "bad.json"
            path.write_text("{", encoding="utf-8")
            stderr = io.StringIO()
            with redirect_stderr(stderr):
                code = main([str(path)])
        self.assertEqual(code, 3)
        self.assertIn("Invalid JSON", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
