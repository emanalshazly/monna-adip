import importlib.util
import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

from monna_adip.cli import main
from monna_adip.generate import ManifestError, generate_from_mcp

JSONSCHEMA_AVAILABLE = importlib.util.find_spec("jsonschema") is not None


def sample_manifest():
    return {
        "tools": [
            {
                "name": "send_message",
                "description": "Send a chat message.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "recipient_id": {"type": "string"},
                        "body": {"type": "string"},
                    },
                },
            },
            {
                "name": "lookup_contact",
                "description": "Look up a contact.",
                "inputSchema": {
                    "type": "object",
                    "properties": {"query": {"type": "string"}},
                },
                "outputSchema": {
                    "type": "object",
                    "properties": {
                        "contact_id": {"type": "string"},
                        "match_count": {"type": "integer"},
                        "mode": {"enum": ["exact", "fuzzy"]},
                    },
                },
            },
        ]
    }


class GenerateFromMcpTests(unittest.TestCase):
    def test_draft_is_marked_and_actions_map_to_tools(self):
        draft = generate_from_mcp(sample_manifest())
        self.assertTrue(draft["draft"])
        self.assertEqual(draft["generator"]["source"], "mcp")
        self.assertEqual([action["id"] for action in draft["actions"]], ["send_message", "lookup_contact"])
        self.assertTrue(all(action["impact"] == "high" for action in draft["actions"]))

    def test_tool_descriptions_are_untrusted(self):
        draft = generate_from_mcp(sample_manifest())
        catalog = next(obj for obj in draft["data_objects"] if obj["id"] == "tool-catalog")
        self.assertEqual(
            {field["trust"] for field in catalog["fields"]}, {"untrusted"}
        )

    def test_parameters_resolve_to_unknown_agent_context_fields(self):
        draft = generate_from_mcp(sample_manifest())
        context = next(obj for obj in draft["data_objects"] if obj["id"] == "agent-context")
        field_names = {field["name"] for field in context["fields"]}
        self.assertIn("send_message.recipient_id", field_names)
        self.assertEqual({field["trust"] for field in context["fields"]}, {"unknown"})
        parameter = draft["actions"][0]["parameters"][0]
        self.assertEqual(parameter["source"]["object"], "agent-context")
        self.assertFalse(parameter["deterministic_validation"])
        self.assertFalse(parameter["provenance_check"])

    def test_output_schema_free_text_untrusted_constrained_unknown(self):
        draft = generate_from_mcp(sample_manifest())
        response = next(
            obj for obj in draft["data_objects"] if obj["id"] == "lookup_contact-response"
        )
        trust_by_name = {field["name"]: field["trust"] for field in response["fields"]}
        self.assertEqual(trust_by_name["contact_id"], "untrusted")
        self.assertEqual(trust_by_name["match_count"], "unknown")
        self.assertEqual(trust_by_name["mode"], "unknown")

    def test_jsonrpc_and_bare_list_shapes_are_accepted(self):
        tools = sample_manifest()["tools"]
        for shape in ({"result": {"tools": tools}}, tools):
            draft = generate_from_mcp(shape)
            self.assertEqual(len(draft["actions"]), 2)

    def test_unusable_manifests_are_rejected(self):
        for manifest in ({}, {"tools": []}, {"tools": [{"description": "no name"}]}, "text"):
            with self.assertRaises(ManifestError):
                generate_from_mcp(manifest)

    def test_draft_analysis_flags_unknown_provenance(self):
        from monna_adip import analyze_inventory

        result = analyze_inventory(generate_from_mcp(sample_manifest()))
        ids = {finding["id"] for finding in result["findings"]}
        self.assertEqual(result["status"], "EXPOSED")
        self.assertIn("ADIP-01", ids)

    @unittest.skipUnless(JSONSCHEMA_AVAILABLE, "jsonschema optional extra not installed")
    def test_draft_conforms_to_packaged_schema(self):
        from monna_adip.validation import validate_inventory

        self.assertEqual(validate_inventory(generate_from_mcp(sample_manifest())), [])


class GenerateCliTests(unittest.TestCase):
    def test_generate_writes_draft_file(self):
        with tempfile.TemporaryDirectory() as directory_name:
            directory = Path(directory_name)
            manifest_path = directory / "manifest.json"
            manifest_path.write_text(json.dumps(sample_manifest()), encoding="utf-8")
            output = directory / "draft.json"
            stderr = io.StringIO()
            with redirect_stderr(stderr):
                code = main(
                    ["generate", "--from", "mcp", str(manifest_path), "--output", str(output)]
                )
            draft = json.loads(output.read_text(encoding="utf-8"))
        self.assertEqual(code, 0)
        self.assertTrue(draft["draft"])
        self.assertIn("review", stderr.getvalue().lower())

    def test_generate_rejects_unusable_manifest(self):
        with tempfile.TemporaryDirectory() as directory_name:
            manifest_path = Path(directory_name) / "manifest.json"
            manifest_path.write_text("{}", encoding="utf-8")
            stderr = io.StringIO()
            with redirect_stderr(stderr):
                code = main(["generate", "--from", "mcp", str(manifest_path)])
        self.assertEqual(code, 3)
        self.assertIn("tools", stderr.getvalue())

    def test_generate_stdout_is_valid_json(self):
        with tempfile.TemporaryDirectory() as directory_name:
            manifest_path = Path(directory_name) / "manifest.json"
            manifest_path.write_text(json.dumps(sample_manifest()), encoding="utf-8")
            stdout = io.StringIO()
            stderr = io.StringIO()
            with redirect_stdout(stdout), redirect_stderr(stderr):
                code = main(["generate", "--from", "mcp", str(manifest_path), "--compact"])
        self.assertEqual(code, 0)
        self.assertEqual(len(json.loads(stdout.getvalue())["actions"]), 2)


if __name__ == "__main__":
    unittest.main()
