import importlib.util
import json
import unittest

from monna_adip import analyze_inventory
from monna_adip.renderers import build_sarif, render_markdown, render_text
from monna_adip.report import build_report
from monna_adip.validation import load_schema, validate_inventory

JSONSCHEMA_AVAILABLE = importlib.util.find_spec("jsonschema") is not None


def controlled_inventory():
    return {
        "system": {"name": "multi-model-agent", "description": "v0.3 fixture"},
        "threat_context": {
            "cia_impacts": ["integrity", "confidentiality", "integrity"],
            "attack_paths": ["multi_model", "indirect"],
            "external_references": [
                {
                    "namespace": "hiddenlayer-ape",
                    "version": "2026-06-18",
                    "source_url": "https://github.com/hiddenlayerai/ape-taxonomy",
                    "ids": ["HLT08.02", "HLT08.01", "HLT08.01"],
                }
            ],
        },
        "data_objects": [
            {
                "id": "retrieved-document",
                "format": "json",
                "structural_isolation": True,
                "structural_isolation_evidence": "serializer-test-22",
                "fields": [
                    {
                        "name": "body",
                        "trust": "untrusted",
                        "origin": "external retrieval corpus",
                        "security_role": "content",
                    }
                ],
            }
        ],
        "actions": [
            {
                "id": "approve",
                "impact": "high",
                "verification": {
                    "type": "external_service",
                    "verifier": "policy-engine",
                    "independent": True,
                    "evidence": "policy-integration-test-9",
                },
                "parameters": [
                    {
                        "name": "document",
                        "source": {"object": "retrieved-document", "field": "body"},
                        "deterministic_validation": True,
                        "validation_evidence": "schema-test-10",
                        "provenance_check": True,
                        "provenance_evidence": "retrieval-envelope-test-5",
                    }
                ],
            }
        ],
        "outputs": [
            {
                "id": "review-context",
                "source_fields": [{"object": "retrieved-document", "field": "body"}],
                "consumer": {"type": "llm", "id": "review-model"},
                "sink_type": "forward_to_model",
                "impact": "high",
                "provenance_preserved": True,
                "provenance_evidence": "context-label-test-4",
                "deterministic_validation": True,
                "validation_evidence": "output-schema-test-3",
                "independent_verification": True,
                "verification_evidence": "policy-gate-test-7",
            }
        ],
        "mitigations": [],
    }


class ThreatContextAnalyzerTests(unittest.TestCase):
    def test_controlled_multi_model_inventory_is_review_ready(self):
        result = analyze_inventory(controlled_inventory())
        self.assertEqual(result["status"], "REVIEW_READY")
        self.assertEqual(result["findings"], [])

    def test_threat_context_is_normalized_without_importing_taxonomy_content(self):
        context = analyze_inventory(controlled_inventory())["threat_context"]
        self.assertEqual(context["cia_impacts"], ["confidentiality", "integrity"])
        self.assertEqual(context["attack_paths"], ["indirect", "multi_model"])
        self.assertEqual(
            context["external_references"][0]["ids"], ["HLT08.01", "HLT08.02"]
        )

    def test_non_independent_judge_is_adip05(self):
        inventory = controlled_inventory()
        inventory["actions"][0]["verification"] = {
            "type": "llm_judge",
            "verifier": "shared-context-judge",
            "independent": False,
        }
        ids = {item["id"] for item in analyze_inventory(inventory)["findings"]}
        self.assertIn("ADIP-05", ids)

    def test_downstream_model_without_provenance_is_adip06(self):
        inventory = controlled_inventory()
        inventory["outputs"][0]["provenance_preserved"] = False
        ids = {item["id"] for item in analyze_inventory(inventory)["findings"]}
        self.assertIn("ADIP-06", ids)

    def test_unverified_high_impact_sink_is_adip03(self):
        inventory = controlled_inventory()
        inventory["outputs"][0]["independent_verification"] = False
        ids = {item["id"] for item in analyze_inventory(inventory)["findings"]}
        self.assertIn("ADIP-03", ids)

    def test_claimed_output_controls_need_evidence(self):
        inventory = controlled_inventory()
        output = inventory["outputs"][0]
        output.pop("provenance_evidence")
        output.pop("validation_evidence")
        output.pop("verification_evidence")
        adip07 = [
            item
            for item in analyze_inventory(inventory)["findings"]
            if item["id"] == "ADIP-07"
        ]
        self.assertEqual(len(adip07), 3)


class ThreatContextReportTests(unittest.TestCase):
    def report(self):
        result = analyze_inventory(controlled_inventory())
        return build_report([{"source": "multi-model.json", "result": result}])

    def test_aggregate_preserves_context(self):
        report = self.report()
        self.assertEqual(
            report["threat_context"]["cia_impacts"], ["confidentiality", "integrity"]
        )
        self.assertEqual(
            report["threat_context"]["external_references"][0]["namespace"],
            "hiddenlayer-ape",
        )

    def test_text_and_markdown_show_external_references(self):
        report = self.report()
        self.assertIn("hiddenlayer-ape:HLT08.01", render_text(report))
        self.assertIn(
            "CIA impacts: confidentiality, integrity", render_markdown(report)
        )

    def test_sarif_carries_context_properties(self):
        report = self.report()
        report["findings"] = [
            {
                "source": "multi-model.json",
                "id": "ADIP-05",
                "severity": "high",
                "location": "actions.approve.verification",
                "message": "Non-independent verification.",
                "recommendation": "Use an independent verifier.",
                "basis": "declared",
            }
        ]
        sarif = build_sarif(report)
        json.dumps(sarif)
        run = sarif["runs"][0]
        self.assertIn(
            "hiddenlayer-ape:HLT08.02", run["properties"]["externalTaxonomyReferences"]
        )
        self.assertIn(
            "external/taxonomy/hiddenlayer-ape/HLT08.01",
            run["results"][0]["properties"]["tags"],
        )

    def test_schema_exposes_v03_extensions(self):
        schema = load_schema()
        self.assertIn("threat_context", schema["properties"])
        self.assertIn("outputs", schema["properties"])
        self.assertIn(
            "verification", schema["properties"]["actions"]["items"]["properties"]
        )

    @unittest.skipUnless(
        JSONSCHEMA_AVAILABLE, "jsonschema optional extra not installed"
    )
    def test_schema_rejects_external_reference_without_ids(self):
        inventory = controlled_inventory()
        inventory["threat_context"]["external_references"][0].pop("ids")
        errors = validate_inventory(inventory)
        self.assertTrue(any("ids" in error for error in errors))

    @unittest.skipUnless(
        JSONSCHEMA_AVAILABLE, "jsonschema optional extra not installed"
    )
    def test_schema_rejects_output_without_source_fields(self):
        inventory = controlled_inventory()
        inventory["outputs"][0].pop("source_fields")
        errors = validate_inventory(inventory)
        self.assertTrue(any("source_fields" in error for error in errors))


if __name__ == "__main__":
    unittest.main()
