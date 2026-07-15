import json
import unittest

from monna_adip.renderers import build_sarif, render_markdown


class RendererTests(unittest.TestCase):
    def report(self):
        return {
            "version": "0.2.0",
            "status": "EXPOSED",
            "inventory_count": 1,
            "finding_counts": {"high": 1},
            "findings": [
                {
                    "source": "agent|one.json",
                    "id": "ADIP-07",
                    "severity": "medium",
                    "location": "mitigations.M|1",
                    "message": "Evidence | missing",
                    "recommendation": "Add evidence",
                }
            ],
        }

    def test_markdown_escapes_table_cells(self):
        markdown = render_markdown(self.report())
        self.assertIn("agent\\|one.json", markdown)
        self.assertIn("Evidence \\| missing", markdown)

    def test_sarif_is_json_serializable_and_has_rule(self):
        sarif = build_sarif(self.report())
        json.dumps(sarif)
        self.assertEqual(sarif["runs"][0]["tool"]["driver"]["rules"][0]["id"], "ADIP-07")


if __name__ == "__main__":
    unittest.main()
