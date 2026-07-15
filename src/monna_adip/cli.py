"""Command-line interface for MONNA ADIP Lite."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Sequence

from .analyzer import analyze_inventory
from .generate import ManifestError, generate_from_mcp
from .renderers import render_report
from .report import build_report, discover_inventory_paths
from .validation import ValidationDependencyError, validate_inventory
from .version import __version__


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="monna-adip",
        description="Run defensive field-level trust checks on AI-agent inventories.",
    )
    parser.add_argument("inventory", nargs="+", type=Path, help="JSON file or directory")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument(
        "--format",
        choices=("json", "text", "markdown", "sarif"),
        default="json",
        help="Report format (default: json)",
    )
    parser.add_argument("--output", type=Path, help="Write the report to a file")
    parser.add_argument("--validate", action="store_true", help="Validate against JSON Schema")
    parser.add_argument("--recursive", action="store_true", help="Scan directories recursively")
    parser.add_argument("--compact", action="store_true", help="Compact JSON or SARIF output")
    return parser


def build_generate_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="monna-adip generate",
        description="Draft an ADIP inventory from a public interface description.",
    )
    parser.add_argument("manifest", type=Path, help="Path to a tool manifest JSON file")
    parser.add_argument(
        "--from",
        dest="source_kind",
        choices=("mcp",),
        required=True,
        help="Manifest kind (currently only 'mcp': a tools/list manifest)",
    )
    parser.add_argument("--output", type=Path, help="Write the draft inventory to a file")
    parser.add_argument("--compact", action="store_true", help="Compact JSON output")
    return parser


def _run_generate(argv: Sequence[str]) -> int:
    args = build_generate_parser().parse_args(argv)
    try:
        manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
    except FileNotFoundError:
        print(f"Manifest not found: {args.manifest}", file=sys.stderr)
        return 3
    except json.JSONDecodeError as exc:
        print(f"Invalid JSON in {args.manifest}: {exc}", file=sys.stderr)
        return 3
    except OSError as exc:
        print(f"Cannot read {args.manifest}: {exc}", file=sys.stderr)
        return 3

    try:
        draft = generate_from_mcp(manifest)
    except ManifestError as exc:
        print(f"Cannot generate from {args.manifest}: {exc}", file=sys.stderr)
        return 3

    if args.compact:
        rendered = json.dumps(draft, ensure_ascii=False, separators=(",", ":"))
    else:
        rendered = json.dumps(draft, ensure_ascii=False, indent=2)
    if args.output:
        try:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(rendered + "\n", encoding="utf-8")
        except OSError as exc:
            print(f"Cannot write {args.output}: {exc}", file=sys.stderr)
            return 3
    else:
        print(rendered)
    print(
        "Draft inventory only: review every trust label, origin, and impact "
        "before analysis.",
        file=sys.stderr,
    )
    return 0


def _source_label(path: Path) -> str:
    try:
        return path.resolve().relative_to(Path.cwd().resolve()).as_posix()
    except ValueError:
        return path.resolve().as_posix()


def main(argv: Sequence[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    if arguments and arguments[0] == "generate":
        return _run_generate(arguments[1:])

    parser = build_parser()
    args = parser.parse_args(arguments)
    if args.compact and args.format not in {"json", "sarif"}:
        parser.error("--compact is only valid with --format json or sarif")

    try:
        inventory_paths = discover_inventory_paths(args.inventory, args.recursive)
    except FileNotFoundError as exc:
        print(f"Inventory path not found: {exc}", file=sys.stderr)
        return 3
    if not inventory_paths:
        print("No JSON inventories found.", file=sys.stderr)
        return 3

    records = []
    for path in inventory_paths:
        try:
            inventory = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            print(f"Invalid JSON in {path}: {exc}", file=sys.stderr)
            return 3
        except OSError as exc:
            print(f"Cannot read {path}: {exc}", file=sys.stderr)
            return 3

        if args.validate:
            try:
                errors = validate_inventory(inventory)
            except ValidationDependencyError as exc:
                print(str(exc), file=sys.stderr)
                return 3
            if errors:
                print(f"Schema validation failed for {path}:", file=sys.stderr)
                for error in errors:
                    print(f"  - {error}", file=sys.stderr)
                return 3

        records.append({"source": _source_label(path), "result": analyze_inventory(inventory)})

    report = build_report(records)
    rendered = render_report(report, args.format, args.compact)
    if args.output:
        try:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(rendered + "\n", encoding="utf-8")
        except OSError as exc:
            print(f"Cannot write {args.output}: {exc}", file=sys.stderr)
            return 3
    else:
        print(rendered)

    return 2 if report["status"] in {"INCOMPLETE", "EXPOSED"} else 0
