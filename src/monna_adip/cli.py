"""Command-line interface for MONNA ADIP Lite."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Sequence

from .analyzer import analyze_inventory


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="monna-adip",
        description="Run defensive field-level trust checks on an AI-agent inventory.",
    )
    parser.add_argument("inventory", type=Path, help="Path to an ADIP JSON inventory")
    parser.add_argument(
        "--compact",
        action="store_true",
        help="Emit compact JSON instead of indented JSON",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        inventory = json.loads(args.inventory.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise SystemExit(f"Inventory not found: {args.inventory}")
    except json.JSONDecodeError as exc:
        raise SystemExit(f"Invalid JSON in {args.inventory}: {exc}")

    result = analyze_inventory(inventory)
    if args.compact:
        print(json.dumps(result, ensure_ascii=False, separators=(",", ":")))
    else:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    return 2 if result["status"] in {"INCOMPLETE", "EXPOSED"} else 0

