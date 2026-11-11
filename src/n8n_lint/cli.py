from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys
from typing import Any

from n8n_lint import __version__
from n8n_lint.formatters import format_report
from n8n_lint.redact import redact_workflow_data
from n8n_lint.rules import ALL_RULES, lint_workflow_data

SKIP_DIRS = {".git", ".venv", "venv", "node_modules", "__pycache__", "dist", "build"}


def _collect_json_files(targets: list[str]) -> tuple[list[Path], list[str]]:
    files: list[Path] = []
    missing: list[str] = []
    for raw in targets:
        p = Path(raw)
        if not p.exists():
            missing.append(raw)
            continue
        if p.is_file():
            files.append(p)
        elif p.is_dir():
            for root, dirs, filenames in os.walk(p):
                dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS)
                for fn in sorted(filenames):
                    if fn.endswith(".json"):
                        files.append(Path(root) / fn)
    return files, missing


def _parse_ignore(raw: str | None) -> set[str]:
    if not raw:
        return set()
    return {item.strip().upper() for item in raw.split(",") if item.strip()}


def _run_scan(args: argparse.Namespace) -> int:
    files, missing = _collect_json_files(args.paths)
    if missing:
        print(f"n8n-lint: path not found: {', '.join(missing)}", file=sys.stderr)
        return 2
    if not files:
        print("n8n-lint: no workflow JSON files found in target path(s).", file=sys.stderr)
        return 2

    ignore_rules = _parse_ignore(args.ignore)
    all_findings: list[dict[str, Any]] = []
    for wf_path in files:
        try:
            data = json.loads(wf_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            all_findings.append(
                {
                    "rule_id": "SCHEMA001",
                    "severity": "error",
                    "category": "schema",
                    "title": "Invalid workflow JSON root",
                    "detail": f"Could not parse JSON ({exc}).",
                    "remediation": "Ensure the file is valid UTF-8 JSON exported from n8n.",
                    "file": str(wf_path),
                    "node": "<file>",
                }
            )
            continue
        all_findings.extend(lint_workflow_data(data, str(wf_path), ignore_rules=ignore_rules))

    use_color = sys.stdout.isatty() and not args.no_color and os.environ.get("NO_COLOR") is None
    rendered = format_report(all_findings, files_scanned=len(files), fmt=args.format, use_color=use_color)

    if args.output:
        out_path = Path(args.output)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(rendered + "\n", encoding="utf-8")
    else:
        print(rendered)

    errors = sum(1 for f in all_findings if f["severity"] == "error")
    warnings = sum(1 for f in all_findings if f["severity"] == "warn")
    if errors > 0:
        return 1
    if args.strict and warnings > 0:
        return 1
    return 0


def _run_redact(args: argparse.Namespace) -> int:
    src = Path(args.file)
    if not src.is_file():
        print(f"n8n-lint: file not found: {args.file}", file=sys.stderr)
        return 2
    try:
        data = json.loads(src.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"n8n-lint: invalid JSON in {args.file}: {exc}", file=sys.stderr)
        return 2
    if not isinstance(data, dict):
        print(f"n8n-lint: expected JSON object in {args.file}", file=sys.stderr)
        return 2

    cleaned = redact_workflow_data(data, deactivate=args.deactivate)
    serialized = json.dumps(cleaned, indent=2) + "\n"

    target = src if args.in_place else (Path(args.output) if args.output else None)
    if target is not None:
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(serialized, encoding="utf-8")
    else:
        print(serialized, end="")
    return 0


def _run_rules(args: argparse.Namespace) -> int:
    if args.json:
        payload = [
            {
                "id": r.id,
                "severity": r.severity,
                "category": r.category,
                "title": r.title,
                "description": r.description,
            }
            for r in ALL_RULES
        ]
        print(json.dumps(payload, indent=2))
        return 0

    for r in ALL_RULES:
        print(f"{r.id:<10} {r.severity.upper():<5} [{r.category}] {r.title}: {r.description}")
    return 0


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="n8n-lint",
        description="Deterministic static linter and redactor for n8n workflow JSON files.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command")

    p_scan = sub.add_parser("scan", help="Lint one or more workflow JSON files or directories.")
    p_scan.add_argument("paths", nargs="+", help="Workflow JSON file(s) or directory(ies).")
    p_scan.add_argument("--format", choices=["text", "json", "sarif", "markdown"], default="text")
    p_scan.add_argument("--output", help="Write report output to file instead of stdout.")
    p_scan.add_argument("--strict", action="store_true", help="Exit 1 on warnings as well as errors.")
    p_scan.add_argument("--ignore", help="Comma-separated rule IDs to suppress (e.g. REL002,URL001).")
    p_scan.add_argument("--no-color", action="store_true", help="Disable ANSI colors in text mode.")

    p_redact = sub.add_parser("redact", help="Scrub secrets, pinData, and credential IDs from workflow JSON.")
    p_redact.add_argument("file", help="Path to workflow JSON file.")
    p_redact.add_argument("--output", help="Write redacted JSON to path.")
    p_redact.add_argument("--in-place", action="store_true", help="Overwrite input file in place.")
    p_redact.add_argument("--deactivate", action="store_true", help="Set top-level active=false for safe export.")

    p_rules = sub.add_parser("rules", help="List all built-in lint rules.")
    p_rules.add_argument("--json", action="store_true", help="Emit rules catalog as JSON.")
    return parser


def main(argv: list[str] | None = None) -> int:
    args_list = list(sys.argv[1:] if argv is None else argv)
    known_cmds = {"scan", "redact", "rules", "-h", "--help", "--version"}
    if args_list and args_list[0] not in known_cmds and not args_list[0].startswith("-"):
        args_list = ["scan", *args_list]

    parser = _build_parser()
    if not args_list:
        parser.print_help()
        return 2

    args = parser.parse_args(args_list)
    if args.command == "scan":
        return _run_scan(args)
    if args.command == "redact":
        return _run_redact(args)
    if args.command == "rules":
        return _run_rules(args)

    parser.print_help()
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
