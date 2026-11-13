"""Command line entry point: python -m iac_check <command> <path>."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from iac_check.parse import load_module
from iac_check.report import build_report, exit_code, to_text


def cmd_list(path: str) -> int:
    module = load_module(path)
    for resource in module.resources:
        print(f"{resource.address}  ({resource.file}:{resource.line})")
    print(f"{len(module.resources)} resources in {module.path}")
    return 0


def cmd_check(path: str, json_out: str | None, strict: bool, quiet: bool) -> int:
    report = build_report(path)
    if json_out == "-":
        print(json.dumps(report, indent=2))
    else:
        if json_out:
            out = Path(json_out)
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        if not quiet:
            print(to_text(report))
    return exit_code(report, strict)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="iac_check", description="Grade Terraform for common mistakes.")
    commands = parser.add_subparsers(dest="command", required=True)

    list_cmd = commands.add_parser("list", help="list the resources in a Terraform folder")
    list_cmd.add_argument("path")

    check_cmd = commands.add_parser("check", help="run every rule and report pass or fail")
    check_cmd.add_argument("path")
    check_cmd.add_argument("--json", metavar="FILE", help="also write a JSON report here (use - for stdout)")
    check_cmd.add_argument("--strict", action="store_true", help="treat \"can't tell\" as a failure")
    check_cmd.add_argument("--quiet", action="store_true", help="no text output, just the exit code")

    args = parser.parse_args(argv)
    try:
        if args.command == "list":
            return cmd_list(args.path)
        return cmd_check(args.path, args.json, args.strict, args.quiet)
    except FileNotFoundError as error:
        print(f"iac_check: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
