"""Command line entry point: python -m iac_check <command> <path>."""
from __future__ import annotations

import argparse
import sys

from iac_check.parse import load_module


def cmd_list(path: str) -> int:
    module = load_module(path)
    for resource in module.resources:
        print(f"{resource.address}  ({resource.file})")
    print(f"{len(module.resources)} resources in {module.path}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="iac_check")
    commands = parser.add_subparsers(dest="command", required=True)

    list_cmd = commands.add_parser("list", help="list the resources in a Terraform directory")
    list_cmd.add_argument("path")

    args = parser.parse_args(argv)
    if args.command == "list":
        return cmd_list(args.path)
    return 2


if __name__ == "__main__":
    sys.exit(main())
