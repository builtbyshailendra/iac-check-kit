"""Run every rule over a folder and turn the findings into a report.

The JSON report is for machines (CI, a grader, another script). The text
version is for a person reading a terminal. Both come from the same dict.
"""
from __future__ import annotations

from pathlib import Path

from iac_check.parse import load_module
from iac_check.rules import FAIL, PASS, UNKNOWN, all_rules

STATUSES = (PASS, FAIL, UNKNOWN)


def _counts(findings: list[dict]) -> dict[str, int]:
    return {status: sum(1 for f in findings if f["status"] == status) for status in STATUSES}


def build_report(path: str | Path) -> dict:
    module = load_module(path)
    rules = []
    for rule in all_rules():
        findings = [f.to_dict() for f in rule.check(module)]
        rules.append({"id": rule.id, "title": rule.title, **_counts(findings), "findings": findings})

    every = [f for r in rules for f in r["findings"]]
    return {
        "path": Path(path).as_posix(),
        "resources": len(module.resources),
        "summary": _counts(every),
        "rules": rules,
    }


def exit_code(report: dict, strict: bool = False) -> int:
    """0 when nothing failed. With strict, "can't tell" also counts as a failure."""
    summary = report["summary"]
    if summary[FAIL] or (strict and summary[UNKNOWN]):
        return 1
    return 0


def to_text(report: dict) -> str:
    lines = [f"iac-check: {report['path']} ({report['resources']} resources)", ""]
    for rule in report["rules"]:
        lines.append(f"{rule['id']}: {rule['title']}")
        if not rule["findings"]:
            lines.append("  (nothing to check)")
        for f in rule["findings"]:
            where = f"{f['file']}:{f['line']}"
            lines.append(f"  {f['status'].upper():<7} {f['resource']}  {where}")
            lines.append(f"          {f['reason']}")
        lines.append("")
    s = report["summary"]
    lines.append(f"{s[PASS]} passed, {s[FAIL]} failed, {s[UNKNOWN]} can't tell")
    return "\n".join(lines)
