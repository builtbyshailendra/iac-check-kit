"""The checks. Each rule reads a Module and returns one Finding per resource it looked at."""
from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Callable

from iac_check.parse import Module, Resource

PASS = "pass"
FAIL = "fail"
UNKNOWN = "unknown"


@dataclass
class Finding:
    rule: str
    resource: str
    file: str
    line: int
    status: str
    reason: str

    @classmethod
    def for_resource(cls, rule: str, resource: Resource, status: str, reason: str) -> "Finding":
        return cls(rule, resource.address, resource.file, resource.line, status, reason)

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    check: Callable[[Module], list[Finding]]


def all_rules() -> list[Rule]:
    # Imported here so each rule module can import Finding from this package.
    from iac_check.rules import s3_public_access

    return [s3_public_access.RULE]
