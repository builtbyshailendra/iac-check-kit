"""Load Terraform files and give the rules something simple to work with.

python-hcl2 turns a .tf file into nested dicts. Anything that isn't a plain
value comes back as a string like "${var.office_cidr}". The Module here keeps
the resources, variables and locals together so a rule can follow those
references as far as the text allows, without running Terraform.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import hcl2
from hcl2.utils import SerializationOptions

# Version 8 of python-hcl2 keeps the quotes around string literals and adds
# __is_block__ markers by default. Neither helps a rule, so turn both off.
_OPTIONS = SerializationOptions(
    with_comments=False, explicit_blocks=False, strip_string_quotes=True
)
_EXPRESSION = re.compile(r"^\$\{(.+)\}$", re.DOTALL)
_REFERENCE = re.compile(
    r"^([A-Za-z_][\w-]*)\.([A-Za-z_][\w-]*)(\[[^\]]*\])?(?:\.([A-Za-z_]\w*))?$"
)
# python-hcl2 has no line numbers in this mode, so find each block in the text.
# [ \t]* rather than \s* at the start, or the match swallows the blank line above.
_RESOURCE_LINE = re.compile(r'^[ \t]*resource\s+"([^"]+)"\s+"([^"]+)"', re.MULTILINE)
# Things that look like references but can't be followed from the text alone.
_NOT_FOLLOWABLE = {"each", "count", "module", "data", "path", "terraform", "self"}


@dataclass(frozen=True)
class Ref:
    """A reference to another resource, such as aws_s3_bucket.logs.id."""

    type: str
    name: str
    attr: str | None = None

    @property
    def address(self) -> str:
        return f"{self.type}.{self.name}"


@dataclass(frozen=True)
class Unknown:
    """A value the kit can't work out without running Terraform."""

    expr: str


@dataclass
class Resource:
    type: str
    name: str
    attrs: dict[str, Any]
    file: str
    line: int = 0

    @property
    def address(self) -> str:
        return f"{self.type}.{self.name}"

    def blocks(self, key: str) -> list[dict[str, Any]]:
        """Nested blocks such as `ingress`, always as a list."""
        value = self.attrs.get(key, [])
        if isinstance(value, dict):
            return [value]
        return [v for v in value if isinstance(v, dict)]


@dataclass
class Module:
    path: Path
    resources: list[Resource] = field(default_factory=list)
    variables: dict[str, dict[str, Any]] = field(default_factory=dict)
    locals: dict[str, Any] = field(default_factory=dict)

    def of_type(self, type_: str) -> list[Resource]:
        return [r for r in self.resources if r.type == type_]

    def resolve(self, value: Any, _depth: int = 0) -> Any:
        """Follow var.x, local.x and resource references as far as the text allows.

        Plain values come back unchanged. A list is resolved element by element.
        A resource reference becomes a Ref. Anything else that needs Terraform to
        evaluate (functions, for_each, data sources, ...) becomes an Unknown, so a
        rule can say "I can't tell" instead of guessing.
        """
        if _depth > 10:
            return Unknown(str(value))
        if isinstance(value, list):
            return [self.resolve(v, _depth + 1) for v in value]
        if not isinstance(value, str):
            return value
        match = _EXPRESSION.match(value)
        if not match:
            return value
        expr = match.group(1).strip()
        ref = _REFERENCE.match(expr)
        if not ref:
            return Unknown(expr)
        head, name, index, attr = ref.groups()
        if index and head in ("var", "local"):
            return Unknown(expr)
        if head == "var":
            variable = self.variables.get(name)
            if variable is None or "default" not in variable:
                return Unknown(expr)
            return self.resolve(variable["default"], _depth + 1)
        if head == "local":
            if name not in self.locals:
                return Unknown(expr)
            return self.resolve(self.locals[name], _depth + 1)
        if head in _NOT_FOLLOWABLE:
            return Unknown(expr)
        return Ref(head, name, attr)


def load_module(path: str | Path) -> Module:
    """Read every .tf file in a directory (or one file) into a Module."""
    path = Path(path)
    files = [path] if path.is_file() else sorted(path.glob("*.tf"))
    if not files:
        raise FileNotFoundError(f"No .tf files found in {path}")

    module = Module(path=path)
    for file in files:
        text = file.read_text(encoding="utf-8")
        data = hcl2.loads(text, serialization_options=_OPTIONS)
        lines = {
            (m.group(1), m.group(2)): text.count("\n", 0, m.start()) + 1
            for m in _RESOURCE_LINE.finditer(text)
        }
        for block in data.get("resource", []):
            for type_, by_name in block.items():
                for name, attrs in by_name.items():
                    line = lines.get((type_, name), 0)
                    module.resources.append(Resource(type_, name, attrs, file.name, line))
        for block in data.get("variable", []):
            for name, attrs in block.items():
                module.variables[name] = attrs
        for block in data.get("locals", []):
            module.locals.update(block)
    return module
