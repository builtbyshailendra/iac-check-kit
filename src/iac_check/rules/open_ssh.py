"""Rule: SSH (port 22) is not open to the whole internet.

Ingress can be written three ways in the AWS provider, and the rule reads all of them:
  - `ingress` blocks inside aws_security_group
  - aws_security_group_rule with type = "ingress"
  - aws_vpc_security_group_ingress_rule (the newer one-rule-per-resource style)

A rule opens SSH when its protocol is TCP (or all protocols) and its port range
includes 22. It is open to the whole internet when a source CIDR has a /0 prefix,
which covers 0.0.0.0/0 and ::/0.
"""
from __future__ import annotations

import ipaddress
from typing import Any

from iac_check.parse import Module, Resource, Unknown
from iac_check.rules import FAIL, PASS, UNKNOWN, Finding, Rule

RULE_ID = "no-open-ssh"
SSH = 22
ALL_PROTOCOLS = {"-1", "all"}
TCP = {"tcp", "6"}


def _flatten(values: list[Any]) -> list[Any]:
    out = []
    for value in values:
        if isinstance(value, list):
            out.extend(_flatten(value))
        elif value is not None:
            out.append(value)
    return out


def _port(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _covers_ssh(module: Module, protocol: Any, from_port: Any, to_port: Any) -> tuple[bool | None, str]:
    """Does this protocol and port range include SSH? Returns (answer, description)."""
    protocol = module.resolve(protocol)
    if protocol is None:
        return None, "no protocol"
    if isinstance(protocol, Unknown):
        return None, f"protocol {protocol.expr}"
    protocol = str(protocol).lower()
    if protocol in ALL_PROTOCOLS:
        return True, "every port"
    if protocol not in TCP:
        return False, f"{protocol} only"
    low, high = _port(module.resolve(from_port)), _port(module.resolve(to_port))
    if low is None or high is None:
        return None, "ports it can't work out"
    if not low <= SSH <= high:
        return False, f"port {low}" if low == high else f"ports {low}-{high}"
    return True, "port 22" if low == high else f"ports {low}-{high}, including 22,"


def _world_sources(module: Module, *sources: Any) -> tuple[list[str], list[str]]:
    """Split the sources into CIDRs open to everyone, and ones it can't work out."""
    world, unsure = [], []
    for value in _flatten([module.resolve(s) for s in sources]):
        if isinstance(value, Unknown):
            unsure.append(value.expr)
            continue
        try:
            network = ipaddress.ip_network(str(value), strict=False)
        except ValueError:
            unsure.append(str(value))
            continue
        if network.prefixlen == 0:
            world.append(str(value))
    return world, unsure


def _evaluate(module: Module, protocol, from_port, to_port, *sources) -> tuple[str, str]:
    """Return (status, reason) for one ingress rule."""
    covers, ports = _covers_ssh(module, protocol, from_port, to_port)
    if covers is False:
        return PASS, ""
    world, unsure = _world_sources(module, *sources)
    if covers and world:
        opens = f"Opens {ports} to {' and '.join(world)}"
        if ports == "every port":
            opens += ", which includes SSH"
        return FAIL, opens
    if covers is None and world:
        return UNKNOWN, f"Open to {' and '.join(world)} on {ports}"
    if unsure:
        return UNKNOWN, f"Can't tell where {', '.join(unsure)} points"
    return PASS, ""


def _finding(resource: Resource, results: list[tuple[str, str]]) -> Finding:
    failed = [reason for status, reason in results if status == FAIL]
    unsure = [reason for status, reason in results if status == UNKNOWN]
    if failed:
        return Finding.for_resource(RULE_ID, resource, FAIL, "; ".join(failed))
    if unsure:
        return Finding.for_resource(RULE_ID, resource, UNKNOWN, "; ".join(unsure))
    return Finding.for_resource(RULE_ID, resource, PASS, "No ingress rule opens SSH to the whole internet")


def _attached_to(module: Module, resource: Resource) -> str:
    target = module.resolve(resource.attrs.get("security_group_id"))
    address = getattr(target, "address", None)
    return f" (on {address})" if address else ""


def check(module: Module) -> list[Finding]:
    findings = []

    for group in module.of_type("aws_security_group"):
        ingress = group.blocks("ingress")
        if not ingress:
            continue  # nothing inline; separate rule resources are checked below
        results = [
            _evaluate(
                module,
                rule.get("protocol"),
                rule.get("from_port"),
                rule.get("to_port"),
                rule.get("cidr_blocks", []),
                rule.get("ipv6_cidr_blocks", []),
            )
            for rule in ingress
        ]
        findings.append(_finding(group, results))

    for rule in module.of_type("aws_security_group_rule"):
        kind = module.resolve(rule.attrs.get("type"))
        if kind == "egress":
            continue
        a = rule.attrs
        status, reason = _evaluate(
            module, a.get("protocol"), a.get("from_port"), a.get("to_port"),
            a.get("cidr_blocks", []), a.get("ipv6_cidr_blocks", []),
        )
        if isinstance(kind, Unknown) and status != PASS:
            status, reason = UNKNOWN, f"Can't tell if this is ingress or egress. {reason}"
        findings.append(_finding(rule, [(status, reason + _attached_to(module, rule) if reason else reason)]))

    for rule in module.of_type("aws_vpc_security_group_ingress_rule"):
        a = rule.attrs
        status, reason = _evaluate(
            module, a.get("ip_protocol"), a.get("from_port"), a.get("to_port"),
            a.get("cidr_ipv4"), a.get("cidr_ipv6"),
        )
        findings.append(_finding(rule, [(status, reason + _attached_to(module, rule) if reason else reason)]))

    return findings


RULE = Rule(RULE_ID, "SSH (port 22) is not open to the whole internet", check)
