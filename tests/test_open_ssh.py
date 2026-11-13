from pathlib import Path

import pytest

from iac_check.parse import load_module
from iac_check.rules.open_ssh import check

SAMPLES = Path(__file__).parent.parent / "samples"


def run(tmp_path, text):
    (tmp_path / "main.tf").write_text(text, encoding="utf-8")
    return {f.resource: f for f in check(load_module(tmp_path))}


def inline(protocol, from_port, to_port, cidrs):
    return f"""
    resource "aws_security_group" "sg" {{
      ingress {{
        protocol    = "{protocol}"
        from_port   = {from_port}
        to_port     = {to_port}
        cidr_blocks = {cidrs}
      }}
    }}
    """


def test_good_sample_passes():
    findings = check(load_module(SAMPLES / "good"))
    assert [(f.resource, f.status) for f in findings] == [("aws_security_group.web", "pass")]


def test_flawed_sample_catches_both_ways_of_opening_ssh():
    findings = {f.resource: f for f in check(load_module(SAMPLES / "flawed_open_ssh"))}
    assert findings["aws_security_group.bastion"].status == "fail"
    assert findings["aws_security_group.bastion"].reason == "Opens port 22 to 0.0.0.0/0"
    admin = findings["aws_vpc_security_group_ingress_rule.admin_all"]
    assert admin.status == "fail"
    assert admin.reason == "Opens every port to 0.0.0.0/0, which includes SSH (on aws_security_group.admin)"
    # The admin group has no inline rules, so it isn't reported on its own.
    assert "aws_security_group.admin" not in findings


def test_https_open_to_the_world_is_fine():
    findings = {f.resource: f for f in check(load_module(SAMPLES / "flawed_public_bucket"))}
    assert findings["aws_security_group.web"].status == "pass"


@pytest.mark.parametrize(
    "protocol, low, high, cidrs, status",
    [
        ("tcp", 22, 22, '["0.0.0.0/0"]', "fail"),
        ("tcp", 0, 65535, '["0.0.0.0/0"]', "fail"),       # a wide range that includes 22
        ("6", 22, 22, '["0.0.0.0/0"]', "fail"),           # TCP written as its protocol number
        ("-1", 0, 0, '["0.0.0.0/0"]', "fail"),            # every protocol, every port
        ("tcp", 2222, 2222, '["0.0.0.0/0"]', "pass"),     # a different port
        ("udp", 22, 22, '["0.0.0.0/0"]', "pass"),         # UDP 22 isn't SSH
        ("tcp", 22, 22, '["10.0.0.0/8"]', "pass"),        # a private range
        ("tcp", 22, 22, '["203.0.113.7/32"]', "pass"),    # one address
    ],
)
def test_inline_ingress(tmp_path, protocol, low, high, cidrs, status):
    findings = run(tmp_path, inline(protocol, low, high, cidrs))
    assert findings["aws_security_group.sg"].status == status


def test_ipv6_everywhere_counts_too(tmp_path):
    findings = run(
        tmp_path,
        """
        resource "aws_security_group" "sg" {
          ingress {
            protocol         = "tcp"
            from_port        = 22
            to_port          = 22
            ipv6_cidr_blocks = ["::/0"]
          }
        }
        """,
    )
    assert findings["aws_security_group.sg"].reason == "Opens port 22 to ::/0"


def test_open_cidr_hidden_behind_a_local(tmp_path):
    findings = run(
        tmp_path,
        """
        variable "anywhere" { default = "0.0.0.0/0" }
        locals { ssh_from = [var.anywhere] }
        resource "aws_security_group" "sg" {
          ingress {
            protocol    = "tcp"
            from_port   = 22
            to_port     = 22
            cidr_blocks = local.ssh_from
          }
        }
        """,
    )
    assert findings["aws_security_group.sg"].status == "fail"


def test_legacy_security_group_rule(tmp_path):
    findings = run(
        tmp_path,
        """
        resource "aws_security_group" "sg" { name = "demo" }
        resource "aws_security_group_rule" "ssh_in" {
          type              = "ingress"
          security_group_id = aws_security_group.sg.id
          protocol          = "tcp"
          from_port         = 22
          to_port           = 22
          cidr_blocks       = ["0.0.0.0/0"]
        }
        resource "aws_security_group_rule" "all_out" {
          type              = "egress"
          security_group_id = aws_security_group.sg.id
          protocol          = "-1"
          from_port         = 0
          to_port           = 0
          cidr_blocks       = ["0.0.0.0/0"]
        }
        """,
    )
    assert findings["aws_security_group_rule.ssh_in"].status == "fail"
    assert findings["aws_security_group_rule.ssh_in"].reason.endswith("(on aws_security_group.sg)")
    # Egress to anywhere is normal and isn't SSH exposure.
    assert "aws_security_group_rule.all_out" not in findings


def test_one_bad_rule_fails_the_group_and_names_it(tmp_path):
    findings = run(
        tmp_path,
        """
        resource "aws_security_group" "sg" {
          ingress {
            protocol    = "tcp"
            from_port   = 443
            to_port     = 443
            cidr_blocks = ["0.0.0.0/0"]
          }
          ingress {
            protocol    = "tcp"
            from_port   = 20
            to_port     = 25
            cidr_blocks = ["0.0.0.0/0"]
          }
        }
        """,
    )
    assert findings["aws_security_group.sg"].reason == "Opens ports 20-25, including 22, to 0.0.0.0/0"


# When the kit can't tell, it says so instead of guessing.

def test_cidr_from_a_variable_without_default_is_unknown(tmp_path):
    findings = run(
        tmp_path,
        """
        variable "ssh_from" { type = list(string) }
        resource "aws_security_group" "sg" {
          ingress {
            protocol    = "tcp"
            from_port   = 22
            to_port     = 22
            cidr_blocks = var.ssh_from
          }
        }
        """,
    )
    assert findings["aws_security_group.sg"].status == "unknown"
    assert "var.ssh_from" in findings["aws_security_group.sg"].reason


def test_port_from_a_variable_without_default_is_unknown(tmp_path):
    findings = run(
        tmp_path,
        """
        variable "port" { type = number }
        resource "aws_vpc_security_group_ingress_rule" "r" {
          security_group_id = "sg-123"
          ip_protocol       = "tcp"
          from_port         = var.port
          to_port           = var.port
          cidr_ipv4         = "0.0.0.0/0"
        }
        """,
    )
    assert findings["aws_vpc_security_group_ingress_rule.r"].status == "unknown"
