from pathlib import Path

import pytest

from iac_check.parse import Ref, Unknown, load_module

SAMPLES = Path(__file__).parent.parent / "samples"


def write_tf(tmp_path, name, text):
    (tmp_path / name).write_text(text, encoding="utf-8")
    return tmp_path


def test_lists_every_resource_in_the_good_sample():
    module = load_module(SAMPLES / "good")
    assert {r.address for r in module.resources} == {
        "aws_s3_bucket.logs",
        "aws_s3_bucket_public_access_block.logs",
        "aws_security_group.web",
    }
    assert module.of_type("aws_s3_bucket")[0].attrs["bucket"] == "demo-app-logs"


def test_nested_blocks_come_back_as_a_list():
    module = load_module(SAMPLES / "good")
    web = module.of_type("aws_security_group")[0]
    assert [b["from_port"] for b in web.blocks("ingress")] == [443, 22]
    assert web.blocks("missing") == []


def test_resolves_a_variable_default():
    module = load_module(SAMPLES / "good")
    assert module.resolve("${var.office_cidr}") == "203.0.113.0/24"


def test_resolves_a_resource_reference():
    module = load_module(SAMPLES / "good")
    ref = module.resolve("${aws_s3_bucket.logs.id}")
    assert ref == Ref("aws_s3_bucket", "logs", "id")
    assert ref.address == "aws_s3_bucket.logs"


def test_resolves_lists_element_by_element(tmp_path):
    write_tf(
        tmp_path,
        "main.tf",
        """
        variable "office" { default = "203.0.113.0/24" }
        locals { sources = [var.office, "198.51.100.0/24"] }
        """,
    )
    module = load_module(tmp_path)
    assert module.resolve("${local.sources}") == ["203.0.113.0/24", "198.51.100.0/24"]


def test_marks_what_it_cannot_follow_as_unknown(tmp_path):
    write_tf(tmp_path, "main.tf", 'variable "no_default" { type = string }')
    module = load_module(tmp_path)
    assert module.resolve("${var.no_default}") == Unknown("var.no_default")
    assert module.resolve("${each.key}") == Unknown("each.key")
    assert module.resolve("${cidrsubnet(var.vpc, 8, 1)}") == Unknown("cidrsubnet(var.vpc, 8, 1)")
    assert module.resolve("plain text") == "plain text"
    assert module.resolve(22) == 22


def test_merges_several_files_in_one_directory(tmp_path):
    write_tf(tmp_path, "variables.tf", 'variable "name" { default = "demo" }')
    write_tf(tmp_path, "main.tf", 'resource "aws_s3_bucket" "b" { bucket = var.name }')
    module = load_module(tmp_path)
    assert [r.address for r in module.resources] == ["aws_s3_bucket.b"]
    assert [r.file for r in module.resources] == ["main.tf"]
    assert module.resolve(module.resources[0].attrs["bucket"]) == "demo"


def test_empty_directory_is_an_error(tmp_path):
    with pytest.raises(FileNotFoundError):
        load_module(tmp_path)
