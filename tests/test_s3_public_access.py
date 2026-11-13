from pathlib import Path

from iac_check.parse import load_module
from iac_check.rules.s3_public_access import check

SAMPLES = Path(__file__).parent.parent / "samples"

ALL_ON = """
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
"""


def run(tmp_path, text):
    (tmp_path / "main.tf").write_text(text, encoding="utf-8")
    return {f.resource: f for f in check(load_module(tmp_path))}


def test_good_sample_passes():
    findings = check(load_module(SAMPLES / "good"))
    assert [(f.resource, f.status) for f in findings] == [("aws_s3_bucket.logs", "pass")]
    assert "All four settings are on" in findings[0].reason


def test_flawed_sample_catches_both_mistakes():
    findings = {f.resource: f for f in check(load_module(SAMPLES / "flawed_public_bucket"))}
    assert findings["aws_s3_bucket.assets"].status == "fail"
    assert findings["aws_s3_bucket.assets"].reason.startswith("No public access block")
    assert findings["aws_s3_bucket.uploads"].status == "fail"
    assert "block_public_policy and restrict_public_buckets are off" in findings["aws_s3_bucket.uploads"].reason


def test_findings_point_at_the_right_line():
    findings = {f.resource: f for f in check(load_module(SAMPLES / "flawed_public_bucket"))}
    lines = (SAMPLES / "flawed_public_bucket" / "main.tf").read_text().splitlines()
    assets = findings["aws_s3_bucket.assets"]
    assert lines[assets.line - 1].startswith('resource "aws_s3_bucket" "assets"')


def test_a_missing_setting_counts_as_off(tmp_path):
    findings = run(
        tmp_path,
        """
        resource "aws_s3_bucket" "b" { bucket = "demo" }
        resource "aws_s3_bucket_public_access_block" "b" {
          bucket            = aws_s3_bucket.b.id
          block_public_acls = true
        }
        """,
    )
    assert findings["aws_s3_bucket.b"].status == "fail"
    assert "block_public_policy, ignore_public_acls and restrict_public_buckets are off" in findings[
        "aws_s3_bucket.b"
    ].reason


# A fair check passes a different correct answer. These are all safe, just written differently.

def test_account_level_block_covers_every_bucket(tmp_path):
    findings = run(
        tmp_path,
        f"""
        resource "aws_s3_bucket" "a" {{ bucket = "demo-a" }}
        resource "aws_s3_bucket" "b" {{ bucket = "demo-b" }}
        resource "aws_s3_account_public_access_block" "this" {{ {ALL_ON} }}
        """,
    )
    assert {f.status for f in findings.values()} == {"pass"}
    assert "aws_s3_account_public_access_block.this" in findings["aws_s3_bucket.a"].reason


def test_account_and_bucket_settings_combine(tmp_path):
    # AWS applies whichever level is stricter, so two half blocks make a whole one.
    findings = run(
        tmp_path,
        """
        resource "aws_s3_bucket" "b" { bucket = "demo" }
        resource "aws_s3_bucket_public_access_block" "b" {
          bucket              = aws_s3_bucket.b.id
          block_public_acls   = true
          block_public_policy = true
        }
        resource "aws_s3_account_public_access_block" "this" {
          ignore_public_acls      = true
          restrict_public_buckets = true
        }
        """,
    )
    assert findings["aws_s3_bucket.b"].status == "pass"


def test_block_can_name_the_bucket_as_text(tmp_path):
    findings = run(
        tmp_path,
        f"""
        resource "aws_s3_bucket" "b" {{ bucket = "demo-logs" }}
        resource "aws_s3_bucket_public_access_block" "b" {{
          bucket = "demo-logs"
          {ALL_ON}
        }}
        """,
    )
    assert findings["aws_s3_bucket.b"].status == "pass"


def test_settings_from_a_variable_default(tmp_path):
    findings = run(
        tmp_path,
        """
        variable "lock" { default = true }
        resource "aws_s3_bucket" "b" { bucket = "demo" }
        resource "aws_s3_bucket_public_access_block" "b" {
          bucket                  = aws_s3_bucket.b.id
          block_public_acls       = var.lock
          block_public_policy     = var.lock
          ignore_public_acls      = var.lock
          restrict_public_buckets = var.lock
        }
        """,
    )
    assert findings["aws_s3_bucket.b"].status == "pass"


def test_counted_buckets_match_their_counted_blocks(tmp_path):
    findings = run(
        tmp_path,
        f"""
        resource "aws_s3_bucket" "b" {{
          count  = 2
          bucket = "demo-${{count.index}}"
        }}
        resource "aws_s3_bucket_public_access_block" "b" {{
          count  = 2
          bucket = aws_s3_bucket.b[count.index].id
          {ALL_ON}
        }}
        """,
    )
    assert findings["aws_s3_bucket.b"].status == "pass"


# When the kit can't tell, it says so instead of guessing.

def test_setting_from_a_variable_without_default_is_unknown(tmp_path):
    findings = run(
        tmp_path,
        """
        variable "lock" { type = bool }
        resource "aws_s3_bucket" "b" { bucket = "demo" }
        resource "aws_s3_bucket_public_access_block" "b" {
          bucket                  = aws_s3_bucket.b.id
          block_public_acls       = true
          block_public_policy     = true
          ignore_public_acls      = true
          restrict_public_buckets = var.lock
        }
        """,
    )
    assert findings["aws_s3_bucket.b"].status == "unknown"
    assert "restrict_public_buckets" in findings["aws_s3_bucket.b"].reason


def test_block_pointing_somewhere_unclear_is_unknown(tmp_path):
    findings = run(
        tmp_path,
        f"""
        resource "aws_s3_bucket" "b" {{ bucket = "demo" }}
        resource "aws_s3_bucket_public_access_block" "b" {{
          bucket = data.aws_s3_bucket.existing.id
          {ALL_ON}
        }}
        """,
    )
    assert findings["aws_s3_bucket.b"].status == "unknown"
