import json
from pathlib import Path

import pytest

from iac_check.__main__ import main
from iac_check.report import build_report, exit_code, to_text

SAMPLES = Path(__file__).parent.parent / "samples"


def statuses(report):
    return {(f["rule"], f["resource"]): f["status"] for r in report["rules"] for f in r["findings"]}


def test_good_sample_report():
    report = build_report(SAMPLES / "good")
    assert report["summary"] == {"pass": 2, "fail": 0, "unknown": 0}
    assert [r["id"] for r in report["rules"]] == ["s3-public-access-block", "no-open-ssh"]
    assert exit_code(report) == 0


def test_flawed_samples_report_exactly_the_planted_mistakes():
    bucket = statuses(build_report(SAMPLES / "flawed_public_bucket"))
    assert bucket == {
        ("s3-public-access-block", "aws_s3_bucket.assets"): "fail",
        ("s3-public-access-block", "aws_s3_bucket.uploads"): "fail",
        ("no-open-ssh", "aws_security_group.web"): "pass",
    }
    ssh = statuses(build_report(SAMPLES / "flawed_open_ssh"))
    assert ssh == {
        ("s3-public-access-block", "aws_s3_bucket.logs"): "pass",
        ("no-open-ssh", "aws_security_group.bastion"): "fail",
        ("no-open-ssh", "aws_vpc_security_group_ingress_rule.admin_all"): "fail",
    }


def test_report_counts_per_rule():
    report = build_report(SAMPLES / "flawed_public_bucket")
    s3 = report["rules"][0]
    assert (s3["pass"], s3["fail"], s3["unknown"]) == (0, 2, 0)


def test_report_is_plain_json():
    report = build_report(SAMPLES / "flawed_open_ssh")
    assert json.loads(json.dumps(report)) == report


def test_strict_mode_fails_on_cant_tell(tmp_path):
    (tmp_path / "main.tf").write_text(
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
        encoding="utf-8",
    )
    report = build_report(tmp_path)
    assert report["summary"]["unknown"] == 1
    assert exit_code(report) == 0
    assert exit_code(report, strict=True) == 1


def test_text_report_reads_well():
    text = to_text(build_report(SAMPLES / "flawed_open_ssh"))
    assert "FAIL    aws_security_group.bastion  main.tf:32" in text
    assert "Opens port 22 to 0.0.0.0/0" in text
    assert text.endswith("1 passed, 2 failed, 0 can't tell")


@pytest.mark.parametrize("sample, code", [("good", 0), ("flawed_public_bucket", 1), ("flawed_open_ssh", 1)])
def test_cli_exit_codes(sample, code, capsys):
    assert main(["check", str(SAMPLES / sample), "--quiet"]) == code
    assert capsys.readouterr().out == ""


def test_cli_writes_json_file(tmp_path, capsys):
    out = tmp_path / "reports" / "good.json"
    assert main(["check", str(SAMPLES / "good"), "--json", str(out)]) == 0
    assert json.loads(out.read_text())["summary"]["pass"] == 2
    assert "2 passed, 0 failed" in capsys.readouterr().out


def test_cli_json_to_stdout(capsys):
    main(["check", str(SAMPLES / "flawed_open_ssh"), "--json", "-"])
    assert json.loads(capsys.readouterr().out)["summary"]["fail"] == 2


def test_cli_missing_folder(tmp_path, capsys):
    assert main(["check", str(tmp_path)]) == 2
    assert "No .tf files" in capsys.readouterr().err


def test_same_safe_setup_written_differently_also_passes():
    # Account-level block, separate rule resources, a /32 in a local, an IPv6 range.
    report = build_report(SAMPLES / "good_alternative")
    assert report["summary"] == {"pass": 5, "fail": 0, "unknown": 0}


def test_cli_unreadable_terraform_is_exit_2_not_a_failed_check(tmp_path, capsys):
    (tmp_path / "main.tf").write_text('resource "aws_s3_bucket" "b" {\n  bucket = \n', encoding="utf-8")
    assert main(["check", str(tmp_path)]) == 2
    assert "Can't parse main.tf" in capsys.readouterr().err
