import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from terraform_security_scanner import (
    audit,
    build_json_report,
    build_report,
    collect_tf_files,
    find_resources,
    find_subblocks,
    get_attr,
    get_list_attr,
    main,
)

SAMPLES = Path(__file__).resolve().parent.parent / "sample_terraform"


def checks_in(findings):
    return {f["check"] for f in findings}


def audit_sample(name):
    return audit((SAMPLES / name).read_text(encoding="utf-8"))


def test_find_resources_extracts_type_name_and_body():
    text = 'resource "aws_s3_bucket" "data" {\n  acl = "private"\n}\n'
    resources = find_resources(text)
    assert len(resources) == 1
    assert resources[0]["type"] == "aws_s3_bucket"
    assert resources[0]["name"] == "data"
    assert 'acl = "private"' in resources[0]["body"]


def test_find_resources_handles_nested_braces():
    text = 'resource "aws_security_group" "web" {\n  ingress {\n    from_port = 22\n  }\n}\n'
    resources = find_resources(text)
    assert len(resources) == 1
    assert "ingress" in resources[0]["body"]
    assert "from_port = 22" in resources[0]["body"]


def test_find_subblocks_extracts_nested_block_body():
    body = 'ingress {\n  from_port = 22\n}\ningress {\n  from_port = 443\n}\n'
    blocks = find_subblocks(body, "ingress")
    assert len(blocks) == 2
    assert "from_port = 22" in blocks[0]
    assert "from_port = 443" in blocks[1]


def test_get_attr_reads_quoted_and_bare_values():
    assert get_attr('acl = "public-read"', "acl") == "public-read"
    assert get_attr("publicly_accessible = true", "publicly_accessible") == "true"
    assert get_attr("from_port = 22", "from_port") == "22"
    assert get_attr("", "missing") is None


def test_get_list_attr_reads_string_list():
    assert get_list_attr('cidr_blocks = ["0.0.0.0/0", "10.0.0.0/8"]', "cidr_blocks") == ["0.0.0.0/0", "10.0.0.0/8"]
    assert get_list_attr("no list here", "cidr_blocks") == []


def test_s3_public_acl_flagged_high():
    findings = audit_sample("insecure_example.tf")
    assert any(f["check"] == "s3_public_acl" and f["severity"] == "HIGH" for f in findings)


def test_s3_private_acl_not_flagged():
    findings = audit_sample("hardened_example.tf")
    assert not any(f["check"] == "s3_public_acl" for f in findings)


def test_s3_versioning_disabled_flagged_low():
    findings = audit_sample("insecure_example.tf")
    assert any(f["check"] == "s3_versioning_disabled" and f["severity"] == "LOW" for f in findings)


def test_s3_versioning_enabled_not_flagged():
    findings = audit_sample("hardened_example.tf")
    assert not any(f["check"] == "s3_versioning_disabled" for f in findings)


def test_s3_encryption_missing_flagged_medium():
    findings = audit_sample("insecure_example.tf")
    assert any(f["check"] == "s3_encryption_missing" and f["severity"] == "MEDIUM" for f in findings)


def test_s3_encryption_present_not_flagged():
    findings = audit_sample("hardened_example.tf")
    assert not any(f["check"] == "s3_encryption_missing" for f in findings)


def test_security_group_open_ssh_flagged_high():
    findings = audit_sample("insecure_example.tf")
    ssh_findings = [f for f in findings if f["check"] == "security_group_open_to_world"]
    assert len(ssh_findings) == 1
    assert ssh_findings[0]["severity"] == "HIGH"
    assert "22" in ssh_findings[0]["reason"]


def test_security_group_open_https_not_flagged_since_not_sensitive():
    findings = audit_sample("insecure_example.tf")
    sg_findings = [f for f in findings if f["check"] == "security_group_open_to_world"]
    assert not any("443" in f["reason"] for f in sg_findings)


def test_security_group_restricted_ssh_not_flagged():
    findings = audit_sample("hardened_example.tf")
    assert not any(f["check"] == "security_group_open_to_world" for f in findings)


def test_security_group_all_ports_open_flagged_high():
    text = (
        'resource "aws_security_group" "any" {\n'
        "  ingress {\n"
        "    from_port   = 0\n"
        "    to_port     = 65535\n"
        '    cidr_blocks = ["0.0.0.0/0"]\n'
        "  }\n"
        "}\n"
    )
    findings = audit(text)
    assert any(f["check"] == "security_group_open_to_world" for f in findings)


def test_rds_publicly_accessible_flagged_high():
    findings = audit_sample("insecure_example.tf")
    assert any(f["check"] == "rds_publicly_accessible" and f["severity"] == "HIGH" for f in findings)


def test_rds_not_publicly_accessible_not_flagged():
    findings = audit_sample("hardened_example.tf")
    assert not any(f["check"] == "rds_publicly_accessible" for f in findings)


def test_rds_storage_not_encrypted_flagged_medium():
    findings = audit_sample("insecure_example.tf")
    assert any(f["check"] == "rds_storage_not_encrypted" and f["severity"] == "MEDIUM" for f in findings)


def test_rds_storage_encrypted_not_flagged():
    findings = audit_sample("hardened_example.tf")
    assert not any(f["check"] == "rds_storage_not_encrypted" for f in findings)


def test_hardcoded_password_attribute_flagged_high():
    findings = audit_sample("insecure_example.tf")
    assert any(
        f["check"] == "hardcoded_secret" and f["severity"] == "HIGH" and "password" in f["reason"]
        for f in findings
    )


def test_password_variable_reference_not_flagged():
    findings = audit_sample("hardened_example.tf")
    assert not any(f["check"] == "hardcoded_secret" for f in findings)


def test_variable_with_hardcoded_secret_default_flagged():
    text = 'variable "api_key" {\n  type    = string\n  default = "sk_live_abc123"\n}\n'
    findings = audit(text)
    assert any(f["check"] == "hardcoded_secret" and "variable" in f["resource"] for f in findings)


def test_variable_with_no_default_not_flagged():
    text = 'variable "api_key" {\n  type      = string\n  sensitive = true\n}\n'
    findings = audit(text)
    assert not any(f["check"] == "hardcoded_secret" for f in findings)


def test_hardened_example_has_no_findings():
    assert audit_sample("hardened_example.tf") == []


def test_insecure_example_finding_counts():
    findings = audit_sample("insecure_example.tf")
    high = sum(1 for f in findings if f["severity"] == "HIGH")
    medium = sum(1 for f in findings if f["severity"] == "MEDIUM")
    low = sum(1 for f in findings if f["severity"] == "LOW")
    assert (high, medium, low) == (4, 2, 1)


def test_collect_tf_files_on_directory():
    files = collect_tf_files(SAMPLES)
    names = {f.name for f in files}
    assert names == {"insecure_example.tf", "hardened_example.tf"}


def test_collect_tf_files_on_single_file():
    assert len(collect_tf_files(SAMPLES / "hardened_example.tf")) == 1


def test_build_report_lists_findings_in_markdown_table():
    results = [("insecure_example.tf", audit_sample("insecure_example.tf"))]
    report = build_report(results)
    assert "HIGH" in report
    assert "s3_public_acl" in report


def test_build_report_clean_says_no_issues():
    results = [("hardened_example.tf", audit_sample("hardened_example.tf"))]
    report = build_report(results)
    assert "No issues found." in report


def test_json_report_is_valid_and_matches_findings():
    results = [("insecure_example.tf", audit_sample("insecure_example.tf"))]
    payload = json.loads(build_json_report(results))
    assert payload["files_scanned"] == 1
    assert payload["summary"]["high"] == 4


def run_main(monkeypatch, tmp_path, target_path, extra_args):
    out = str(tmp_path / "out.md")
    argv = ["terraform_security_scanner.py", "--path", str(target_path), "--output", out] + extra_args
    monkeypatch.setattr(sys, "argv", argv)
    return main()


def test_fail_on_high_exits_nonzero_for_insecure_example(monkeypatch, tmp_path):
    assert run_main(monkeypatch, tmp_path, SAMPLES / "insecure_example.tf", ["--fail-on", "high"]) == 1


def test_fail_on_high_exits_zero_for_hardened_example(monkeypatch, tmp_path):
    assert run_main(monkeypatch, tmp_path, SAMPLES / "hardened_example.tf", ["--fail-on", "high"]) == 0


def test_fail_on_none_always_exits_zero(monkeypatch, tmp_path):
    assert run_main(monkeypatch, tmp_path, SAMPLES / "insecure_example.tf", []) == 0
