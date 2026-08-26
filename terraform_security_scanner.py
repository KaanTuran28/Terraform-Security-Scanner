#!/usr/bin/env python3
"""Static security scanner for Terraform (HCL) configuration files.

A lightweight, regex + brace-depth block extractor (not a full HCL parser)
that flags common AWS infrastructure misconfigurations: public S3 buckets,
security groups open to the world on sensitive ports, publicly accessible
or unencrypted RDS instances, and hardcoded secrets. For IAM policy JSON
documents specifically, see the companion `Cloud-IAM-Policy-Auditor`
project — this tool focuses on infrastructure-level resources.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

SENSITIVE_PORTS = {
    22: "SSH", 23: "Telnet", 3389: "RDP", 3306: "MySQL", 5432: "PostgreSQL",
    6379: "Redis", 27017: "MongoDB", 9200: "Elasticsearch", 1433: "MSSQL",
}

SECRET_ATTR_RE = re.compile(
    r'\b(password|secret|access_key|private_key|api_key)\s*=\s*"([^"$][^"]*)"', re.IGNORECASE
)

RESOURCE_RE = re.compile(r'resource\s+"(?P<rtype>[a-zA-Z0-9_]+)"\s+"(?P<rname>[a-zA-Z0-9_-]+)"\s*\{')
VARIABLE_RE = re.compile(r'variable\s+"(?P<vname>[a-zA-Z0-9_-]+)"\s*\{')


def _extract_block_body(text: str, brace_start: int) -> tuple:
    depth = 1
    i = brace_start
    while i < len(text) and depth > 0:
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
        i += 1
    return text[brace_start:i - 1], i


def find_resources(text: str, resource_type: str | None = None) -> list:
    resources = []
    for m in RESOURCE_RE.finditer(text):
        if resource_type and m.group("rtype") != resource_type:
            continue
        body, _ = _extract_block_body(text, m.end())
        line = text[:m.start()].count("\n") + 1
        resources.append({"type": m.group("rtype"), "name": m.group("rname"), "body": body, "line": line})
    return resources


def find_variables(text: str) -> list:
    variables = []
    for m in VARIABLE_RE.finditer(text):
        body, _ = _extract_block_body(text, m.end())
        line = text[:m.start()].count("\n") + 1
        variables.append({"name": m.group("vname"), "body": body, "line": line})
    return variables


def find_subblocks(body: str, block_name: str) -> list:
    pattern = re.compile(rf'\b{re.escape(block_name)}\s*\{{')
    blocks = []
    for m in pattern.finditer(body):
        sub_body, _ = _extract_block_body(body, m.end())
        blocks.append(sub_body)
    return blocks


def get_attr(body: str, key: str):
    m = re.search(rf'\b{re.escape(key)}\s*=\s*"?([a-zA-Z0-9_.\-:]+)"?', body)
    return m.group(1) if m else None


def get_list_attr(body: str, key: str) -> list:
    m = re.search(rf'\b{re.escape(key)}\s*=\s*\[(.*?)\]', body, re.DOTALL)
    if not m:
        return []
    return re.findall(r'"([^"]*)"', m.group(1))


def finding(severity: str, resource: str, line: int, check: str, reason: str, recommendation: str) -> dict:
    return {
        "severity": severity, "resource": resource, "line": line,
        "check": check, "reason": reason, "recommendation": recommendation,
    }


def audit(text: str) -> list:
    findings = []

    for r in find_resources(text, "aws_s3_bucket"):
        label = f'aws_s3_bucket.{r["name"]}'
        acl = get_attr(r["body"], "acl")
        if acl in ("public-read", "public-read-write"):
            findings.append(finding(
                "HIGH", label, r["line"], "s3_public_acl",
                f'ACL is "{acl}" — the bucket (or its object listing/contents) is readable by anyone on the internet.',
                'Set acl = "private" and use bucket policies/pre-signed URLs for any access that must be granted.',
            ))

        versioning_blocks = find_subblocks(r["body"], "versioning")
        if not versioning_blocks or get_attr(versioning_blocks[0], "enabled") != "true":
            findings.append(finding(
                "LOW", label, r["line"], "s3_versioning_disabled",
                "No versioning enabled — an accidental overwrite or delete (or a ransomware-style attack) "
                "is unrecoverable.",
                'Add a versioning { enabled = true } block.',
            ))

        if not find_subblocks(r["body"], "server_side_encryption_configuration"):
            findings.append(finding(
                "MEDIUM", label, r["line"], "s3_encryption_missing",
                "No server_side_encryption_configuration block — objects are stored unencrypted at rest "
                "(or with defaults you haven't verified).",
                "Add a server_side_encryption_configuration block (SSE-S3 or SSE-KMS).",
            ))

    for r in find_resources(text, "aws_security_group"):
        label = f'aws_security_group.{r["name"]}'
        for ingress_body in find_subblocks(r["body"], "ingress"):
            cidrs = get_list_attr(ingress_body, "cidr_blocks")
            if "0.0.0.0/0" not in cidrs:
                continue
            from_port_raw, to_port_raw = get_attr(ingress_body, "from_port"), get_attr(ingress_body, "to_port")
            try:
                from_port, to_port = int(from_port_raw), int(to_port_raw)
            except (TypeError, ValueError):
                continue
            hit_ports = [p for p in SENSITIVE_PORTS if from_port <= p <= to_port]
            if hit_ports:
                names = ", ".join(f"{p}/{SENSITIVE_PORTS[p]}" for p in sorted(hit_ports))
                findings.append(finding(
                    "HIGH", label, r["line"], "security_group_open_to_world",
                    f"Ingress rule allows 0.0.0.0/0 on port(s) {from_port}-{to_port}, including sensitive "
                    f"port(s) {names}.",
                    "Restrict cidr_blocks to known, trusted ranges (VPN/bastion/office IP), not the open internet.",
                ))
            elif to_port - from_port >= 60000:
                findings.append(finding(
                    "HIGH", label, r["line"], "security_group_open_to_world",
                    f"Ingress rule allows 0.0.0.0/0 across essentially all ports ({from_port}-{to_port}).",
                    "Scope the rule to the specific port(s) actually required.",
                ))

    for r in find_resources(text, "aws_db_instance"):
        label = f'aws_db_instance.{r["name"]}'
        if get_attr(r["body"], "publicly_accessible") == "true":
            findings.append(finding(
                "HIGH", label, r["line"], "rds_publicly_accessible",
                "publicly_accessible = true — the database is reachable directly from the internet.",
                "Set publicly_accessible = false and access the database through a VPC/bastion/VPN.",
            ))
        if get_attr(r["body"], "storage_encrypted") != "true":
            findings.append(finding(
                "MEDIUM", label, r["line"], "rds_storage_not_encrypted",
                "storage_encrypted is not set to true — data at rest is unencrypted.",
                "Set storage_encrypted = true (must be set at creation time; existing instances need a snapshot/restore).",
            ))

    for m in SECRET_ATTR_RE.finditer(text):
        line = text[:m.start()].count("\n") + 1
        findings.append(finding(
            "HIGH", "(file-level)", line, "hardcoded_secret",
            f'"{m.group(1)}" is assigned a literal string directly in the configuration.',
            "Reference a variable (marked sensitive = true) populated from a secret manager or environment, "
            "never a literal value in .tf source.",
        ))

    for v in find_variables(text):
        if not re.search(r"(password|secret|api_?key|private_key|access_key)", v["name"], re.IGNORECASE):
            continue
        default_match = re.search(r'default\s*=\s*"([^"]+)"', v["body"])
        if default_match and default_match.group(1):
            findings.append(finding(
                "HIGH", f'variable.{v["name"]}', v["line"], "hardcoded_secret",
                f'variable "{v["name"]}" has a non-empty literal default value baked into the configuration.',
                "Remove the default (force it to be supplied at apply time) and mark the variable sensitive = true.",
            ))

    return findings


def build_report(results: list) -> str:
    all_findings = [(f, source) for source, findings in results for f in findings]
    high = [f for f, _ in all_findings if f["severity"] == "HIGH"]
    medium = [f for f, _ in all_findings if f["severity"] == "MEDIUM"]
    low = [f for f, _ in all_findings if f["severity"] == "LOW"]

    lines = [
        "# Terraform Security Scan Report",
        "",
        f"- **Files scanned:** {len(results)}",
        f"- **Findings:** {len(high)} HIGH, {len(medium)} MEDIUM, {len(low)} LOW",
        "",
    ]
    if all_findings:
        lines += ["| Severity | File | Resource | Line | Check | Reason |", "|---|---|---|---|---|---|"]
        order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
        for f, source in sorted(all_findings, key=lambda pair: order[pair[0]["severity"]]):
            reason = f["reason"].replace("|", "\\|")
            lines.append(f"| {f['severity']} | {source} | {f['resource']} | {f['line']} | {f['check']} | {reason} |")
    else:
        lines.append("No issues found.")
    lines.append("")
    return "\n".join(lines)


def build_json_report(results: list) -> str:
    all_findings = [f for _, findings in results for f in findings]
    payload = {
        "files_scanned": len(results),
        "summary": {
            "high": sum(1 for f in all_findings if f["severity"] == "HIGH"),
            "medium": sum(1 for f in all_findings if f["severity"] == "MEDIUM"),
            "low": sum(1 for f in all_findings if f["severity"] == "LOW"),
        },
        "results": [{"file": source, "findings": findings} for source, findings in results],
    }
    return json.dumps(payload, indent=2, ensure_ascii=False) + "\n"


def collect_tf_files(path: Path) -> list:
    if path.is_file():
        return [path]
    return sorted(path.rglob("*.tf"))


def main():
    parser = argparse.ArgumentParser(description="Static security scan of Terraform (.tf) configuration.")
    parser.add_argument("--path", required=True, help="Path to a .tf file or a directory to scan recursively.")
    parser.add_argument("--output", default="sample_report.md", help="Path to write the report.")
    parser.add_argument(
        "--format", choices=["markdown", "json"], default="markdown", help="Output report format."
    )
    parser.add_argument(
        "--fail-on",
        choices=["none", "medium", "high"],
        default="none",
        help="Exit with code 1 if findings at/above this severity are present (for CI gating).",
    )
    args = parser.parse_args()

    target = Path(args.path)
    files = collect_tf_files(target)
    results = [(str(f), audit(f.read_text(encoding="utf-8"))) for f in files]

    report = build_json_report(results) if args.format == "json" else build_report(results)
    with open(args.output, "w", encoding="utf-8") as fh:
        fh.write(report)

    all_findings = [f for _, findings in results for f in findings]
    high_count = sum(1 for f in all_findings if f["severity"] == "HIGH")
    medium_count = sum(1 for f in all_findings if f["severity"] == "MEDIUM")
    print(f"Scanned {len(files)} file(s): {high_count} HIGH, {medium_count} MEDIUM finding(s).")
    print(f"Report written to {args.output}")

    if args.fail_on == "high" and high_count > 0:
        return 1
    if args.fail_on == "medium" and (high_count > 0 or medium_count > 0):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
