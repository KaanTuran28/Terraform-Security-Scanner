# Terraform Security Scan Report

- **Files scanned:** 1
- **Findings:** 4 HIGH, 2 MEDIUM, 1 LOW

| Severity | File | Resource | Line | Check | Reason |
|---|---|---|---|---|---|
| HIGH | sample_terraform\insecure_example.tf | aws_s3_bucket.data | 1 | s3_public_acl | ACL is "public-read" — the bucket (or its object listing/contents) is readable by anyone on the internet. |
| HIGH | sample_terraform\insecure_example.tf | aws_security_group.web | 6 | security_group_open_to_world | Ingress rule allows 0.0.0.0/0 on port(s) 22-22, including sensitive port(s) 22/SSH. |
| HIGH | sample_terraform\insecure_example.tf | aws_db_instance.primary | 26 | rds_publicly_accessible | publicly_accessible = true — the database is reachable directly from the internet. |
| HIGH | sample_terraform\insecure_example.tf | (file-level) | 31 | hardcoded_secret | "password" is assigned a literal string directly in the configuration. |
| MEDIUM | sample_terraform\insecure_example.tf | aws_s3_bucket.data | 1 | s3_encryption_missing | No server_side_encryption_configuration block — objects are stored unencrypted at rest (or with defaults you haven't verified). |
| MEDIUM | sample_terraform\insecure_example.tf | aws_db_instance.primary | 26 | rds_storage_not_encrypted | storage_encrypted is not set to true — data at rest is unencrypted. |
| LOW | sample_terraform\insecure_example.tf | aws_s3_bucket.data | 1 | s3_versioning_disabled | No versioning enabled — an accidental overwrite or delete (or a ransomware-style attack) is unrecoverable. |
