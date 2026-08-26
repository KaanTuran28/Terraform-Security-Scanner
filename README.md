# Terraform Security Scanner

![CI](https://github.com/KaanTuran28/Terraform-Security-Scanner/actions/workflows/ci.yml/badge.svg)
![Python](https://img.shields.io/badge/python-3.9%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)

<p align="center"><b><a href="#english">English</a></b> · <b><a href="#türkçe">Türkçe</a></b></p>

---

## English

A static security scanner for Terraform (HCL) configuration files. No `terraform` binary, no cloud credentials, no `terraform plan` — just parses the `.tf` text and flags common AWS infrastructure misconfigurations before they're ever applied.

### Overview

- **S3 buckets**: public ACL (`public-read`/`public-read-write`), missing versioning, missing server-side encryption.
- **Security groups**: an `ingress` rule open to `0.0.0.0/0` on a sensitive port (SSH, RDP, database ports, ...), or effectively all ports open to the world.
- **RDS instances**: `publicly_accessible = true`, or `storage_encrypted` not set to `true`.
- **Hardcoded secrets**: a `password`/`secret`/`api_key`/`access_key`-like attribute assigned a literal string, or a `variable` with a secret-like name carrying a non-empty literal `default`.

> For auditing IAM **policy documents** specifically (wildcard actions, privilege-escalation vectors), see the companion [`Cloud-IAM-Policy-Auditor`](../Cloud-IAM-Policy-Auditor) — this tool focuses on infrastructure resources, not IAM policy JSON.

### Installation

Requires Python 3.9+. No external dependencies.

```bash
git clone <this-repo>
cd Terraform-Security-Scanner
pip install -e .
```

This installs a `terraform-security-scanner` command. You can also run the script directly with `python terraform_security_scanner.py` without installing.

### Usage

```bash
terraform-security-scanner --path infra/ --output report.md
terraform-security-scanner --path main.tf --format json --output report.json
```

| Flag | Default | Description |
|---|---|---|
| `--path` | *(required)* | A single `.tf` file, or a directory to scan recursively |
| `--output` | `sample_report.md` | Path to write the report |
| `--format` | `markdown` | `markdown` or `json` |
| `--fail-on` | `none` | `none`, `medium`, or `high` — exit code `1` if a finding at/above this severity exists |

### CI Integration

Run this on every pull request that touches Terraform, before `terraform apply`:

```bash
terraform-security-scanner --path infra/ --fail-on high
```

```yaml
# GitHub Actions step
- name: Static Terraform security scan
  run: terraform-security-scanner --path infra/ --fail-on high
```

### Example Output

[`sample_terraform/insecure_example.tf`](./sample_terraform/insecure_example.tf) demonstrates every check above; [`sample_terraform/hardened_example.tf`](./sample_terraform/hardened_example.tf) is its fixed counterpart (private ACL + versioning + encryption, restricted SSH CIDR, non-public encrypted RDS, secret sourced from a `sensitive` variable) and produces **zero findings**. See [`sample_report.md`](./sample_report.md) — real output from scanning `insecure_example.tf`: 4 HIGH, 2 MEDIUM, 1 LOW.

### How it works

This is a regex + brace-depth block extractor, not a full HCL parser (no `hashicorp/hcl` grammar, no expression evaluator). It finds `resource "TYPE" "NAME" { ... }` blocks by tracking brace depth, then looks for known nested blocks (`ingress`, `versioning`, `server_side_encryption_configuration`) and attributes within them the same way. This is enough to catch the common, literal-value misconfigurations above, but it will not evaluate interpolated expressions, `for_each`/`count`, or values that come from modules/data sources.

### Limitations

Heuristic and AWS-provider-specific (S3/security-group/RDS resource shapes). It won't catch every possible misconfiguration a full policy-as-code tool (e.g. `tfsec`, `checkov`) would, and a resource whose risky attribute is set via a variable or expression rather than a literal won't be evaluated. Treat it as a fast first pass, not a replacement for a real IaC scanning pipeline.

### Testing

```bash
pip install -r requirements-dev.txt
ruff check .
pytest -v
```

### Project Structure

```
Terraform-Security-Scanner/
├── terraform_security_scanner.py
├── pyproject.toml
├── sample_terraform/
│   ├── insecure_example.tf
│   └── hardened_example.tf
├── sample_report.md
├── tests/
│   └── test_terraform_security_scanner.py
├── .github/workflows/ci.yml
├── requirements.txt
├── requirements-dev.txt
├── LICENSE
└── DURUM.md
```

### License

MIT — see [LICENSE](./LICENSE).

---

## Türkçe

Terraform (HCL) yapılandırma dosyaları için statik bir güvenlik tarayıcısı. `terraform` binary'sine, bulut kimlik bilgilerine veya `terraform plan` çalıştırmaya gerek yok — sadece `.tf` metnini ayrıştırır ve yaygın AWS altyapı yanlış yapılandırmalarını, kod uygulanmadan önce tespit eder.

### Genel Bakış

- **S3 bucket'ları**: açık (public) ACL (`public-read`/`public-read-write`), eksik versiyonlama, eksik sunucu taraflı şifreleme.
- **Security group'lar**: hassas bir port için (SSH, RDP, veritabanı portları, ...) `0.0.0.0/0`'a açık bir `ingress` kuralı, ya da pratikte tüm portların dünyaya açık olması.
- **RDS instance'ları**: `publicly_accessible = true` olması, veya `storage_encrypted` değerinin `true` olarak ayarlanmamış olması.
- **Sabit kodlanmış (hardcoded) sırlar**: `password`/`secret`/`api_key`/`access_key` benzeri bir özelliğe literal bir string atanması, ya da sır benzeri bir isme sahip bir `variable`'ın boş olmayan literal bir `default` değeri taşıması.

> Özellikle IAM **policy döküman**larını denetlemek için (joker karakterli aksiyonlar, ayrıcalık yükseltme vektörleri) birlikte çalışan [`Cloud-IAM-Policy-Auditor`](../Cloud-IAM-Policy-Auditor) aracına bakın — bu araç IAM policy JSON'ına değil, altyapı kaynaklarına odaklanır.

### Kurulum

Python 3.9+ gerektirir. Harici bağımlılık yoktur.

```bash
git clone <this-repo>
cd Terraform-Security-Scanner
pip install -e .
```

Bu, bir `terraform-security-scanner` komutu kurar. Kurulum yapmadan doğrudan `python terraform_security_scanner.py` ile de scripti çalıştırabilirsiniz.

### Kullanım

```bash
terraform-security-scanner --path infra/ --output report.md
terraform-security-scanner --path main.tf --format json --output report.json
```

| Bayrak (Flag) | Varsayılan | Açıklama |
|---|---|---|
| `--path` | *(zorunlu)* | Tek bir `.tf` dosyası, veya recursive olarak taranacak bir dizin |
| `--output` | `sample_report.md` | Raporun yazılacağı dosya yolu |
| `--format` | `markdown` | `markdown` veya `json` |
| `--fail-on` | `none` | `none`, `medium`, veya `high` — bu ciddiyet seviyesinde veya üzerinde bir bulgu varsa çıkış kodu `1` olur |

### CI Entegrasyonu

Terraform'a dokunan her pull request'te, `terraform apply` öncesinde bunu çalıştırın:

```bash
terraform-security-scanner --path infra/ --fail-on high
```

```yaml
# GitHub Actions step
- name: Static Terraform security scan
  run: terraform-security-scanner --path infra/ --fail-on high
```

### Örnek Çıktı

[`sample_terraform/insecure_example.tf`](./sample_terraform/insecure_example.tf) yukarıdaki her kontrolü örnekler; [`sample_terraform/hardened_example.tf`](./sample_terraform/hardened_example.tf) ise düzeltilmiş karşılığıdır (özel ACL + versiyonlama + şifreleme, kısıtlı SSH CIDR'i, herkese açık olmayan şifrelenmiş RDS, `sensitive` bir değişkenden kaynaklanan sır) ve **sıfır bulgu** üretir. `insecure_example.tf` taramasından gerçek çıktı için [`sample_report.md`](./sample_report.md) dosyasına bakın: 4 HIGH, 2 MEDIUM, 1 LOW.

### Nasıl Çalışır

Bu, tam bir HCL ayrıştırıcısı değil (`hashicorp/hcl` grameri yok, ifade değerlendiricisi yok), regex + parantez-derinliği (brace-depth) tabanlı bir blok çıkarıcıdır. Parantez derinliğini takip ederek `resource "TYPE" "NAME" { ... }` bloklarını bulur, ardından bilinen iç içe blokları (`ingress`, `versioning`, `server_side_encryption_configuration`) ve bunların içindeki özellikleri de aynı şekilde arar. Bu, yukarıdaki yaygın, literal-değerli yanlış yapılandırmaları yakalamak için yeterlidir, ancak interpolasyonlu ifadeleri, `for_each`/`count`'u veya modüllerden/veri kaynaklarından (data source) gelen değerleri değerlendirmez.

### Sınırlamalar

Sezgisel (heuristic) ve AWS-provider'a özgüdür (S3/security-group/RDS kaynak şekilleri). Tam bir policy-as-code aracının (örn. `tfsec`, `checkov`) yakalayacağı her olası yanlış yapılandırmayı yakalamaz ve riskli özelliği literal yerine bir değişken veya ifade üzerinden ayarlanmış bir kaynak değerlendirilmez. Bunu gerçek bir IaC tarama pipeline'ının yerine değil, hızlı bir ilk geçiş olarak değerlendirin.

### Test

```bash
pip install -r requirements-dev.txt
ruff check .
pytest -v
```

### Proje Yapısı

```
Terraform-Security-Scanner/
├── terraform_security_scanner.py
├── pyproject.toml
├── sample_terraform/
│   ├── insecure_example.tf
│   └── hardened_example.tf
├── sample_report.md
├── tests/
│   └── test_terraform_security_scanner.py
├── .github/workflows/ci.yml
├── requirements.txt
├── requirements-dev.txt
├── LICENSE
└── DURUM.md
```

### Lisans

MIT — bkz. [LICENSE](./LICENSE).

---
