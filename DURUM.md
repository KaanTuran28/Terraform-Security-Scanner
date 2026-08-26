# Durum Günlüğü

> En üstteki kayıt en güncelidir. Her çalışma sonrası buraya kısa bir not düşülür.

---

## 2026-08-21 — Proje oluşturuldu, test edildi, CI eklendi

- Konu: Terraform (.tf) dosyalarını statik denetleyen CLI aracı — `hashicorp/hcl` grameri kullanmadan, regex + brace-depth (süslü parantez derinliği) ile blok çıkaran hafif bir yaklaşım. Denetimler: S3 public ACL, versioning/encryption eksikliği, security group'ta 0.0.0.0/0'a açık hassas port (SSH/RDP/DB portları) veya tüm portlar, RDS `publicly_accessible`/`storage_encrypted`, koda gömülü secret (attribute veya `variable` default'u).
- Önemli bir tasarım düzeltmesi geliştirme sırasında yakalandı: ilk taslakta birden fazla dosya `"\n".join(...)` ile birleştirilip tek metin olarak analiz ediliyordu — bu, ilk dosyadan sonraki dosyalarda satır numaralarını yanlış hale getirirdi. `Python-Security-Code-Scanner`'daki dosya-bazlı sonuç deseniyle (`list[(dosya, findings)]`) tutarlı hale getirildi.
- `Cloud-IAM-Policy-Auditor` ile kasıtlı olarak örtüşmüyor: IAM policy JSON denetimi o projede kalıyor, bu proje sadece altyapı kaynaklarına (S3/SG/RDS) odaklanıyor — README'de çapraz referans var.
- Dosya: `terraform_security_scanner.py`, 2 örnek dosya (`insecure_example.tf` — 7 bulgu, `hardened_example.tf` — 0 bulgu), `tests/test_terraform_security_scanner.py` (33 test), `pyproject.toml`, `.github/workflows/ci.yml`.
- Baştan itibaren eklenenler: `--format json`, `--fail-on {none,medium,high}`.
- Durum: ✅ 33/33 test gerçekten çalıştırılıp geçti, `ruff check .` temiz (bir `RUF013` implicit-Optional uyarısı `str | None` ile düzeltildi). CLI her iki örneğe karşı gerçekten çalıştırıldı: `insecure_example.tf` → 4 HIGH + 2 MEDIUM + 1 LOW, `hardened_example.tf` → 0 bulgu. `sample_report.md` gerçek çalıştırmadan üretildi. Henüz push edilmedi (repo local).

**Sıradaki iş:** GitHub'da `Terraform-Security-Scanner` adıyla repo aç, git init + push.
