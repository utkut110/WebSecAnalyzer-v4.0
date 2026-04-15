<div align="center">

```
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║   ██╗    ██╗███████╗██████╗ ███████╗███████╗ ██████╗        ║
║   ██║    ██║██╔════╝██╔══██╗██╔════╝██╔════╝██╔════╝        ║
║   ██║ █╗ ██║█████╗  ██████╔╝███████╗█████╗  ██║             ║
║   ██║███╗██║██╔══╝  ██╔══██╗╚════██║██╔══╝  ██║             ║
║   ╚███╔███╔╝███████╗██████╔╝███████║███████╗╚██████╗        ║
║    ╚══╝╚══╝ ╚══════╝╚═════╝ ╚══════╝╚══════╝ ╚═════╝        ║
║                                                              ║
║              WebSecAnalyzer  v4.0                           ║
╚══════════════════════════════════════════════════════════════╝
```

# 🛡️ WebSecAnalyzer v4.0

**Profesyonel Web Güvenlik Analiz Çerçevesi**

[![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?style=flat-square&logo=python&logoColor=white)](https://python.org)
[![Anthropic](https://img.shields.io/badge/Powered%20by-Claude%20AI-D97757?style=flat-square)](https://anthropic.com)
[![License](https://img.shields.io/badge/License-MIT-22C55E?style=flat-square)](#lisans)
[![Modules](https://img.shields.io/badge/Modül-30%2B-8B5CF6?style=flat-square)](#modüller)
[![CVSS](https://img.shields.io/badge/CVSS-3.1-EF4444?style=flat-square)](#)

> ⚠️ **Yasal Uyarı:** Bu araç **yalnızca yazılı izin aldığınız sistemlerde** kullanılmalıdır.  
> İzinsiz tarama yasa dışıdır. Tüm sorumluluk kullanıcıya aittir.

</div>

---

## 📖 İçindekiler

- [Özellikler](#-özellikler)
- [Modüller](#-modüller)
- [Kurulum](#-kurulum)
- [Kullanım](#-kullanım)
- [Yapılandırma](#-yapılandırma)
- [Rapor Formatları](#-rapor-formatları)
- [Plugin Sistemi](#-plugin-sistemi)
- [Ekran Görüntüleri](#-ekran-görüntüleri)
- [Lisans](#-lisans)

---

## ✨ Özellikler

| Özellik | Açıklama |
|---|---|
| 🚀 **Async Engine** | Tüm modüller paralel çalışır, hız odaklı tasarım |
| 🤖 **Anthropic AI** | Claude ile akıllı bulgu analizi ve öneri üretimi |
| 📊 **CVSS 3.1** | Her bulgu için standart güvenlik skoru |
| 🧩 **Plugin Sistemi** | Kendi modüllerinizi kolayca ekleyin |
| 📄 **Çoklu Rapor** | HTML, JSON, Markdown ve PDF çıktı desteği |
| 🌍 **Çok Dil** | Türkçe ve İngilizce rapor seçeneği |
| 🎨 **Rich TUI** | Renkli, modern terminal arayüzü |
| ⚙️ **YAML Config** | Esnek yapılandırma sistemi |

---

## 🔍 Modüller

WebSecAnalyzer 30+ güvenlik modülü ile birlikte gelir:

### 🌐 Grup 1 — Network & Pasif Tarama
| # | Modül | Açıklama |
|---|---|---|
| 01 | **Port & Service Scan** | Açık port ve servis tespiti |
| 02 | **Security Headers** | HTTP güvenlik başlığı analizi |
| 03 | **Teknoloji Tespiti** | Backend, framework, CDN tanımlama |
| 04 | **Subdomain Scanner** | Alt domain keşfi |
| 07 | **SSL/TLS Analizi** | Sertifika ve şifreleme analizi |
| 22 | **DNS Analizi** | SPF, DKIM, DMARC, Zone Transfer kontrolü |

### ⚡ Grup 2 — Aktif Web Testleri
| # | Modül | Açıklama |
|---|---|---|
| 05 | **Subdomain Takeover** | Alt domain ele geçirme riski |
| 06 | **Directory Bruteforce** | Gizli dizin ve dosya keşfi |
| 08 | **Cookie Güvenlik** | Cookie bayrak ve güvenlik analizi |
| 13 | **JWT Analizi** | Token zafiyetleri ve imza kontrolü |
| 14 | **CORS / CSRF** | Cross-origin ve CSRF testleri |
| 15 | **Hassas Dosya Tespiti** | `.env`, `id_rsa`, `backup` vb. |
| 16 | **HTTP Method Test** | Tehlikeli HTTP metot kontrolü |
| 17 | **Clickjacking** | Frame koruma testleri |
| 18 | **WAF / Rate Limit** | Güvenlik duvarı ve hız sınırı tespiti |
| 19 | **API Endpoint Enum** | GraphQL, REST, Swagger keşfi |
| 23 | **Information Disclosure** | Bilgi sızdırma tespiti |
| 24 | **Open Redirect** | Açık yönlendirme testleri |
| 25 | **HTTP Request Smuggling** | Smuggling zafiyet taraması |
| 26 | **Broken Link Checker** | Kırık bağlantı analizi |
| 27 | **WebSocket Test** | WS/WSS bağlantı testleri |
| 28 | **Header Injection** | Başlık enjeksiyonu testleri |

### 💉 Grup 3 — Injection Testleri
| # | Modül | Açıklama |
|---|---|---|
| 09 | **SQL Injection** | Form tabanlı SQLi taraması |
| 10 | **XSS / SSTI** | Cross-site scripting & template injection |
| 11 | **Path Traversal / LFI** | Dosya dahil etme zafiyetleri |
| 12 | **SSRF Probe** | Sunucu taraflı istek sahteciliği |
| 29 | **Business Logic** | Uygulama mantığı zafiyetleri |

### 🧠 Grup 4 — Intelligence & CVE
| # | Modül | Açıklama |
|---|---|---|
| 20 | **OSINT / Email Harvester** | Açık kaynak istihbarat toplama |
| 21 | **CVE Lookup** | Tespit edilen bileşenler için CVE eşleştirme |

---

## 📦 Kurulum

### Gereksinimler

- Python 3.10+
- pip

### Adımlar

```bash
# Repoyu klonla
git clone https://github.com/kullaniciadi/websec-analyzer.git
cd websec-analyzer

# Bağımlılıkları yükle
pip install -r requirements.txt

# (Opsiyonel) PDF rapor desteği için
pip install reportlab

# (Opsiyonel) Gelişmiş DNS analizi için
pip install dnspython
```

### API Anahtarı Yapılandırması

AI destekli analiz için bir Anthropic API anahtarı gereklidir:

```bash
# Linux / macOS
export ANTHROPIC_API_KEY="sk-ant-..."

# Windows (CMD)
set ANTHROPIC_API_KEY=sk-ant-...

# Windows (PowerShell)
$env:ANTHROPIC_API_KEY="sk-ant-..."
```

---

## 🚀 Kullanım

### Temel Kullanım

```bash
python websec_v4.py https://hedef-site.com
```

### Gelişmiş Kullanım

```bash
# Özel rapor dosya adları
python websec_v4.py https://hedef-site.com -o sonuc.html --json sonuc.json --md sonuc.md

# Belirli modülleri atla
python websec_v4.py https://hedef-site.com --skip 4 21 22

# Cookie ile kimlik doğrulama
python websec_v4.py https://hedef-site.com --cookies "session=abc123; token=xyz"

# Ekstra başlık ekle
python websec_v4.py https://hedef-site.com --headers "Authorization:Bearer <token>"

# AI analizini devre dışı bırak
python websec_v4.py https://hedef-site.com --no-ai

# Detaylı çıktı
python websec_v4.py https://hedef-site.com --verbose

# İngilizce rapor
python websec_v4.py https://hedef-site.com --lang en
```

### Tüm Parametreler

```
Zorunlu:
  url                  Hedef URL (örn: https://example.com)

Opsiyonel:
  -o, --output FILE    HTML rapor çıktısı (varsayılan: rapor.html)
  --json FILE          JSON rapor çıktısı (varsayılan: rapor.json)
  --md FILE            Markdown rapor çıktısı (varsayılan: rapor.md)
  --config FILE        Config dosyası (varsayılan: config.yaml)
  --plugins DIR        Plugin dizini (varsayılan: plugins/)
  --skip N [N ...]     Atlanacak modül numaraları
  --cookies STR        Cookie stringi
  --headers STR        Ekstra HTTP başlıkları
  --no-ai              AI analizini devre dışı bırak
  -v, --verbose        Detaylı çıktı modu
  --lang {tr,en}       Rapor dili
```

---

## ⚙️ Yapılandırma

`config.yaml` dosyasını düzenleyerek tarama davranışını özelleştirebilirsiniz:

```yaml
# config.yaml örneği
timeout: 10
max_redirects: 5
user_agent: "WebSecAnalyzer/4.0"

wordlists:
  directories: wordlists/dirs.txt
  subdomains: wordlists/subdomains.txt

rate_limit:
  requests_per_second: 10

ai:
  model: claude-sonnet-4-20250514
  max_tokens: 2048
```

---

## 📊 Rapor Formatları

WebSecAnalyzer dört farklı formatta rapor üretir:

```
📁 çıktılar/
├── rapor.html     ← İnteraktif HTML raporu (grafikler, filtreleme)
├── rapor.json     ← Makine tarafından okunabilir ham veri
├── rapor.md       ← GitHub/Jira uyumlu Markdown raporu
└── rapor.pdf      ← Yazdırılabilir PDF (reportlab gerekli)
```

Her rapor şunları içerir:
- 🎯 Yönetici özeti ve risk skoru
- 📋 CVSS 3.1 skorlu bulgular listesi
- 🔧 Her bulgu için iyileştirme önerileri
- 📚 CVE referansları ve OWASP kategorizasyonu
- 🤖 Claude AI destekli analiz ve öncelik sıralaması

---

## 🧩 Plugin Sistemi

Kendi güvenlik modüllerinizi `plugins/` dizinine ekleyebilirsiniz:

```python
# plugins/ornek_plugin.py
from websec_v4 import Finding, ScanResult, make_finding
from typing import List

async def run(result: ScanResult, cfg: dict) -> List[Finding]:
    """Kendi güvenlik testinizi buraya yazın."""
    findings = []
    
    # Test mantığı...
    
    findings.append(make_finding(
        module="ornek_plugin",
        title="Örnek Bulgu",
        severity="medium",
        description="Açıklama buraya",
        remediation="Çözüm önerisi buraya",
    ))
    
    return findings
```

Plugin dosyasını `plugins/` klasörüne attıktan sonra otomatik olarak yüklenir.

---

## 🏗️ Proje Yapısı

```
websec-analyzer/
├── websec_v4.py        # Ana uygulama
├── config.yaml         # Yapılandırma dosyası
├── requirements.txt    # Python bağımlılıkları
├── open_redirect.py    # Ek modül
├── plugins/            # Özel plugin dizini
│   └── ...
└── wordlists/          # Sözlük dosyaları (opsiyonel)
    ├── dirs.txt
    └── subdomains.txt
```

---

## 🤝 Katkıda Bulunma

1. Bu repoyu fork'layın
2. Feature branch oluşturun (`git checkout -b feature/yeni-modul`)
3. Değişikliklerinizi commit edin (`git commit -m 'feat: yeni modül eklendi'`)
4. Branch'i push edin (`git push origin feature/yeni-modul`)
5. Pull Request açın

---

## 📄 Lisans

Bu proje MIT Lisansı ile lisanslanmıştır. Daha fazla bilgi için [LICENSE](LICENSE) dosyasına bakın.

---

<div align="center">

**⚠️ Etik Kullanım Hatırlatması**

Bu araç penetrasyon testi ve güvenlik araştırması amacıyla geliştirilmiştir.  
Yalnızca **izin aldığınız** sistemlerde kullanın.  
Yasadışı kullanımdan doğacak tüm sorumluluk kullanıcıya aittir.

---

Güvenlik topluluğu için ❤️ ile yapıldı

</div>
