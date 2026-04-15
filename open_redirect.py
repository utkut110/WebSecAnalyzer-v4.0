"""
Örnek Plugin: Open Redirect Tester
────────────────────────────────────
plugins/ klasörüne koyun, otomatik yüklenir.
Her plugin run_module(result, cfg) fonksiyonu tanımlamalıdır.
"""

import aiohttp
from dataclasses import dataclass


async def run_module(result, cfg) -> list:
    """Open Redirect zafiyeti testi"""
    findings = []
    payloads = [
        "https://evil.com",
        "//evil.com",
        "/\\evil.com",
        "https:evil.com",
    ]
    params = ["redirect", "url", "next", "return", "goto", "target", "dest", "redir"]
    base   = result.url.rstrip("/")

    connector = aiohttp.TCPConnector(ssl=False)
    timeout   = aiohttp.ClientTimeout(total=cfg.get("timeout", 8))

    async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
        for param in params:
            for payload in payloads[:2]:
                url = f"{base}?{param}={payload}"
                try:
                    async with session.get(url, allow_redirects=False) as r:
                        location = r.headers.get("Location", "")
                        if "evil.com" in location:
                            from dataclasses import dataclass

                            class F:
                                pass

                            f = F()
                            f.module = "open_redirect"
                            f.title  = f"Open Redirect: ?{param}="
                            f.severity = "medium"
                            f.owasp    = "A01-Broken Access Control"
                            f.description = f"Parametre '{param}' open redirect'e izin veriyor."
                            f.evidence    = f"Location: {location}"
                            f.cvss        = 6.1
                            f.remediation = "Redirect URL'ini whitelist ile doğrulayın."
                            findings.append(f)
                            print(f"  [PLUGIN] Open Redirect: ?{param}={payload}")
                            break
                except Exception:
                    pass

    return findings
