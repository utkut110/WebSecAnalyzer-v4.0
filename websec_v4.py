#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║  WebSecAnalyzer v4.0  –  Profesyonel Web Güvenlik Analiz Çerçevesi         ║
║  30+ Modül │ Async Engine │ AI Destekli Analiz │ Çoklu Rapor Formatı       ║
║  CVSS 3.1 │ Plugin Sistemi │ Paralel Tarama │ Streaming AI                  ║
╠══════════════════════════════════════════════════════════════════════════════╣
║  ⚠  YASAL UYARI: Yalnızca yazılı izin aldığınız sistemlerde kullanın.     ║
║     İzinsiz tarama yasadışıdır. Tüm sorumluluk kullanıcıya aittir.        ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""

import asyncio
import aiohttp
import anthropic
import argparse
import socket
import ssl
import json
import sys
import os
import re
import time
import importlib
import importlib.util
import yaml
import base64
import hashlib
import subprocess
import struct
import random
import string
from pathlib import Path
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, quote
from datetime import datetime
from dataclasses import dataclass, field, asdict
from typing import Optional, List, Dict, Any
from concurrent.futures import ThreadPoolExecutor

# ─── Rich TUI ────────────────────────────────────────────────────────────────
try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn, TimeElapsedColumn
    from rich.live import Live
    from rich.layout import Layout
    from rich.text import Text
    from rich.markdown import Markdown
    from rich import box
    from rich.rule import Rule
    from rich.columns import Columns
    from rich.align import Align
    HAS_RICH = True
except ImportError:
    HAS_RICH = False

console = Console(highlight=False) if HAS_RICH else None
VERBOSE = False

def cprint(msg, style="", verbose_only=False):
    if verbose_only and not VERBOSE:
        return
    if HAS_RICH:
        console.print(msg, style=style)
    else:
        # Rich markup'ı temizle
        clean = re.sub(r'\[/?[^\]]+\]', '', msg)
        print(clean)

def banner():
    if HAS_RICH:
        console.print(Panel(
            "[bold cyan]WebSecAnalyzer v4.0[/]\n"
            "[dim]30+ Modül │ Async Engine │ Anthropic AI │ Plugin Sistemi[/]\n"
            "[dim]CVSS 3.1 │ Paralel Tarama │ HTML/JSON/MD/PDF Rapor[/]\n"
            "[bold red]⚠  Yalnızca yetkili sistemlerde kullanın[/]",
            border_style="bright_cyan",
            box=box.DOUBLE_EDGE,
            expand=False,
            padding=(1, 4)
        ))
    else:
        print("=" * 70)
        print("  WebSecAnalyzer v4.0 – Profesyonel Web Güvenlik Analiz Çerçevesi")
        print("=" * 70)

def section(title: str):
    if HAS_RICH:
        console.print(Rule(f"[bold cyan]{title}[/]", style="cyan"))
    else:
        print(f"\n{'─'*60}\n  {title}\n{'─'*60}")

# ─── Veri Yapıları ────────────────────────────────────────────────────────────
@dataclass
class CVSS:
    """CVSS 3.1 vektör hesaplayıcı"""
    AV: str = "N"   # Attack Vector:       N/A/L/P
    AC: str = "L"   # Attack Complexity:   L/H
    PR: str = "N"   # Privileges Required: N/L/H
    UI: str = "N"   # User Interaction:    N/R
    S:  str = "U"   # Scope:               U/C
    C:  str = "H"   # Confidentiality:     N/L/H
    I:  str = "H"   # Integrity:           N/L/H
    A:  str = "H"   # Availability:        N/L/H

    def score(self) -> float:
        AV = {"N":0.85,"A":0.62,"L":0.55,"P":0.2}[self.AV]
        AC = {"L":0.77,"H":0.44}[self.AC]
        PR = {"N":0.85,"L":0.62,"H":0.27}[self.PR]
        UI = {"N":0.85,"R":0.62}[self.UI]
        S_changed = self.S == "C"
        if S_changed:
            PR = {"N":0.85,"L":0.68,"H":0.50}[self.PR]
        C = {"N":0.0,"L":0.22,"H":0.56}[self.C]
        I = {"N":0.0,"L":0.22,"H":0.56}[self.I]
        A = {"N":0.0,"L":0.22,"H":0.56}[self.A]
        ISS = 1 - (1-C)*(1-I)*(1-A)
        if S_changed:
            Impact = 7.52*(ISS-0.029) - 3.25*((ISS-0.02)**15)
        else:
            Impact = 6.42*ISS
        Exploitability = 8.22*AV*AC*PR*UI
        if Impact <= 0:
            return 0.0
        if S_changed:
            raw = min(1.08*(Impact+Exploitability), 10)
        else:
            raw = min(Impact+Exploitability, 10)
        return round(raw, 1)

    def vector(self) -> str:
        return f"CVSS:3.1/AV:{self.AV}/AC:{self.AC}/PR:{self.PR}/UI:{self.UI}/S:{self.S}/C:{self.C}/I:{self.I}/A:{self.A}"

@dataclass
class Finding:
    module:      str
    title:       str
    severity:    str        # critical / high / medium / low / info
    description: str
    evidence:    str  = ""
    owasp:       str  = ""
    cwe:         str  = ""
    cvss_score:  float = 0.0
    cvss_vector: str  = ""
    remediation: str  = ""
    references:  List[str] = field(default_factory=list)
    tags:        List[str] = field(default_factory=list)

@dataclass
class ScanResult:
    url:          str
    host:         str
    ip:           str  = ""
    scan_time:    str  = ""
    scan_duration: float = 0.0
    findings:     List[Finding] = field(default_factory=list)
    raw:          Dict[str, Any] = field(default_factory=dict)
    overall_risk: int  = 0
    ai_report:    str  = ""
    technologies: List[str] = field(default_factory=list)

SEVERITY_ORDER  = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
SEVERITY_STYLE  = {"critical": "bold red", "high": "red", "medium": "yellow", "low": "cyan", "info": "dim"}
SEVERITY_EMOJI  = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "info": "⚪"}
SEVERITY_COLOR  = {"critical": "#ff3b3b", "high": "#ff8c00", "medium": "#ffd700", "low": "#4da6ff", "info": "#888888"}

# ─── Config ──────────────────────────────────────────────────────────────────
DEFAULT_CONFIG = {
    "timeout":          10,
    "connect_timeout":  5,
    "max_workers":      30,
    "user_agent":       "Mozilla/5.0 (WebSecAnalyzer/4.0; +https://github.com/websecanalyzer)",
    "follow_redirects": True,
    "anthropic_api_key": "",
    "language":         "tr",       # tr / en
    "max_forms_test":   5,
    "max_dir_concurrency": 50,
    "retry_count":      2,
    "retry_delay":      1.0,
    "wordlists": {
        "dirs": [
            "admin","login","wp-admin","dashboard","api","backup","config",
            "test","dev","uploads","files","images",".git",".env","robots.txt",
            "sitemap.xml","phpinfo.php","server-status","admin.php","wp-login.php",
            "console","swagger","graphql","actuator","health","metrics","v1","v2",
            "api/v1","api/v2","api/v3","api/users","api/admin","api/config",
            ".well-known","crossdomain.xml","clientaccesspolicy.xml","security.txt",
            "readme.txt","README.md","CHANGELOG.md","license.txt","install.php",
            "setup.php","update.php","upgrade.php","migrate.php","debug.php",
            "info.php","test.php","shell.php","cmd.php","webshell.php",
            "old","bak","backup","tmp","temp","cache","log","logs","data",
            "database","db","sql","dump","export","import","restore",
            "api/internal","api/private","admin/api","system","sys","manage",
            "management","panel","cpanel","plesk","webmail","mail","smtp",
            ".htpasswd",".htaccess",".bash_history",".ssh","id_rsa","known_hosts",
        ],
        "subdomains": [
            "www","mail","ftp","admin","api","dev","test","stage","portal","vpn",
            "remote","blog","shop","cdn","static","app","beta","demo","dashboard",
            "webmail","secure","auth","login","sso","git","jenkins","gitlab","jira",
            "confluence","monitoring","grafana","kibana","splunk","elasticsearch",
            "redis","mysql","postgres","db","database","files","media","assets",
            "old","legacy","staging","uat","qa","preprod","prod","mx","smtp",
            "imap","pop","autodiscover","autoconfig","ns1","ns2","backup","dr",
        ],
        "sqli_payloads": [
            "'", "''", "`", "1' OR '1'='1", "1' OR 1=1--",
            "' UNION SELECT NULL--", "admin'--", "1' AND SLEEP(2)--",
            "1 WAITFOR DELAY '0:0:2'--", "1' AND 1=CONVERT(int,'a')--",
            "'; EXEC xp_cmdshell('whoami')--", "1' AND extractvalue(1,concat(0x7e,version()))--",
        ],
        "xss_payloads": [
            "<script>alert(1)</script>",
            '"><script>alert(1)</script>',
            "';alert(1)//",
            "<img src=x onerror=alert(1)>",
            "<svg onload=alert(1)>",
            "javascript:alert(1)",
            "<iframe src=javascript:alert(1)>",
            "'-alert(1)-'",
            "${7*7}",  # Template injection
            "{{7*7}}",
        ],
        "lfi_payloads": [
            "../etc/passwd", "../../etc/passwd", "../../../etc/passwd",
            "....//....//etc/passwd", "..%2F..%2Fetc%2Fpasswd",
            "%2e%2e%2fetc%2fpasswd", "..%252F..%252Fetc%252Fpasswd",
            "/etc/passwd", "C:\\Windows\\system32\\drivers\\etc\\hosts",
            "php://filter/convert.base64-encode/resource=index.php",
        ],
        "ssrf_payloads": [
            "http://169.254.169.254/latest/meta-data/",
            "http://metadata.google.internal/computeMetadata/v1/",
            "http://100.100.100.200/latest/meta-data/",
            "http://192.168.1.1/",
            "http://localhost/",
            "http://0.0.0.0/",
            "http://[::1]/",
            "file:///etc/passwd",
        ],
        "path_traversal": [
            "../../../../etc/passwd",
            "..\\..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "..%c0%afetc%c0%afpasswd",
        ],
    },
    "ports": [
        21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 465,
        587, 993, 995, 1433, 1521, 2375, 2376, 3000, 3306,
        3389, 4444, 5432, 5900, 6379, 7001, 8000, 8080,
        8443, 8888, 9000, 9200, 9300, 27017, 50000,
    ],
    "sensitive_files": [
        ".env", ".env.local", ".env.production", ".env.backup",
        ".git/config", ".git/HEAD", ".git/COMMIT_EDITMSG",
        ".htaccess", ".htpasswd", "web.config", "Web.config",
        "config.php", "database.php", "db.php", "connect.php",
        "database.yml", "database.yaml", "settings.py", "settings.py.bak",
        "wp-config.php", "wp-config.php.bak", "wp-config.php.orig",
        "composer.json", "composer.lock", "package.json", "package-lock.json",
        "yarn.lock", "Gemfile", "Gemfile.lock", "requirements.txt",
        "Dockerfile", "docker-compose.yml", "docker-compose.yaml",
        ".dockerignore", "k8s.yaml", "kubernetes.yaml",
        "backup.sql", "dump.sql", "database.sql", "db.sql",
        "backup.tar.gz", "backup.zip", "site.tar.gz",
        "id_rsa", ".ssh/id_rsa", ".ssh/authorized_keys",
        ".bash_history", ".zsh_history", ".profile",
        ".aws/credentials", ".aws/config",
        "error_log", "access_log", "debug.log", "app.log",
        "app.properties", "application.properties", "application.yml",
        "secrets.yml", "secrets.yaml", "config/secrets.yml",
        ".npmrc", "yarn.lock", ".pypirc", "pip.conf",
        "server.key", "server.crt", "server.pem", "private.key",
        "phpinfo.php", "test.php", "info.php", "debug.php",
        "config/database.yml", "config/application.yml",
        "storage/logs/laravel.log", "var/log/prod.log",
    ],
}

def load_config(path: str = "config.yaml") -> dict:
    cfg = {k: (v.copy() if isinstance(v, dict) else v) for k, v in DEFAULT_CONFIG.items()}
    if Path(path).exists():
        with open(path, encoding="utf-8") as f:
            user = yaml.safe_load(f) or {}
        # Derin birleştirme
        for key, val in user.items():
            if isinstance(val, dict) and isinstance(cfg.get(key), dict):
                cfg[key].update(val)
            else:
                cfg[key] = val
        cprint(f"[dim]Config yüklendi: {path}[/]")
    return cfg

# ─── Plugin Sistemi ────────────────────────────────────────────────────────────
class PluginManager:
    def __init__(self, plugin_dir: str = "plugins"):
        self.plugins = []
        self.plugin_dir = Path(plugin_dir)

    def load(self):
        if not self.plugin_dir.exists():
            return
        for py in sorted(self.plugin_dir.glob("*.py")):
            try:
                spec = importlib.util.spec_from_file_location(py.stem, py)
                mod  = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(mod)
                if hasattr(mod, "run_module"):
                    self.plugins.append(mod)
                    cprint(f"[dim]Plugin yüklendi: {py.name}[/]")
            except Exception as e:
                cprint(f"[yellow]Plugin yükleme hatası ({py.name}): {e}[/]")

    async def run_all(self, result: ScanResult, cfg: dict) -> list:
        findings = []
        for plugin in self.plugins:
            try:
                cprint(f"\n[bold]▶ [PLUGIN] {plugin.__name__}[/]")
                pf = await plugin.run_module(result, cfg)
                if pf:
                    findings.extend(pf)
            except Exception as e:
                cprint(f"[yellow]Plugin çalışma hatası ({plugin.__name__}): {e}[/]")
        return findings

# ─── HTTP Oturumu ──────────────────────────────────────────────────────────────
class HttpSession:
    def __init__(self, cfg: dict, cookies: dict = None, headers: dict = None):
        self.cfg = cfg
        self.cookies = cookies or {}
        self.extra_headers = headers or {}
        self._session: Optional[aiohttp.ClientSession] = None

    async def __aenter__(self):
        connector = aiohttp.TCPConnector(ssl=False, limit=100, limit_per_host=20)
        timeout   = aiohttp.ClientTimeout(
            total=self.cfg["timeout"],
            connect=self.cfg.get("connect_timeout", 5)
        )
        hdrs = {
            "User-Agent": self.cfg["user_agent"],
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "tr-TR,tr;q=0.9,en-US;q=0.8,en;q=0.7",
            "Accept-Encoding": "gzip, deflate, br",
        }
        hdrs.update(self.extra_headers)
        self._session = aiohttp.ClientSession(
            connector=connector, timeout=timeout,
            headers=hdrs, cookies=self.cookies
        )
        return self

    async def __aexit__(self, *_):
        if self._session:
            await self._session.close()

    async def _retry_get(self, url, retry=0, **kw):
        try:
            return self._session.get(url, allow_redirects=self.cfg.get("follow_redirects", True), **kw)
        except (aiohttp.ClientError, asyncio.TimeoutError):
            if retry < self.cfg.get("retry_count", 2):
                await asyncio.sleep(self.cfg.get("retry_delay", 1.0))
                return await self._retry_get(url, retry+1, **kw)
            raise

    async def get(self, url, **kw):
        return self._session.get(url, allow_redirects=self.cfg.get("follow_redirects", True), **kw)

    async def post(self, url, **kw):
        return self._session.post(url, **kw)

    async def request(self, method, url, **kw):
        return self._session.request(method, url, **kw)

# ════════════════════════════════════════════════════════════════════════════
# YARDIMCI FONKSİYONLAR
# ════════════════════════════════════════════════════════════════════════════
def make_finding(module, title, severity, description, evidence="",
                 owasp="", cwe="", cvss: CVSS = None, remediation="",
                 references=None, tags=None) -> Finding:
    score  = cvss.score()  if cvss else 0.0
    vector = cvss.vector() if cvss else ""
    return Finding(
        module=module, title=title, severity=severity,
        description=description, evidence=evidence,
        owasp=owasp, cwe=cwe, cvss_score=score, cvss_vector=vector,
        remediation=remediation, references=references or [], tags=tags or []
    )

def severity_from_cvss(score: float) -> str:
    if score >= 9.0: return "critical"
    if score >= 7.0: return "high"
    if score >= 4.0: return "medium"
    if score > 0:    return "low"
    return "info"

async def dns_lookup(host: str) -> str:
    loop = asyncio.get_event_loop()
    try:
        result = await loop.run_in_executor(None, socket.gethostbyname, host)
        return result
    except:
        return ""

# ════════════════════════════════════════════════════════════════════════════
# MODÜL 1 – Port & Service Scan
# ════════════════════════════════════════════════════════════════════════════
async def module_port_scan(result: ScanResult, cfg: dict) -> List[Finding]:
    cprint("\n[bold]▶ [01] Port & Service Scan[/]")
    host     = result.host
    findings = []
    open_ports = {}
    service_banners = {}

    def scan_port(port):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1.5)
            if s.connect_ex((host, port)) == 0:
                # Banner grab
                banner_data = ""
                try:
                    if port in [80, 8080]:
                        s.send(b"HEAD / HTTP/1.0\r\nHost: " + host.encode() + b"\r\n\r\n")
                    elif port == 21:
                        pass  # FTP banner otomatik gelir
                    s.settimeout(0.5)
                    data = s.recv(1024)
                    banner_data = data.decode("utf-8", errors="ignore").strip()[:100]
                except: pass
                try:    svc = socket.getservbyport(port)
                except: svc = "unknown"
                return port, svc, banner_data
        except: pass
        finally:
            try: s.close()
            except: pass
        return None

    loop = asyncio.get_event_loop()
    with ThreadPoolExecutor(max_workers=50) as ex:
        tasks = [loop.run_in_executor(ex, scan_port, p) for p in cfg["ports"]]
        for res in await asyncio.gather(*tasks):
            if res:
                port, svc, banner = res
                open_ports[port] = svc
                if banner:
                    service_banners[port] = banner
                cprint(f"  [green]✔ {port}/{svc}[/]{'  ' + banner[:60] if banner and VERBOSE else ''}")

    result.raw["port_scan"] = {"open_ports": open_ports, "banners": service_banners}

    risky_ports = {
        21:    ("FTP – şifresiz veri transferi", "high",    CVSS("N","L","N","N","U","L","L","N")),
        22:    ("SSH – brute force hedefi",       "info",    None),
        23:    ("Telnet – şifresiz protokol",     "critical",CVSS("N","L","N","N","U","H","H","N")),
        25:    ("SMTP – açık relay riski",         "medium",  None),
        1433:  ("MSSQL doğrudan erişilebilir",    "high",    CVSS("N","L","N","N","U","H","H","H")),
        1521:  ("Oracle DB doğrudan erişilebilir","high",    CVSS("N","L","N","N","U","H","H","H")),
        2375:  ("Docker API (TLS'siz!)",          "critical",CVSS("N","L","N","N","C","H","H","H")),
        2376:  ("Docker API (TLS)",               "medium",  None),
        3306:  ("MySQL doğrudan erişilebilir",    "high",    CVSS("N","L","N","N","U","H","H","H")),
        3389:  ("RDP açık",                       "high",    CVSS("N","L","N","N","U","H","H","H")),
        5432:  ("PostgreSQL doğrudan erişilebilir","high",   CVSS("N","L","N","N","U","H","H","H")),
        5900:  ("VNC açık",                       "high",    CVSS("N","L","N","N","U","H","H","H")),
        6379:  ("Redis auth'suz açık",            "critical",CVSS("N","L","N","N","U","H","H","H")),
        7001:  ("WebLogic açık",                  "high",    CVSS("N","L","N","N","U","H","H","H")),
        9200:  ("Elasticsearch auth'suz",         "critical",CVSS("N","L","N","N","U","H","H","H")),
        27017: ("MongoDB auth'suz",               "critical",CVSS("N","L","N","N","U","H","H","H")),
    }

    for port, svc in open_ports.items():
        if port in risky_ports:
            desc_text, sev, cvss_obj = risky_ports[port]
            f = make_finding(
                module="port_scan",
                title=f"Riskli Port Açık: {port}/{svc} – {desc_text.split('–')[0].strip()}",
                severity=sev,
                description=f"{desc_text}. Port {port} internete açık.",
                evidence=f"Port {port} açık, banner: {service_banners.get(port, 'yok')}",
                owasp="A05-Security Misconfiguration",
                cwe="CWE-732",
                cvss=cvss_obj,
                remediation=f"Port {port}'i güvenlik duvarıyla kısıtlayın veya VPN arkasına alın.",
                tags=["network", "exposure"]
            )
            findings.append(f)

    if not open_ports:
        cprint("  [yellow]Taranan portlarda açık port bulunamadı[/]")

    return findings

# ════════════════════════════════════════════════════════════════════════════
# MODÜL 2 – Security Headers
# ════════════════════════════════════════════════════════════════════════════
async def module_security_headers(result: ScanResult, cfg: dict, session: HttpSession) -> List[Finding]:
    cprint("\n[bold]▶ [02] Security Headers[/]")
    findings = []
    try:
        async with await session.get(result.url) as r:
            headers = dict(r.headers)
    except Exception as e:
        cprint(f"  [red]Header alınamadı: {e}[/]")
        return []

    result.raw["security_headers"] = headers

    required = {
        "Strict-Transport-Security": {
            "severity": "high",
            "desc": "HSTS eksik – SSL stripping ve downgrade saldırısına açık",
            "remediation": "Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
            "owasp": "A05-Security Misconfiguration",
            "cwe": "CWE-319",
            "cvss": CVSS("N","L","N","N","U","L","N","N"),
        },
        "Content-Security-Policy": {
            "severity": "high",
            "desc": "CSP eksik – XSS saldırılarına karşı savunmasız",
            "remediation": "Content-Security-Policy: default-src 'self'; script-src 'self'; ...",
            "owasp": "A05-Security Misconfiguration",
            "cwe": "CWE-693",
            "cvss": CVSS("N","L","N","R","U","L","L","N"),
        },
        "X-Frame-Options": {
            "severity": "medium",
            "desc": "Clickjacking koruması yok – iframe içine alınabilir",
            "remediation": "X-Frame-Options: DENY ya da CSP'ye frame-ancestors ekleyin",
            "owasp": "A05-Security Misconfiguration",
            "cwe": "CWE-1021",
            "cvss": CVSS("N","L","N","R","U","N","L","N"),
        },
        "X-Content-Type-Options": {
            "severity": "medium",
            "desc": "MIME type sniffing riski – tarayıcı içerik tipini yanlış yorumlayabilir",
            "remediation": "X-Content-Type-Options: nosniff",
            "owasp": "A05-Security Misconfiguration",
            "cwe": "CWE-430",
            "cvss": CVSS("N","L","N","N","U","L","N","N"),
        },
        "Referrer-Policy": {
            "severity": "low",
            "desc": "Referrer başlığı politikası yok – URL'ler üçüncü taraflara sızabilir",
            "remediation": "Referrer-Policy: strict-origin-when-cross-origin",
            "owasp": "A05-Security Misconfiguration",
            "cwe": "CWE-116",
            "cvss": CVSS("N","L","N","N","U","L","N","N"),
        },
        "Permissions-Policy": {
            "severity": "low",
            "desc": "İzin politikası tanımlanmamış – kamera/mikrofon/konum izinleri kontrolsüz",
            "remediation": "Permissions-Policy: geolocation=(), microphone=(), camera=()",
            "owasp": "A05-Security Misconfiguration",
            "cwe": "CWE-183",
            "cvss": CVSS("N","L","N","N","U","L","N","N"),
        },
        "Cross-Origin-Opener-Policy": {
            "severity": "low",
            "desc": "COOP eksik – cross-origin izolasyonu sağlanmıyor",
            "remediation": "Cross-Origin-Opener-Policy: same-origin",
            "owasp": "A05-Security Misconfiguration",
            "cwe": "CWE-693",
            "cvss": CVSS("N","L","N","N","U","L","N","N"),
        },
        "Cross-Origin-Resource-Policy": {
            "severity": "low",
            "desc": "CORP eksik – kaynaklar cross-origin'den yüklenebilir",
            "remediation": "Cross-Origin-Resource-Policy: same-origin",
            "owasp": "A05-Security Misconfiguration",
            "cwe": "CWE-693",
            "cvss": None,
        },
    }

    for header, info in required.items():
        if header not in headers:
            findings.append(make_finding(
                module="security_headers",
                title=f"Eksik Header: {header}",
                severity=info["severity"],
                description=info["desc"],
                owasp=info["owasp"],
                cwe=info.get("cwe",""),
                cvss=info.get("cvss"),
                remediation=info["remediation"],
                tags=["headers"]
            ))
            cprint(f"  [yellow]✗ {header} eksik[/]")
        else:
            cprint(f"  [green]✔ {header}: {headers[header][:60]}[/]", verbose_only=True)

    # HSTS değer analizi
    hsts = headers.get("Strict-Transport-Security", "")
    if hsts:
        age_match = re.search(r"max-age=(\d+)", hsts)
        if age_match and int(age_match.group(1)) < 15552000:  # 180 gün
            findings.append(make_finding(
                module="security_headers",
                title="HSTS max-age Çok Kısa",
                severity="low",
                description=f"HSTS max-age={age_match.group(1)} saniye – minimum 180 gün (15552000s) önerilir",
                owasp="A05-Security Misconfiguration",
                remediation="max-age değerini en az 31536000 (1 yıl) yapın",
                tags=["headers", "hsts"]
            ))
        if "preload" not in hsts:
            cprint("  [yellow]⚠ HSTS preload direktifi yok[/]", verbose_only=True)
        if "includeSubDomains" not in hsts:
            findings.append(make_finding(
                module="security_headers",
                title="HSTS includeSubDomains Eksik",
                severity="low",
                description="Alt domainler HSTS kapsamı dışında kalıyor",
                owasp="A05-Security Misconfiguration",
                remediation="Strict-Transport-Security başlığına includeSubDomains ekleyin",
                tags=["headers", "hsts"]
            ))

    # CSP analizi
    csp = headers.get("Content-Security-Policy", "")
    if csp:
        if "unsafe-inline" in csp:
            findings.append(make_finding(
                module="security_headers",
                title="CSP 'unsafe-inline' Kullanıyor",
                severity="medium",
                description="unsafe-inline direktifi CSP'yi büyük ölçüde etkisiz kılıyor",
                owasp="A05-Security Misconfiguration",
                cwe="CWE-693",
                remediation="unsafe-inline yerine nonce veya hash tabanlı CSP kullanın",
                tags=["headers", "csp"]
            ))
        if "unsafe-eval" in csp:
            findings.append(make_finding(
                module="security_headers",
                title="CSP 'unsafe-eval' Kullanıyor",
                severity="medium",
                description="unsafe-eval direktifi JavaScript eval() kullanımına izin veriyor",
                owasp="A05-Security Misconfiguration",
                remediation="unsafe-eval'i kaldırın, eval() kullanımından kaçının",
                tags=["headers", "csp"]
            ))

    # Tehlikeli bilgi ifşası
    for reveal_header in ["Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version"]:
        if reveal_header in headers:
            cprint(f"  [red]⚠ {reveal_header}: {headers[reveal_header]}[/]")
            findings.append(make_finding(
                module="security_headers",
                title=f"{reveal_header} Header Bilgi İfşası",
                severity="low",
                description=f"{reveal_header}: {headers[reveal_header]} – teknoloji stack'i açıkça görünüyor",
                evidence=f"{reveal_header}: {headers[reveal_header]}",
                owasp="A05-Security Misconfiguration",
                cwe="CWE-200",
                remediation=f"Sunucu yapılandırmasından {reveal_header} başlığını kaldırın veya değiştirin",
                tags=["headers", "information_disclosure"]
            ))

    return findings

# ════════════════════════════════════════════════════════════════════════════
# MODÜL 3 – Teknoloji Tespiti & Parmak İzi
# ════════════════════════════════════════════════════════════════════════════
async def module_fingerprint(result: ScanResult, cfg: dict, headers: dict, html: str) -> List[Finding]:
    cprint("\n[bold]▶ [03] Teknoloji Tespiti[/]")
    findings = []
    techs = {}

    signatures = {
        "WordPress":   {"patterns": [r"wp-content", r"wp-includes", r"/wp-json/"], "type": "cms"},
        "Joomla":      {"patterns": [r"Joomla!", r"/components/com_", r"/media/jui/"], "type": "cms"},
        "Drupal":      {"patterns": [r"Drupal", r"/sites/default/files", r"drupal\.js"], "type": "cms"},
        "Magento":     {"patterns": [r"Mage\.Cookies", r"/skin/frontend/", r"mage/"], "type": "ecommerce"},
        "Shopify":     {"patterns": [r"Shopify\.theme", r"cdn\.shopify\.com"], "type": "ecommerce"},
        "React":       {"patterns": [r"__REACT", r"react-dom", r"data-reactroot", r"_reactFiber"], "type": "framework"},
        "Vue.js":      {"patterns": [r"__vue__", r"Vue\.config", r"data-v-"], "type": "framework"},
        "Angular":     {"patterns": [r"ng-version", r"angular\.min\.js", r"\[_nghost"], "type": "framework"},
        "Next.js":     {"patterns": [r"__NEXT_DATA__", r"_next/static", r"__next"], "type": "framework"},
        "Nuxt.js":     {"patterns": [r"__NUXT__", r"_nuxt/", r"nuxt\.js"], "type": "framework"},
        "jQuery":      {"patterns": [r"jquery"], "type": "library"},
        "Bootstrap":   {"patterns": [r"bootstrap\.min\.css", r"bootstrap\.bundle"], "type": "library"},
        "Laravel":     {"patterns": [r"laravel_session", r"laravel\.js", r"XSRF-TOKEN"], "type": "backend"},
        "Django":      {"patterns": [r"csrfmiddlewaretoken", r"django"], "type": "backend"},
        "ASP.NET":     {"patterns": [r"__VIEWSTATE", r"ASP\.NET", r"aspx"], "type": "backend"},
        "Ruby on Rails":{"patterns":[r"_session_id", r"authenticity_token", r"rails"], "type": "backend"},
        "Spring":      {"patterns": [r"JSESSIONID", r"spring", r"_csrf"], "type": "backend"},
        "PHP":         {"patterns": [r"\.php", r"PHPSESSID", r"php-fpm"], "type": "backend"},
        "Node.js":     {"patterns": [r"express", r"node\.js", r"connect\.sid"], "type": "backend"},
        "Nginx":       {"patterns": [r"nginx"], "type": "server"},
        "Apache":      {"patterns": [r"apache", r"mod_"], "type": "server"},
        "Cloudflare":  {"patterns": [r"cloudflare", r"CF-Ray", r"__cfduid"], "type": "cdn"},
        "AWS":         {"patterns": [r"awselb", r"x-amz", r"\.amazonaws\.com"], "type": "cloud"},
        "Google Cloud":{"patterns": [r"goog-", r"\.googleapis\.com"], "type": "cloud"},
    }

    header_str = " ".join(f"{k}: {v}" for k, v in headers.items()).lower()

    for tech, info in signatures.items():
        for p in info["patterns"]:
            if re.search(p, html, re.IGNORECASE) or re.search(p, header_str, re.IGNORECASE):
                techs[tech] = info["type"]
                cprint(f"  [yellow]  {info['type'].upper()}: {tech}[/]")
                break

    # Header'dan versiyon bilgisi çıkar
    version_headers = ["Server", "X-Powered-By", "X-Generator", "X-Runtime", "X-Version"]
    for h in version_headers:
        if h in headers:
            techs[h] = headers[h]

    result.raw["fingerprint"] = {"technologies": techs}
    result.raw["_detected_techs"] = list(techs.keys())
    result.technologies = list(techs.keys())

    if techs:
        cprint(f"  [dim]Tespit edilen: {', '.join(techs.keys())}[/]")
    else:
        cprint("  [yellow]Teknoloji tespiti yapılamadı[/]")

    return findings

# ════════════════════════════════════════════════════════════════════════════
# MODÜL 4 – Subdomain Scanner
# ════════════════════════════════════════════════════════════════════════════
async def module_subdomain_scan(result: ScanResult, cfg: dict) -> List[Finding]:
    cprint("\n[bold]▶ [04] Subdomain Scanner[/]")
    domain   = result.host
    findings = []
    found    = []

    def check(sub):
        host = f"{sub}.{domain}"
        try:
            ip = socket.gethostbyname(host)
            return host, ip
        except: return None

    loop = asyncio.get_event_loop()
    with ThreadPoolExecutor(max_workers=40) as ex:
        tasks = [loop.run_in_executor(ex, check, s) for s in cfg["wordlists"]["subdomains"]]
        for res in await asyncio.gather(*tasks):
            if res:
                host, ip = res
                found.append({"host": host, "ip": ip})
                cprint(f"  [green]✔ {host} → {ip}[/]")

    result.raw["subdomain_scan"] = {"subdomains": found}

    risky_names = ["dev", "test", "stage", "beta", "old", "backup", "uat", "qa", "preprod", "legacy"]
    for item in found:
        for name in risky_names:
            if f".{name}." in item["host"] or item["host"].startswith(f"{name}."):
                findings.append(make_finding(
                    module="subdomain_scan",
                    title=f"Riskli Subdomain Açık: {item['host']}",
                    severity="medium",
                    description=f"Test/geliştirme ortamı subdomain'i halka açık: {item['host']} ({item['ip']})",
                    evidence=f"{item['host']} → {item['ip']}",
                    owasp="A05-Security Misconfiguration",
                    cwe="CWE-200",
                    remediation="Geliştirme ortamlarına IP kısıtlaması uygulayın",
                    tags=["subdomain", "exposure"]
                ))

    if not found:
        cprint("  [yellow]Subdomain bulunamadı[/]")

    return findings

# ════════════════════════════════════════════════════════════════════════════
# MODÜL 5 – Subdomain Takeover Kontrolü
# ════════════════════════════════════════════════════════════════════════════
async def module_subdomain_takeover(result: ScanResult, cfg: dict) -> List[Finding]:
    cprint("\n[bold]▶ [05] Subdomain Takeover[/]")
    findings = []

    # Bilinen takeover imzaları
    takeover_signatures = {
        "AWS S3":          ["NoSuchBucket", "The specified bucket does not exist"],
        "GitHub Pages":    ["There isn't a GitHub Pages site here"],
        "Heroku":          ["No such app", "herokucdn.com"],
        "Fastly":          ["Fastly error: unknown domain"],
        "Shopify":         ["Sorry, this shop is currently unavailable"],
        "Ghost":           ["The thing you were looking for is no longer here"],
        "Surge.sh":        ["project not found"],
        "Azure":           ["The page you requested is temporarily unavailable"],
        "Tumblr":          ["Whatever you were looking for doesn't live here"],
        "Zendesk":         ["Help Center Closed"],
        "Cargo":           ["If you're moving your domain away from Cargo"],
        "UserVoice":       ["This UserVoice subdomain is currently available"],
    }

    subdomains = result.raw.get("subdomain_scan", {}).get("subdomains", [])

    connector = aiohttp.TCPConnector(ssl=False)
    timeout   = aiohttp.ClientTimeout(total=cfg["timeout"])

    async with aiohttp.ClientSession(connector=connector, timeout=timeout,
                                     headers={"User-Agent": cfg["user_agent"]}) as session:
        async def check_takeover(item):
            for scheme in ["https", "http"]:
                try:
                    async with session.get(f"{scheme}://{item['host']}", allow_redirects=True) as r:
                        body = await r.text()
                        for service, sigs in takeover_signatures.items():
                            for sig in sigs:
                                if sig.lower() in body.lower():
                                    return item["host"], service, sig
                except: pass
            return None

        tasks = [check_takeover(item) for item in subdomains]
        for res in await asyncio.gather(*tasks):
            if res:
                host, service, sig = res
                cprint(f"  [bold red]⚠ Takeover Riski: {host} ({service})[/]")
                findings.append(make_finding(
                    module="subdomain_takeover",
                    title=f"Subdomain Takeover Riski: {host}",
                    severity="critical",
                    description=f"{host} üzerinde {service} takeover imzası bulundu",
                    evidence=f"İmza: '{sig}'",
                    owasp="A01-Broken Access Control",
                    cwe="CWE-284",
                    cvss=CVSS("N","L","N","N","U","H","H","N"),
                    remediation=f"CNAME kaydını kaldırın veya {service} üzerinde hesap talep edin",
                    references=["https://github.com/EdOverflow/can-i-take-over-xyz"],
                    tags=["subdomain", "takeover"]
                ))

    if not findings:
        cprint("  [green]Subdomain takeover belirtisi bulunamadı[/]")

    return findings

# ════════════════════════════════════════════════════════════════════════════
# MODÜL 6 – Directory Bruteforce
# ════════════════════════════════════════════════════════════════════════════
async def module_directory_brute(result: ScanResult, cfg: dict, session: HttpSession) -> List[Finding]:
    cprint("\n[bold]▶ [06] Directory Bruteforce[/]")
    findings  = []
    found     = []
    base      = result.url.rstrip("/")
    semaphore = asyncio.Semaphore(cfg.get("max_dir_concurrency", 50))

    async def check(path):
        async with semaphore:
            url = f"{base}/{path}"
            try:
                async with await session.get(url) as r:
                    if r.status not in [404, 410]:
                        size = len(await r.read())
                        return {"url": url, "status": r.status, "size": size, "path": path}
            except: pass
        return None

    tasks = [check(p) for p in cfg["wordlists"]["dirs"]]

    if HAS_RICH:
        results_list = []
        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
                      BarColumn(), TaskProgressColumn(), TimeElapsedColumn(), console=console) as prog:
            task = prog.add_task("  Dizin taranıyor...", total=len(tasks))
            for coro in asyncio.as_completed(tasks):
                r = await coro
                if r: results_list.append(r)
                prog.advance(task)
    else:
        results_raw = await asyncio.gather(*tasks)
        results_list = [r for r in results_raw if r]

    for item in results_list:
        found.append(item)
        style = "bold red" if item["status"] == 200 else "yellow"
        cprint(f"  [{style}][{item['status']}] {item['url']} ({item['size']} bytes)[/]")

    result.raw["dir_brute"] = {"found_paths": found}

    for item in found:
        path_lower = item["path"].lower()
        if item["status"] == 200 and any(s in path_lower for s in
            [".git", ".env", "phpinfo", "backup", ".sql", "config", "debug", "shell", "cmd", ".ssh"]):
            findings.append(make_finding(
                module="dir_brute",
                title=f"Hassas Kaynak Erişilebilir: /{item['path']}",
                severity="critical",
                description=f"Hassas dosya/dizin doğrudan erişime açık: {item['url']}",
                evidence=f"HTTP {item['status']}, {item['size']} bytes",
                owasp="A01-Broken Access Control",
                cwe="CWE-548",
                cvss=CVSS("N","L","N","N","U","H","N","N"),
                remediation="Bu kaynağa web sunucusu düzeyinde erişimi engelleyin",
                tags=["exposure", "information_disclosure"]
            ))

    if not found:
        cprint("  [green]Erişilebilir dizin/dosya bulunamadı[/]")

    return findings

# ════════════════════════════════════════════════════════════════════════════
# MODÜL 7 – SSL/TLS Analizi
# ════════════════════════════════════════════════════════════════════════════
async def module_ssl_analysis(result: ScanResult, cfg: dict) -> List[Finding]:
    cprint("\n[bold]▶ [07] SSL/TLS Analizi[/]")
    host     = result.host
    findings = []
    ssl_data = {}

    try:
        ctx  = ssl.create_default_context()
        loop = asyncio.get_event_loop()

        def _connect():
            with ctx.wrap_socket(socket.socket(), server_hostname=host) as s:
                s.settimeout(cfg["timeout"])
                s.connect((host, 443))
                return s.getpeercert(), s.cipher(), s.version()

        cert, cipher, version = await loop.run_in_executor(None, _connect)

        ssl_data["subject"]   = dict(x[0] for x in cert.get("subject", []))
        ssl_data["issuer"]    = dict(x[0] for x in cert.get("issuer", []))
        ssl_data["notBefore"] = cert.get("notBefore")
        ssl_data["notAfter"]  = cert.get("notAfter")
        ssl_data["cipher"]    = cipher[0] if cipher else "?"
        ssl_data["bits"]      = cipher[2] if cipher else 0
        ssl_data["version"]   = version
        ssl_data["san"]       = [v for t, v in cert.get("subjectAltName", []) if t == "DNS"]

        cprint(f"  Sertifika: {ssl_data['subject'].get('commonName','?')}")
        cprint(f"  Veren: {ssl_data['issuer'].get('organizationName','?')}")
        cprint(f"  Geçerlilik: {ssl_data['notBefore']} → {ssl_data['notAfter']}")
        cprint(f"  Cipher: {ssl_data['cipher']} ({ssl_data['bits']} bit) / {version}")
        cprint(f"  SANs: {', '.join(ssl_data['san'][:5])}" if ssl_data["san"] else "")

        # Zayıf cipher
        weak_ciphers = ["RC4", "DES", "3DES", "MD5", "NULL", "EXPORT", "ANON"]
        for w in weak_ciphers:
            if w in ssl_data["cipher"].upper():
                findings.append(make_finding(
                    module="ssl",
                    title=f"Zayıf SSL Cipher: {ssl_data['cipher']}",
                    severity="high",
                    description=f"Zayıf cipher kullanılıyor: {ssl_data['cipher']}",
                    owasp="A02-Cryptographic Failures",
                    cwe="CWE-326",
                    cvss=CVSS("N","H","N","N","U","H","N","N"),
                    remediation="Güvenli cipher suite'ler yapılandırın: AES-GCM, ChaCha20-Poly1305",
                    tags=["ssl", "crypto"]
                ))

        # Eski TLS sürümü
        if version in ["TLSv1", "TLSv1.1", "SSLv3", "SSLv2"]:
            findings.append(make_finding(
                module="ssl",
                title=f"Eski TLS Sürümü: {version}",
                severity="high",
                description=f"{version} protokolü demode ve güvensiz (POODLE, BEAST vb.)",
                owasp="A02-Cryptographic Failures",
                cwe="CWE-326",
                cvss=CVSS("N","H","N","N","U","L","L","N"),
                remediation="Minimum TLS 1.2, tercihan TLS 1.3 kullanın",
                tags=["ssl", "crypto"]
            ))

        # Sertifika süre kontrolü
        from email.utils import parsedate
        import calendar
        exp = cert.get("notAfter", "")
        if exp:
            exp_ts  = calendar.timegm(parsedate(exp))
            now_ts  = time.time()
            days    = int((exp_ts - now_ts) / 86400)
            ssl_data["days_remaining"] = days

            if days < 0:
                findings.append(make_finding(
                    module="ssl", title="SSL Sertifikası Süresi Dolmuş",
                    severity="critical",
                    description=f"Sertifika {abs(days)} gün önce sona erdi",
                    owasp="A02-Cryptographic Failures",
                    cwe="CWE-298",
                    cvss=CVSS("N","L","N","N","U","H","N","N"),
                    remediation="Sertifikayı hemen yenileyin",
                    tags=["ssl", "expired"]
                ))
            elif days < 14:
                cprint(f"  [bold red]⚠ Sertifika {days} GÜN SONRA sona eriyor![/]")
                findings.append(make_finding(
                    module="ssl", title=f"Kritik: Sertifika {days} Gün İçinde Sona Eriyor",
                    severity="high",
                    description=f"SSL sertifikası {days} gün içinde sona eriyor",
                    owasp="A02-Cryptographic Failures",
                    remediation="Sertifikayı acil olarak yenileyin",
                    tags=["ssl", "expiry"]
                ))
            elif days < 30:
                cprint(f"  [red]⚠ Sertifika {days} gün içinde sona eriyor[/]")
                findings.append(make_finding(
                    module="ssl", title=f"Sertifika {days} Gün İçinde Sona Eriyor",
                    severity="medium",
                    description=f"SSL sertifikası {days} gün içinde sona eriyor",
                    owasp="A02-Cryptographic Failures",
                    remediation="Sertifikayı yenileyin",
                    tags=["ssl", "expiry"]
                ))

        # Self-signed sertifika
        subject_cn = ssl_data["subject"].get("commonName", "")
        issuer_on  = ssl_data["issuer"].get("organizationName", "")
        if ssl_data["subject"] == ssl_data["issuer"]:
            findings.append(make_finding(
                module="ssl",
                title="Self-Signed Sertifika",
                severity="medium",
                description="Sertifika güvenilir bir CA tarafından imzalanmamış",
                owasp="A02-Cryptographic Failures",
                cwe="CWE-295",
                remediation="Let's Encrypt veya ticari CA'dan geçerli sertifika alın",
                tags=["ssl", "trust"]
            ))

    except ssl.SSLError as e:
        ssl_data["error"] = str(e)
        cprint(f"  [red]SSL hatası: {e}[/]")
        findings.append(make_finding(
            module="ssl",
            title="SSL Bağlantı Hatası",
            severity="high",
            description=f"SSL/TLS bağlantısı kurulamadı: {e}",
            owasp="A02-Cryptographic Failures",
            remediation="SSL yapılandırmasını kontrol edin",
            tags=["ssl"]
        ))
    except Exception as e:
        ssl_data["error"] = str(e)
        cprint(f"  [yellow]SSL analiz hatası: {e}[/]")

    result.raw["ssl_analysis"] = ssl_data
    return findings

# ════════════════════════════════════════════════════════════════════════════
# MODÜL 8 – Cookie Güvenlik Analizi
# ════════════════════════════════════════════════════════════════════════════
async def module_cookie_analysis(result: ScanResult, cfg: dict, session: HttpSession) -> List[Finding]:
    cprint("\n[bold]▶ [08] Cookie Güvenlik Analizi[/]")
    findings = []

    try:
        async with await session.get(result.url) as r:
            cookies = r.cookies
            headers = dict(r.headers)
    except Exception as e:
        cprint(f"  [yellow]Cookie analiz hatası: {e}[/]")
        return []

    set_cookie_headers = headers.get("Set-Cookie", "")
    all_set_cookies    = [h for k, h in headers.items() if k.lower() == "set-cookie"]

    cookie_data = []
    for cookie_str in all_set_cookies:
        name = cookie_str.split("=")[0].strip()
        lower = cookie_str.lower()
        info  = {
            "name": name,
            "secure": "secure" in lower,
            "httponly": "httponly" in lower,
            "samesite": "samesite" in lower,
            "raw": cookie_str[:150]
        }
        cookie_data.append(info)
        cprint(f"  Cookie: {name} | Secure:{info['secure']} | HttpOnly:{info['httponly']} | SameSite:{info['samesite']}")

        # Hassas isimler
        sensitive_names = ["session", "sess", "auth", "token", "jwt", "admin", "user", "login", "id"]
        is_sensitive = any(s in name.lower() for s in sensitive_names)

        if not info["secure"] and is_sensitive:
            findings.append(make_finding(
                module="cookies",
                title=f"Oturum Cookie'si Secure Bayraksız: {name}",
                severity="high",
                description=f"'{name}' cookie'si Secure bayrağı olmadan gönderiliyor – HTTP üzerinde ele geçirilebilir",
                evidence=cookie_str[:100],
                owasp="A02-Cryptographic Failures",
                cwe="CWE-614",
                cvss=CVSS("N","H","N","N","U","H","N","N"),
                remediation=f"Set-Cookie: {name}=...; Secure; ...",
                tags=["cookies", "session"]
            ))
        if not info["httponly"] and is_sensitive:
            findings.append(make_finding(
                module="cookies",
                title=f"Oturum Cookie'si HttpOnly Bayraksız: {name}",
                severity="medium",
                description=f"'{name}' cookie'si HttpOnly bayrağı olmadan – XSS ile çalınabilir",
                evidence=cookie_str[:100],
                owasp="A02-Cryptographic Failures",
                cwe="CWE-1004",
                cvss=CVSS("N","L","N","R","U","H","N","N"),
                remediation=f"Set-Cookie: {name}=...; HttpOnly; ...",
                tags=["cookies", "xss"]
            ))
        if not info["samesite"] and is_sensitive:
            findings.append(make_finding(
                module="cookies",
                title=f"Cookie SameSite Eksik: {name}",
                severity="medium",
                description=f"'{name}' cookie'sinde SameSite direktifi yok – CSRF riski",
                evidence=cookie_str[:100],
                owasp="A01-Broken Access Control",
                cwe="CWE-1275",
                remediation=f"Set-Cookie: {name}=...; SameSite=Strict; ...",
                tags=["cookies", "csrf"]
            ))

    result.raw["cookie_analysis"] = cookie_data

    if not cookie_data:
        cprint("  [yellow]Cookie bulunamadı[/]")

    return findings

# ════════════════════════════════════════════════════════════════════════════
# MODÜL 9 – SQL Injection Tester
# ════════════════════════════════════════════════════════════════════════════
async def module_sqli_test(result: ScanResult, cfg: dict, session: HttpSession, html: str) -> List[Finding]:
    cprint("\n[bold]▶ [09] SQL Injection Tester[/]")
    findings = []
    payloads  = cfg["wordlists"]["sqli_payloads"]
    sql_errors = [
        "sql syntax", "mysql_fetch", "ORA-01756", "sqlite_",
        "pg_query", "unclosed quotation", "syntax error", "SQLSTATE",
        "mysql error", "warning: mysql", "division by zero",
        "supplied argument is not a valid MySQL", "Column count doesn't match",
        "ODBC Microsoft Access Driver", "JET Database Engine",
        "Microsoft OLE DB Provider for ODBC", "Incorrect syntax near",
        "Unclosed quotation mark", "quoted string not properly terminated",
        "You have an error in your SQL syntax", "MySQL server version",
        "Syntax error converting", "Operand should contain",
    ]
    time_payloads = [
        ("1' AND SLEEP(3)--",  3.0, "MySQL"),
        ("1; WAITFOR DELAY '0:0:3'--", 3.0, "MSSQL"),
        ("1' AND pg_sleep(3)--", 3.0, "PostgreSQL"),
    ]

    soup  = BeautifulSoup(html, "html.parser")
    forms = soup.find_all("form")[:cfg.get("max_forms_test", 5)]

    # URL parametrelerini de test et
    parsed = urlparse(result.url)
    url_params = parse_qs(parsed.query)

    for form in forms:
        action = form.get("action", result.url)
        method = form.get("method", "get").upper()
        url    = urljoin(result.url, action)
        inputs = {i.get("name","test"): "1" for i in form.find_all("input")
                  if i.get("type","text") not in ["submit","hidden","checkbox","radio"]}
        if not inputs:
            continue

        for param in list(inputs.keys())[:3]:
            # Error-based SQLi
            for payload in payloads[:6]:
                data = dict(inputs)
                data[param] = payload
                try:
                    if method == "POST":
                        async with session._session.post(url, data=data,
                                   timeout=aiohttp.ClientTimeout(total=5)) as r:
                            body = await r.text()
                    else:
                        async with await session.get(url + "?" + urlencode(data)) as r:
                            body = await r.text()
                    for err in sql_errors:
                        if err.lower() in body.lower():
                            findings.append(make_finding(
                                module="sqli",
                                title="SQL Injection (Error-Based) Tespit Edildi",
                                severity="critical",
                                description=f"Parametre '{param}' SQL injection'a açık (hata mesajı sızdı)",
                                evidence=f"Payload: {payload!r} → SQL hatası: '{err}'",
                                owasp="A03-Injection",
                                cwe="CWE-89",
                                cvss=CVSS("N","L","N","N","C","H","H","H"),
                                remediation="Prepared statement/parameterized query kullanın",
                                references=["https://owasp.org/www-community/attacks/SQL_Injection"],
                                tags=["sqli", "injection"]
                            ))
                            cprint(f"  [bold red]⚠ SQLi (Error-Based): param={param}[/]")
                            break
                except: pass

            # Time-based blind SQLi
            for tp, expected_delay, db_type in time_payloads:
                data = dict(inputs)
                data[param] = tp
                start = time.time()
                try:
                    if method == "POST":
                        async with session._session.post(url, data=data,
                                   timeout=aiohttp.ClientTimeout(total=expected_delay+2)) as r:
                            await r.read()
                    else:
                        async with await session.get(url+"?"+urlencode(data)) as r:
                            await r.read()
                    elapsed = time.time() - start
                    if elapsed >= expected_delay - 0.5:
                        findings.append(make_finding(
                            module="sqli",
                            title=f"SQL Injection (Time-Based Blind) Tespit Edildi – {db_type}",
                            severity="critical",
                            description=f"Parametre '{param}' time-based blind SQLi'ya açık ({db_type})",
                            evidence=f"Payload: {tp!r} → Gecikme: {elapsed:.1f}s",
                            owasp="A03-Injection",
                            cwe="CWE-89",
                            cvss=CVSS("N","L","N","N","C","H","H","H"),
                            remediation="Prepared statement kullanın, sorgu süreleri sınırlayın",
                            tags=["sqli", "blind", "injection"]
                        ))
                        cprint(f"  [bold red]⚠ SQLi (Time-Based): {db_type}, {elapsed:.1f}s[/]")
                except: pass

    if not findings:
        cprint(f"  [green]SQLi belirtisi bulunamadı ({len(forms)} form test edildi)[/]")
    result.raw["sqli_test"] = {"tested_forms": len(forms), "findings_count": len(findings)}
    return findings

# ════════════════════════════════════════════════════════════════════════════
# MODÜL 10 – XSS Tester
# ════════════════════════════════════════════════════════════════════════════
async def module_xss_test(result: ScanResult, cfg: dict, session: HttpSession, html: str) -> List[Finding]:
    cprint("\n[bold]▶ [10] XSS Tester[/]")
    findings = []
    payloads = cfg["wordlists"]["xss_payloads"]

    soup  = BeautifulSoup(html, "html.parser")
    forms = soup.find_all("form")[:cfg.get("max_forms_test", 5)]

    for form in forms:
        action = form.get("action", result.url)
        method = form.get("method", "get").upper()
        url    = urljoin(result.url, action)
        inputs = {i.get("name","q"): "test" for i in form.find_all("input")
                  if i.get("type","text") not in ["submit","hidden"]}
        if not inputs:
            continue

        for param in list(inputs.keys())[:3]:
            for payload in payloads[:5]:
                data = dict(inputs)
                data[param] = payload
                try:
                    if method == "POST":
                        async with session._session.post(url, data=data,
                                   timeout=aiohttp.ClientTimeout(total=5)) as r:
                            body = await r.text()
                    else:
                        async with await session.get(url+"?"+urlencode(data)) as r:
                            body = await r.text()

                    if payload in body:
                        # DOM'da encode ediliyor mu kontrol et
                        encoded = payload.replace("<","&lt;").replace(">","&gt;")
                        if encoded not in body:
                            sev = "high"
                            title = "Reflected XSS Tespit Edildi"
                        else:
                            sev = "low"
                            title = "XSS Payload HTML-Encoded (Muhtemelen Güvenli)"

                        findings.append(make_finding(
                            module="xss",
                            title=title,
                            severity=sev,
                            description=f"Parametre '{param}' XSS yansıması içeriyor",
                            evidence=f"Payload: {payload!r} yansıtıldı",
                            owasp="A03-Injection",
                            cwe="CWE-79",
                            cvss=CVSS("N","L","N","R","U","L","L","N") if sev=="high" else None,
                            remediation="Tüm çıktıları bağlama göre encode edin, CSP ekleyin",
                            references=["https://owasp.org/www-community/attacks/xss/"],
                            tags=["xss", "injection"]
                        ))
                        cprint(f"  [bold red]⚠ XSS ({sev}): param={param}[/]")
                        break
                except: pass

    # Template Injection kontrolü
    for payload in ["{{7*7}}", "${7*7}", "<%= 7*7 %>"]:
        try:
            async with await session.get(result.url + "?q=" + quote(payload)) as r:
                body = await r.text()
                if "49" in body:
                    findings.append(make_finding(
                        module="xss",
                        title="Server-Side Template Injection (SSTI) Olası",
                        severity="critical",
                        description=f"Template expression '{payload}' değerlendi → 49 döndü",
                        evidence=f"Payload: {payload}",
                        owasp="A03-Injection",
                        cwe="CWE-94",
                        cvss=CVSS("N","L","N","N","U","H","H","H"),
                        remediation="Template engine'de güvenli sandbox kullanın, user input'u template'e geçirmeyin",
                        tags=["ssti", "injection", "rce"]
                    ))
                    cprint(f"  [bold red]⚠ SSTI olası: {payload}[/]")
        except: pass

    if not findings:
        cprint(f"  [green]XSS/SSTI belirtisi bulunamadı[/]")
    result.raw["xss_test"] = {"findings_count": len(findings)}
    return findings

# ════════════════════════════════════════════════════════════════════════════
# MODÜL 11 – Path Traversal / LFI Tester
# ════════════════════════════════════════════════════════════════════════════
async def module_path_traversal(result: ScanResult, cfg: dict, session: HttpSession) -> List[Finding]:
    cprint("\n[bold]▶ [11] Path Traversal / LFI[/]")
    findings = []
    payloads = cfg["wordlists"]["lfi_payloads"]

    lfi_indicators = [
        "root:x:0:0", "bin:x:1:1",  # /etc/passwd
        "[boot loader]", "[operating systems]",  # win ini
        "127.0.0.1\tlocalhost",  # hosts
        "<?php", "define('DB_",  # PHP config
    ]

    # URL parametrelerini test et
    parsed = urlparse(result.url)
    params = parse_qs(parsed.query)
    path_params = [p for p in params if any(kw in p.lower() for kw in
                   ["file","page","path","dir","include","doc","template","view","load","content"])]

    for param in path_params[:3]:
        for payload in payloads:
            test_url = result.url.replace(
                f"{param}={params[param][0]}",
                f"{param}={quote(payload)}"
            )
            try:
                async with await session.get(test_url) as r:
                    body = await r.text()
                    for indicator in lfi_indicators:
                        if indicator in body:
                            findings.append(make_finding(
                                module="lfi",
                                title="Path Traversal / LFI Tespit Edildi",
                                severity="critical",
                                description=f"Parametre '{param}' yerel dosya okumaya izin veriyor",
                                evidence=f"Payload: {payload!r} → İndikatör: '{indicator}'",
                                owasp="A01-Broken Access Control",
                                cwe="CWE-22",
                                cvss=CVSS("N","L","N","N","U","H","N","N"),
                                remediation="Dosya yollarını whitelist ile doğrulayın, realpath kullanın",
                                tags=["lfi", "traversal"]
                            ))
                            cprint(f"  [bold red]⚠ LFI: param={param}, payload={payload!r}[/]")
                            break
            except: pass

    if not findings:
        cprint("  [green]Path traversal / LFI belirtisi bulunamadı[/]")
    result.raw["lfi_test"] = {"findings_count": len(findings)}
    return findings

# ════════════════════════════════════════════════════════════════════════════
# MODÜL 12 – SSRF Probe
# ════════════════════════════════════════════════════════════════════════════
async def module_ssrf(result: ScanResult, cfg: dict, session: HttpSession) -> List[Finding]:
    cprint("\n[bold]▶ [12] SSRF Probe[/]")
    findings = []
    payloads = cfg["wordlists"]["ssrf_payloads"]

    parsed      = urlparse(result.url)
    url_params  = parse_qs(parsed.query)
    ssrf_params = [p for p in url_params if any(kw in p.lower() for kw in
                   ["url","uri","link","src","dest","redirect","path","next","webhook","endpoint","proxy","fetch","target","host"])]

    # HTML'deki formları da kontrol et
    ssrf_indicators = [
        ("169.254.169.254", "AWS Metadata"),
        ("metadata.google.internal", "GCP Metadata"),
        ("100.100.100.200", "Alibaba Metadata"),
    ]

    for param in ssrf_params[:3]:
        for payload in payloads[:3]:
            test_url = result.url.replace(
                f"{param}={url_params[param][0]}",
                f"{param}={quote(payload)}"
            )
            try:
                async with await session.get(test_url) as r:
                    body = await r.text()[:500]
                    # Cloud metadata belirtisi
                    if any(sig in body for sig in ["ami-id", "instance-id", "project-id", "hostname"]):
                        findings.append(make_finding(
                            module="ssrf",
                            title="SSRF – Cloud Metadata İfşası",
                            severity="critical",
                            description=f"Parametre '{param}' cloud metadata endpoint'ini çekebiliyor",
                            evidence=f"Payload: {payload!r} → {body[:200]}",
                            owasp="A10-Server-Side Request Forgery",
                            cwe="CWE-918",
                            cvss=CVSS("N","L","N","N","C","H","H","N"),
                            remediation="URL girdilerini whitelist ile kısıtlayın, internal ağa erişimi engelleyin",
                            tags=["ssrf", "cloud"]
                        ))
                        cprint(f"  [bold red]⚠ SSRF Cloud Metadata: param={param}[/]")
            except: pass

    if not findings:
        cprint("  [green]SSRF belirtisi bulunamadı[/]")
    result.raw["ssrf_test"] = {"findings_count": len(findings)}
    return findings

# ════════════════════════════════════════════════════════════════════════════
# MODÜL 13 – JWT Analizi
# ════════════════════════════════════════════════════════════════════════════
async def module_jwt_analysis(result: ScanResult, cfg: dict, session: HttpSession) -> List[Finding]:
    cprint("\n[bold]▶ [13] JWT Analizi[/]")
    findings = []
    jwt_data  = {}

    try:
        async with await session.get(result.url) as r:
            cookies = {k: v.value for k, v in r.cookies.items()}
            headers = dict(r.headers)
    except:
        return []

    jwt_pattern = r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*"
    sources     = list(cookies.values()) + list(headers.values())
    jwts_found  = []
    for src in sources:
        matches = re.findall(jwt_pattern, str(src))
        jwts_found.extend(matches)

    if not jwts_found:
        cprint("  [yellow]JWT token bulunamadı[/]")
        result.raw["jwt_analysis"] = {"found": False}
        return findings

    cprint(f"  [cyan]{len(jwts_found)} JWT token bulundu[/]")

    for token in jwts_found[:5]:
        parts = token.split(".")
        if len(parts) != 3:
            continue
        try:
            pad     = lambda s: s + "=" * (-len(s) % 4)
            header  = json.loads(base64.urlsafe_b64decode(pad(parts[0])))
            payload = json.loads(base64.urlsafe_b64decode(pad(parts[1])))
            jwt_data = {"header": header, "payload": payload}
            cprint(f"  Alg: {header.get('alg','?')} | Sub: {payload.get('sub','?')} | Exp: {payload.get('exp','?')}")

            if header.get("alg","").lower() == "none":
                findings.append(make_finding(
                    module="jwt", title="JWT alg:none Açığı",
                    severity="critical",
                    description="JWT 'alg:none' kullanıyor – imzasız token kabul ediliyor olabilir",
                    owasp="A02-Cryptographic Failures",
                    cwe="CWE-347",
                    cvss=CVSS("N","L","N","N","U","H","H","N"),
                    remediation="Sunucuda alg:none'ı kesinlikle reddedin",
                    tags=["jwt", "auth"]
                ))

            if header.get("alg") in ["HS256","HS384","HS512"]:
                findings.append(make_finding(
                    module="jwt", title=f"Simetrik JWT: {header.get('alg')}",
                    severity="medium",
                    description="HS* algoritmaları secret sızması durumunda token sahteciliğine açık",
                    owasp="A02-Cryptographic Failures",
                    cwe="CWE-326",
                    remediation="RS256 veya ES256 (asimetrik) algoritmalar kullanın",
                    tags=["jwt", "crypto"]
                ))

            # Zayıf secret bruteforce ipucu
            weak_secrets = ["secret","password","123456","admin","key","jwt","token"]
            sig_data     = f"{parts[0]}.{parts[1]}"
            import hmac as _hmac
            for s in weak_secrets:
                try:
                    import hashlib as _hl
                    expected = base64.urlsafe_b64encode(
                        _hmac.new(s.encode(), sig_data.encode(), _hl.sha256).digest()
                    ).rstrip(b"=").decode()
                    if expected == parts[2]:
                        findings.append(make_finding(
                            module="jwt",
                            title=f"Zayıf JWT Secret: '{s}'",
                            severity="critical",
                            description=f"JWT secret olarak '{s}' kullanılıyor – kolayca brute-force edilebilir",
                            evidence=f"Secret: '{s}'",
                            owasp="A02-Cryptographic Failures",
                            cwe="CWE-521",
                            cvss=CVSS("N","L","N","N","U","H","H","N"),
                            remediation="En az 256-bit rastgele secret kullanın veya asimetrik algoritmalara geçin",
                            tags=["jwt", "weak_secret"]
                        ))
                        cprint(f"  [bold red]⚠ Zayıf JWT secret: '{s}'[/]")
                        break
                except: pass

            exp = payload.get("exp")
            if exp:
                remaining = exp - time.time()
                if remaining < 0:
                    findings.append(make_finding(module="jwt", title="Süresi Dolmuş JWT Kabul Ediliyor Olabilir",
                        severity="low", description="Token süresi dolmuş – sunucu hâlâ kabul ediyorsa kritik",
                        owasp="A07-Identification and Authentication Failures",
                        remediation="Token doğrulamasında exp kontrolü zorunlu tutun",
                        tags=["jwt"]))
                elif remaining > 86400 * 30:
                    findings.append(make_finding(module="jwt", title=f"Aşırı Uzun JWT Ömrü ({int(remaining/86400)} gün)",
                        severity="low", description=f"JWT {int(remaining/86400)} gün geçerli",
                        owasp="A07-Identification and Authentication Failures",
                        remediation="Token süresini 15-60 dakikayla sınırlayın",
                        tags=["jwt"]))
        except Exception as e:
            cprint(f"  [yellow]JWT parse hatası: {e}[/]")

    result.raw["jwt_analysis"] = jwt_data
    return findings

# ════════════════════════════════════════════════════════════════════════════
# MODÜL 14 – CORS / CSRF Tester
# ════════════════════════════════════════════════════════════════════════════
async def module_cors_csrf(result: ScanResult, cfg: dict, session: HttpSession) -> List[Finding]:
    cprint("\n[bold]▶ [14] CORS / CSRF Tester[/]")
    findings = []
    origins  = [
        "https://evil.com",
        "null",
        f"https://evil.{result.host}",
        f"https://{result.host}.evil.com",
        "https://attacker.com",
        "http://localhost",
    ]

    try:
        for origin in origins:
            async with session._session.get(result.url,
                    headers={"Origin": origin, "User-Agent": cfg["user_agent"]}) as r:
                acao = r.headers.get("Access-Control-Allow-Origin", "")
                acac = r.headers.get("Access-Control-Allow-Credentials", "")
                acam = r.headers.get("Access-Control-Allow-Methods", "")

                if acao == "*":
                    findings.append(make_finding(
                        module="cors", title="CORS Wildcard (*) – Herkese Açık",
                        severity="medium",
                        description="Tüm originlerden cross-origin istek kabul ediliyor",
                        evidence=f"ACAO: *",
                        owasp="A01-Broken Access Control",
                        cwe="CWE-942",
                        remediation="Sadece güvenilir origin'lere izin verin",
                        tags=["cors"]
                    ))
                    cprint(f"  [yellow]⚠ CORS wildcard (*)[/]")
                    break
                elif acao and acao == origin:
                    sev = "critical" if acac.lower() == "true" else "high"
                    findings.append(make_finding(
                        module="cors",
                        title=f"CORS Origin Yansıtma {'+ Credentials' if acac.lower()=='true' else ''}",
                        severity=sev,
                        description=f"Origin '{origin}' yansıtılıyor. ACAC={acac}. Credentials çalınabilir.",
                        evidence=f"Origin: {origin} → ACAO: {acao}, ACAC: {acac}",
                        owasp="A01-Broken Access Control",
                        cwe="CWE-942",
                        cvss=CVSS("N","L","N","R","U","H","H","N"),
                        remediation="Origin whitelist kullanın, null origin'e asla izin vermeyin",
                        tags=["cors", "credentials"]
                    ))
                    cprint(f"  [red]⚠ CORS yansıtma: {origin}[/]")

        # CSRF token kontrolü
        async with await session.get(result.url) as r:
            body = await r.text()
        soup   = BeautifulSoup(body, "html.parser")
        forms  = soup.find_all("form", method=re.compile("post", re.I))
        tokens = ["csrf","token","_token","authenticity_token","csrfmiddlewaretoken","__requestverificationtoken"]

        for form in forms[:5]:
            inputs    = [i.get("name","").lower() for i in form.find_all("input")]
            has_token = any(any(t in inp for t in tokens) for inp in inputs)
            if not has_token:
                action = form.get("action","?")
                findings.append(make_finding(
                    module="csrf",
                    title=f"CSRF Token Eksik: {action}",
                    severity="high",
                    description=f"POST formu CSRF token içermiyor: {action}",
                    owasp="A01-Broken Access Control",
                    cwe="CWE-352",
                    cvss=CVSS("N","L","N","R","U","N","H","N"),
                    remediation="Tüm state-changing formlara synchronizer token ekleyin",
                    tags=["csrf"]
                ))
                cprint(f"  [red]⚠ CSRF token yok: {action}[/]")

    except Exception as e:
        cprint(f"  [yellow]CORS/CSRF test hatası: {e}[/]")

    if not findings:
        cprint("  [green]CORS/CSRF sorun tespit edilmedi[/]")
    result.raw["cors_csrf"] = {"findings_count": len(findings)}
    return findings

# ════════════════════════════════════════════════════════════════════════════
# MODÜL 15 – Hassas Dosya Tespiti
# ════════════════════════════════════════════════════════════════════════════
async def module_sensitive_files(result: ScanResult, cfg: dict, session: HttpSession) -> List[Finding]:
    cprint("\n[bold]▶ [15] Hassas Dosya Tespiti[/]")
    findings = []
    exposed  = []
    semaphore = asyncio.Semaphore(30)

    async def check(path):
        async with semaphore:
            url = urljoin(result.url.rstrip("/") + "/", path)
            try:
                async with await session.get(url) as r:
                    if r.status == 200:
                        body = await r.read()
                        if len(body) > 5:
                            text = body[:500].decode("utf-8", errors="ignore")
                            return {"url": url, "path": path, "size": len(body), "snippet": text}
            except: pass
        return None

    tasks   = [check(p) for p in cfg["sensitive_files"]]
    results = await asyncio.gather(*tasks)

    for r in results:
        if r:
            exposed.append(r)
            # Kritiklik değerlendirmesi
            path = r["path"].lower()
            if any(s in path for s in [".env", "id_rsa", ".aws", "credentials", "secret", "private"]):
                sev = "critical"
                cvss_obj = CVSS("N","L","N","N","U","H","H","N")
            elif any(s in path for s in ["config", "database", ".git", "backup", ".sql"]):
                sev = "high"
                cvss_obj = CVSS("N","L","N","N","U","H","N","N")
            else:
                sev = "medium"
                cvss_obj = None

            findings.append(make_finding(
                module="sensitive_files",
                title=f"Hassas Dosya Erişilebilir: {r['path']}",
                severity=sev,
                description=f"Hassas kaynak doğrudan erişilebilir: {r['url']} ({r['size']} bytes)",
                evidence=r["snippet"][:200],
                owasp="A05-Security Misconfiguration",
                cwe="CWE-200",
                cvss=cvss_obj,
                remediation=f"'{r['path']}' dosyasına web üzerinden erişimi engelleyin",
                tags=["sensitive_files", "exposure"]
            ))
            cprint(f"  [bold red]⚠ EXPOSED ({sev}): {r['url']} ({r['size']} bytes)[/]")

    if not exposed:
        cprint("  [green]Hassas dosya tespit edilmedi[/]")
    result.raw["sensitive_files"] = {"exposed": exposed}
    return findings

# ════════════════════════════════════════════════════════════════════════════
# MODÜL 16 – HTTP Method Test
# ════════════════════════════════════════════════════════════════════════════
async def module_http_methods(result: ScanResult, cfg: dict, session: HttpSession) -> List[Finding]:
    cprint("\n[bold]▶ [16] HTTP Method Test[/]")
    findings = []
    methods  = ["GET","POST","PUT","DELETE","PATCH","OPTIONS","TRACE","CONNECT","HEAD","PROPFIND","SEARCH"]
    method_results = {}

    for method in methods:
        try:
            async with session._session.request(method, result.url,
                    timeout=aiohttp.ClientTimeout(total=5)) as r:
                method_results[method] = r.status
                style = "green" if r.status < 400 else "dim"
                cprint(f"  [{style}]{method}: {r.status}[/]")

                if method == "TRACE" and r.status == 200:
                    findings.append(make_finding(
                        module="http_methods", title="HTTP TRACE Aktif (XST Riski)",
                        severity="medium",
                        description="TRACE metodu aktif – Cross-Site Tracing ile oturum cookie'si çalınabilir",
                        owasp="A05-Security Misconfiguration",
                        cwe="CWE-16",
                        remediation="TraceEnable Off (Apache) veya Nginx'de TRACE metodunu engelleyin",
                        tags=["http_methods"]
                    ))
                if method == "DELETE" and r.status in [200, 201, 204]:
                    findings.append(make_finding(
                        module="http_methods", title="HTTP DELETE İzin Veriyor",
                        severity="high",
                        description="DELETE metodu başarılı yanıt döndürüyor – kaynaklar silinebilir",
                        evidence=f"DELETE → HTTP {r.status}",
                        owasp="A01-Broken Access Control",
                        cwe="CWE-650",
                        cvss=CVSS("N","L","N","N","U","N","H","N"),
                        remediation="Gereksiz HTTP metodlarını devre dışı bırakın",
                        tags=["http_methods"]
                    ))
                if method == "PUT" and r.status in [200, 201, 204]:
                    findings.append(make_finding(
                        module="http_methods", title="HTTP PUT İzin Veriyor",
                        severity="high",
                        description="PUT metodu başarılı yanıt döndürüyor – dosya yüklenebilir",
                        evidence=f"PUT → HTTP {r.status}",
                        owasp="A01-Broken Access Control",
                        cwe="CWE-650",
                        cvss=CVSS("N","L","N","N","U","H","H","N"),
                        remediation="PUT metodunu whitelist ile kısıtlayın",
                        tags=["http_methods"]
                    ))
                if method == "PROPFIND" and r.status in [200, 207]:
                    findings.append(make_finding(
                        module="http_methods", title="WebDAV PROPFIND Aktif",
                        severity="medium",
                        description="WebDAV PROPFIND metodu aktif – dosya sistemi bilgisi sızabilir",
                        owasp="A05-Security Misconfiguration",
                        remediation="WebDAV'ı kapatın veya kısıtlayın",
                        tags=["http_methods", "webdav"]
                    ))
        except Exception:
            method_results[method] = "ERROR"

    result.raw["http_methods"] = {"methods": method_results}
    return findings

# ════════════════════════════════════════════════════════════════════════════
# MODÜL 17 – Clickjacking Testi
# ════════════════════════════════════════════════════════════════════════════
async def module_clickjacking(result: ScanResult, cfg: dict, session: HttpSession) -> List[Finding]:
    cprint("\n[bold]▶ [17] Clickjacking Testi[/]")
    findings = []

    try:
        async with await session.get(result.url) as r:
            headers = dict(r.headers)
            html    = await r.text()

        xfo = headers.get("X-Frame-Options","").upper()
        csp = headers.get("Content-Security-Policy","").lower()

        # frame-ancestors direktifi
        has_fa = "frame-ancestors" in csp
        # X-Frame-Options
        has_xfo = xfo in ["DENY","SAMEORIGIN"]

        if not has_xfo and not has_fa:
            findings.append(make_finding(
                module="clickjacking",
                title="Clickjacking – Koruma Yok",
                severity="medium",
                description="Sayfa iframe içine alınabilir. Clickjacking saldırısına açık.",
                owasp="A05-Security Misconfiguration",
                cwe="CWE-1021",
                cvss=CVSS("N","L","N","R","U","N","L","N"),
                remediation="X-Frame-Options: DENY veya CSP frame-ancestors 'none' ekleyin",
                tags=["clickjacking"]
            ))
            cprint("  [yellow]⚠ Clickjacking koruması yok[/]")
        else:
            cprint(f"  [green]✔ Koruma var: XFO={xfo}, CSP frame-ancestors={has_fa}[/]")

        # frame-busting JavaScript kontrolü
        if "top.location" in html or "top!=self" in html or "framebusting" in html.lower():
            cprint("  [dim]JS frame-busting bulundu (yedek)[/]", verbose_only=True)

    except Exception as e:
        cprint(f"  [yellow]Clickjacking test hatası: {e}[/]")

    return findings

# ════════════════════════════════════════════════════════════════════════════
# MODÜL 18 – WAF / Rate Limit Testi
# ════════════════════════════════════════════════════════════════════════════
async def module_rate_waf(result: ScanResult, cfg: dict, session: HttpSession) -> List[Finding]:
    cprint("\n[bold]▶ [18] WAF / Rate Limit Testi[/]")
    findings = []
    waf_data = {"detected": False, "names": [], "rate_limited": False, "bypass_hints": []}

    waf_signatures = {
        "Cloudflare":   ["CF-Ray", "cf-cache-status", "__cfduid", "cloudflare"],
        "Sucuri":       ["X-Sucuri-ID", "sucuri"],
        "Akamai":       ["X-Akamai", "akamaiedge", "akamai"],
        "AWS WAF":      ["awswaf", "x-amz-cf"],
        "Imperva":      ["X-CDN", "incapsula", "visid_incap"],
        "F5 BIG-IP":    ["X-Cnection", "BigIP", "BIGIP"],
        "ModSecurity":  ["ModSecurity", "Mod_Security"],
        "Nginx WAF":    ["nginx"],
        "Barracuda":    ["barra_counter_session", "barracuda"],
    }

    try:
        async with await session.get(result.url) as r:
            resp_headers = {k.lower(): v.lower() for k, v in r.headers.items()}
            resp_text    = await r.text()
            resp_lower   = resp_text.lower()

        for waf_name, sigs in waf_signatures.items():
            for sig in sigs:
                if sig.lower() in resp_headers or sig.lower() in resp_lower:
                    waf_data["detected"] = True
                    if waf_name not in waf_data["names"]:
                        waf_data["names"].append(waf_name)
                        cprint(f"  [yellow]⚠ WAF/CDN tespit edildi: {waf_name}[/]")
                    break

        # WAF bypass header dene
        bypass_headers = {
            "X-Forwarded-For": "127.0.0.1",
            "X-Real-IP": "127.0.0.1",
            "X-Originating-IP": "127.0.0.1",
            "X-Remote-IP": "127.0.0.1",
        }
        async with session._session.get(result.url + "?q=<script>alert(1)</script>",
                headers={**{"User-Agent": cfg["user_agent"]}, **bypass_headers}) as r:
            if r.status not in [403, 406, 429]:
                waf_data["bypass_hints"].append("IP spoof header bypass denenebilir")
                cprint("  [yellow]⚠ WAF bypass potansiyeli: IP spoof headerlar[/]")

        # Rate limit testi (15 hızlı istek)
        codes   = []
        tasks   = [session._session.get(result.url, timeout=aiohttp.ClientTimeout(total=3))
                   for _ in range(15)]
        responses = await asyncio.gather(*tasks, return_exceptions=True)
        for res in responses:
            if isinstance(res, Exception): continue
            codes.append(res.status)
            await res.release()

        if 429 in codes:
            waf_data["rate_limited"] = True
            cprint("  [green]✔ Rate limiting aktif (429 alındı)[/]")
        else:
            findings.append(make_finding(
                module="rate_waf",
                title="Rate Limiting Tespit Edilmedi",
                severity="medium",
                description=f"15 ardışık istek sonrası 429 dönmedi – brute force/DoS riski",
                owasp="A05-Security Misconfiguration",
                cwe="CWE-770",
                remediation="Nginx limit_req veya uygulama katmanında rate limiting ekleyin",
                tags=["rate_limiting", "dos"]
            ))
            cprint("  [yellow]⚠ Rate limiting tespit edilmedi[/]")

    except Exception as e:
        cprint(f"  [yellow]WAF/Rate test hatası: {e}[/]")

    result.raw["rate_waf"] = waf_data
    return findings

# ════════════════════════════════════════════════════════════════════════════
# MODÜL 19 – API Endpoint Enumeration
# ════════════════════════════════════════════════════════════════════════════
async def module_api_enum(result: ScanResult, cfg: dict, session: HttpSession, html: str) -> List[Finding]:
    cprint("\n[bold]▶ [19] API Endpoint Enumeration[/]")
    findings   = []
    found_apis = []
    api_paths  = [
        "swagger.json","swagger.yaml","swagger-ui.html","swagger-ui/",
        "openapi.json","openapi.yaml","openapi/","api-docs","api-docs/",
        "api/swagger","api/docs","redoc","graphql","graphiql","playground",
        "v1/","v2/","v3/","api/v1/","api/v2/","api/v3/",
        "api/v1/users","api/v2/users","api/users","api/admin",
        "api/v1/admin","api/health","api/status","api/ping","api/info",
        ".well-known/openid-configuration",".well-known/oauth-authorization-server",
        "api/schema","api/config","api/settings","api/debug",
        "rest/","rest/api/2/","rest/api/latest/",  # Jira
        "api/json","api/xml","rpc","jsonrpc","xmlrpc",
    ]

    semaphore = asyncio.Semaphore(20)

    async def check(path):
        async with semaphore:
            url = urljoin(result.url.rstrip("/") + "/", path)
            try:
                async with await session.get(url) as r:
                    if r.status in [200, 401, 403]:
                        ct   = r.headers.get("Content-Type","")
                        body = await r.text()
                        return {
                            "url": url, "status": r.status,
                            "content_type": ct,
                            "is_json": "json" in ct or body.strip().startswith("{") or body.strip().startswith("["),
                            "snippet": body[:200]
                        }
            except: pass
        return None

    tasks   = [check(p) for p in api_paths]
    results = await asyncio.gather(*tasks)

    for r in results:
        if r:
            found_apis.append(r)
            cprint(f"  [cyan][{r['status']}] {r['url']}{'  (JSON)' if r['is_json'] else ''}[/]")

            if r["status"] == 200 and ("swagger" in r["url"] or "openapi" in r["url"] or "api-docs" in r["url"]):
                findings.append(make_finding(
                    module="api_enum",
                    title=f"API Dokümantasyonu Herkese Açık: {r['url'].split('/',3)[-1]}",
                    severity="medium",
                    description="Swagger/OpenAPI dokümantasyonu kimlik doğrulama gerektirmeden erişilebilir",
                    evidence=r["url"],
                    owasp="A05-Security Misconfiguration",
                    cwe="CWE-200",
                    remediation="Production ortamında API dokümantasyonuna erişimi kısıtlayın",
                    tags=["api", "documentation"]
                ))

            if "graphql" in r["url"] and r["status"] == 200:
                # Introspection kontrolü
                introspection_query = '{"query":"{__schema{types{name}}}"}'
                try:
                    async with session._session.post(r["url"],
                            data=introspection_query,
                            headers={"Content-Type":"application/json"}) as gr:
                        gbody = await gr.text()
                        if "__schema" in gbody:
                            findings.append(make_finding(
                                module="api_enum",
                                title="GraphQL Introspection Aktif",
                                severity="medium",
                                description="GraphQL introspection açık – tüm şema öğrenilebilir",
                                evidence=gbody[:200],
                                owasp="A05-Security Misconfiguration",
                                cwe="CWE-200",
                                remediation="Production'da introspection'ı devre dışı bırakın",
                                tags=["api", "graphql"]
                            ))
                            cprint(f"  [yellow]⚠ GraphQL introspection açık[/]")
                except: pass

    # HTML kaynak kodundan API endpoint ipuçları
    api_pattern = r'["\']/(api|v\d|rest|graphql)[^\s"\'>]{2,80}["\']'
    found_inline = re.findall(api_pattern, html)
    if found_inline:
        cprint(f"  [dim]HTML'de {len(found_inline)} API referansı[/]")

    if not found_apis:
        cprint("  [yellow]Bilinen API endpoint bulunamadı[/]")
    result.raw["api_enum"] = {"found": found_apis, "inline_count": len(found_inline) if found_inline else 0}
    return findings

# ════════════════════════════════════════════════════════════════════════════
# MODÜL 20 – OSINT / Email Harvester
# ════════════════════════════════════════════════════════════════════════════
async def module_osint_harvest(result: ScanResult, cfg: dict, html: str) -> List[Finding]:
    cprint("\n[bold]▶ [20] OSINT / Email & Info Harvester[/]")
    findings = []

    emails   = list(set(re.findall(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}", html)))
    phones   = list(set(re.findall(r"(\+90|0)[\s\-]?(\d{3})[\s\-]?(\d{3})[\s\-]?(\d{2})[\s\-]?(\d{2})", html)))
    comments = re.findall(r"<!--(.+?)-->", html, re.DOTALL)
    # API key / secret tespiti
    secret_patterns = {
        "AWS Key":      r"AKIA[0-9A-Z]{16}",
        "Google API":   r"AIza[0-9A-Za-z\-_]{35}",
        "Stripe Key":   r"sk_live_[0-9a-zA-Z]{24}",
        "GitHub Token": r"gh[pousr]_[A-Za-z0-9_]{36}",
        "Private Key":  r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----",
        "JWT Token":    r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*",
        "Auth Token":   r'(?:api[_-]?key|auth[_-]?token|access[_-]?token|bearer)["\s:=]+[A-Za-z0-9_\-\.]{20,}',
    }

    found_secrets = {}
    for name, pattern in secret_patterns.items():
        matches = re.findall(pattern, html, re.IGNORECASE)
        if matches:
            found_secrets[name] = matches[:3]

    osint_data = {
        "emails": emails,
        "phones": [" ".join(p) for p in phones],
        "html_comments": len(comments),
        "found_secrets": {k: v for k, v in found_secrets.items()},
    }

    if emails:
        cprint(f"  [yellow]📧 {len(emails)} email: {', '.join(emails[:3])}[/]")
        findings.append(make_finding(
            module="osint", title=f"{len(emails)} Email Adresi Açık",
            severity="low",
            description=f"Sayfada email adresleri tespit edildi: {', '.join(emails[:3])}",
            owasp="A05-Security Misconfiguration",
            cwe="CWE-200",
            remediation="Email adreslerini contact form ile gizleyin veya base64/obfuscate edin",
            tags=["osint", "email"]
        ))

    if found_secrets:
        for name, vals in found_secrets.items():
            cprint(f"  [bold red]🔑 {name} tespit edildi![/]")
            findings.append(make_finding(
                module="osint",
                title=f"Kaynak Kodda Credential: {name}",
                severity="critical",
                description=f"HTML kaynak kodu içinde {name} bulundu",
                evidence=str(vals[0])[:100],
                owasp="A02-Cryptographic Failures",
                cwe="CWE-312",
                cvss=CVSS("N","L","N","N","U","H","H","N"),
                remediation="Anahtarı hemen iptal edin, ortam değişkenlerine taşıyın, git geçmişini temizleyin",
                tags=["osint", "credentials", "secret"]
            ))

    if comments:
        cprint(f"  [yellow]{len(comments)} HTML yorum[/]")
        sensitive_kws = ["password","passwd","todo","hack","debug","admin","secret","key","token","fixme","xxx","bug"]
        for c in comments:
            if any(kw in c.lower() for kw in sensitive_kws):
                findings.append(make_finding(
                    module="osint", title="Hassas HTML Yorum Satırı",
                    severity="medium",
                    description=f"HTML yorumunda hassas bilgi: {c.strip()[:100]}",
                    owasp="A05-Security Misconfiguration",
                    cwe="CWE-615",
                    remediation="Production kodundaki yorum satırlarını kaldırın",
                    tags=["osint", "comments"]
                ))

    result.raw["osint_harvest"] = osint_data
    return findings

# ════════════════════════════════════════════════════════════════════════════
# MODÜL 21 – CVE Lookup
# ════════════════════════════════════════════════════════════════════════════
async def module_cve_lookup(result: ScanResult, cfg: dict) -> List[Finding]:
    cprint("\n[bold]▶ [21] CVE Lookup[/]")
    findings = []
    techs    = result.raw.get("_detected_techs", [])

    # NVD API'den çekme denemesi (ağ erişimi yoksa statik DB kullanılır)
    vuln_db = {
        "WordPress": [
            {"cve":"CVE-2023-2745","cvss":6.4,"title":"WP Core Path Traversal","year":2023},
            {"cve":"CVE-2022-21661","cvss":7.5,"title":"WP SQL Injection via WP_Query","year":2022},
        ],
        "jQuery": [
            {"cve":"CVE-2020-11022","cvss":6.1,"title":"jQuery XSS in HTML Parsing","year":2020},
            {"cve":"CVE-2019-11358","cvss":6.1,"title":"jQuery Prototype Pollution","year":2019},
        ],
        "Apache": [
            {"cve":"CVE-2021-41773","cvss":9.8,"title":"Apache Path Traversal + RCE","year":2021},
            {"cve":"CVE-2021-42013","cvss":9.8,"title":"Apache Path Traversal Bypass","year":2021},
            {"cve":"CVE-2017-7679","cvss":9.8,"title":"Apache mod_mime Buffer Overflow","year":2017},
        ],
        "PHP": [
            {"cve":"CVE-2022-31625","cvss":8.1,"title":"PHP Nullable Type UAF","year":2022},
            {"cve":"CVE-2021-21705","cvss":5.3,"title":"PHP SSRF in SoapClient","year":2021},
        ],
        "Laravel": [
            {"cve":"CVE-2021-3129","cvss":9.8,"title":"Laravel Debug Mode RCE","year":2021},
        ],
        "Drupal": [
            {"cve":"CVE-2019-6340","cvss":9.8,"title":"Drupalgeddon3 RCE","year":2019},
            {"cve":"CVE-2018-7600","cvss":9.8,"title":"Drupalgeddon2 RCE","year":2018},
        ],
        "Joomla": [
            {"cve":"CVE-2023-23752","cvss":5.3,"title":"Joomla Improper Access Check","year":2023},
        ],
        "Nginx": [
            {"cve":"CVE-2021-23017","cvss":7.7,"title":"Nginx DNS Resolver Buffer Overflow","year":2021},
        ],
        "Spring": [
            {"cve":"CVE-2022-22965","cvss":9.8,"title":"Spring4Shell RCE","year":2022},
            {"cve":"CVE-2022-22963","cvss":9.8,"title":"Spring Cloud Function SpEL RCE","year":2022},
        ],
        "Elasticsearch": [
            {"cve":"CVE-2015-1427","cvss":10.0,"title":"Elasticsearch Groovy Sandbox Escape","year":2015},
        ],
        "Redis": [
            {"cve":"CVE-2022-0543","cvss":10.0,"title":"Redis Lua Sandbox Escape RCE","year":2022},
        ],
        "MongoDB": [
            {"cve":"CVE-2019-2388","cvss":7.1,"title":"MongoDB Operator Injection","year":2019},
        ],
    }

    for tech in techs:
        for key, cves in vuln_db.items():
            if key.lower() in str(tech).lower():
                for cve in cves:
                    sev = severity_from_cvss(cve["cvss"])
                    findings.append(make_finding(
                        module="cve_lookup",
                        title=f"{cve['cve']}: {cve['title']}",
                        severity=sev,
                        description=f"Tespit edilen '{key}' bileşeni için bilinen zafiyet: {cve['cve']} (CVSS: {cve['cvss']})",
                        owasp="A06-Vulnerable and Outdated Components",
                        cwe="CWE-1035",
                        remediation=f"'{key}' bileşenini güncel sürüme yükseltin, {cve['cve']} yamasını uygulayın",
                        references=[f"https://nvd.nist.gov/vuln/detail/{cve['cve']}"],
                        tags=["cve", "components"]
                    ))
                    findings[-1].cvss_score = cve["cvss"]
                    cprint(f"  [red]⚠ {cve['cve']} (CVSS {cve['cvss']}) → {key}[/]")

    if not findings:
        cprint("  [green]Bilinen CVE eşleşmesi bulunamadı[/]")
    result.raw["cve_lookup"] = {"checked_techs": techs, "count": len(findings)}
    return findings

# ════════════════════════════════════════════════════════════════════════════
# MODÜL 22 – DNS Analizi (SPF/DKIM/DMARC/Zone Transfer)
# ════════════════════════════════════════════════════════════════════════════
async def module_dns_analysis(result: ScanResult, cfg: dict) -> List[Finding]:
    cprint("\n[bold]▶ [22] DNS Analizi (SPF/DKIM/DMARC)[/]")
    findings = []
    domain   = result.host
    dns_data = {}

    def run_dig(cmd_args):
        try:
            out = subprocess.check_output(["dig"] + cmd_args + ["+short"],
                                          timeout=5, stderr=subprocess.DEVNULL).decode().strip()
            return out
        except: return ""

    def nslookup_txt(name):
        try:
            import socket
            answers = socket.getaddrinfo(name, None)
            return str(answers)
        except: return ""

    loop = asyncio.get_event_loop()

    # SPF
    spf = await loop.run_in_executor(None, run_dig, ["TXT", domain])
    dns_data["spf"] = spf
    if "v=spf1" not in spf:
        findings.append(make_finding(
            module="dns",
            title="SPF Kaydı Eksik",
            severity="medium",
            description=f"{domain} için SPF kaydı bulunamadı – email spoofing riski",
            owasp="A05-Security Misconfiguration",
            cwe="CWE-183",
            remediation=f'"{domain}" için TXT kaydı ekleyin: v=spf1 include:... -all',
            tags=["dns", "email", "spf"]
        ))
        cprint("  [yellow]⚠ SPF kaydı yok[/]")
    else:
        cprint(f"  [green]✔ SPF bulundu[/]")
        if "+all" in spf:
            findings.append(make_finding(
                module="dns", title="SPF '+all' – Tüm Sunuculara İzin",
                severity="high",
                description="SPF kaydında '+all' var – herhangi bir sunucu bu domain adına mail gönderebilir",
                evidence=spf,
                owasp="A05-Security Misconfiguration",
                remediation="'+all' yerine '-all' (hard fail) kullanın",
                tags=["dns", "spf"]
            ))

    # DMARC
    dmarc = await loop.run_in_executor(None, run_dig, ["TXT", f"_dmarc.{domain}"])
    dns_data["dmarc"] = dmarc
    if "v=DMARC1" not in dmarc:
        findings.append(make_finding(
            module="dns", title="DMARC Kaydı Eksik",
            severity="medium",
            description=f"_dmarc.{domain} DMARC kaydı yok – phishing koruması eksik",
            owasp="A05-Security Misconfiguration",
            remediation=f'TXT kaydı ekleyin: _dmarc.{domain} → v=DMARC1; p=quarantine; rua=mailto:...',
            tags=["dns", "email", "dmarc"]
        ))
        cprint("  [yellow]⚠ DMARC kaydı yok[/]")
    else:
        cprint(f"  [green]✔ DMARC bulundu[/]")
        if "p=none" in dmarc:
            findings.append(make_finding(
                module="dns", title="DMARC Politikası 'none' – Koruma Yok",
                severity="low",
                description="DMARC p=none ayarlı – raporlama var ama eylem yok",
                evidence=dmarc,
                owasp="A05-Security Misconfiguration",
                remediation="p=quarantine veya p=reject olarak güncelleyin",
                tags=["dns", "dmarc"]
            ))

    # Zone Transfer dene
    ns = await loop.run_in_executor(None, run_dig, ["NS", domain])
    dns_data["nameservers"] = ns

    if ns:
        for nameserver in ns.split("\n")[:2]:
            ns = nameserver.strip()
            if ns:
                zone_transfer = await loop.run_in_executor(None,
                    lambda ns=ns: subprocess.check_output(
                        ["dig", "AXFR", domain, f"@{ns}"], timeout=5, stderr=subprocess.DEVNULL
                    ).decode()[:500] if ns else "",
                )
                if zone_transfer and "Transfer failed" not in zone_transfer and len(zone_transfer) > 100:
                    findings.append(make_finding(
                        module="dns",
                        title=f"DNS Zone Transfer İzin Veriyor: {ns}",
                        severity="high",
                        description=f"NS sunucusu {ns} AXFR zone transfer'ine izin veriyor – tüm DNS kaydı sızabilir",
                        evidence=zone_transfer[:200],
                        owasp="A05-Security Misconfiguration",
                        cwe="CWE-200",
                        cvss=CVSS("N","L","N","N","U","H","N","N"),
                        remediation="NS sunucusunda zone transfer'i yalnızca secondary NS'lere izin verecek şekilde kısıtlayın",
                        tags=["dns", "zone_transfer"]
                    ))
                    cprint(f"  [bold red]⚠ Zone transfer izin veriyor: {ns}[/]")

    result.raw["dns_analysis"] = dns_data
    return findings

# ════════════════════════════════════════════════════════════════════════════
# MODÜL 23 – Information Disclosure
# ════════════════════════════════════════════════════════════════════════════
async def module_info_disclosure(result: ScanResult, cfg: dict, session: HttpSession) -> List[Finding]:
    cprint("\n[bold]▶ [23] Information Disclosure[/]")
    findings = []

    # Error sayfası tetikleme
    error_urls = [
        result.url + "/nonexistent_path_xyz_12345",
        result.url + "/?id='" ,
        result.url + "/../../../etc/passwd",
        result.url.replace("https://","https://x@").replace("http://","http://x@"),  # Auth header
    ]

    stack_trace_patterns = [
        r"Traceback \(most recent call last\)",  # Python
        r"at [\w\.]+\.[\w]+\([\w]+\.java:\d+\)",  # Java
        r"Exception in thread",
        r"System\.NullReferenceException",  # .NET
        r"Fatal error.*on line \d+",  # PHP
        r"Warning.*in.*on line",  # PHP
        r"Notice:.*in.*on line",  # PHP
        r"ActiveRecord::[\w]+Error",  # Rails
        r"ActionController::RoutingError",  # Rails
        r"django\.core\.exceptions",  # Django
        r"DEBUG = True",  # Django debug
        r"Whoops\\Exception",  # Laravel debug
        r"Symfony\\Component",  # Symfony
    ]

    for url in error_urls:
        try:
            async with await session.get(url) as r:
                body = await r.text()
                for pattern in stack_trace_patterns:
                    if re.search(pattern, body, re.IGNORECASE):
                        findings.append(make_finding(
                            module="info_disclosure",
                            title="Stack Trace / Debug Bilgisi İfşası",
                            severity="high",
                            description=f"Hata sayfasında stack trace veya debug bilgisi görünüyor",
                            evidence=body[:300],
                            owasp="A05-Security Misconfiguration",
                            cwe="CWE-209",
                            cvss=CVSS("N","L","N","N","U","H","N","N"),
                            remediation="Production modunda debug/verbose hata mesajlarını kapatın",
                            tags=["info_disclosure", "debug"]
                        ))
                        cprint(f"  [red]⚠ Stack trace / debug bilgisi ifşa: {url}[/]")
                        break
        except: pass

    # robots.txt analizi
    try:
        async with await session.get(result.url.rstrip("/") + "/robots.txt") as r:
            if r.status == 200:
                robots_content = await r.text()
                disallow_paths = re.findall(r"Disallow:\s*(.+)", robots_content)
                if disallow_paths:
                    cprint(f"  [dim]robots.txt'de {len(disallow_paths)} Disallow[/]")
                    sensitive_disallows = [p for p in disallow_paths
                                          if any(kw in p.lower() for kw in
                                                 ["admin","config","backup","api","secret","private"])]
                    if sensitive_disallows:
                        findings.append(make_finding(
                            module="info_disclosure",
                            title="robots.txt Hassas Dizin Referansı",
                            severity="info",
                            description=f"robots.txt hassas dizinlere referans içeriyor: {', '.join(sensitive_disallows[:3])}",
                            evidence=robots_content[:300],
                            owasp="A05-Security Misconfiguration",
                            cwe="CWE-200",
                            remediation="Hassas dizinlerin varlığını robots.txt'e eklemeyin, erişimi sunucu tarafında kısıtlayın",
                            tags=["info_disclosure", "robots"]
                        ))
    except: pass

    # security.txt kontrolü
    for sec_path in ["/.well-known/security.txt", "/security.txt"]:
        try:
            async with await session.get(result.url.rstrip("/") + sec_path) as r:
                if r.status == 200:
                    cprint(f"  [green]✔ security.txt bulundu[/]")
                    break
        except: pass

    if not findings:
        cprint("  [green]Belirgin bilgi ifşası tespit edilmedi[/]")

    result.raw["info_disclosure"] = {"findings_count": len(findings)}
    return findings

# ════════════════════════════════════════════════════════════════════════════
# MODÜL 24 – Open Redirect Testi
# ════════════════════════════════════════════════════════════════════════════
async def module_open_redirect(result: ScanResult, cfg: dict, session: HttpSession) -> List[Finding]:
    cprint("\n[bold]▶ [24] Open Redirect Testi[/]")
    findings = []
    payloads = [
        "https://evil.com",
        "//evil.com",
        "/\\evil.com",
        "https:evil.com",
        "///evil.com",
        "/%09/evil.com",
        "https://evil%E3%80%82com",
    ]
    params = ["redirect","url","next","return","goto","target","dest","redir",
              "location","continue","link","back","forward","out","jump","ref"]
    base   = result.url.rstrip("/")

    async def check(param, payload):
        url = f"{base}?{param}={quote(payload)}"
        try:
            async with session._session.get(url, allow_redirects=False,
                    timeout=aiohttp.ClientTimeout(total=5)) as r:
                location = r.headers.get("Location","")
                if "evil.com" in location:
                    return param, payload, location
        except: pass
        return None

    tasks   = [check(p, pl) for p in params for pl in payloads[:3]]
    results = await asyncio.gather(*tasks)

    for r in results:
        if r:
            param, payload, location = r
            findings.append(make_finding(
                module="open_redirect",
                title=f"Open Redirect: ?{param}=",
                severity="medium",
                description=f"Parametre '{param}' open redirect'e izin veriyor",
                evidence=f"?{param}={payload} → Location: {location}",
                owasp="A01-Broken Access Control",
                cwe="CWE-601",
                cvss=CVSS("N","L","N","R","U","L","N","N"),
                remediation="Redirect URL'ini whitelist ile doğrulayın, relative path kullanın",
                references=["https://cwe.mitre.org/data/definitions/601.html"],
                tags=["redirect", "phishing"]
            ))
            cprint(f"  [yellow]⚠ Open Redirect: ?{param}={payload}[/]")

    if not findings:
        cprint("  [green]Open redirect tespit edilmedi[/]")
    result.raw["open_redirect"] = {"findings_count": len(findings)}
    return findings

# ════════════════════════════════════════════════════════════════════════════
# MODÜL 25 – HTTP Request Smuggling İpuçları
# ════════════════════════════════════════════════════════════════════════════
async def module_request_smuggling(result: ScanResult, cfg: dict, session: HttpSession) -> List[Finding]:
    cprint("\n[bold]▶ [25] HTTP Request Smuggling Testi[/]")
    findings = []

    # CL.TE probe
    try:
        cl_te_payload = (
            "POST / HTTP/1.1\r\n"
            f"Host: {result.host}\r\n"
            "Content-Type: application/x-www-form-urlencoded\r\n"
            "Content-Length: 6\r\n"
            "Transfer-Encoding: chunked\r\n\r\n"
            "0\r\n\r\n"
            "X"
        )
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(result.host, 80 if result.url.startswith("http://") else 443,
                                    ssl=result.url.startswith("https://")),
            timeout=5
        )
        writer.write(cl_te_payload.encode())
        await writer.drain()
        try:
            response = await asyncio.wait_for(reader.read(512), timeout=3)
            resp_text = response.decode("utf-8", errors="ignore")
            # Anormal yanıt HTTP Desync belirtisi olabilir
            if "HTTP/1.1" in resp_text and ("400" not in resp_text and "505" not in resp_text):
                findings.append(make_finding(
                    module="smuggling",
                    title="HTTP Request Smuggling – CL.TE Potansiyeli",
                    severity="high",
                    description="Anormal CL+TE yanıtı alındı – HTTP desync testi gerekiyor",
                    owasp="A01-Broken Access Control",
                    cwe="CWE-444",
                    cvss=CVSS("N","H","N","N","C","H","H","H"),
                    remediation="HTTP/2 kullanın veya proxy/sunucu uyumluluğunu kontrol edin",
                    references=["https://portswigger.net/web-security/request-smuggling"],
                    tags=["smuggling", "desync"]
                ))
                cprint("  [yellow]⚠ CL.TE anormal yanıt – daha derin test önerilir[/]")
        except asyncio.TimeoutError:
            # Timeout da smuggling belirtisi olabilir
            cprint("  [dim]CL.TE probe timeout (olası belirtiler için manuel test gerekiyor)[/]", verbose_only=True)
        finally:
            writer.close()
    except Exception as e:
        cprint(f"  [dim]Smuggling probe hatası: {e}[/]", verbose_only=True)

    if not findings:
        cprint("  [green]Belirgin smuggling ipucu bulunamadı (manuel doğrulama önerilir)[/]")
    return findings

# ════════════════════════════════════════════════════════════════════════════
# MODÜL 26 – Broken Link Checker
# ════════════════════════════════════════════════════════════════════════════
async def module_broken_links(result: ScanResult, cfg: dict, session: HttpSession, html: str) -> List[Finding]:
    cprint("\n[bold]▶ [26] Broken Link Checker[/]")
    findings  = []
    soup      = BeautifulSoup(html, "html.parser")
    all_links = []

    for tag in soup.find_all(["a","link","script","img","iframe"], href=True):
        href = tag.get("href") or tag.get("src","")
        if href and href.startswith("http") and result.host not in href:
            all_links.append(href)
    for tag in soup.find_all(["script","img","iframe"], src=True):
        src = tag.get("src","")
        if src and src.startswith("http") and result.host not in src:
            all_links.append(src)

    all_links = list(set(all_links))[:50]
    semaphore = asyncio.Semaphore(10)

    async def check(url):
        async with semaphore:
            try:
                async with session._session.head(url, timeout=aiohttp.ClientTimeout(total=5),
                        allow_redirects=True) as r:
                    return url, r.status
            except:
                return url, 0

    results = await asyncio.gather(*[check(l) for l in all_links])
    broken  = [(u,s) for u,s in results if s in [0,404,410,500,502,503]]

    for url, status in broken[:10]:
        cprint(f"  [yellow]✗ {status} {url[:80]}[/]")

    if broken:
        findings.append(make_finding(
            module="broken_links",
            title=f"{len(broken)} Kırık Harici Bağlantı",
            severity="low",
            description=f"Kırık harici bağlantılar subdomain takeover veya phishing için kullanılabilir",
            evidence="\n".join(f"{s}: {u}" for u,s in broken[:5]),
            owasp="A05-Security Misconfiguration",
            cwe="CWE-1236",
            remediation="Kırık bağlantıları kaldırın veya güncelleyin",
            tags=["broken_links"]
        ))

    result.raw["broken_links"] = {"checked": len(all_links), "broken": len(broken)}
    if not broken:
        cprint(f"  [green]Kırık bağlantı bulunamadı ({len(all_links)} kontrol edildi)[/]")
    return findings

# ════════════════════════════════════════════════════════════════════════════
# MODÜL 27 – WebSocket Testi
# ════════════════════════════════════════════════════════════════════════════
async def module_websocket(result: ScanResult, cfg: dict, html: str) -> List[Finding]:
    cprint("\n[bold]▶ [27] WebSocket Testi[/]")
    findings = []

    ws_urls = re.findall(r"""(?:new\s+WebSocket|WebSocket\(|io\()\s*\(\s*['"]?(wss?://[^'")\s]+)""", html)
    ws_urls += re.findall(r"""wss?://[^\s'"<>]+""", html)
    ws_urls = list(set(ws_urls))[:5]

    if not ws_urls:
        cprint("  [yellow]WebSocket bağlantısı bulunamadı[/]")
        return findings

    cprint(f"  [cyan]{len(ws_urls)} WebSocket endpoint tespit edildi[/]")

    for ws_url in ws_urls:
        cprint(f"  WebSocket: {ws_url}")
        findings.append(make_finding(
            module="websocket",
            title=f"WebSocket Endpoint Tespit Edildi: {ws_url[:80]}",
            severity="info",
            description=f"WebSocket endpoint bulundu: {ws_url}. Origin/auth kontrolü manuel doğrulanmalı.",
            evidence=ws_url,
            owasp="A01-Broken Access Control",
            cwe="CWE-346",
            remediation="WebSocket handshake sırasında Origin header'ını doğrulayın, auth token zorunlu kılın",
            tags=["websocket"]
        ))

    result.raw["websocket"] = {"endpoints": ws_urls}
    return findings

# ════════════════════════════════════════════════════════════════════════════
# MODÜL 28 – HTTP Response Splitting / Header Injection
# ════════════════════════════════════════════════════════════════════════════
async def module_header_injection(result: ScanResult, cfg: dict, session: HttpSession) -> List[Finding]:
    cprint("\n[bold]▶ [28] Header Injection Testi[/]")
    findings = []

    payloads = [
        "%0d%0aSet-Cookie:injected=true",
        "%0aSet-Cookie:injected=true",
        "\r\nSet-Cookie:injected=true",
        "%0d%0aLocation:https://evil.com",
    ]
    params = ["redirect","url","next","return","location"]
    base   = result.url.rstrip("/")

    for param in params:
        for payload in payloads[:2]:
            try:
                async with session._session.get(f"{base}?{param}={payload}",
                        allow_redirects=False,
                        timeout=aiohttp.ClientTimeout(total=5)) as r:
                    if "injected" in str(r.cookies) or "injected" in str(dict(r.headers)):
                        findings.append(make_finding(
                            module="header_injection",
                            title="HTTP Response Splitting / Header Injection",
                            severity="high",
                            description=f"Parametre '{param}' header injection'a izin veriyor",
                            evidence=f"?{param}={payload}",
                            owasp="A03-Injection",
                            cwe="CWE-113",
                            cvss=CVSS("N","L","N","R","U","L","L","N"),
                            remediation="Tüm girdilerden CR/LF karakterlerini temizleyin",
                            tags=["injection", "header"]
                        ))
                        cprint(f"  [red]⚠ Header injection: ?{param}={payload}[/]")
                        break
            except: pass

    if not findings:
        cprint("  [green]Header injection tespit edilmedi[/]")
    return findings

# ════════════════════════════════════════════════════════════════════════════
# MODÜL 29 – Business Logic Testi
# ════════════════════════════════════════════════════════════════════════════
async def module_business_logic(result: ScanResult, cfg: dict, session: HttpSession, html: str) -> List[Finding]:
    cprint("\n[bold]▶ [29] Business Logic Testi[/]")
    findings = []

    soup  = BeautifulSoup(html, "html.parser")
    forms = soup.find_all("form")

    bl_payloads = {
        "negative_price": ["-1", "-99999", "-0.01"],
        "zero_price":     ["0", "0.00"],
        "overflow":       ["99999999999", "2147483648"],
        "float_bypass":   ["0.0001", "1e-100"],
    }

    price_params = []
    for form in forms:
        for inp in form.find_all("input"):
            name = (inp.get("name") or "").lower()
            if any(kw in name for kw in ["price","amount","qty","quantity","count","total","cost"]):
                price_params.append((form, inp.get("name")))

    for form, param in price_params[:3]:
        action = form.get("action", result.url)
        method = form.get("method", "get").upper()
        url    = urljoin(result.url, action)
        inputs = {i.get("name","x"): "1" for i in form.find_all("input") if i.get("name")}

        for bl_type, payloads in bl_payloads.items():
            for pl in payloads:
                data = dict(inputs)
                data[param] = pl
                try:
                    if method == "POST":
                        async with session._session.post(url, data=data,
                                   timeout=aiohttp.ClientTimeout(total=5)) as r:
                            body = await r.text()
                    else:
                        async with await session.get(url+"?"+urlencode(data)) as r:
                            body = await r.text()
                    # Başarı indikatörleri
                    success_patterns = ["success","added","cart","order","thank","payment","checkout"]
                    if any(p in body.lower() for p in success_patterns) and r.status == 200:
                        findings.append(make_finding(
                            module="business_logic",
                            title=f"Business Logic Açığı – {bl_type.replace('_',' ').title()}: {param}",
                            severity="high",
                            description=f"Parametre '{param}' = '{pl}' ({bl_type}) kabul edildi",
                            evidence=f"POST {url} | {param}={pl} → {r.status}",
                            owasp="A04-Insecure Design",
                            cwe="CWE-840",
                            cvss=CVSS("N","L","L","N","U","H","H","N"),
                            remediation="Sunucu tarafında değer aralığı ve işaretini doğrulayın",
                            tags=["business_logic", "logic_flaw"]
                        ))
                        cprint(f"  [red]⚠ Business Logic: {param}={pl} ({bl_type})[/]")
                        break
                except: pass

    if not findings:
        cprint("  [green]Belirgin business logic açığı tespit edilmedi[/]")
    return findings

# ════════════════════════════════════════════════════════════════════════════
# MODÜL 30 – AI Analiz (OWASP Mapping + Risk Scoring + Aksiyon Planı)
# ════════════════════════════════════════════════════════════════════════════
async def module_ai_analysis(result: ScanResult, cfg: dict) -> None:
    cprint("\n[bold]▶ [30] AI Analiz – OWASP + Risk + Aksiyon Planı[/]")
    cprint("  [dim]🤖 Claude ile derin analiz yapılıyor...[/]")

    api_key = cfg.get("anthropic_api_key") or os.environ.get("ANTHROPIC_API_KEY","")
    if not api_key:
        cprint(
            "  [bold red]✗ Anthropic API anahtarı bulunamadı![/]\n"
            "  [yellow]  Çözüm:[/]\n"
            "  [dim]  1) config.yaml → anthropic_api_key: \"sk-ant-...\"\n"
            "  2) Ortam değişkeni → set ANTHROPIC_API_KEY=sk-ant-...[/]"
        )
        return

    findings_summary = [
        {
            "module": f.module,
            "title": f.title,
            "severity": f.severity,
            "owasp": f.owasp,
            "cwe": f.cwe,
            "cvss": f.cvss_score,
            "cvss_vector": f.cvss_vector,
            "description": f.description[:200],
            "evidence": f.evidence[:100] if f.evidence else "",
        }
        for f in result.findings
    ]

    lang = cfg.get("language","tr")
    if lang == "en":
        prompt = f"""You are a senior penetration tester (OSCP/CEH/CISSP). Analyze these security findings.

## Target
URL: {result.url}
Host: {result.host}
IP: {result.ip}
Technologies: {', '.join(result.technologies[:10])}
Scan Time: {result.scan_time}
Total Findings: {len(result.findings)}

## Findings
{json.dumps(findings_summary, indent=2, ensure_ascii=False)}

## Required Output

### 1. Executive Summary
2-3 sentences for management audience.

### 2. Critical & High Findings Analysis
For each critical/high finding: real-world impact, exploitation scenario, likelihood.

### 3. OWASP Top 10 2021 Mapping
Group all findings by OWASP category. Show counts.

### 4. Risk Matrix
| Finding | Impact | Likelihood | Risk Level | Priority |
Table for each finding.

### 5. Overall Risk Score (0-100)
Formula: weighted average of CVSS scores + bonus for chains. Show calculation.

### 6. Attack Chains
Identify 1-3 potential multi-step attack chains combining multiple findings.

### 7. Action Plan
- 🔴 Immediate (0-48h): Critical items
- 🟡 Short-term (1 week): High items  
- 🟢 Long-term (1 month): Medium/Low items

### 8. Compliance Impact
GDPR, ISO 27001, PCI-DSS implications if applicable.

### 9. Professional Conclusion
2-3 sentences on overall security posture.

Respond in English. Use Markdown. Be technical and precise."""
    else:
        prompt = f"""Sen kıdemli bir penetrasyon testi uzmanısın (OSCP/CEH/CISSP). Aşağıdaki güvenlik bulgularını analiz et.

## Hedef Bilgileri
URL: {result.url}
Host: {result.host}
IP: {result.ip}
Teknolojiler: {', '.join(result.technologies[:10])}
Tarama Tarihi: {result.scan_time}
Toplam Bulgu: {len(result.findings)}

## Bulgular
{json.dumps(findings_summary, indent=2, ensure_ascii=False)}

## Gerekli Çıktı

### 1. Yönetici Özeti
Yönetici kitlesi için 2-3 cümle.

### 2. Kritik ve Yüksek Bulgular Analizi
Her kritik/yüksek bulgu için: gerçek dünya etkisi, sömürü senaryosu, olasılık değerlendirmesi.

### 3. OWASP Top 10 2021 Haritalama
Tüm bulguları OWASP kategorilerine göre grupla ve sayıları göster.

### 4. Risk Matrisi
| Bulgu | Etki | Olasılık | Risk Seviyesi | Öncelik |
Her bulgu için satır oluştur.

### 5. Genel Risk Skoru (0-100)
Hesaplama formülünü göster: CVSS ağırlıklı ortalama + zincir bonusu.

### 6. Saldırı Zincirleri
Birden fazla bulguyu birleştiren 1-3 potansiyel çok adımlı saldırı senaryosu.

### 7. Aksiyon Planı
- 🔴 Acil (0-48 saat): Kritik maddeler
- 🟡 Kısa vadeli (1 hafta): Yüksek maddeler
- 🟢 Uzun vadeli (1 ay): Orta/düşük maddeler

### 8. Uyumluluk Etkisi
KVKK/GDPR, ISO 27001, PCI-DSS açısından değerlendirme.

### 9. Profesyonel Sonuç
Sistemin genel güvenlik duruşuna ilişkin 2-3 cümle.

Türkçe yanıt ver. Markdown kullan. Teknik ve özlü ol."""

    try:
        client = anthropic.Anthropic(api_key=api_key)

        # Streaming AI yanıtı
        ai_text = ""
        if HAS_RICH:
            cprint("\n")
            with console.status("[bold cyan]Claude analiz yapıyor...[/]", spinner="dots"):
                with client.messages.stream(
                    model="claude-opus-4-5-20251101",
                    max_tokens=6000,
                    messages=[{"role":"user","content":prompt}]
                ) as stream:
                    for text in stream.text_stream:
                        ai_text += text
        else:
            message = client.messages.create(
                model="claude-opus-4-5-20251101",
                max_tokens=6000,
                messages=[{"role":"user","content":prompt}]
            )
            ai_text = message.content[0].text

        result.ai_report = ai_text

        if HAS_RICH:
            console.print(Markdown(ai_text))
        else:
            print(ai_text)

        # Risk skorunu çıkar
        m = re.search(r"(?:genel risk skoru|overall risk score)[:\s]+(\d+)", ai_text, re.I)
        if m:
            result.overall_risk = int(m.group(1))
        else:
            # CVSS tabanlı hesaplama
            if result.findings:
                weights = {"critical":4,"high":3,"medium":2,"low":1,"info":0.5}
                total_w = sum(weights.get(f.severity,1) for f in result.findings)
                w_cvss  = sum(f.cvss_score * weights.get(f.severity,1) for f in result.findings if f.cvss_score)
                result.overall_risk = min(100, int((w_cvss / max(total_w,1)) * 10))

    except anthropic.APIError as e:
        cprint(f"  [red]Anthropic API hatası: {e}[/]")
    except Exception as e:
        cprint(f"  [red]AI analiz hatası: {e}[/]")

# ════════════════════════════════════════════════════════════════════════════
# RAPOR – HTML (Profesyonel, interaktif, chart.js)
# ════════════════════════════════════════════════════════════════════════════
def export_html(result: ScanResult, path: str):
    counts   = {s: sum(1 for f in result.findings if f.severity==s)
                for s in ["critical","high","medium","low","info"]}
    sev_clrs = {"critical":"#ff3b3b","high":"#ff8c00","medium":"#ffd700","low":"#4da6ff","info":"#888"}
    risk_clr = "#ff3b3b" if result.overall_risk>=70 else "#ff8c00" if result.overall_risk>=40 else "#00cc88"

    findings_html = ""
    for i, f in enumerate(sorted(result.findings, key=lambda x: SEVERITY_ORDER.get(x.severity,9))):
        clr = sev_clrs.get(f.severity, "#888")
        findings_html += f"""
        <div class="finding" data-severity="{f.severity}" data-module="{f.module}">
          <div class="finding-header" onclick="toggleFinding({i})">
            <span class="badge" style="background:{clr}">{f.severity.upper()}</span>
            <span class="finding-title">{f.title}</span>
            <span class="finding-meta">{f.module}</span>
            {f'<span class="cvss-badge">CVSS {f.cvss_score:.1f}</span>' if f.cvss_score else ''}
            <span class="toggle-icon" id="ti-{i}">▼</span>
          </div>
          <div class="finding-body" id="fb-{i}" style="display:none">
            <p>{f.description}</p>
            {f'<div class="evidence"><strong>Kanıt:</strong><br><code>{f.evidence[:300]}</code></div>' if f.evidence else ''}
            {f'<div class="owasp-tag">{f.owasp}</div>' if f.owasp else ''}
            {f'<div class="cwe-tag">{f.cwe}</div>' if f.cwe else ''}
            {f'<div class="cvss-vector"><code>{f.cvss_vector}</code></div>' if f.cvss_vector else ''}
            {f'<div class="remediation"><span>🔧</span> {f.remediation}</div>' if f.remediation else ''}
            {('<div class="refs">' + ''.join(f'<a href="{r}" target="_blank">{r}</a>' for r in f.references) + '</div>') if f.references else ''}
          </div>
        </div>"""

    techs_badges = "".join(f'<span class="tech-badge">{t}</span>' for t in result.technologies[:15])
    ai_html = ""
    if result.ai_report:
        import re as _re
        # Markdown → basit HTML
        ai_md = result.ai_report
        ai_md = _re.sub(r'^### (.+)$', r'<h3>\1</h3>', ai_md, flags=re.M)
        ai_md = _re.sub(r'^## (.+)$',  r'<h2>\1</h2>', ai_md, flags=re.M)
        ai_md = _re.sub(r'^# (.+)$',   r'<h1>\1</h1>', ai_md, flags=re.M)
        ai_md = _re.sub(r'\*\*(.+?)\*\*', r'<strong>\1</strong>', ai_md)
        ai_md = _re.sub(r'\*(.+?)\*', r'<em>\1</em>', ai_md)
        ai_md = ai_md.replace("\n","<br>")
        ai_html = ai_md

    raw_json = json.dumps(result.raw, indent=2, ensure_ascii=False, default=str)

    html = f"""<!DOCTYPE html>
<html lang="tr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>WebSecAnalyzer v4.0 – {result.url}</title>
<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.0/chart.umd.min.js"></script>
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
:root{{
  --bg:#0a0e17;--surface:#111827;--surface2:#1a2235;
  --border:#1f2d45;--text:#e2e8f0;--text-dim:#64748b;
  --accent:#3b82f6;--accent2:#06b6d4;
  --crit:#ff3b3b;--high:#ff8c00;--med:#ffd700;--low:#4da6ff;--info:#888;
  --green:#22c55e;--radius:8px;
}}
body{{font-family:'Inter','Segoe UI',system-ui,sans-serif;background:var(--bg);color:var(--text);line-height:1.6;font-size:14px}}
a{{color:var(--accent);text-decoration:none}}
a:hover{{text-decoration:underline}}
.header{{
  background:linear-gradient(135deg,var(--surface) 0%,#0d1f3c 100%);
  border-bottom:1px solid var(--border);padding:28px 40px;
  display:flex;align-items:center;justify-content:space-between;
}}
.header-left h1{{font-size:20px;font-weight:700;color:var(--accent2);letter-spacing:-0.5px}}
.header-left .subtitle{{color:var(--text-dim);font-size:13px;margin-top:4px}}
.risk-pill{{
  background:var(--surface2);border:2px solid {risk_clr};border-radius:50px;
  padding:10px 24px;text-align:center;
}}
.risk-pill .num{{font-size:36px;font-weight:800;color:{risk_clr};line-height:1}}
.risk-pill .lbl{{font-size:11px;color:var(--text-dim);text-transform:uppercase;letter-spacing:1px}}
.container{{max-width:1300px;margin:0 auto;padding:28px 40px}}
.stats-row{{display:grid;grid-template-columns:repeat(5,1fr);gap:12px;margin-bottom:28px}}
.stat-card{{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:16px;text-align:center}}
.stat-card .num{{font-size:32px;font-weight:700;line-height:1}}
.stat-card .lbl{{font-size:11px;color:var(--text-dim);text-transform:uppercase;letter-spacing:.5px;margin-top:4px}}
.charts-row{{display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:28px}}
.chart-card{{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:20px}}
.chart-card h3{{font-size:13px;font-weight:600;color:var(--text-dim);text-transform:uppercase;letter-spacing:.5px;margin-bottom:16px}}
.section{{margin-bottom:28px}}
.section-header{{display:flex;align-items:center;justify-content:space-between;margin-bottom:16px}}
.section-header h2{{font-size:16px;font-weight:600;color:var(--accent2)}}
.controls{{display:flex;gap:8px;flex-wrap:wrap}}
.filter-btn{{padding:5px 14px;background:var(--surface2);border:1px solid var(--border);border-radius:20px;cursor:pointer;font-size:12px;color:var(--text-dim);transition:all .2s}}
.filter-btn:hover,.filter-btn.active{{background:var(--accent);border-color:var(--accent);color:#fff}}
input.search{{padding:6px 14px;background:var(--surface2);border:1px solid var(--border);border-radius:20px;color:var(--text);font-size:13px;width:220px;outline:none}}
input.search:focus{{border-color:var(--accent)}}
.finding{{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);margin-bottom:8px;overflow:hidden;transition:border-color .2s}}
.finding:hover{{border-color:var(--accent)}}
.finding-header{{display:flex;align-items:center;gap:10px;padding:12px 16px;cursor:pointer;user-select:none}}
.finding-title{{flex:1;font-weight:500}}
.finding-meta{{font-size:11px;color:var(--text-dim);background:var(--surface2);padding:2px 8px;border-radius:4px}}
.badge{{padding:3px 10px;border-radius:20px;font-size:10px;font-weight:700;color:#000;text-transform:uppercase;letter-spacing:.3px}}
.cvss-badge{{font-size:11px;font-weight:600;color:var(--high)}}
.toggle-icon{{color:var(--text-dim);font-size:11px;transition:transform .2s}}
.finding-body{{padding:16px;border-top:1px solid var(--border);font-size:13px}}
.finding-body p{{margin-bottom:10px;color:var(--text)}}
.evidence{{background:var(--surface2);border-left:3px solid var(--accent);padding:10px 14px;border-radius:0 4px 4px 0;margin:10px 0;font-size:12px}}
.evidence code{{font-family:'JetBrains Mono','Fira Code',monospace;word-break:break-all;color:#94a3b8}}
.owasp-tag,.cwe-tag{{display:inline-block;background:rgba(59,130,246,.15);border:1px solid rgba(59,130,246,.3);color:#93c5fd;padding:2px 10px;border-radius:4px;font-size:11px;margin:2px}}
.cvss-vector{{font-family:monospace;font-size:11px;color:var(--text-dim);margin-top:6px}}
.remediation{{background:rgba(34,197,94,.1);border:1px solid rgba(34,197,94,.2);border-radius:4px;padding:10px 14px;margin-top:10px;color:#86efac;font-size:12px}}
.refs a{{display:block;margin-top:4px;font-size:11px}}
.tech-badge{{display:inline-block;background:var(--surface2);border:1px solid var(--border);border-radius:4px;padding:3px 10px;font-size:12px;margin:2px;color:var(--text-dim)}}
.ai-report{{background:var(--surface);border:1px solid var(--border);border-left:3px solid var(--accent);border-radius:var(--radius);padding:28px;line-height:1.8;font-size:13px}}
.ai-report h1,.ai-report h2,.ai-report h3{{color:var(--accent2);margin:16px 0 8px}}
.ai-report table{{width:100%;border-collapse:collapse;margin:12px 0;font-size:12px}}
.ai-report th{{background:var(--surface2);padding:8px;text-align:left;border:1px solid var(--border)}}
.ai-report td{{padding:6px 8px;border:1px solid var(--border)}}
.ai-report tr:nth-child(even){{background:var(--surface2)}}
pre{{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:16px;overflow-x:auto;font-size:11px;font-family:monospace}}
.scan-meta{{display:flex;flex-wrap:wrap;gap:16px;background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:16px;margin-bottom:28px}}
.meta-item{{font-size:12px}}.meta-item .k{{color:var(--text-dim);margin-right:6px}}
footer{{text-align:center;padding:24px;color:var(--text-dim);font-size:12px;border-top:1px solid var(--border);margin-top:32px}}
.no-findings{{text-align:center;padding:40px;color:var(--text-dim)}}
@media(max-width:768px){{.stats-row{{grid-template-columns:repeat(3,1fr)}}.charts-row{{grid-template-columns:1fr}}.header{{flex-direction:column;gap:16px}}}}
</style>
</head>
<body>
<div class="header">
  <div class="header-left">
    <h1>🔒 WebSecAnalyzer v4.0</h1>
    <div class="subtitle">Hedef: <strong>{result.url}</strong> &nbsp;|&nbsp; {result.scan_time} &nbsp;|&nbsp; Süre: {result.scan_duration:.1f}s</div>
  </div>
  <div class="risk-pill">
    <div class="num">{result.overall_risk}</div>
    <div class="lbl">Risk Skoru</div>
  </div>
</div>

<div class="container">

  <div class="scan-meta">
    <div class="meta-item"><span class="k">Host:</span>{result.host}</div>
    <div class="meta-item"><span class="k">IP:</span>{result.ip}</div>
    <div class="meta-item"><span class="k">Toplam Bulgu:</span>{len(result.findings)}</div>
    <div class="meta-item"><span class="k">Teknolojiler:</span>{', '.join(result.technologies[:8]) or 'Tespit edilemedi'}</div>
  </div>

  <div class="stats-row">
    <div class="stat-card"><div class="num" style="color:var(--crit)">{counts['critical']}</div><div class="lbl">Critical</div></div>
    <div class="stat-card"><div class="num" style="color:var(--high)">{counts['high']}</div><div class="lbl">High</div></div>
    <div class="stat-card"><div class="num" style="color:var(--med)">{counts['medium']}</div><div class="lbl">Medium</div></div>
    <div class="stat-card"><div class="num" style="color:var(--low)">{counts['low']}</div><div class="lbl">Low</div></div>
    <div class="stat-card"><div class="num" style="color:var(--info)">{counts['info']}</div><div class="lbl">Info</div></div>
  </div>

  <div class="charts-row">
    <div class="chart-card">
      <h3>Bulgu Dağılımı</h3>
      <canvas id="donutChart" height="200"></canvas>
    </div>
    <div class="chart-card">
      <h3>Modül Başına Bulgular</h3>
      <canvas id="barChart" height="200"></canvas>
    </div>
  </div>

  {'<div style="margin-bottom:16px">' + techs_badges + '</div>' if techs_badges else ''}

  <div class="section">
    <div class="section-header">
      <h2>Bulgular ({len(result.findings)})</h2>
      <div class="controls">
        <input class="search" type="text" placeholder="Ara..." oninput="filterFindings()">
        <button class="filter-btn active" onclick="filterSev('all',this)">Tümü</button>
        <button class="filter-btn" onclick="filterSev('critical',this)">Critical</button>
        <button class="filter-btn" onclick="filterSev('high',this)">High</button>
        <button class="filter-btn" onclick="filterSev('medium',this)">Medium</button>
        <button class="filter-btn" onclick="filterSev('low',this)">Low</button>
      </div>
    </div>
    <div id="findings-container">
      {findings_html if findings_html else '<div class="no-findings">✅ Bulgu bulunamadı</div>'}
    </div>
  </div>

  {'<div class="section"><h2 style="color:var(--accent2);margin-bottom:16px">🤖 AI Analiz Raporu</h2><div class="ai-report">' + ai_html + '</div></div>' if ai_html else ''}

  <div class="section">
    <h2 style="color:var(--accent2);margin-bottom:16px">Ham Veri (JSON)</h2>
    <pre id="rawjson">{raw_json[:12000]}{'\\n...(kesildi, tam veri JSON dosyasında)' if len(raw_json)>12000 else ''}</pre>
  </div>

</div>
<footer>WebSecAnalyzer v4.0 &bull; Anthropic Claude &bull; {result.scan_time}</footer>

<script>
// Charts
const donut = new Chart(document.getElementById('donutChart'), {{
  type:'doughnut',
  data:{{
    labels:['Critical','High','Medium','Low','Info'],
    datasets:[{{
      data:[{counts['critical']},{counts['high']},{counts['medium']},{counts['low']},{counts['info']}],
      backgroundColor:['#ff3b3b','#ff8c00','#ffd700','#4da6ff','#888'],
      borderWidth:2, borderColor:'#111827'
    }}]
  }},
  options:{{responsive:true,plugins:{{legend:{{labels:{{color:'#e2e8f0',font:{{size:11}}}}}}}}}}
}});

// Bar chart – modül bazlı
const modCounts = {{}};
document.querySelectorAll('.finding').forEach(f=>{{
  const m = f.dataset.module;
  modCounts[m] = (modCounts[m]||0)+1;
}});
const sortedMods = Object.entries(modCounts).sort((a,b)=>b[1]-a[1]).slice(0,10);
new Chart(document.getElementById('barChart'), {{
  type:'bar',
  data:{{
    labels: sortedMods.map(e=>e[0]),
    datasets:[{{
      label:'Bulgu Sayısı',
      data: sortedMods.map(e=>e[1]),
      backgroundColor:'#3b82f6',borderRadius:4
    }}]
  }},
  options:{{
    responsive:true,indexAxis:'y',
    plugins:{{legend:{{display:false}}}},
    scales:{{
      x:{{ticks:{{color:'#64748b'}},grid:{{color:'#1f2d45'}}}},
      y:{{ticks:{{color:'#e2e8f0',font:{{size:11}}}},grid:{{display:false}}}}
    }}
  }}
}});

// Finding toggle
function toggleFinding(i){{
  const body = document.getElementById('fb-'+i);
  const icon = document.getElementById('ti-'+i);
  const vis  = body.style.display!=='none';
  body.style.display = vis?'none':'block';
  icon.style.transform = vis?'':'rotate(180deg)';
}}

// Filters
let activeSev = 'all';
function filterSev(sev, btn){{
  activeSev = sev;
  document.querySelectorAll('.filter-btn').forEach(b=>b.classList.remove('active'));
  if(btn) btn.classList.add('active');
  applyFilters();
}}
function filterFindings(){{ applyFilters(); }}
function applyFilters(){{
  const q = document.querySelector('.search').value.toLowerCase();
  document.querySelectorAll('.finding').forEach(f=>{{
    const sevOk  = activeSev==='all' || f.dataset.severity===activeSev;
    const textOk = !q || f.innerText.toLowerCase().includes(q);
    f.style.display = (sevOk && textOk)?'':'none';
  }});
}}
</script>
</body>
</html>"""

    with open(path,"w",encoding="utf-8") as f:
        f.write(html)
    cprint(f"  [green]✔ HTML rapor: {path}[/]")

# ════════════════════════════════════════════════════════════════════════════
# RAPOR – JSON
# ════════════════════════════════════════════════════════════════════════════
def export_json(result: ScanResult, path: str):
    data = {
        "meta": {
            "tool": "WebSecAnalyzer v4.0",
            "url": result.url,
            "host": result.host,
            "ip": result.ip,
            "scan_time": result.scan_time,
            "scan_duration_seconds": result.scan_duration,
            "technologies": result.technologies,
        },
        "summary": {
            "overall_risk": result.overall_risk,
            "total_findings": len(result.findings),
            "by_severity": {s: sum(1 for f in result.findings if f.severity==s)
                            for s in ["critical","high","medium","low","info"]},
            "by_module": {},
        },
        "findings": [asdict(f) for f in result.findings],
        "ai_report": result.ai_report,
        "raw": result.raw,
    }
    for f in result.findings:
        data["summary"]["by_module"][f.module] = data["summary"]["by_module"].get(f.module,0)+1

    with open(path,"w",encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False, default=str)
    cprint(f"  [green]✔ JSON çıktı: {path}[/]")

# ════════════════════════════════════════════════════════════════════════════
# RAPOR – Markdown
# ════════════════════════════════════════════════════════════════════════════
def export_markdown(result: ScanResult, path: str):
    counts = {s: sum(1 for f in result.findings if f.severity==s)
              for s in ["critical","high","medium","low","info"]}
    lines  = [
        f"# 🔒 WebSecAnalyzer v4.0 – Güvenlik Raporu",
        f"> **Hedef:** {result.url}  ",
        f"> **Tarih:** {result.scan_time}  ",
        f"> **Risk Skoru:** {result.overall_risk}/100  ",
        f"> **Süre:** {result.scan_duration:.1f}s",
        "",
        "## Özet",
        "",
        "| Seviye | Sayı |",
        "|--------|:----:|",
    ]
    for s in ["critical","high","medium","low","info"]:
        lines.append(f"| {SEVERITY_EMOJI[s]} {s.upper()} | **{counts[s]}** |")

    lines += ["", f"**Toplam:** {len(result.findings)} bulgu  ",
              f"**Teknolojiler:** {', '.join(result.technologies[:10])}", "",
              "---", "", "## Bulgular", ""]

    for f in sorted(result.findings, key=lambda x: SEVERITY_ORDER.get(x.severity,9)):
        emoji = SEVERITY_EMOJI.get(f.severity,"⚪")
        lines += [
            f"### {emoji} [{f.severity.upper()}] {f.title}",
            "",
            f"| Alan | Değer |",
            f"|------|-------|",
            f"| Modül | `{f.module}` |",
            f"| OWASP | {f.owasp} |" if f.owasp else "",
            f"| CWE | {f.cwe} |" if f.cwe else "",
            f"| CVSS | {f.cvss_score:.1f} – `{f.cvss_vector}` |" if f.cvss_score else "",
            "",
            f"**Açıklama:** {f.description}",
            "",
            f"**Kanıt:** `{f.evidence[:200]}`" if f.evidence else "",
            "",
            f"**Öneri:** {f.remediation}" if f.remediation else "",
            "",
        ]
        if f.references:
            lines += ["**Kaynaklar:**"] + [f"- {r}" for r in f.references] + [""]
        lines.append("---")
        lines.append("")

    if result.ai_report:
        lines += ["", "## 🤖 AI Analiz Raporu", "", result.ai_report]

    content = "\n".join(l for l in lines if l is not None)
    with open(path,"w",encoding="utf-8") as f:
        f.write(content)
    cprint(f"  [green]✔ Markdown rapor: {path}[/]")

# ════════════════════════════════════════════════════════════════════════════
# ÖZET TABLO (Rich)
# ════════════════════════════════════════════════════════════════════════════
def print_summary_table(result: ScanResult):
    if not HAS_RICH:
        return

    counts = {s: sum(1 for f in result.findings if f.severity==s)
              for s in ["critical","high","medium","low","info"]}

    # Stats paneli
    stats = Table.grid(expand=True)
    stats.add_column()
    for sev in ["critical","high","medium","low","info"]:
        stats.add_column(justify="center")

    stats.add_row(
        "",
        f"[bold red]{counts['critical']} CRITICAL[/]",
        f"[red]{counts['high']} HIGH[/]",
        f"[yellow]{counts['medium']} MEDIUM[/]",
        f"[cyan]{counts['low']} LOW[/]",
        f"[dim]{counts['info']} INFO[/]",
    )
    console.print(Panel(stats, title="[bold]Bulgu Özeti[/]", border_style="cyan"))

    # Detay tablosu
    table = Table(
        title=f"[bold cyan]Bulgular ({len(result.findings)} adet)[/]",
        box=box.SIMPLE_HEAD, border_style="dim",
        show_lines=False, expand=True
    )
    table.add_column("SEV", width=8, style="bold")
    table.add_column("BAŞLIK", min_width=40)
    table.add_column("MODÜL", width=16, style="dim")
    table.add_column("OWASP", width=28, style="dim")
    table.add_column("CVSS", width=6, justify="right")
    table.add_column("CWE", width=10, style="dim")

    for f in sorted(result.findings, key=lambda x: SEVERITY_ORDER.get(x.severity,9)):
        sty = SEVERITY_STYLE.get(f.severity,"")
        table.add_row(
            f.severity.upper(),
            f.title[:65] + ("…" if len(f.title)>65 else ""),
            f.module[:15],
            f.owasp[:27] if f.owasp else "–",
            f"{f.cvss_score:.1f}" if f.cvss_score else "–",
            f.cwe[:9] if f.cwe else "–",
            style=sty
        )
    console.print(table)

# ════════════════════════════════════════════════════════════════════════════
# ANA AKIŞ – Paralel Modül Gruplaması
# ════════════════════════════════════════════════════════════════════════════
async def run(url: str, output_html: str, output_json: str, output_md: str,
              config_path: str, skip: list, cookies: dict, extra_headers: dict,
              plugin_dir: str, verbose: bool, language: str):
    global VERBOSE
    VERBOSE = verbose

    banner()
    cfg  = load_config(config_path)
    if language:
        cfg["language"] = language

    parsed = urlparse(url)
    host   = parsed.hostname

    result = ScanResult(
        url=url, host=host,
        scan_time=datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    )
    start_time = time.time()

    # DNS çözümleme
    result.ip = await dns_lookup(host) or ""
    cprint(f"\n[cyan]Hedef: {url}[/]")
    cprint(f"[dim]IP: {result.ip}[/]")

    # İlk sayfa verisi
    try:
        async with HttpSession(cfg, cookies, extra_headers) as session:
            async with await session.get(url) as r:
                page_headers = dict(r.headers)
                html         = await r.text()
    except Exception as e:
        cprint(f"[bold red]Hedef erişilemiyor: {e}[/]")
        sys.exit(1)

    all_findings = []

    async with HttpSession(cfg, cookies, extra_headers) as session:

        # ── Grup 1: Network & Passive (paralel) ──────────────────────────
        section("Grup 1: Network & Passive Tarama")
        group1_tasks = []
        if "1"  not in skip: group1_tasks.append(module_port_scan(result, cfg))
        if "2"  not in skip: group1_tasks.append(module_security_headers(result, cfg, session))
        if "3"  not in skip: group1_tasks.append(module_fingerprint(result, cfg, page_headers, html))
        if "4"  not in skip: group1_tasks.append(module_subdomain_scan(result, cfg))
        if "7"  not in skip: group1_tasks.append(module_ssl_analysis(result, cfg))
        if "22" not in skip: group1_tasks.append(module_dns_analysis(result, cfg))

        g1_results = await asyncio.gather(*group1_tasks)
        for r in g1_results:
            if isinstance(r, list):
                all_findings.extend(r)

        # ── Grup 2: Active Web Tests (paralel) ───────────────────────────
        section("Grup 2: Aktif Web Testleri")
        group2_tasks = []
        if "5"  not in skip: group2_tasks.append(module_subdomain_takeover(result, cfg))
        if "6"  not in skip: group2_tasks.append(module_directory_brute(result, cfg, session))
        if "8"  not in skip: group2_tasks.append(module_cookie_analysis(result, cfg, session))
        if "13" not in skip: group2_tasks.append(module_jwt_analysis(result, cfg, session))
        if "14" not in skip: group2_tasks.append(module_cors_csrf(result, cfg, session))
        if "15" not in skip: group2_tasks.append(module_sensitive_files(result, cfg, session))
        if "16" not in skip: group2_tasks.append(module_http_methods(result, cfg, session))
        if "17" not in skip: group2_tasks.append(module_clickjacking(result, cfg, session))
        if "18" not in skip: group2_tasks.append(module_rate_waf(result, cfg, session))
        if "19" not in skip: group2_tasks.append(module_api_enum(result, cfg, session, html))
        if "23" not in skip: group2_tasks.append(module_info_disclosure(result, cfg, session))
        if "24" not in skip: group2_tasks.append(module_open_redirect(result, cfg, session))
        if "25" not in skip: group2_tasks.append(module_request_smuggling(result, cfg, session))
        if "26" not in skip: group2_tasks.append(module_broken_links(result, cfg, session, html))
        if "27" not in skip: group2_tasks.append(module_websocket(result, cfg, html))
        if "28" not in skip: group2_tasks.append(module_header_injection(result, cfg, session))

        g2_results = await asyncio.gather(*group2_tasks)
        for r in g2_results:
            if isinstance(r, list):
                all_findings.extend(r)

        # ── Grup 3: Injection Tests (sıralı – form reuse) ─────────────────
        section("Grup 3: Injection Testleri")
        if "9"  not in skip: all_findings += await module_sqli_test(result, cfg, session, html)
        if "10" not in skip: all_findings += await module_xss_test(result, cfg, session, html)
        if "11" not in skip: all_findings += await module_path_traversal(result, cfg, session)
        if "12" not in skip: all_findings += await module_ssrf(result, cfg, session)
        if "29" not in skip: all_findings += await module_business_logic(result, cfg, session, html)

        # ── Grup 4: Intelligence ──────────────────────────────────────────
        section("Grup 4: Intelligence & CVE")
        if "20" not in skip: all_findings += await module_osint_harvest(result, cfg, html)
        if "21" not in skip: all_findings += await module_cve_lookup(result, cfg)

        # ── Plugins ───────────────────────────────────────────────────────
        pm = PluginManager(plugin_dir)
        pm.load()
        if pm.plugins:
            section("Eklentiler (Plugins)")
            all_findings += await pm.run_all(result, cfg)

    result.findings = all_findings
    result.scan_duration = time.time() - start_time

    # Özet tablo
    section("Tarama Tamamlandı")
    print_summary_table(result)

    # AI Analiz
    if "30" not in skip:
        await module_ai_analysis(result, cfg)

    # Raporlar
    section("Rapor Dışa Aktarma")
    if output_html: export_html(result, output_html)
    if output_json: export_json(result, output_json)
    if output_md:   export_markdown(result, output_md)

    # Final özet
    risk_style = "bold red" if result.overall_risk>=70 else "bold yellow" if result.overall_risk>=40 else "bold green"
    cprint(f"\n[bold green]✔ Tarama tamamlandı![/]  [dim]Süre: {result.scan_duration:.1f}s[/]")
    cprint(f"[bold]Toplam bulgu: {len(all_findings)}[/]  ·  Risk skoru: [{risk_style}]{result.overall_risk}/100[/]")

# ════════════════════════════════════════════════════════════════════════════
# CLI
# ════════════════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="WebSecAnalyzer v4.0 – Profesyonel Web Güvenlik Analiz Çerçevesi",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""Örnekler:
  python websec_v4.py https://example.com
  python websec_v4.py https://example.com -o rapor.html --json rapor.json --md rapor.md
  python websec_v4.py https://example.com --skip 4 21 22 --no-ai
  python websec_v4.py https://example.com --cookies "session=abc123" --headers "Authorization:Bearer eyJ..."
  python websec_v4.py https://example.com --config custom.yaml --plugins ./my_plugins --lang en
  python websec_v4.py https://example.com --verbose
"""
    )
    parser.add_argument("url",           help="Hedef URL (örn: https://example.com)")
    parser.add_argument("-o","--output", default="rapor.html",  help="HTML rapor (varsayılan: rapor.html)")
    parser.add_argument("--json",        default="rapor.json",  help="JSON rapor (varsayılan: rapor.json)")
    parser.add_argument("--md",          default="rapor.md",    help="Markdown rapor (varsayılan: rapor.md)")
    parser.add_argument("--config",      default="config.yaml", help="Config dosyası")
    parser.add_argument("--plugins",     default="plugins",     help="Plugin dizini")
    parser.add_argument("--skip",        nargs="*", default=[], help="Atlanacak modül no'ları (örn: --skip 4 21 22)")
    parser.add_argument("--cookies",     default="",            help="Cookie (örn: 'session=abc; token=xyz')")
    parser.add_argument("--headers",     default="",            help="Ekstra header (örn: 'Authorization:Bearer token')")
    parser.add_argument("--no-ai",       action="store_true",   help="AI analizini atla")
    parser.add_argument("--verbose","-v",action="store_true",   help="Detaylı çıktı")
    parser.add_argument("--lang",        default="",            choices=["tr","en"], help="Rapor dili (tr/en)")
    args = parser.parse_args()

    if not args.url.startswith("http"):
        args.url = "https://" + args.url

    cookies = {}
    if args.cookies:
        for pair in args.cookies.split(";"):
            pair = pair.strip()
            if "=" in pair:
                k, v = pair.split("=",1)
                cookies[k.strip()] = v.strip()

    extra_headers = {}
    if args.headers:
        for pair in args.headers.split(";"):
            pair = pair.strip()
            if ":" in pair:
                k, v = pair.split(":",1)
                extra_headers[k.strip()] = v.strip()

    skip = list(args.skip)
    if args.no_ai:
        skip.append("30")

    asyncio.run(run(
        url=args.url,
        output_html=args.output,
        output_json=args.json,
        output_md=args.md,
        config_path=args.config,
        skip=skip,
        cookies=cookies,
        extra_headers=extra_headers,
        plugin_dir=args.plugins,
        verbose=args.verbose,
        language=args.lang,
    ))