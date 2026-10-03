#!/usr/bin/env python3
"""
╔═══════════════════════════════════════════════════════════════╗
║      BountyFlow v3 - Recon Profundo + Intelligence           ║
║   Resolve → Enum → Live → DNS → Takeover → Crawl → Correlate  ║
║   → Score → Nuclei   (modo VPN-safe: stagger + bajo paralelo) ║
╚═══════════════════════════════════════════════════════════════╝

Uso:
    python3 bountyflow.py -d example.com
    python3 bountyflow.py -d example.com --skip nuclei
    python3 bountyflow.py -d example.com --only recon,resolve,httpx
    python3 bountyflow.py -d example.com --output ~/pentests
    python3 bountyflow.py -d example.com --focus api
    python3 bountyflow.py -d example.com --focus auth,upload
    python3 bountyflow.py --check

Fases disponibles:
    recon        → Enumeración de subdominios en paralelo (incluye crtsh)
    resolve      → Filtra subdominios que resuelven DNS desde afuera (clave con VPN)
    httpx        → Hosts vivos + tecnologías (JSONL)
    dns          → Resolución A + CNAME (JSON) con dnsx
    takeover     → Verificación de takeover con subzy sobre hosts con CNAME
    social       → OSINT con socialhunter
    crawl        → Crawling katana + gau + waybackurls + uro + normalización
    grep         → Grepping por categorías en paralelo
    gf           → Patrones gf en paralelo
    jsleak       → Secretos en JS vía jsleak (pre-filtrado solo .js)
    jsregex      → Regex propios sobre .js (endpoints, keys, JWT, subdominios)
    intelligence → Correlación + scoring + targets accionables
    nuclei       → Hosts (live.txt) + URLs scored (high_value)

Modos de foco (--focus):
    api, auth, upload, admin, secrets, sqli, ssrf

NOTA VPN-safe:
    Todas las fases que pegan contra la red corren con paralelismo bajo
    y un delay entre el lanzamiento de cada tool (CONFIG["vpn_safe"]).
    Pensado para correr tranquilo con VPN sin colgar el escaneo.

NOTA crtsh.py:
    Editá CONFIG["recon_tools"]["crtsh"]["script_path"] con la ruta real
    a tu script, y "output_glob" con el patrón de archivo que genera en
    SU PROPIA carpeta (el script no respeta -o). Si no lo configurás,
    el pipeline simplemente lo omite sin romper nada más.
"""

import subprocess
import sys
import re
import argparse
import shutil
import time
import json
import urllib.request
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict, List, Set, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse


# ═══════════════════════════════════════════════════════════════
#   CONFIGURACIÓN CENTRAL — modifica aquí flags y herramientas
# ═══════════════════════════════════════════════════════════════

CONFIG = {

    # ── Modo VPN-safe: aplica a TODAS las fases que lanzan tools ──
    # en paralelo contra la red (recon, crawlers). No satura la
    # VPN con una ráfaga de conexiones simultáneas.
    "vpn_safe": {
        "max_parallel_tools": 2,   # tools de red corriendo en simultáneo
        "stagger_delay": 2.0,      # segundos entre el lanzamiento de cada tool
    },

    # ── Herramientas de enumeración de subdominios ──────────────
    "recon_tools": {
        "subfinder": {
            "enabled": True,
            "cmd": ["subfinder", "-d", "{domain}", "-o", "{output}",
                    "-silent", "-recursive", "-all"],
            "stdout_mode": False,
        },
        "assetfinder": {
            "enabled": True,
            "cmd": ["assetfinder", "--subs-only", "{domain}"],
            "stdout_mode": True,
        },
        "sublist3r": {
            "enabled": True,
            "cmd": ["sublist3r", "-d", "{domain}", "-o", "{output}", "-v"],
            "stdout_mode": False,
        },
        "shodanx": {
            "enabled": True,
            "cmd": ["shodanx", "subdomain", "-d", "{domain}", "-o", "{output}", "-silent"],
            "stdout_mode": False,
        },
        "findomain": {
            "enabled": True,
            "cmd": ["findomain", "-t", "{domain}", "-u", "{output}", "--quiet"],
            "stdout_mode": False,
        },
        # ── crtsh.py: script propio en Python ───────────────────
        # No es un binario en PATH, así que se maneja distinto: corre
        # con cwd = carpeta del script (porque ahí tira su output) y
        # después se busca el archivo más reciente que matchee
        # "output_glob" para copiarlo al pipeline.
        "crtsh": {
            "enabled": True,  # poné False si todavía no configuraste la ruta
            "script_path": "/ruta/completa/a/crtsh.py",   # <-- EDITÁ ESTO
            "cmd": ["python3", "{script_path}", "{domain}"],
            # Patrón para encontrar el archivo que el script deja en SU
            # PROPIA carpeta. Ajustalo según cómo nombre el output tu script.
            # Ejemplos: "{domain}.txt", "crt.sh_{domain}*.txt", "*{domain}*"
            "output_glob": "*{domain}*",
            "timeout": 600,
        },
    },

    # ── dnsx: filtro de resolución externa (FASE RESOLVE) ───────
    # Corre ANTES de httpx. Filtra subdominios internos / que no
    # resuelven desde afuera (típico problema al laburar con VPN,
    # ya que algunos subs salen de fuentes que listan hosts internos).
    "dnsx_resolve": {
        "enabled": True,
        "cmd": ["dnsx", "-l", "{input}", "-o", "{output}",
                "-a", "-silent", "-threads", "15", "-retry", "2"],
    },

    # ── httpx básico: solo detección de vivos ───────────────────
    "httpx_live": {
        "enabled": True,
        "cmd": [
            "httpx",
            "-l", "{input}",
            "-o", "{output}",
            "-fr",              # seguir redirecciones
            "-silent",
            "-threads", "15",   # conservador: VPN-safe
            "-timeout", "15",
            "-retries", "1",
        ],
    },

    # ── httpx completo: tech, IPs, CDN, JSONL ───────────────────
    "httpx_tech": {
        "enabled": True,
        "cmd": [
            "httpx",
            "-l", "{input}",
            "-o", "{output}",
            "-fr",
            "-silent",
            "-threads", "15",
            "-timeout", "15",
            "-retries", "1",
            "-tech-detect",
            "-ip",
            "-title",
            "-status-code",
            "-content-length",
            "-web-server",
            "-cdn",
            "-asn",
            "-json",            # JSONL → consumido por phase_intelligence
        ],
    },

    # ── dnsx: A + CNAME en JSON (para DNS + takeover) ───────────
    # Se usa JSON para poder correlacionar host→CNAME de forma
    # robusta (en vez de parsear texto plano), y alimenta tanto
    # el registro legible como cname_hosts.txt para takeover.
    "dnsx": {
        "enabled": True,
        "cmd": [
            "dnsx",
            "-l", "{input}",
            "-o", "{output}",
            "-a", "-cname",
            "-resp",
            "-json",
            "-silent",
            "-threads", "20",
            "-retry", "2",
        ],
    },

    # ── subzy: takeover inteligente sobre hosts con CNAME ───────
    "subzy": {
        "enabled": True,
        "cmd": ["subzy", "run", "--targets", "{input}",
                "--concurrency", "5", "--hide_fails"],
        "stdout_mode": True,
        "timeout": 1800,
    },

    # ── socialhunter ─────────────────────────────────────────────
    "socialhunter": {
        "enabled": True,
        "cmd": ["socialhunter", "-f", "{input}", "-w", "5"],
        "stdout_mode": True,
    },

    # ── katana: conservador para entornos con rate limiting ──────
    "katana": {
        "enabled": True,
        "cmd": [
            "katana",
            "-list", "{input}",
            "-o", "{output}",
            "-d", "4",
            "-jc",
            "-kf", "all",
            "-aff",
            "-ef", "png,jpg,jpeg,gif,css,woff,woff2,ttf,svg,ico,mp4,mp3",
            "-c", "8",           # concurrencia baja: VPN-safe
            "-p", "4",
            "-timeout", "10",
            "-silent",
            "-xhr",
            "-hl",
        ],
        "timeout": 7200,
    },

    # ── gau: URLs históricas (Wayback, Common Crawl, OTX, etc.) ──
    "gau": {
        "enabled": True,
        "cmd": ["gau", "--threads", "2", "--subs", "{domain}"],
        "stdout_mode": True,
        "timeout": 1800,
    },

    # ── waybackurls: URLs históricas vía Wayback Machine ─────────
    "waybackurls": {
        "enabled": True,
        "cmd": ["waybackurls", "{domain}"],
        "stdout_mode": True,
        "timeout": 1800,
    },

    # ── uro: deduplicación básica de URLs ────────────────────────
    "uro": {
        "enabled": True,
        "cmd": ["uro", "-i", "{input}", "-o", "{output}"],
    },

    # ── gf patterns ─────────────────────────────────────────────
    "gf_patterns": [
        "xss", "sqli", "ssrf", "ssti", "lfi", "rce", "idor",
        "redirect", "debug_logic", "interestingparams", "interestingEXT",
        "cors", "aws-keys", "s3-buckets", "php-errors",
        "upload-fields", "img-traversal", "base64",
    ],

    # ── jsleak ───────────────────────────────────────────────────
    "jsleak": {
        "enabled": True,
        "cmd": ["jsleak", "-s", "-v", "-k", "-l", "{input}"],
        "stdout_mode": True,
    },

    # ── js_regex: regex propios sobre el contenido de los .js ────
    # Fase propia, liviana, con descarga de a poco (VPN-safe) y
    # correlación directa con intelligence si encuentra secretos.
    "js_regex": {
        "enabled": True,
        "max_workers": 3,       # fetchs simultáneos de .js
        "stagger_delay": 0.5,   # segundos entre el lanzamiento de cada fetch
        "timeout": 10,          # timeout por archivo .js
        "max_bytes": 3 * 1024 * 1024,  # tope de lectura por archivo (3MB)
    },

    # ── nuclei: split en host templates y URL templates ──────────
    "nuclei": {
        "enabled": True,
        "host_templates": [
            "takeovers/",
            "misconfiguration/",
            "default-logins/",
            "dns/",
            "network/",
            "technologies/",
        ],
        "url_templates": [
            "cves/",
            "vulnerabilities/",
            "exposures/",
        ],
        "score_threshold": 5,
        "cmd": [
            "nuclei",
            "-l", "{input}",
            "-o", "{output}",
            "-t", "{templates}",
            "-severity", "low,medium,high,critical",
            "-c", "8",           # concurrencia baja: VPN-safe
            "-rl", "20",         # rate limit conservador
            "-etags", "dos,fuzz",
            "-silent",
            "-stats",
            "-timeout", "10",
        ],
    },

    # ── Grep keywords por categoría ──────────────────────────────
    "grep_keywords": {
        "admin":      r"admin",
        "login":      r"login|signin|sign-in|log-in",
        "auth":       r"auth|oauth|sso|saml|jwt|bearer|token",
        "dashboard":  r"dashboard|panel|portal|console",
        "api":        r"[/\?&]api[/\?&]?|/v[0-9]+/|/rest/|/graphql",
        "upload":     r"upload|file|attachment|media|import",
        "backup":     r"backup|\.bak|\.old|\.zip|\.tar\.gz|dump|export",
        "config":     r"config|configuration|settings|setup|install",
        "secret":     r"secret|apikey|api_key|private_key|access_key",
        "debug":      r"debug|test|dev|staging|qa|uat|sandbox",
        "password":   r"password|passwd|pwd|pass=|credential",
        "redirect":   r"redirect|url=|next=|return=|goto=|target=|dest=",
        "graphql":    r"graphql|gql|__schema|introspect",
        "swagger":    r"swagger|openapi|api-docs|api\.json|api\.yaml",
        "jenkins":    r"jenkins|hudson|build|pipeline",
        "git":        r"\.git|\.gitignore|\.env|\.htaccess|\.DS_Store",
        "php":        r"\.php(\?|$|/)",
        "sql":        r"\.sql|db=|database=|query=|select=",
        "email":      r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}",
        "aws":        r"s3\.amazonaws|cloudfront|\.s3\.|aws\.amazon",
        "firebase":   r"firebase|firebaseio\.com",
        "wordpress":  r"wp-admin|wp-content|wp-login|xmlrpc\.php",
        "java":       r"\.jsp|\.do|\.action|struts|spring",
        "dotnet":     r"\.aspx|\.ashx|\.asmx|__viewstate",
        "laravel":    r"laravel|artisan|\.env\.example",
        "spring":     r"actuator|spring|/health|/info|/metrics|/beans",
        "ssrf":       r"url=|path=|host=|endpoint=|proxy=|fetch=|request=",
    },

    # ── Focus map: filtrado y boost de scoring por tipo de bug ───
    "focus_map": {
        "api": {
            "grep": ["api", "graphql", "swagger", "redirect", "ssrf"],
            "gf":   ["ssrf", "idor", "redirect", "interestingparams", "cors"],
            "score_boost": 2,
        },
        "auth": {
            "grep": ["auth", "login", "password", "token", "redirect"],
            "gf":   ["xss", "sqli", "redirect", "cors", "idor"],
            "score_boost": 3,
        },
        "upload": {
            "grep": ["upload", "file", "import"],
            "gf":   ["upload-fields", "img-traversal"],
            "score_boost": 3,
        },
        "admin": {
            "grep": ["admin", "dashboard", "panel", "debug", "jenkins"],
            "gf":   ["debug_logic", "interestingEXT", "interestingparams"],
            "score_boost": 2,
        },
        "secrets": {
            "grep": ["secret", "config", "backup", "git", "aws", "firebase"],
            "gf":   ["aws-keys", "s3-buckets", "base64"],
            "score_boost": 4,
        },
        "sqli": {
            "grep": ["sql", "php", "java", "dotnet"],
            "gf":   ["sqli"],
            "score_boost": 4,
        },
        "ssrf": {
            "grep": ["ssrf", "redirect", "api"],
            "gf":   ["ssrf", "redirect"],
            "score_boost": 4,
        },
    },

    # ── Pesos del scoring ────────────────────────────────────────
    "scoring": {
        "gf_critical":         6,   # rce, ssti, sqli, ssrf, lfi
        "gf_high":             4,   # xss, idor, cors
        "gf_medium":           2,   # redirect, interestingparams, etc.
        "grep_critical":       3,   # secret, aws, sql, password, backup, git, firebase
        "grep_medium":         1,
        "js_leak_host":        4,   # jsleak encontró algo en el host
        "js_regex_secret_host": 5,  # regex propio encontró api_key/aws_key/jwt en el host
        "has_params":          1,
        "tech_legacy":         1,
        "status_200":          1,
        "cdn_penalty":        -2,
    },

    # ── Cuántos targets incluir en final_targets.txt ─────────────
    "final_targets_top_n": 200,
}


# ═══════════════════════════════════════════════════════════════
#   COLORES Y LOGGING
# ═══════════════════════════════════════════════════════════════

class C:
    RED     = "\033[91m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    BLUE    = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN    = "\033[96m"
    WHITE   = "\033[97m"
    BOLD    = "\033[1m"
    DIM     = "\033[2m"
    RESET   = "\033[0m"

    @staticmethod
    def supports_color() -> bool:
        return hasattr(sys.stdout, "isatty") and sys.stdout.isatty()


def strip_color(text: str) -> str:
    return re.compile(r'\033\[[0-9;]*m').sub('', text)


def validate_domain(domain: str) -> bool:
    pattern = r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    return bool(re.match(pattern, domain))


def normalize_url(url: str) -> str:
    """
    Normaliza una URL vaciando los valores de los query params.
    /api/user?id=123&page=2  →  /api/user?id=&page=
    """
    try:
        url = url.strip()
        parsed = urlparse(url)
        if parsed.query:
            pairs = parse_qsl(parsed.query, keep_blank_values=True)
            normalized_query = urlencode([(k, "") for k, _ in pairs])
            normalized = parsed._replace(query=normalized_query)
            return urlunparse(normalized)
        return url
    except Exception:
        return url.strip()


class Logger:
    """Logger con file handle persistente (un open por run, no por línea)."""

    def __init__(self, log_file: Optional[Path] = None):
        self.log_file    = log_file
        self._fh         = None
        if log_file:
            try:
                self._fh = open(log_file, "a", buffering=1)  # line-buffered
            except Exception:
                self._fh = None

    def close(self):
        if self._fh:
            try:
                self._fh.close()
            except Exception:
                pass
            self._fh = None

    def _write(self, msg: str):
        print(msg)
        if self._fh:
            try:
                self._fh.write(strip_color(msg) + "\n")
            except Exception:
                pass

    def phase(self, name: str, description: str = ""):
        sep = "═" * 68
        self._write(f"\n{C.BOLD}{C.BLUE}{sep}{C.RESET}")
        self._write(f"{C.BOLD}{C.BLUE}  ▶  {name.upper()}{C.RESET}")
        if description:
            self._write(f"{C.YELLOW}  [➤] {description}{C.RESET}")
        self._write(f"{C.BOLD}{C.BLUE}{sep}{C.RESET}")

    def ok(self, msg: str):
        self._write(f"{C.GREEN}  [✓]{C.RESET} {msg}")

    def info(self, msg: str):
        self._write(f"{C.CYAN}  [i]{C.RESET} {msg}")

    def run(self, tool: str, cmd: list):
        self._write(f"{C.MAGENTA}  [>]{C.RESET} {C.WHITE}Ejecutando {tool}{C.RESET} "
                    f"{C.DIM}{' '.join(cmd)}{C.RESET}")

    def warn(self, msg: str):
        self._write(f"{C.YELLOW}  [!]{C.RESET} {msg}")

    def error(self, msg: str):
        self._write(f"{C.RED}  [✗]{C.RESET} {msg}")

    def skip(self, msg: str):
        self._write(f"{C.DIM}  [-] SKIP: {msg}{C.RESET}")

    def result(self, label: str, value):
        self._write(f"{C.GREEN}  [+]{C.RESET} {C.BOLD}{label}:{C.RESET} "
                    f"{C.YELLOW}{value}{C.RESET}")


def banner():
    print(f"""{C.CYAN}{C.BOLD}
 ██████╗ ███████╗███╗  ██╗████████╗███████╗███████╗████████╗
 ██╔══██╗██╔════╝████╗ ██║╚══██╔══╝██╔════╝██╔════╝╚══██╔══╝
 ██████╔╝█████╗  ██╔██╗██║   ██║   █████╗  ███████╗   ██║
 ██╔═══╝ ██╔══╝  ██║╚████║   ██║   ██╔══╝  ╚════██║   ██║
 ██║     ███████╗██║ ╚███║   ██║   ███████╗███████║   ██║
 ╚═╝     ╚══════╝╚═╝  ╚══╝   ╚═╝   ╚══════╝╚══════╝   ╚═╝
{C.RESET}{C.YELLOW}{C.BOLD}         Joapath  ─  ARG-team  ─  v3 (VPN-safe){C.RESET}
{C.DIM}         github.com/Joapath/BountyFlow{C.RESET}
""")


# ═══════════════════════════════════════════════════════════════
#   CLASE PRINCIPAL
# ═══════════════════════════════════════════════════════════════

class PentestFlow:

    def __init__(self, domain: str, output_dir: Path,
                 skip_phases: list, only_phases: list,
                 focus_areas: list):
        self.domain       = domain
        self.base_dir     = output_dir / domain.replace(".", "_")
        self.skip_phases  = [p.lower() for p in skip_phases]
        self.only_phases  = [p.lower() for p in only_phases]
        self.focus_areas  = [f.lower() for f in focus_areas]
        self.start_time   = datetime.now()
        self.stats: Dict[str, dict] = {}

        # Estructura de directorios numerada para navegación fácil
        self.dirs = {
            "root":         self.base_dir,
            "recon":        self.base_dir / "01_recon",
            "resolve":      self.base_dir / "02_resolve",
            "httpx":        self.base_dir / "03_httpx",
            "dns":          self.base_dir / "04_dns",
            "takeover":     self.base_dir / "05_takeover",
            "social":       self.base_dir / "06_social",
            "crawl":        self.base_dir / "07_crawl",
            "grep":         self.base_dir / "08_grep",
            "gf":           self.base_dir / "09_gf",
            "jsleak":       self.base_dir / "10_jsleak",
            "jsregex":      self.base_dir / "11_jsregex",
            "intelligence": self.base_dir / "12_intelligence",
            "nuclei":       self.base_dir / "13_nuclei",
            "diff":         self.base_dir / "diff",
            "history":      self.base_dir / "_history",
            "logs":         self.base_dir / "logs",
        }

        for d in self.dirs.values():
            d.mkdir(parents=True, exist_ok=True)

        # Archivos clave del pipeline
        self.files = {
            # Recon
            "allsubs":       self.dirs["recon"]        / "allsubs.txt",
            # Resolve
            "resolved":      self.dirs["resolve"]      / "resolved.txt",
            "unresolved":    self.dirs["resolve"]      / "unresolved.txt",
            # HTTPX
            "live":          self.dirs["httpx"]        / "live.txt",
            "live_tech":     self.dirs["httpx"]        / "live_tech.json",
            # DNS
            "dns_json":      self.dirs["dns"]          / "dns_records.json",
            "dns":           self.dirs["dns"]          / "dns_records.txt",
            "cname_hosts":   self.dirs["dns"]          / "cname_hosts.txt",
            # Takeover
            "takeover":      self.dirs["takeover"]     / "takeover_findings.txt",
            # Social
            "social":        self.dirs["social"]       / "socialhunter.txt",
            # Crawl
            "urls":          self.dirs["crawl"]        / "urls.txt",
            "cleanurls":     self.dirs["crawl"]        / "cleanurls.txt",
            "urls_norm":     self.dirs["crawl"]        / "urls_normalized.txt",
            # JSLeak
            "js_urls":       self.dirs["jsleak"]       / "js_urls.txt",
            "jsleak_out":    self.dirs["jsleak"]       / "jsleak_results.txt",
            # JS Regex
            "jsregex_secrets_hosts": self.dirs["jsregex"] / "secrets_hosts.txt",
            # Intelligence
            "url_map":       self.dirs["intelligence"] / "url_map.json",
            "final_targets": self.dirs["intelligence"] / "final_targets.txt",
            "high_value":    self.dirs["intelligence"] / "high_value_targets.txt",
            # Nuclei
            "nuclei_hosts":  self.dirs["nuclei"]       / "findings_hosts.txt",
            "nuclei_urls":   self.dirs["nuclei"]       / "findings_urls.txt",
            # Diff
            "new_subs":      self.dirs["diff"]         / "new_subdomains.txt",
            "gone_subs":     self.dirs["diff"]         / "gone_subdomains.txt",
            "new_urls":      self.dirs["diff"]         / "new_urls.txt",
        }

        log_file  = self.dirs["logs"] / f"run_{self.start_time.strftime('%Y%m%d_%H%M%S')}.log"
        self.log  = Logger(log_file=log_file)

    # ──────────────────────────────────────────────────────────────
    #   UTILIDADES DE EJECUCIÓN
    # ──────────────────────────────────────────────────────────────

    def check_tool(self, name: str) -> bool:
        if shutil.which(name) is None:
            self.log.warn(f"'{name}' no encontrado en PATH, omitiendo.")
            return False
        return True

    def run_cmd(self, tool: str, cmd: list,
                output_file: Optional[Path] = None,
                stdout_mode: bool = False,
                timeout: int = 3600,
                cwd: Optional[Path] = None) -> bool:
        """
        Ejecuta un comando externo.
        Retorna True solo si:
          - el proceso terminó sin excepción, Y
          - el exit code es 0 o el output_file tiene contenido (algunos
            tools retornan != 0 pero escriben resultados válidos).
        """
        self.log.run(tool, cmd)
        try:
            run_cwd = str(cwd) if cwd else None
            if stdout_mode and output_file:
                with open(output_file, "w") as f:
                    result = subprocess.run(
                        cmd, stdout=f, stderr=subprocess.PIPE,
                        timeout=timeout, text=True, cwd=run_cwd,
                    )
            else:
                result = subprocess.run(
                    cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                    timeout=timeout, text=True, cwd=run_cwd,
                )

            if result.returncode != 0:
                preview = result.stderr[:300].strip() if result.stderr else ""
                if preview:
                    self.log.warn(f"stderr [{tool}]: {preview}")

            if output_file and output_file.exists():
                has_output = output_file.stat().st_size > 0
                if result.returncode != 0 and not has_output:
                    self.log.warn(f"[{tool}] exit code {result.returncode} y sin output.")
                    return False
                return True

            return result.returncode == 0

        except FileNotFoundError:
            self.log.error(f"'{tool}' no está instalado o no está en PATH.")
            return False
        except subprocess.TimeoutExpired:
            self.log.error(f"'{tool}' superó el timeout de {timeout}s.")
            return False
        except Exception as e:
            self.log.error(f"Error inesperado ejecutando '{tool}': {e}")
            return False

    def count_lines(self, file: Path) -> int:
        if not file.exists():
            return 0
        try:
            with open(file) as f:
                return sum(1 for line in f if line.strip())
        except Exception:
            return 0

    def read_lines(self, file: Path) -> List[str]:
        if not file.exists():
            return []
        try:
            with open(file) as f:
                return [line.strip() for line in f if line.strip()]
        except Exception:
            return []

    def should_run(self, phase: str) -> bool:
        phase = phase.lower()
        if self.only_phases:
            return phase in self.only_phases
        return phase not in self.skip_phases

    def build_cmd(self, template: list,
                  domain: Optional[str] = None,
                  input_file: Optional[Path] = None,
                  output_file: Optional[Path] = None,
                  extra: Optional[dict] = None) -> list:
        replacements = {
            "{domain}": domain or self.domain,
            "{input}":  str(input_file)  if input_file  else "",
            "{output}": str(output_file) if output_file else "",
        }
        if extra:
            replacements.update(extra)
        result = []
        for token in template:
            for ph, val in replacements.items():
                token = token.replace(ph, val)
            result.append(token)
        return result

    def merge_and_sort(self, input_files: list, output_file: Path) -> int:
        """Merge para subdominios: minúsculas + dedup (DNS es case-insensitive)."""
        lines: Set[str] = set()
        for f in input_files:
            if f.exists():
                with open(f) as fh:
                    for line in fh:
                        clean = line.strip().lower()
                        if clean and not clean.startswith("#"):
                            lines.add(clean)
        with open(output_file, "w") as fh:
            for line in sorted(lines):
                fh.write(line + "\n")
        return len(lines)

    def merge_urls(self, input_files: list, output_file: Path) -> int:
        """
        Merge para URLs: preserva mayúsculas/minúsculas (los paths SÍ son
        case-sensitive, a diferencia de los subdominios).
        """
        lines: Set[str] = set()
        for f in input_files:
            if f.exists():
                with open(f) as fh:
                    for line in fh:
                        clean = line.strip()
                        if clean and not clean.startswith("#"):
                            lines.add(clean)
        with open(output_file, "w") as fh:
            for line in sorted(lines):
                fh.write(line + "\n")
        return len(lines)

    # ──────────────────────────────────────────────────────────────
    #   FASE 1: RECON — Parallelizado con ThreadPoolExecutor
    # ──────────────────────────────────────────────────────────────

    def phase_recon(self):
        if not self.should_run("recon"):
            self.log.skip("Fase recon omitida.")
            return

        self.log.phase("FASE 1: RECONOCIMIENTO",
                       "🔎 Buscando subdominios con subfinder, assetfinder, sublist3r, "
                       "shodanx, findomain y crtsh")
        t0 = time.time()

        tools_to_run = []
        for name, cfg in CONFIG["recon_tools"].items():
            if not cfg.get("enabled", True):
                continue
            if "script_path" in cfg:
                script_path = Path(cfg["script_path"]).expanduser()
                if not script_path.exists():
                    self.log.warn(f"'{name}': script no encontrado en {script_path}, omitiendo.")
                    continue
            else:
                if not self.check_tool(name):
                    continue
            tools_to_run.append((name, cfg))

        if not tools_to_run:
            self.log.warn("Ningún tool de recon disponible.")
            self.stats["recon"] = {"lines": 0, "time": 0, "status": "error"}
            return

        max_workers = min(CONFIG["vpn_safe"]["max_parallel_tools"], len(tools_to_run))
        stagger     = CONFIG["vpn_safe"]["stagger_delay"]
        self.log.info(f"Lanzando {len(tools_to_run)} tools "
                      f"({max_workers} en paralelo, stagger {stagger}s — modo VPN-safe)...")

        def _run_tool(tool_name: str, tool_cfg: dict) -> Tuple[str, Path, bool, int]:
            out_file = self.dirs["recon"] / f"{tool_name}.txt"

            if "script_path" in tool_cfg:
                # Tool tipo script (ej: crtsh.py) — corre en su propia carpeta
                # y después se busca el output que haya generado ahí.
                script_path = Path(tool_cfg["script_path"]).expanduser()
                cmd = [
                    tok.replace("{script_path}", str(script_path)).replace("{domain}", self.domain)
                    for tok in tool_cfg["cmd"]
                ]
                ok = self.run_cmd(
                    tool_name, cmd, output_file=None, stdout_mode=False,
                    timeout=tool_cfg.get("timeout", 900), cwd=script_path.parent,
                )
                if ok:
                    ok = self._resolve_script_output(tool_name, tool_cfg, out_file)
            else:
                cmd = self.build_cmd(tool_cfg["cmd"], domain=self.domain, output_file=out_file)
                ok = self.run_cmd(
                    tool_name, cmd, output_file=out_file,
                    stdout_mode=tool_cfg.get("stdout_mode", False),
                    timeout=tool_cfg.get("timeout", 1800),
                )

            count = self.count_lines(out_file) if ok and out_file.exists() else 0
            return tool_name, out_file, ok, count

        raw_files: List[Path] = []
        with ThreadPoolExecutor(max_workers=max_workers) as ex:
            futures = {}
            for n, c in tools_to_run:
                futures[ex.submit(_run_tool, n, c)] = n
                time.sleep(stagger)  # escalona el lanzamiento, no satura la VPN
            for fut in as_completed(futures):
                try:
                    tool_name, out_file, ok, count = fut.result()
                    raw_files.append(out_file)
                    if ok:
                        self.log.ok(f"{tool_name}: {count} subdominios → {out_file.name}")
                    else:
                        self.log.warn(f"{tool_name}: falló o sin resultados.")
                except Exception as e:
                    self.log.error(f"Error en thread de recon: {e}")

        self.log.info("Combinando y deduplicando → allsubs.txt")
        total = self.merge_and_sort(raw_files, self.files["allsubs"])
        self.log.result("Subdominios únicos totales", total)

        status = "ok" if total > 0 else "empty"
        if total == 0:
            self.log.warn("allsubs.txt vacío — verificá API keys y conectividad.")
        else:
            self.log.ok("Recon completo: subdominios listos")
        self.stats["recon"] = {"lines": total, "time": time.time() - t0, "status": status}

    def _resolve_script_output(self, tool_name: str, tool_cfg: dict, out_file: Path) -> bool:
        """
        Para tools tipo script (ej: crtsh.py) que escriben su output en su
        propia carpeta en lugar de respetar -o. Busca el archivo más
        reciente que matchee 'output_glob' y lo copia a out_file.
        """
        script_path = Path(tool_cfg["script_path"]).expanduser()
        script_dir  = script_path.parent
        pattern     = tool_cfg.get("output_glob", "").replace("{domain}", self.domain)
        if not pattern:
            self.log.warn(f"{tool_name}: no se configuró 'output_glob', no puedo localizar el output.")
            return False
        try:
            candidates = sorted(script_dir.glob(pattern), key=lambda p: p.stat().st_mtime, reverse=True)
        except Exception as e:
            self.log.warn(f"{tool_name}: error buscando output ({e}).")
            return False
        if not candidates:
            self.log.warn(f"{tool_name}: no encontré ningún archivo que matchee "
                          f"'{pattern}' en {script_dir}.")
            return False
        try:
            shutil.copy2(candidates[0], out_file)
            return True
        except Exception as e:
            self.log.warn(f"{tool_name}: no pude copiar '{candidates[0]}' → {e}")
            return False

    # ──────────────────────────────────────────────────────────────
    #   FASE 2: RESOLVE — Filtra subdominios con resolución externa
    # ──────────────────────────────────────────────────────────────

    def phase_resolve(self):
        if not self.should_run("resolve"):
            self.log.skip("Fase resolve omitida.")
            return
        if not self.files["allsubs"].exists() or self.count_lines(self.files["allsubs"]) == 0:
            self.log.warn("allsubs.txt vacío, omitiendo resolve.")
            return
        if not CONFIG["dnsx_resolve"]["enabled"] or not self.check_tool("dnsx"):
            return

        self.log.phase("FASE 2: RESOLUCIÓN DNS EXTERNA",
                       "🧬 Filtrando subdominios que resuelven desde afuera "
                       "(clave si usás VPN o hay subs internos mezclados)")
        t0 = time.time()

        cmd = self.build_cmd(CONFIG["dnsx_resolve"]["cmd"],
                             input_file=self.files["allsubs"],
                             output_file=self.files["resolved"])
        ok = self.run_cmd("dnsx (resolve)", cmd,
                          output_file=self.files["resolved"],
                          timeout=1800)

        resolved_count = self.count_lines(self.files["resolved"])

        all_set      = set(self.read_lines(self.files["allsubs"]))
        resolved_set = set(self.read_lines(self.files["resolved"]))
        unresolved   = all_set - resolved_set

        if unresolved:
            with open(self.files["unresolved"], "w") as f:
                f.write("\n".join(sorted(unresolved)) + "\n")

        self.log.result("Subdominios que resuelven externamente", resolved_count)
        if unresolved:
            self.log.info(f"Subdominios sin resolución externa (posibles internos): "
                          f"{len(unresolved)} → unresolved.txt")

        status = "ok" if (ok and resolved_count > 0) else ("empty" if ok else "error")
        if resolved_count == 0:
            self.log.warn("Ningún subdominio resolvió desde afuera — httpx usará "
                          "allsubs.txt completo (más riesgo de cuelgues por DNS interno).")
        else:
            self.log.ok("Resolve completo: subdominios externos filtrados")
        self.stats["resolve"] = {"lines": resolved_count, "time": time.time() - t0, "status": status}

    # ──────────────────────────────────────────────────────────────
    #   FASE 3: HTTPX — Doble pase (live + tech JSONL)
    # ──────────────────────────────────────────────────────────────

    def phase_httpx(self):
        if not self.should_run("httpx"):
            self.log.skip("Fase httpx omitida.")
            return

        # Preferí resolved.txt (subs que resuelven desde afuera). Si la fase
        # resolve no corrió o quedó vacía, cae a allsubs.txt sin romper nada.
        input_source = self.files["resolved"]
        source_label = "resolved.txt (fase resolve)"
        if not input_source.exists() or self.count_lines(input_source) == 0:
            input_source = self.files["allsubs"]
            source_label = "allsubs.txt (fase resolve omitida o vacía)"

        if not input_source.exists() or self.count_lines(input_source) == 0:
            self.log.warn("No hay subdominios disponibles para httpx (allsubs.txt vacío).")
            return
        if not self.check_tool("httpx"):
            return

        self.log.phase("FASE 3: DETECCIÓN DE HOSTS VIVOS",
                       f"🌐 Verificando hosts vivos y tecnologías con httpx "
                       f"(input: {source_label})")
        t0 = time.time()

        if CONFIG["httpx_live"]["enabled"]:
            cmd = self.build_cmd(CONFIG["httpx_live"]["cmd"],
                                 input_file=input_source,
                                 output_file=self.files["live"])
            ok = self.run_cmd("httpx (live)", cmd,
                              output_file=self.files["live"],
                              timeout=3600)
            count = self.count_lines(self.files["live"])
            if not ok or count == 0:
                self.log.warn("httpx live: sin hosts vivos o falló.")
            else:
                self.log.result("Hosts vivos", count)

        if CONFIG["httpx_tech"]["enabled"]:
            cmd = self.build_cmd(CONFIG["httpx_tech"]["cmd"],
                                 input_file=input_source,
                                 output_file=self.files["live_tech"])
            ok_tech = self.run_cmd("httpx (tech)", cmd,
                                   output_file=self.files["live_tech"],
                                   timeout=3600)
            count_tech = self.count_lines(self.files["live_tech"])
            if ok_tech and count_tech > 0:
                self.log.ok(f"Tech JSONL guardado → {self.files['live_tech'].name} "
                            f"({count_tech} hosts)")
            else:
                self.log.warn("httpx tech: sin datos o falló.")

        elapsed    = time.time() - t0
        live_count = self.count_lines(self.files["live"])
        status     = "ok" if live_count > 0 else "empty"
        if status == "ok":
            self.log.ok("HTTPX completo: hosts vivos detectados")
        self.stats["httpx"] = {"lines": live_count, "time": elapsed, "status": status}

    # ──────────────────────────────────────────────────────────────
    #   FASE 4: DNS — A + CNAME (JSON) para detectar takeovers
    # ──────────────────────────────────────────────────────────────

    def phase_dns(self):
        if not self.should_run("dns"):
            self.log.skip("Fase dns omitida.")
            return
        if not self.files["live"].exists() or self.count_lines(self.files["live"]) == 0:
            self.log.warn("live.txt vacío, omitiendo dnsx.")
            return
        if not CONFIG["dnsx"]["enabled"] or not self.check_tool("dnsx"):
            return

        self.log.phase("FASE 4: RESOLUCIÓN DNS",
                       "🧭 Resolviendo A/CNAME (JSON) para detectar riesgos de takeover")
        t0 = time.time()

        cmd = self.build_cmd(CONFIG["dnsx"]["cmd"],
                             input_file=self.files["live"],
                             output_file=self.files["dns_json"])
        ok = self.run_cmd("dnsx", cmd,
                          output_file=self.files["dns_json"],
                          timeout=1800)

        records     = self._parse_dnsx_json(self.files["dns_json"])
        cname_hosts: Set[str] = set()

        if records:
            with open(self.files["dns"], "w") as f:
                for rec in records:
                    host  = rec.get("host", "")
                    a_rec = rec.get("a", []) or []
                    c_rec = rec.get("cname", []) or rec.get("CNAME", []) or []
                    f.write(f"{host}  A:{','.join(a_rec) or '-'}  CNAME:{','.join(c_rec) or '-'}\n")
                    if c_rec and host:
                        cname_hosts.add(host)

            if cname_hosts:
                with open(self.files["cname_hosts"], "w") as f:
                    f.write("\n".join(sorted(cname_hosts)) + "\n")

        count  = len(records)
        status = "ok" if (ok and count > 0) else ("empty" if ok else "error")
        if count == 0 and ok:
            self.log.warn("dnsx: sin registros resueltos.")
        else:
            self.log.result("Registros DNS resueltos", count)
        if cname_hosts:
            self.log.info(f"Hosts con CNAME (candidatos a takeover): "
                          f"{len(cname_hosts)} → cname_hosts.txt")
        if status == "ok":
            self.log.ok("DNS completo: registros resueltos correctamente")
        self.stats["dns"] = {"lines": count, "time": time.time() - t0, "status": status}

    def _parse_dnsx_json(self, file: Path) -> List[dict]:
        """Parsea dns_records.json (JSONL de dnsx) de forma defensiva."""
        records: List[dict] = []
        if not file.exists():
            return records
        try:
            with open(file) as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        records.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
        except Exception as e:
            self.log.warn(f"Error leyendo dns_records.json: {e}")
        return records

    # ──────────────────────────────────────────────────────────────
    #   FASE 5: TAKEOVER — subzy sobre hosts con CNAME
    # ──────────────────────────────────────────────────────────────

    def phase_takeover(self):
        if not self.should_run("takeover"):
            self.log.skip("Fase takeover omitida.")
            return
        if not self.files["cname_hosts"].exists() or self.count_lines(self.files["cname_hosts"]) == 0:
            self.log.warn("Sin hosts con CNAME detectados (o fase dns omitida), "
                          "saltando takeover.")
            return
        if not CONFIG["subzy"]["enabled"] or not self.check_tool("subzy"):
            return

        self.log.phase("FASE 5: TAKEOVER INTELIGENTE",
                       "🎯 Verificando CNAMEs colgantes contra fingerprints de servicios (subzy)")
        t0 = time.time()

        cmd = self.build_cmd(CONFIG["subzy"]["cmd"], input_file=self.files["cname_hosts"])
        ok = self.run_cmd(
            "subzy", cmd,
            output_file=self.files["takeover"],
            stdout_mode=CONFIG["subzy"].get("stdout_mode", True),
            timeout=CONFIG["subzy"].get("timeout", 1800),
        )
        count  = self.count_lines(self.files["takeover"])
        status = "ok" if (ok and count > 0) else ("empty" if ok else "error")
        self.log.result("Hallazgos de takeover", count)
        if count > 0:
            self.log.warn(f"⚠ Revisá takeover_findings.txt — posibles {count} "
                          f"subdominios tomables")
        if status == "ok":
            self.log.ok("Takeover completo")
        self.stats["takeover"] = {"lines": count, "time": time.time() - t0, "status": status}

    # ──────────────────────────────────────────────────────────────
    #   FASE 6: SOCIAL (socialhunter)
    # ──────────────────────────────────────────────────────────────

    def phase_social(self):
        if not self.should_run("social"):
            self.log.skip("Fase social omitida.")
            return
        if not self.files["live"].exists() or self.count_lines(self.files["live"]) == 0:
            self.log.warn("live.txt vacío, omitiendo socialhunter.")
            return
        if not CONFIG["socialhunter"]["enabled"] or not self.check_tool("socialhunter"):
            return

        self.log.phase("FASE 6: OSINT",
                       "👥 Recolectando OSINT, correos y links asociados")
        t0 = time.time()

        cmd = self.build_cmd(CONFIG["socialhunter"]["cmd"],
                             input_file=self.files["live"])
        ok = self.run_cmd(
            "socialhunter", cmd,
            output_file=self.files["social"],
            stdout_mode=CONFIG["socialhunter"].get("stdout_mode", False),
            timeout=1800,
        )
        count  = self.count_lines(self.files["social"])
        status = "ok" if (ok and count > 0) else ("empty" if ok else "error")
        self.log.result("Hallazgos socialhunter", count)
        if status == "ok":
            self.log.ok("OSINT completo: hallazgos guardados")
        self.stats["social"] = {"lines": count, "time": time.time() - t0, "status": status}

    # ──────────────────────────────────────────────────────────────
    #   FASE 7: CRAWLING (katana + gau + waybackurls) + URO + NORM
    # ──────────────────────────────────────────────────────────────

    def phase_crawl(self):
        if not self.should_run("crawl"):
            self.log.skip("Fase crawl omitida.")
            return
        if not self.files["live"].exists() or self.count_lines(self.files["live"]) == 0:
            self.log.warn("live.txt vacío, omitiendo crawling.")
            return

        self.log.phase("FASE 7: CRAWLING + NORMALIZACIÓN",
                       "🕸️ Rastreando URLs (katana + gau + waybackurls) y normalizando "
                       "parámetros para el siguiente paso")
        t0 = time.time()

        crawl_dir = self.dirs["crawl"]
        # (nombre, cfg, archivo de salida, usa {domain} en vez de {input})
        engines: List[Tuple[str, dict, Path, bool]] = []

        if CONFIG["katana"]["enabled"] and self.check_tool("katana"):
            engines.append(("katana", CONFIG["katana"], crawl_dir / "katana_raw.txt", False))
        else:
            self.log.warn("katana no disponible o deshabilitado.")

        if CONFIG["gau"]["enabled"] and self.check_tool("gau"):
            engines.append(("gau", CONFIG["gau"], crawl_dir / "gau_raw.txt", True))

        if CONFIG["waybackurls"]["enabled"] and self.check_tool("waybackurls"):
            engines.append(("waybackurls", CONFIG["waybackurls"], crawl_dir / "wayback_raw.txt", True))

        raw_files: List[Path] = []

        if not engines:
            self.log.warn("Ningún crawler disponible, saltando esta parte del crawling.")
        else:
            max_workers = min(CONFIG["vpn_safe"]["max_parallel_tools"], len(engines))
            stagger     = CONFIG["vpn_safe"]["stagger_delay"]
            self.log.info(f"Lanzando {len(engines)} crawlers "
                          f"({max_workers} en paralelo, stagger {stagger}s — modo VPN-safe)...")

            def _run_engine(name: str, cfg: dict, out_file: Path, use_domain: bool) -> Tuple[str, bool, int]:
                if use_domain:
                    cmd = self.build_cmd(cfg["cmd"], domain=self.domain)
                else:
                    cmd = self.build_cmd(cfg["cmd"], input_file=self.files["live"], output_file=out_file)
                ok = self.run_cmd(
                    name, cmd, output_file=out_file,
                    stdout_mode=cfg.get("stdout_mode", use_domain),
                    timeout=cfg.get("timeout", 3600),
                )
                count = self.count_lines(out_file) if ok else 0
                return name, ok, count

            with ThreadPoolExecutor(max_workers=max_workers) as ex:
                futures = {}
                for name, cfg, out_file, use_domain in engines:
                    futures[ex.submit(_run_engine, name, cfg, out_file, use_domain)] = name
                    raw_files.append(out_file)
                    time.sleep(stagger)
                for fut in as_completed(futures):
                    try:
                        name, ok, count = fut.result()
                        if ok:
                            self.log.ok(f"{name}: {count} URLs")
                        else:
                            self.log.warn(f"{name}: falló o sin resultados.")
                    except Exception as e:
                        self.log.error(f"Error en thread de crawling: {e}")

        merged = self.merge_urls(raw_files, self.files["urls"])
        self.log.result("URLs raw combinadas (katana+gau+wayback)", merged)
        if merged == 0:
            self.log.warn("No se obtuvieron URLs de ningún crawler — verificá conectividad/rate limits.")

        # URO: deduplicación básica
        if CONFIG["uro"]["enabled"] and self.check_tool("uro"):
            if self.files["urls"].exists() and self.count_lines(self.files["urls"]) > 0:
                cmd = self.build_cmd(CONFIG["uro"]["cmd"],
                                     input_file=self.files["urls"],
                                     output_file=self.files["cleanurls"])
                self.run_cmd("uro", cmd,
                             output_file=self.files["cleanurls"],
                             timeout=600)
                self.log.result("URLs post-uro", self.count_lines(self.files["cleanurls"]))
            else:
                self.log.warn("urls.txt vacío, saltando uro.")
        else:
            if self.files["urls"].exists():
                shutil.copy2(self.files["urls"], self.files["cleanurls"])
                self.log.warn("uro no disponible, cleanurls = urls.txt sin dedup.")

        # Normalización de params
        self._normalize_urls()

        elapsed     = time.time() - t0
        clean_count = self.count_lines(self.files["cleanurls"])
        norm_count  = self.count_lines(self.files["urls_norm"])
        status      = "ok" if clean_count > 0 else "empty"
        self.stats["crawl"] = {"lines": clean_count, "time": elapsed, "status": status}
        self.log.result("URLs limpias (cleanurls)", clean_count)
        self.log.result("URLs normalizadas únicas", norm_count)
        if status == "ok":
            self.log.ok("Crawl completo: URLs limpias y normalizadas")

    def _normalize_urls(self):
        """
        Genera urls_normalized.txt con params vaciados.
        /api/user?id=1&p=2 y /api/user?id=99&p=5 → /api/user?id=&p= (un solo entry)
        """
        if not self.files["cleanurls"].exists():
            return

        normalized: Dict[str, str] = {}
        with open(self.files["cleanurls"]) as f:
            for line in f:
                url = line.strip()
                if not url:
                    continue
                norm = normalize_url(url)
                if norm not in normalized:
                    normalized[norm] = url

        with open(self.files["urls_norm"], "w") as f:
            for norm_url in sorted(normalized.keys()):
                f.write(norm_url + "\n")

        raw_count = self.count_lines(self.files["cleanurls"])
        self.log.info(f"Normalización: {raw_count} → {len(normalized)} URLs únicas "
                      f"(reducción: {raw_count - len(normalized)})")

    # ──────────────────────────────────────────────────────────────
    #   FASE 8: GREP — Parallelizado sobre cleanurls, filtrado por --focus
    # ──────────────────────────────────────────────────────────────

    def phase_grep(self):
        if not self.should_run("grep"):
            self.log.skip("Fase grep omitida.")
            return

        if not self.files["cleanurls"].exists() or self.count_lines(self.files["cleanurls"]) == 0:
            self.log.warn("cleanurls.txt vacío, omitiendo grep.")
            return

        active_keywords = self._get_active_grep_keywords()
        if not active_keywords:
            self.log.warn("Sin keywords activos (verificá --focus).")
            return

        self.log.phase("FASE 8: GREP DE KEYWORDS",
                       f"🔍 Buscando endpoints sensibles en {len(active_keywords)} categorías"
                       f" sobre cleanurls.txt")
        t0 = time.time()
        total_found = 0

        def _grep_one(keyword: str, pattern: str) -> Tuple[str, int]:
            out_file = self.dirs["grep"] / f"{keyword}.txt"
            cmd = ["grep", "-iEo", f"^.*{pattern}.*$", str(self.files["cleanurls"])]
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
                matches = sorted({line for line in result.stdout.splitlines() if line.strip()})
                if matches:
                    with open(out_file, "w") as f:
                        f.write("\n".join(matches) + "\n")
                    return keyword, len(matches)
                return keyword, 0
            except Exception as e:
                self.log.error(f"grep [{keyword}]: {e}")
                return keyword, 0

        with ThreadPoolExecutor(max_workers=8) as ex:
            futures = {
                ex.submit(_grep_one, kw, pat): kw
                for kw, pat in active_keywords.items()
            }
            for fut in as_completed(futures):
                kw, count = fut.result()
                if count > 0:
                    self.log.ok(f"[{kw}] → {count} URLs")
                    total_found += count
                else:
                    self.log.info(f"[{kw}] → sin resultados")

        self.log.result("Total URLs categorizadas", total_found)
        if total_found > 0:
            self.log.ok("Grep completo: categorías procesadas")
        self.stats["grep"] = {"lines": total_found, "time": time.time() - t0, "status": "ok"}

    def _get_active_grep_keywords(self) -> dict:
        if not self.focus_areas:
            return CONFIG["grep_keywords"]
        active: Set[str] = set()
        for focus in self.focus_areas:
            active.update(CONFIG["focus_map"].get(focus, {}).get("grep", []))
        return {k: v for k, v in CONFIG["grep_keywords"].items() if k in active}

    # ──────────────────────────────────────────────────────────────
    #   FASE 9: GF PATTERNS — Parallelizado, filtrado por --focus
    # ──────────────────────────────────────────────────────────────

    def phase_gf(self):
        if not self.should_run("gf"):
            self.log.skip("Fase gf omitida.")
            return
        if not self.files["cleanurls"].exists() or self.count_lines(self.files["cleanurls"]) == 0:
            self.log.warn("cleanurls.txt vacío, omitiendo gf.")
            return
        if not self.check_tool("gf"):
            return

        active_patterns = self._get_active_gf_patterns()
        if not active_patterns:
            self.log.warn("Sin patrones gf activos (verificá --focus).")
            return

        self.log.phase("FASE 9: GF PATTERNS",
                       f"🧠 Aplicando {len(active_patterns)} patrones GF en paralelo")
        t0 = time.time()
        total_found = 0

        def _run_gf(pattern: str) -> Tuple[str, int]:
            out_file = self.dirs["gf"] / f"gf_{pattern}.txt"
            try:
                with open(self.files["cleanurls"]) as fin:
                    result = subprocess.run(
                        ["gf", pattern],
                        stdin=fin,
                        capture_output=True,
                        text=True,
                        timeout=120,
                    )
                matches = sorted({line for line in result.stdout.splitlines() if line.strip()})
                if matches:
                    with open(out_file, "w") as f:
                        f.write("\n".join(matches) + "\n")
                    return pattern, len(matches)
                return pattern, 0
            except subprocess.TimeoutExpired:
                self.log.warn(f"gf [{pattern}] timeout.")
                return pattern, 0
            except Exception as e:
                self.log.warn(f"gf [{pattern}] falló (¿patrón instalado?): {e}")
                return pattern, 0

        with ThreadPoolExecutor(max_workers=8) as ex:
            futures = {ex.submit(_run_gf, p): p for p in active_patterns}
            for fut in as_completed(futures):
                pattern, count = fut.result()
                if count > 0:
                    self.log.ok(f"gf [{pattern}] → {count} URLs")
                    total_found += count
                else:
                    self.log.info(f"gf [{pattern}] → sin resultados")

        self.log.result("Total URLs con patrones gf", total_found)
        if total_found > 0:
            self.log.ok("GF completo: patrones evaluados")
        self.stats["gf"] = {"lines": total_found, "time": time.time() - t0, "status": "ok"}

    def _get_active_gf_patterns(self) -> List[str]:
        if not self.focus_areas:
            return CONFIG["gf_patterns"]
        active: Set[str] = set()
        for focus in self.focus_areas:
            active.update(CONFIG["focus_map"].get(focus, {}).get("gf", []))
        return [p for p in CONFIG["gf_patterns"] if p in active]

    # ──────────────────────────────────────────────────────────────
    #   FASE 10: JSLEAK — Pre-filtrado a solo URLs .js
    # ──────────────────────────────────────────────────────────────

    def phase_jsleak(self):
        if not self.should_run("jsleak"):
            self.log.skip("Fase jsleak omitida.")
            return
        if not self.files["cleanurls"].exists() or self.count_lines(self.files["cleanurls"]) == 0:
            self.log.warn("cleanurls.txt vacío, omitiendo jsleak.")
            return
        if not CONFIG["jsleak"]["enabled"] or not self.check_tool("jsleak"):
            return

        self.log.phase("FASE 10: JSLEAK",
                       "🧪 Analizando .js por leaks, credenciales y endpoints expuestos")
        t0 = time.time()

        js_count = self._extract_js_urls()
        if js_count == 0:
            self.log.warn("No se encontraron URLs .js en cleanurls.txt, omitiendo jsleak.")
            self.stats["jsleak"] = {"lines": 0, "time": 0, "status": "skip"}
            return

        self.log.info(f"{js_count} URLs .js → pasando a jsleak")

        cmd = self.build_cmd(CONFIG["jsleak"]["cmd"],
                             input_file=self.files["js_urls"])
        ok = self.run_cmd(
            "jsleak", cmd,
            output_file=self.files["jsleak_out"],
            stdout_mode=CONFIG["jsleak"].get("stdout_mode", True),
            timeout=3600,
        )
        count  = self.count_lines(self.files["jsleak_out"])
        status = "ok" if (ok and count > 0) else ("empty" if ok else "error")
        self.log.result("Hallazgos jsleak", count)
        if status == "ok":
            self.log.ok("JSLeak completo: resultados listos")
        self.stats["jsleak"] = {"lines": count, "time": time.time() - t0, "status": status}

    def _extract_js_urls(self) -> int:
        """Filtra solo URLs .js de cleanurls.txt → js_urls.txt. Idempotente."""
        js_urls = []
        with open(self.files["cleanurls"]) as f:
            for line in f:
                url = line.strip()
                if url and re.search(r'\.js(\?|$)', url, re.IGNORECASE):
                    js_urls.append(url)
        if js_urls:
            with open(self.files["js_urls"], "w") as f:
                f.write("\n".join(js_urls) + "\n")
        return len(js_urls)

    # ──────────────────────────────────────────────────────────────
    #   FASE 11: JS REGEX — regex propios sobre el contenido de .js
    # ──────────────────────────────────────────────────────────────

    def phase_js_regex(self):
        if not self.should_run("jsregex"):
            self.log.skip("Fase jsregex omitida.")
            return
        if not CONFIG["js_regex"]["enabled"]:
            self.log.skip("jsregex deshabilitado en CONFIG.")
            return
        if not self.files["cleanurls"].exists() or self.count_lines(self.files["cleanurls"]) == 0:
            self.log.warn("cleanurls.txt vacío, omitiendo jsregex.")
            return

        # Reutiliza el mismo extractor que jsleak (idempotente, no pisa nada)
        js_count = self._extract_js_urls()
        if js_count == 0:
            self.log.warn("No se encontraron URLs .js en cleanurls.txt, omitiendo jsregex.")
            self.stats["jsregex"] = {"lines": 0, "time": 0, "status": "skip"}
            return

        self.log.phase("FASE 11: JS REGEX",
                       f"🧩 Analizando {js_count} archivos .js con regex propios "
                       f"(endpoints, API keys, JWT, subdominios)")
        t0 = time.time()

        cfg         = CONFIG["js_regex"]
        max_workers = cfg.get("max_workers", 3)
        stagger     = cfg.get("stagger_delay", 0.5)
        timeout     = cfg.get("timeout", 10)
        max_bytes   = cfg.get("max_bytes", 3 * 1024 * 1024)

        patterns  = self._build_js_patterns()
        sensitive = {"api_keys", "aws_keys", "jwt"}
        results: Dict[str, Set[str]] = {name: set() for name in patterns}
        secret_hosts: Set[str] = set()
        fetch_errors = 0

        js_urls = self.read_lines(self.files["js_urls"])

        def _fetch_and_match(url: str):
            try:
                req = urllib.request.Request(
                    url, headers={"User-Agent": "Mozilla/5.0 (PentestFlow; +recon)"}
                )
                with urllib.request.urlopen(req, timeout=timeout) as resp:
                    raw = resp.read(max_bytes)
                body = raw.decode("utf-8", errors="ignore")
                local_hits = {}
                for name, pattern in patterns.items():
                    found = pattern.findall(body)
                    if found:
                        local_hits[name] = set(found)
                return url, local_hits, None
            except Exception as e:
                return url, {}, str(e)

        self.log.info(f"Descargando .js con {max_workers} workers "
                      f"(stagger {stagger}s, timeout {timeout}s) — modo VPN-safe")

        with ThreadPoolExecutor(max_workers=max_workers) as ex:
            futures = {}
            for url in js_urls:
                futures[ex.submit(_fetch_and_match, url)] = url
                time.sleep(stagger)
            for fut in as_completed(futures):
                try:
                    url, hits, err = fut.result()
                except Exception:
                    fetch_errors += 1
                    continue
                if err:
                    fetch_errors += 1
                    continue
                for name, vals in hits.items():
                    results[name].update(vals)
                    if name in sensitive and vals:
                        secret_hosts.add(urlparse(url).netloc)

        jsregex_dir = self.dirs["jsregex"]
        total_hits  = 0
        for name, vals in results.items():
            if vals:
                out_f = jsregex_dir / f"{name}.txt"
                with open(out_f, "w") as f:
                    f.write("\n".join(sorted(vals)) + "\n")
                self.log.ok(f"[{name}] → {len(vals)} hallazgos")
                total_hits += len(vals)
            else:
                self.log.info(f"[{name}] → sin resultados")

        if secret_hosts:
            with open(self.files["jsregex_secrets_hosts"], "w") as f:
                f.write("\n".join(sorted(secret_hosts)) + "\n")
            self.log.warn(f"⚠ {len(secret_hosts)} hosts con posibles secretos/keys "
                          f"expuestos en su JS")

        if fetch_errors:
            self.log.warn(f"{fetch_errors} .js no se pudieron descargar (timeout/404/conexión).")

        self.log.result("Total hallazgos JS regex", total_hits)
        status = "ok" if total_hits > 0 else "empty"
        if total_hits > 0:
            self.log.ok("JS Regex completo")
        self.stats["jsregex"] = {"lines": total_hits, "time": time.time() - t0, "status": status}

    def _build_js_patterns(self) -> Dict[str, re.Pattern]:
        domain_re = re.escape(self.domain)
        return {
            "endpoints_abs": re.compile(r'https?://[^\s"\'<>\)]{4,}', re.I),
            "endpoints_rel": re.compile(r'["\'](\/[a-zA-Z0-9_\-\/\.]{2,}?)["\']'),
            "api_keys":      re.compile(
                r'(?:api[_-]?key|apikey|secret|token)["\']?\s*[:=]\s*'
                r'["\']([a-zA-Z0-9_\-\.]{12,})["\']',
                re.I,
            ),
            "aws_keys":      re.compile(r'AKIA[0-9A-Z]{16}'),
            "jwt":           re.compile(
                r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}'
            ),
            "subdomains":    re.compile(r'[a-zA-Z0-9_\-\.]+\.' + domain_re, re.I),
        }

    # ──────────────────────────────────────────────────────────────
    #   FASE 12: INTELLIGENCE — Correlación + Scoring + Targets
    # ──────────────────────────────────────────────────────────────

    def phase_intelligence(self):
        if not self.should_run("intelligence"):
            self.log.skip("Fase intelligence omitida.")
            return

        self.log.phase("FASE 12: INTELLIGENCE",
                       "💡 Correlando hallazgos y priorizando targets con scoring")
        t0 = time.time()

        host_info            = self._load_host_info()
        self.log.info(f"Tech info cargada: {len(host_info)} hosts")

        js_leak_hosts         = self._load_js_leak_hosts()
        self.log.info(f"Hosts con JS leaks (jsleak): {len(js_leak_hosts)}")

        jsregex_secret_hosts  = self._load_jsregex_secret_hosts()
        self.log.info(f"Hosts con secretos vía regex propio: {len(jsregex_secret_hosts)}")

        url_map: Dict[str, dict] = {}
        self._build_url_map(url_map, host_info, js_leak_hosts, jsregex_secret_hosts)
        self.log.info(f"URLs en url_map: {len(url_map)}")

        if not url_map:
            self.log.warn("url_map vacío. Verificá que crawl se haya ejecutado.")
            self.stats["intelligence"] = {"lines": 0, "time": 0, "status": "skip"}
            return

        gf_annotations = self._load_gf_annotations()
        for norm_url, patterns in gf_annotations.items():
            if norm_url in url_map:
                existing = set(url_map[norm_url].get("gf_matches", []))
                url_map[norm_url]["gf_matches"] = list(existing | set(patterns))

        grep_annotations = self._load_grep_annotations()
        for norm_url, categories in grep_annotations.items():
            if norm_url in url_map:
                existing = set(url_map[norm_url].get("grep_matches", []))
                url_map[norm_url]["grep_matches"] = list(existing | set(categories))

        for entry in url_map.values():
            score, reasons = self._score_entry(entry)
            entry["score"]   = score
            entry["reasons"] = reasons

        with open(self.files["url_map"], "w") as f:
            json.dump(url_map, f, indent=2, default=str)
        self.log.ok(f"url_map.json guardado ({len(url_map)} entradas)")

        sorted_entries = sorted(
            url_map.values(), key=lambda e: e["score"], reverse=True
        )

        top_n = CONFIG.get("final_targets_top_n", 200)
        self._write_final_targets(sorted_entries, top_n=top_n)

        threshold  = CONFIG["nuclei"].get("score_threshold", 5)
        high_value = [e for e in sorted_entries if e["score"] >= threshold]
        with open(self.files["high_value"], "w") as f:
            for entry in high_value:
                f.write(entry["url"] + "\n")
        self.log.result(f"High-value targets (score ≥ {threshold})", len(high_value))

        nonzero = sum(1 for e in sorted_entries if e["score"] > 0)
        self.log.result("URLs con score > 0", nonzero)
        if sorted_entries and sorted_entries[0]["score"] > 0:
            top = sorted_entries[0]
            self.log.info(f"Top score: [{top['score']}] {top['url']}")

        self.log.ok("Intelligence completo: targets priorizados")
        self.stats["intelligence"] = {
            "lines": len(url_map), "time": time.time() - t0, "status": "ok",
        }

    # -- Helpers de intelligence ------------------------------------

    def _load_host_info(self) -> Dict[str, dict]:
        host_info: Dict[str, dict] = {}
        if not self.files["live_tech"].exists():
            return host_info
        try:
            with open(self.files["live_tech"]) as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        obj    = json.loads(line)
                        url    = obj.get("url", "")
                        host   = urlparse(url).netloc or url
                        tech   = obj.get("tech", obj.get("technologies", []))
                        cdn    = bool(obj.get("cdn", obj.get("cdn-name", False)))
                        status = obj.get("status-code", obj.get("status_code", 0))
                        host_info[host] = {
                            "tech":   tech if isinstance(tech, list) else [str(tech)],
                            "cdn":    cdn,
                            "status": int(status) if status else 0,
                        }
                    except (json.JSONDecodeError, ValueError):
                        continue
        except Exception as e:
            self.log.warn(f"Error leyendo live_tech.json: {e}")
        return host_info

    def _load_js_leak_hosts(self) -> Set[str]:
        hosts: Set[str] = set()
        if not self.files["jsleak_out"].exists():
            return hosts
        url_re = re.compile(r'https?://([^/\s\]\["\',]+)')
        try:
            with open(self.files["jsleak_out"]) as f:
                for line in f:
                    for match in url_re.finditer(line):
                        hosts.add(match.group(1))
        except Exception:
            pass
        return hosts

    def _load_jsregex_secret_hosts(self) -> Set[str]:
        hosts: Set[str] = set()
        f = self.files.get("jsregex_secrets_hosts")
        if not f or not f.exists():
            return hosts
        for line in self.read_lines(f):
            if line:
                hosts.add(line)
        return hosts

    def _build_url_map(self, url_map: dict,
                       host_info: Dict[str, dict],
                       js_leak_hosts: Set[str],
                       jsregex_secret_hosts: Optional[Set[str]] = None):
        jsregex_secret_hosts = jsregex_secret_hosts or set()

        source = (self.files["urls_norm"] if self.files["urls_norm"].exists()
                  else self.files["cleanurls"])
        if not source.exists():
            return

        with open(source) as f:
            for line in f:
                url = line.strip()
                if not url:
                    continue
                norm   = normalize_url(url)
                parsed = urlparse(url)
                host   = parsed.netloc
                hinfo  = host_info.get(host, {})

                if norm in url_map:
                    continue

                url_map[norm] = {
                    "url":             url,
                    "normalized":      norm,
                    "host":            host,
                    "params":          bool(parsed.query),
                    "tech":            hinfo.get("tech", []),
                    "cdn":             hinfo.get("cdn", False),
                    "status":          hinfo.get("status", 0),
                    "gf_matches":      [],
                    "grep_matches":    [],
                    "js_leak":         host in js_leak_hosts,
                    "js_regex_secret": host in jsregex_secret_hosts,
                    "score":           0,
                    "reasons":         [],
                }

    def _load_gf_annotations(self) -> Dict[str, List[str]]:
        annotations: Dict[str, List[str]] = {}
        if not self.dirs["gf"].exists():
            return annotations
        for gf_file in self.dirs["gf"].glob("gf_*.txt"):
            pattern = gf_file.stem.replace("gf_", "")
            try:
                with open(gf_file) as f:
                    for line in f:
                        url = line.strip()
                        if url:
                            norm = normalize_url(url)
                            annotations.setdefault(norm, []).append(pattern)
            except Exception:
                continue
        return annotations

    def _load_grep_annotations(self) -> Dict[str, List[str]]:
        annotations: Dict[str, List[str]] = {}
        if not self.dirs["grep"].exists():
            return annotations
        for grep_file in self.dirs["grep"].glob("*.txt"):
            category = grep_file.stem
            try:
                with open(grep_file) as f:
                    for line in f:
                        url = line.strip()
                        if url:
                            norm = normalize_url(url)
                            annotations.setdefault(norm, []).append(category)
            except Exception:
                continue
        return annotations

    def _score_entry(self, entry: dict) -> Tuple[int, List[str]]:
        w         = CONFIG["scoring"]
        score     = 0
        reasons: List[str] = []

        if entry.get("params"):
            score += w["has_params"]
            reasons.append("has_params")

        gf_critical = {"sqli", "ssrf", "ssti", "rce", "lfi"}
        gf_high     = {"xss", "idor", "cors"}
        for pattern in entry.get("gf_matches", []):
            if pattern in gf_critical:
                score += w["gf_critical"]
                reasons.append(f"gf:{pattern}(critical)")
            elif pattern in gf_high:
                score += w["gf_high"]
                reasons.append(f"gf:{pattern}(high)")
            else:
                score += w["gf_medium"]
                reasons.append(f"gf:{pattern}")

        grep_critical = {"secret", "aws", "sql", "password", "backup",
                         "firebase", "git"}
        for cat in entry.get("grep_matches", []):
            if cat in grep_critical:
                score += w["grep_critical"]
                reasons.append(f"grep:{cat}(critical)")
            else:
                score += w["grep_medium"]
                reasons.append(f"grep:{cat}")

        if entry.get("js_leak"):
            score += w["js_leak_host"]
            reasons.append("js_leak_on_host")

        if entry.get("js_regex_secret"):
            score += w["js_regex_secret_host"]
            reasons.append("js_regex_secret_on_host")

        tech_str = " ".join(t.lower() for t in entry.get("tech", []))
        legacy = [("php", "php"), ("java", "java/jsp"), ("asp", "dotnet"),
                  ("wordpress", "wordpress"), ("laravel", "laravel"),
                  ("struts", "struts"), ("coldfusion", "coldfusion")]
        for key, label in legacy:
            if key in tech_str:
                score += w["tech_legacy"]
                reasons.append(f"tech:{label}")
                break

        if entry.get("status") == 200:
            score += w["status_200"]
            reasons.append("status:200")

        if entry.get("cdn"):
            score += w["cdn_penalty"]
            reasons.append("cdn(penalty)")

        for focus in self.focus_areas:
            fmap  = CONFIG["focus_map"].get(focus, {})
            boost = fmap.get("score_boost", 0)
            f_gf   = set(fmap.get("gf",   []))
            f_grep = set(fmap.get("grep", []))
            gf_hit   = f_gf   & set(entry.get("gf_matches",   []))
            grep_hit = f_grep & set(entry.get("grep_matches", []))
            if gf_hit or grep_hit:
                score += boost
                reasons.append(f"focus:{focus}+{boost}")

        return max(score, 0), reasons

    def _write_final_targets(self, sorted_entries: list, top_n: int = 200):
        with open(self.files["final_targets"], "w") as f:
            f.write("=" * 76 + "\n")
            f.write(f"  PENTESTFLOW v3 — FINAL TARGETS  |  {self.domain}\n")
            f.write(f"  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"  Top {top_n} por score\n")
            f.write("=" * 76 + "\n\n")

            written = 0
            for entry in sorted_entries:
                if entry["score"] == 0 or written >= top_n:
                    break

                score    = entry["score"]
                url      = entry["url"]
                host     = entry["host"]
                tech     = ", ".join(entry.get("tech", [])) or "unknown"
                cdn_flag = "  [CDN]" if entry.get("cdn") else ""
                status   = entry.get("status", "-")
                gf       = ", ".join(entry.get("gf_matches",   [])) or "-"
                grep_m   = ", ".join(entry.get("grep_matches", [])) or "-"
                js_flag  = "  ⚠ JS LEAK" if entry.get("js_leak") else ""
                sec_flag = "  ⚠ JS SECRET" if entry.get("js_regex_secret") else ""
                reasons  = " | ".join(entry.get("reasons", []))

                bar_fill = min(score, 20)
                bar      = "█" * bar_fill + "░" * (20 - bar_fill)

                f.write(f"[{score:>3}] {url}\n")
                f.write(f"      [{bar}]{js_flag}{sec_flag}\n")
                f.write(f"      host    : {host}{cdn_flag}  HTTP={status}\n")
                f.write(f"      tech    : {tech}\n")
                f.write(f"      gf      : {gf}\n")
                f.write(f"      grep    : {grep_m}\n")
                f.write(f"      reasons : {reasons}\n")
                f.write("\n")
                written += 1

            if written == 0:
                f.write("  Sin targets con score > 0.\n")
                f.write("  Verificá que grep/gf/jsleak/jsregex se hayan ejecutado correctamente.\n")

        self.log.result(f"final_targets.txt generado (top {top_n})", written)
        self.log.info(f"→ {self.files['final_targets']}")

    # ──────────────────────────────────────────────────────────────
    #   FASE 13: NUCLEI — Run A (hosts) + Run B (URLs scored)
    # ──────────────────────────────────────────────────────────────

    def phase_nuclei(self):
        if not self.should_run("nuclei"):
            self.log.skip("Fase nuclei omitida.")
            return
        if not CONFIG["nuclei"]["enabled"] or not self.check_tool("nuclei"):
            return

        self.log.phase("FASE 13: NUCLEI",
                       "⚡ Ejecutando Nuclei sobre hosts vivos y URLs scored")
        t0 = time.time()

        count_a = 0
        if self.files["live"].exists() and self.count_lines(self.files["live"]) > 0:
            host_templates = ",".join(CONFIG["nuclei"]["host_templates"])
            self.log.info(f"[A] Templates: {host_templates}")
            cmd = self.build_cmd(
                CONFIG["nuclei"]["cmd"],
                input_file=self.files["live"],
                output_file=self.files["nuclei_hosts"],
                extra={"{templates}": host_templates},
            )
            self.run_cmd("nuclei (hosts)", cmd,
                         output_file=self.files["nuclei_hosts"],
                         timeout=86400)
            count_a = self.count_lines(self.files["nuclei_hosts"])
            self.log.result("[A] Hallazgos en hosts", count_a)
        else:
            self.log.warn("live.txt vacío, saltando nuclei run A.")

        count_b = 0
        if self.files["high_value"].exists() and self.count_lines(self.files["high_value"]) > 0:
            url_templates = ",".join(CONFIG["nuclei"]["url_templates"])
            threshold     = CONFIG["nuclei"].get("score_threshold", 5)
            hv_count      = self.count_lines(self.files["high_value"])
            self.log.info(f"[B] {hv_count} targets scored (threshold={threshold})")
            self.log.info(f"[B] Templates: {url_templates}")
            cmd = self.build_cmd(
                CONFIG["nuclei"]["cmd"],
                input_file=self.files["high_value"],
                output_file=self.files["nuclei_urls"],
                extra={"{templates}": url_templates},
            )
            self.run_cmd("nuclei (URLs)", cmd,
                         output_file=self.files["nuclei_urls"],
                         timeout=86400)
            count_b = self.count_lines(self.files["nuclei_urls"])
            self.log.result("[B] Hallazgos en URLs scored", count_b)
        else:
            self.log.warn("high_value_targets.txt vacío o no generado.")
            self.log.info("Tip: ejecutá la fase 'intelligence' para generarlo.")

        total = count_a + count_b
        self.log.result("Hallazgos nuclei totales", total)
        if total > 0:
            self.log.ok("Nuclei completo: hallazgos recopilados")
        self.stats["nuclei"] = {"lines": total, "time": time.time() - t0, "status": "ok"}

    # ──────────────────────────────────────────────────────────────
    #   DIFF ENTRE RUNS — Detecta cambios vs run anterior
    # ──────────────────────────────────────────────────────────────

    def _diff_runs(self):
        self.log.phase("DIFF ENTRE RUNS",
                       "Detectando cambios vs run anterior")

        current_subs = set(self.read_lines(self.files["allsubs"]))
        current_urls = set(self.read_lines(self.files["cleanurls"]))

        prev_subs_snap = self._find_latest_snapshot("allsubs")
        prev_urls_snap = self._find_latest_snapshot("cleanurls")

        if prev_subs_snap:
            prev_subs = set(self.read_lines(prev_subs_snap))
            new_subs  = current_subs - prev_subs
            gone_subs = prev_subs - current_subs

            if new_subs:
                with open(self.files["new_subs"], "w") as f:
                    f.write("\n".join(sorted(new_subs)) + "\n")
                self.log.result("🆕 Nuevos subdominios detectados", len(new_subs))
                self.log.warn(
                    f"Tip: {len(new_subs)} nuevos subdominios — "
                    f"correlos de nuevo con --only resolve,httpx,dns,takeover,crawl,"
                    f"grep,gf,jsleak,jsregex,intelligence,nuclei "
                    f"para procesarlos completamente."
                )
            else:
                self.log.info("Sin nuevos subdominios vs run anterior.")

            if gone_subs:
                with open(self.files["gone_subs"], "w") as f:
                    f.write("\n".join(sorted(gone_subs)) + "\n")
                self.log.info(f"Subdominios desaparecidos: {len(gone_subs)}")
        else:
            self.log.info("Sin snapshot anterior de subdominios (primer run).")

        if prev_urls_snap:
            prev_urls = set(self.read_lines(prev_urls_snap))
            new_urls  = current_urls - prev_urls

            if new_urls:
                with open(self.files["new_urls"], "w") as f:
                    f.write("\n".join(sorted(new_urls)) + "\n")
                self.log.result("🆕 Nuevas URLs detectadas", len(new_urls))
            else:
                self.log.info("Sin nuevas URLs vs run anterior.")
        else:
            self.log.info("Sin snapshot anterior de URLs (primer run).")

        ts      = self.start_time.strftime("%Y%m%d_%H%M%S")
        history = self.dirs["history"]
        if current_subs and self.files["allsubs"].exists():
            shutil.copy2(self.files["allsubs"],   history / f"{ts}_allsubs.txt")
        if current_urls and self.files["cleanurls"].exists():
            shutil.copy2(self.files["cleanurls"], history / f"{ts}_cleanurls.txt")
        self.log.info(f"Snapshot guardado: {ts}")

    def _find_latest_snapshot(self, name: str) -> Optional[Path]:
        current_ts = self.start_time.strftime("%Y%m%d_%H%M%S")
        candidates = sorted(
            self.dirs["history"].glob(f"*_{name}.txt"),
            reverse=True,
        )
        for c in candidates:
            if current_ts not in c.name:
                return c
        return None

    # ──────────────────────────────────────────────────────────────
    #   RESUMEN FINAL
    # ──────────────────────────────────────────────────────────────

    def print_summary(self):
        elapsed = (datetime.now() - self.start_time).total_seconds()

        print(f"\n{C.BOLD}{C.CYAN}{'═' * 72}{C.RESET}")
        print(f"{C.BOLD}{C.CYAN}  RESUMEN  ─  {self.domain}{C.RESET}")
        print(f"{C.BOLD}{C.CYAN}{'═' * 72}{C.RESET}")

        labels = {
            "recon":        "Subdominios únicos",
            "resolve":      "Subdominios resueltos (externo)",
            "httpx":        "Hosts vivos",
            "dns":          "Registros DNS",
            "takeover":     "Hallazgos takeover",
            "social":       "Hallazgos OSINT",
            "crawl":        "URLs limpias",
            "grep":         "URLs categorizadas",
            "gf":           "URLs con patrones gf",
            "jsleak":       "Hallazgos JS (jsleak)",
            "jsregex":      "Hallazgos JS (regex propio)",
            "intelligence": "URLs en url_map",
            "nuclei":       "Findings nuclei",
        }

        for phase, label in labels.items():
            if phase in self.stats:
                s    = self.stats[phase]
                mins = int(s["time"] // 60)
                secs = int(s["time"] % 60)

                status = s.get("status", "ok")
                if status == "ok":
                    icon = C.GREEN + "✓" + C.RESET
                elif status == "empty":
                    icon = C.YELLOW + "⚠" + C.RESET
                elif status == "skip":
                    icon = C.DIM + "-" + C.RESET
                else:
                    icon = C.RED + "✗" + C.RESET

                line = (f"  {icon} {label:<36}"
                        f"{C.YELLOW}{s['lines']:<8}{C.RESET}"
                        f"{C.DIM}({mins}m{secs}s){C.RESET}")

                if status == "empty":
                    line += f"  {C.YELLOW}← sin output{C.RESET}"

                print(line)

        total_mins = int(elapsed // 60)
        total_secs = int(elapsed % 60)
        print(f"{C.BOLD}{C.CYAN}{'─' * 72}{C.RESET}")
        print(f"  {C.BOLD}Tiempo total:{C.RESET}  {total_mins}m {total_secs}s")
        print(f"  {C.BOLD}Resultados:{C.RESET}    {C.WHITE}{self.base_dir}{C.RESET}")
        print(f"{C.BOLD}{C.CYAN}{'═' * 72}{C.RESET}\n")

        self.log.info("Archivos generados:")
        key_files = [
            ("allsubs.txt",             self.files["allsubs"]),
            ("resolved.txt",            self.files["resolved"]),
            ("unresolved.txt",          self.files["unresolved"]),
            ("live.txt",                self.files["live"]),
            ("cname_hosts.txt",         self.files["cname_hosts"]),
            ("takeover_findings.txt",   self.files["takeover"]),
            ("cleanurls.txt",           self.files["cleanurls"]),
            ("urls_normalized.txt",     self.files["urls_norm"]),
            ("secrets_hosts.txt (JS)",  self.files["jsregex_secrets_hosts"]),
            ("final_targets.txt  ⭐",   self.files["final_targets"]),
            ("high_value_targets.txt",  self.files["high_value"]),
            ("url_map.json",            self.files["url_map"]),
            ("findings_hosts.txt",      self.files["nuclei_hosts"]),
            ("findings_urls.txt",       self.files["nuclei_urls"]),
            ("new_subdomains.txt",      self.files["new_subs"]),
            ("new_urls.txt",            self.files["new_urls"]),
        ]
        for label, path in key_files:
            if path.exists() and path.stat().st_size > 0:
                lines = self.count_lines(path)
                size  = path.stat().st_size / 1024
                print(f"    {C.GREEN}→{C.RESET} {label:<36}"
                      f"{C.DIM}({lines} líneas, {size:.1f}KB){C.RESET}")

        self.log.close()

    # ──────────────────────────────────────────────────────────────
    #   ORQUESTADOR PRINCIPAL
    # ──────────────────────────────────────────────────────────────

    def run(self):
        banner()
        self.log.info(f"Objetivo   : {C.BOLD}{self.domain}{C.RESET}")
        self.log.info(f"Output dir : {self.base_dir}")
        self.log.info(f"Inicio     : {self.start_time.strftime('%Y-%m-%d %H:%M:%S')}")
        self.log.info(f"VPN-safe   : {CONFIG['vpn_safe']['max_parallel_tools']} tools en paralelo, "
                      f"stagger {CONFIG['vpn_safe']['stagger_delay']}s")

        if self.focus_areas:
            self.log.info(f"Focus mode : {', '.join(self.focus_areas)}")
        if self.only_phases:
            self.log.info(f"Solo fases : {', '.join(self.only_phases)}")
        if self.skip_phases:
            self.log.info(f"Skip fases : {', '.join(self.skip_phases)}")

        self.phase_recon()
        self.phase_resolve()
        self.phase_httpx()
        self.phase_dns()
        self.phase_takeover()
        self.phase_social()
        self.phase_crawl()
        self.phase_grep()
        self.phase_gf()
        self.phase_jsleak()
        self.phase_js_regex()
        self.phase_intelligence()
        self.phase_nuclei()
        self._diff_runs()

        self.print_summary()


# ═══════════════════════════════════════════════════════════════
#   VERIFICACIÓN DE DEPENDENCIAS
# ═══════════════════════════════════════════════════════════════

ALL_TOOLS = [
    "subfinder", "assetfinder", "sublist3r", "findomain", "shodanx",
    "dnsx", "httpx", "socialhunter", "katana", "gau", "waybackurls",
    "uro", "gf", "jsleak", "subzy", "nuclei",
]


def check_dependencies(log: Optional[Logger] = None):
    if log is None:
        log = Logger()
    log.phase("VERIFICACIÓN DE DEPENDENCIAS")
    missing = []
    for tool in ALL_TOOLS:
        if shutil.which(tool):
            log.ok(tool)
        else:
            log.warn(f"{tool}  ← NO ENCONTRADO")
            missing.append(tool)

    # crtsh es un script python, no un binario en PATH: chequeo aparte
    crtsh_cfg   = CONFIG["recon_tools"].get("crtsh", {})
    script_path = crtsh_cfg.get("script_path", "")
    if script_path:
        if Path(script_path).expanduser().exists():
            log.ok(f"crtsh.py ({script_path})")
        else:
            log.warn(f"crtsh.py  ← NO ENCONTRADO en {script_path} "
                     f"(editá CONFIG['recon_tools']['crtsh']['script_path'])")
            missing.append("crtsh.py")

    if missing:
        print(f"\n{C.YELLOW}  Faltantes:{C.RESET} {', '.join(missing)}")
        print(f"  {C.DIM}Revisá la documentación de instalación de cada tool.{C.RESET}")
    else:
        print(f"\n{C.GREEN}  Todas las herramientas disponibles.{C.RESET}")
    return len(missing) == 0


# ═══════════════════════════════════════════════════════════════
#   ARGPARSE + MAIN
# ═══════════════════════════════════════════════════════════════

def parse_args():
    parser = argparse.ArgumentParser(
        description="BountyFlow v3 - Recon Profundo + Intelligence (VPN-safe)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ejemplos:
  python3 bountyflow.py -d example.com
  python3 bountyflow.py -d example.com --skip nuclei,jsleak
  python3 bountyflow.py -d example.com --only recon,resolve,httpx,crawl
  python3 bountyflow.py -d example.com --focus api
  python3 bountyflow.py -d example.com --focus auth,upload
  python3 bountyflow.py -d example.com --output ~/pentests
  python3 bountyflow.py --check

Fases disponibles:
  recon, resolve, httpx, dns, takeover, social, crawl, grep, gf,
  jsleak, jsregex, intelligence, nuclei

Modos de foco (--focus):
  api, auth, upload, admin, secrets, sqli, ssrf
        """,
    )
    parser.add_argument("-d", "--domain",
                        help="Dominio objetivo (ej: example.com)")
    parser.add_argument("-o", "--output", default="./output",
                        help="Directorio de salida (default: ./output)")
    parser.add_argument("--skip", default="",
                        help="Fases a omitir, separadas por coma (ej: --skip nuclei,jsleak)")
    parser.add_argument("--only", default="",
                        help="Ejecutar SOLO estas fases (ej: --only recon,resolve,httpx)")
    parser.add_argument("--focus", default="",
                        help="Modo focus: filtra grep/gf y boostea scoring "
                             "(ej: --focus api,auth)")
    parser.add_argument("--check", action="store_true",
                        help="Verificar herramientas instaladas y salir")
    return parser.parse_args()


def main():
    args = parse_args()

    if args.check:
        check_dependencies()
        sys.exit(0)

    if not args.domain:
        print(f"{C.RED}Error:{C.RESET} Especificá un dominio con -d / --domain")
        print("       Usá --help para ver todas las opciones.")
        sys.exit(1)

    if not validate_domain(args.domain):
        print(f"{C.RED}Error:{C.RESET} '{args.domain}' no tiene un formato válido.")
        print("       Ejemplo válido: example.com, sub.example.co.uk")
        sys.exit(1)

    skip_phases = [p.strip() for p in args.skip.split(",")  if p.strip()]
    only_phases = [p.strip() for p in args.only.split(",")  if p.strip()]
    focus_areas = [f.strip() for f in args.focus.split(",") if f.strip()]
    output_dir  = Path(args.output).expanduser().resolve()

    valid_focus = set(CONFIG["focus_map"].keys())
    for fa in focus_areas:
        if fa not in valid_focus:
            print(f"{C.YELLOW}Aviso:{C.RESET} Focus '{fa}' no reconocido. "
                  f"Válidos: {', '.join(sorted(valid_focus))}")

    flow = PentestFlow(
        domain=args.domain,
        output_dir=output_dir,
        skip_phases=skip_phases,
        only_phases=only_phases,
        focus_areas=focus_areas,
    )
    flow.run()


if __name__ == "__main__":
    main()
