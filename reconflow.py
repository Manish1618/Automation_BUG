#!/usr/bin/env python3
"""
ReconFlow - step-by-step recon orchestrator for AUTHORIZED security testing.

Runs the early recon phases you normally do by hand, in order, and writes one
consolidated report (terminal + report.json + report.html):

    resolve -> port scan -> HTTP probe -> content/directory discovery

Enumeration and information gathering only. No exploitation, no credential
testing, no detection evasion. Use exclusively against assets you are
explicitly authorized to test (bug bounty scope / written permission).
"""

import argparse
import asyncio
import hashlib
import html
import json
import random
import re
import shutil
import socket
import string
import sys
import tempfile
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

# ---- optional deps (fail soft with a clear message) ------------------------
try:
    import aiohttp
except Exception:
    aiohttp = None

try:
    import yaml
except Exception:
    yaml = None

# Arbitrary servers return non-UTF-8 bytes in headers/titles; make the terminal
# writer tolerant so a stray byte can never crash a scan mid-run.
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

try:
    from rich.console import Console
    _console = Console()
except Exception:
    class _Shim:
        _tag = re.compile(r"\[/?[a-zA-Z0-9 _#]+\]")
        def print(self, *a, **k):
            print(*[self._tag.sub("", str(x)) for x in a])
        def rule(self, title=""):
            print("== " + self._tag.sub("", str(title)) + " ==")
    _console = _Shim()

BANNER = "ReconFlow 1.0 - recon orchestrator (authorized testing only)"

# ---- constants -------------------------------------------------------------
COMMON_PORTS = [
    21, 22, 23, 25, 53, 67, 69, 80, 81, 88, 110, 111, 123, 135, 137, 139, 143,
    161, 179, 389, 443, 445, 465, 500, 514, 515, 520, 548, 554, 587, 593, 623,
    631, 636, 873, 902, 993, 995, 1025, 1080, 1099, 1194, 1234, 1433, 1434,
    1521, 1723, 1883, 2049, 2082, 2083, 2086, 2087, 2095, 2096, 2181, 2222,
    2375, 2376, 3000, 3128, 3268, 3306, 3389, 3690, 4000, 4040, 4443, 4444,
    4567, 4646, 4848, 5000, 5001, 5432, 5555, 5601, 5672, 5900, 5901, 5984,
    5985, 5986, 6379, 6443, 6666, 6667, 7000, 7001, 7077, 7443, 7474, 7687,
    8000, 8008, 8009, 8010, 8080, 8081, 8082, 8083, 8086, 8088, 8089, 8090,
    8091, 8140, 8161, 8443, 8500, 8530, 8888, 8983, 9000, 9001, 9042, 9060,
    9090, 9091, 9200, 9300, 9443, 9990, 9999, 10000, 11211, 15672, 27017,
    27018, 50070, 61616,
]

SERVICE_OVERRIDES = {
    8080: "http-proxy", 8443: "https-alt", 8000: "http-alt", 8888: "http-alt",
    3000: "node/dev", 5000: "flask/upnp", 9200: "elasticsearch",
    9300: "elasticsearch", 27017: "mongodb", 27018: "mongodb", 6379: "redis",
    5432: "postgresql", 3306: "mysql", 1433: "mssql", 389: "ldap", 636: "ldaps",
    445: "smb", 3389: "rdp", 5900: "vnc", 11211: "memcached", 2375: "docker",
    2376: "docker-tls", 9000: "php-fpm/sonarqube", 5601: "kibana",
    15672: "rabbitmq-mgmt", 5672: "amqp", 7474: "neo4j", 8983: "solr",
}

HTTPS_PORTS = {443, 8443, 9443, 4443, 7443, 6443, 10443, 8834}
HTTP_PORTS = {80, 8080, 8000, 8008, 8081, 8082, 8083, 8088, 8090, 8983,
              3000, 5000, 9000, 9090, 8888, 5601, 9200, 8161, 4040}
NON_WEB_PORTS = {21, 22, 23, 25, 53, 110, 111, 135, 137, 139, 143, 161, 179,
                 389, 445, 465, 500, 514, 587, 636, 993, 995, 1433, 1521, 2049,
                 3306, 3389, 5432, 5900, 6379, 11211, 27017, 27018, 5672}
FALLBACK_WEB_PORTS = [80, 443, 8080, 8443, 8000, 3000, 5000]

# Ports that conventionally host a real HTTP/HTTPS app. Content discovery and the
# security audit only run against these by default, so a host that fakes HTTP on
# non-web ports (RTSP/IPP/MQTT/Docker/etc.) doesn't get pointlessly fuzzed.
# Any HTTPS service is always treated as a web surface regardless of port.
WEB_PORTS = HTTP_PORTS | HTTPS_PORTS | {
    80, 443, 81, 591, 2080, 3001, 4000, 4443, 5001, 7000, 7001, 7002, 8001,
    8085, 8180, 8280, 8444, 8880, 9001, 9080, 9443, 10000,
    2082, 2083, 2086, 2087, 2095, 2096,  # cPanel / WHM / webmail
}

TITLE_RE = re.compile(rb"<title[^>]*>(.*?)</title>", re.I | re.S)
# Attribute values that reference same-app resources (depth-1 link extraction).
LINK_RE = re.compile(rb"""(?:href|src|action)\s*=\s*["']([^"'>\s]+)["']""", re.I)

# High-signal paths always tried, even without SecLists. Fixes "can't find /login".
BUILTIN_PATHS = [
    "login", "log-in", "signin", "sign-in", "logout", "register", "signup",
    "sign-up", "auth", "oauth", "sso", "account", "accounts", "profile", "user",
    "users", "admin", "administrator", "admin/login", "wp-admin", "wp-login.php",
    "dashboard", "portal", "cms", "console", "manage", "management",
    "password-reset", "forgot-password", "reset-password", "verify",
    "api", "api/v1", "api/v2", "graphql", "rest", "swagger", "swagger-ui",
    "swagger-ui.html", "openapi.json", "api-docs", "docs", "redoc",
    "health", "healthz", "status", "metrics", "actuator", "actuator/health",
    "debug", "test", "dev", "staging", "old", "backup", "backups", "tmp",
    "config", "configuration", "settings", "phpinfo.php", "phpmyadmin",
    "server-status", "server-info", "robots.txt", "sitemap.xml", "crossdomain.xml",
    ".env", ".git/HEAD", ".git/config", ".svn/entries", ".DS_Store",
    "web.config", "config.json", "credentials", "secrets",
    "upload", "uploads", "files", "download", "downloads", "static", "assets",
    "media", "images", "img", "css", "js", "home", "index", "about", "contact",
    "search", "cart", "checkout", "orders", "payment", "billing", "invoice",
    "report", "reports", "export", "import", "webhook", "callback", "internal",
]

CSS = """
body{background:#0d1117;color:#c9d1d9;font:14px/1.5 -apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;margin:0}
.wrap{max-width:1000px;margin:0 auto;padding:24px 16px}
h1{color:#58a6ff;margin:0 0 4px}
h2{color:#79c0ff;border-bottom:1px solid #21262d;padding-bottom:6px;margin-top:32px}
h3{color:#d2a8ff;margin-top:20px;font-size:14px;word-break:break-all}
.muted{color:#8b949e}
.foot{color:#8b949e;margin-top:40px;font-size:12px;border-top:1px solid #21262d;padding-top:12px}
table{border-collapse:collapse;width:100%;margin:8px 0;font-size:13px}
th,td{border:1px solid #21262d;padding:6px 8px;text-align:left;vertical-align:top;word-break:break-all}
th{background:#161b22;color:#8b949e;font-weight:600}
a{color:#58a6ff;text-decoration:none} a:hover{text-decoration:underline}
.s2{color:#3fb950} .s3{color:#d29922} .s4{color:#f85149} .s5{color:#ff7b72}
.sev-critical{color:#ff7b72;font-weight:700}.sev-high{color:#f85149;font-weight:700}
.sev-medium{color:#d29922}.sev-low{color:#58a6ff}.sev-info{color:#8b949e}.sev-unknown{color:#8b949e}
"""

DEFAULT_CONFIG = {
    "seclists_paths": [
        "/usr/share/seclists", "/usr/share/wordlists/seclists", "~/SecLists",
        "~/tools/SecLists", "./SecLists", "C:/Tools/SecLists", "C:/SecLists",
    ],
    "wordlists": {
        "common": "Discovery/Web-Content/common.txt",
        "small": "Discovery/Web-Content/directory-list-2.3-small.txt",
        "medium": "Discovery/Web-Content/directory-list-2.3-medium.txt",
        "big": "Discovery/Web-Content/big.txt",
        "raft": "Discovery/Web-Content/raft-small-directories.txt",
        "exposed": "Discovery/Web-Content/quickhits.txt",
        "api": "Discovery/Web-Content/api/api-endpoints.txt",
    },
    "defaults": {
        "ports": "common", "wordlist": "common", "http_concurrency": 30,
        "port_concurrency": 500, "port_timeout": 1.0, "http_timeout": 8.0,
        "delay": 0.0, "extensions": [],
        "match_codes": [200, 204, 301, 302, 307, 401, 403, 405, 500],
        "user_agent": "ReconFlow/1.0 (+authorized-security-testing)",
        "mode": "sequential", "max_parallel_hosts": 5,
        "nuclei_bin": "nuclei", "wpscan_bin": "wpscan",
        "severity": "low,medium,high,critical", "nuclei_rate": 150,
        "wpscan_api_token": "",
    },
}


# ---- data models -----------------------------------------------------------
@dataclass
class HttpResult:
    url: str
    final_url: str
    port: int
    status: int
    server: str = ""
    powered_by: str = ""
    title: str = ""
    content_type: str = ""
    length: int = 0
    tech: list = field(default_factory=list)
    links: list = field(default_factory=list)


@dataclass
class ContentHit:
    url: str
    status: int
    length: int
    content_type: str = ""
    redirect: str = ""


@dataclass
class VulnFinding:
    source: str          # nuclei | wpscan
    name: str
    severity: str = "info"
    location: str = ""
    reference: str = ""


# ---- config ----------------------------------------------------------------
def load_config(path):
    cfg = {k: (dict(v) if isinstance(v, dict) else list(v) if isinstance(v, list) else v)
           for k, v in DEFAULT_CONFIG.items()}
    p = Path(path)
    if p.exists() and yaml:
        try:
            data = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
            for k, v in data.items():
                cfg[k] = v
        except Exception as e:
            _console.print(f"[yellow]Could not parse {path}: {e}; using built-in defaults[/]")
    elif p.exists() and not yaml:
        _console.print("[yellow]PyYAML not installed; using built-in defaults. pip install -r requirements.txt[/]")
    return cfg


# ---- helpers ---------------------------------------------------------------
def service_name(port):
    if port in SERVICE_OVERRIDES:
        return SERVICE_OVERRIDES[port]
    try:
        return socket.getservbyport(port, "tcp")
    except Exception:
        return "unknown"


def parse_ports(spec, common):
    spec = str(spec).strip().lower()
    if spec == "common":
        return sorted(set(common))
    if spec in ("full", "all"):
        return list(range(1, 65536))
    ports = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            a, b = part.split("-", 1)
            ports.update(range(int(a), int(b) + 1))
        else:
            ports.add(int(part))
    return sorted(p for p in ports if 1 <= p <= 65535)


def parse_int_list(s):
    return [int(x) for x in str(s).split(",") if str(x).strip()]


async def bounded_gather(factories, limit):
    """Run zero-arg coroutine factories concurrently, at most `limit` at once."""
    sem = asyncio.Semaphore(max(1, limit))

    async def _run(factory):
        async with sem:
            return await factory()

    return await asyncio.gather(*(_run(f) for f in factories))


def make_url(scheme, host, port):
    if (scheme == "http" and port == 80) or (scheme == "https" and port == 443):
        return f"{scheme}://{host}"
    return f"{scheme}://{host}:{port}"


def urls_for_port(host, port):
    if port in HTTPS_PORTS:
        return [make_url("https", host, port)]
    if port in HTTP_PORTS:
        return [make_url("http", host, port)]
    if port in NON_WEB_PORTS:
        return []
    return [make_url("http", host, port), make_url("https", host, port)]


def clean_text(s):
    """Drop surrogate/control chars so arbitrary server bytes can't crash output.

    Non-UTF-8 header/title bytes get decoded to lone surrogates (\\udcXX); writing
    those to a UTF-8 terminal or file raises UnicodeEncodeError, so we strip them.
    """
    if not s:
        return s
    return "".join(c for c in str(s)
                   if c == " " or (c.isprintable() and not 0xD800 <= ord(c) <= 0xDFFF))


def scrub(obj):
    """Recursively clean every string in a report structure before writing it out."""
    if isinstance(obj, str):
        return clean_text(obj)
    if isinstance(obj, list):
        return [scrub(x) for x in obj]
    if isinstance(obj, dict):
        return {k: scrub(v) for k, v in obj.items()}
    return obj


def extract_title(body):
    m = TITLE_RE.search(body or b"")
    if not m:
        return ""
    try:
        t = m.group(1).decode("utf-8", "ignore")
    except Exception:
        t = ""
    return clean_text(" ".join(t.split())[:200])


def extract_links(body, base_url):
    """Depth-1 link extraction: same-host paths referenced by the page.

    Finds routes like /login and /register that are linked from the page but
    may not be in any wordlist. Returns clean relative paths (no leading '/').
    """
    try:
        base = urlparse(base_url)
    except Exception:
        return []
    out, seen = [], set()
    for m in LINK_RE.finditer(body or b""):
        try:
            raw = m.group(1).decode("utf-8", "ignore").strip()
        except Exception:
            continue
        if not raw or raw.startswith(("#", "mailto:", "tel:", "javascript:", "data:")):
            continue
        u = urlparse(raw)
        if u.scheme in ("http", "https"):
            if u.hostname and base.hostname and u.hostname != base.hostname:
                continue  # off-site link
            path = u.path
        elif u.scheme:
            continue  # non-web scheme
        else:
            path = u.path
        path = (path or "").lstrip("/").strip()
        if not path or len(path) > 128 or path in seen:
            continue
        seen.add(path)
        out.append(path)
    return out


def detect_tech(headers, body):
    server = headers.get("Server", "")
    powered = headers.get("X-Powered-By", "")
    cookies = headers.get("Set-Cookie", "")
    hay = f"{server} {powered} {cookies}".lower()
    b = (body or b"")[:200_000].lower()
    checks = {
        "nginx": "nginx" in hay,
        "apache": "apache" in hay,
        "iis": "iis" in hay or "asp.net" in hay,
        "php": "php" in hay or b".php" in b,
        "wordpress": b"wp-content" in b or b"wp-includes" in b,
        "drupal": b"drupal" in b,
        "joomla": b"joomla" in b,
        "laravel": "laravel_session" in cookies.lower(),
        "django": "csrftoken" in cookies.lower(),
        "express": "express" in hay,
        "cloudflare": "cloudflare" in hay,
        "tomcat": "tomcat" in hay or b"apache tomcat" in b,
        "jenkins": "jenkins" in hay or b"jenkins" in b,
        "grafana": b"grafana" in b,
        "kibana": b"kbn-name" in b or "kbn" in hay,
    }
    return [name for name, hit in checks.items() if hit]


def find_seclists_base(args, cfg):
    cands = []
    if args.seclists:
        cands.append(args.seclists)
    cands += cfg.get("seclists_paths", [])
    for c in cands:
        p = Path(str(c)).expanduser()
        if p.exists() and p.is_dir():
            return p
    return None


def resolve_wordlist(name, cfg, base):
    p = Path(name).expanduser()
    if p.exists() and p.is_file():
        return str(p)
    wl = cfg.get("wordlists", {})
    if name in wl and base:
        cand = base / wl[name]
        if cand.exists():
            return str(cand)
    return None


def load_words(args, cfg, console):
    base = find_seclists_base(args, cfg)
    names = [n.strip() for n in str(args.wordlist).split(",") if n.strip()]
    words, seen = [], set()
    # Built-in high-signal paths first, so /login, /admin, .env etc. are always
    # tried even when SecLists is absent or the chosen list is tiny.
    if not getattr(args, "no_builtin", False):
        for w in BUILTIN_PATHS:
            if w not in seen:
                seen.add(w)
                words.append(w)
    missing = []
    for name in names:
        path = resolve_wordlist(name, cfg, base)
        if not path:
            missing.append(name)
            continue
        try:
            for line in Path(path).read_text(encoding="utf-8", errors="ignore").splitlines():
                w = line.strip()
                if not w or w.startswith("#"):
                    continue
                w = w.lstrip("/")
                if w not in seen:
                    seen.add(w)
                    words.append(w)
        except Exception as e:
            console.print(f"[yellow]Could not read {path}: {e}[/]")
    if missing:
        only = " only" if len(missing) == len(names) else ""
        console.print(f"[yellow]Wordlist(s) not found: {', '.join(missing)}.[/] "
                      f"Using built-in paths{only}. Point --seclists / config.yaml at "
                      f"SecLists, or pass a file path.")
        if base is None:
            console.print("[dim]No SecLists directory found on this machine.[/]")
    if args.max_paths and len(words) > args.max_paths:
        words = words[: args.max_paths]
    return words


def is_web_surface(r):
    """True if this probed service is a genuine HTTP/HTTPS web surface worth fuzzing.

    A web-port responder, or any HTTPS service on any port. This filters out hosts
    that answer HTTP on non-web ports (RTSP/IPP/MQTT/Docker/etc.).
    """
    try:
        scheme = urlparse(r.final_url or r.url).scheme
    except Exception:
        scheme = ""
    return r.port in WEB_PORTS or scheme == "https"


def compute_bases(args, http_results, web_only=False):
    """Origins to fuzz/audit. Every genuine HTTP/HTTPS responder is a web surface
    (a real web server on a non-standard port still counts). With web_only, restrict
    to recognized web ports to tame hosts that fake HTTP everywhere. Returns
    (bases, skipped_count)."""
    if args.url:
        return [args.url.rstrip("/")], 0
    seen, out, skipped = set(), [], 0
    for r in http_results:
        if web_only and not is_web_surface(r):
            skipped += 1
            continue
        b = (r.final_url or r.url).rstrip("/")
        p = urlparse(b)
        origin = f"{p.scheme}://{p.netloc}"
        if origin not in seen:
            seen.add(origin)
            out.append(origin)
    return out, skipped


def default_outdir(target):
    safe = re.sub(r"[^a-zA-Z0-9._-]", "_", target or "target")
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    return f"reconflow-{safe}-{ts}"


# ---- resolve ---------------------------------------------------------------
def resolve(target, console):
    ips = []
    try:
        for fam, _, _, _, sockaddr in socket.getaddrinfo(target, None):
            ip = sockaddr[0]
            if ip not in ips:
                ips.append(ip)
    except Exception as e:
        console.print(f"[yellow]Could not resolve {target}: {e}[/]")
    for ip in ips:
        console.print(f"  {target} -> {ip}")
    return ips


# ---- port scan -------------------------------------------------------------
async def scan_ports(ip, ports, concurrency, timeout, console):
    q = asyncio.Queue()
    for p in ports:
        q.put_nowait(p)
    open_ports = []

    async def worker():
        while True:
            try:
                port = q.get_nowait()
            except asyncio.QueueEmpty:
                return
            try:
                fut = asyncio.open_connection(ip, port)
                reader, writer = await asyncio.wait_for(fut, timeout=timeout)
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass
                open_ports.append(port)
                console.print(f"  [green]open[/]  {port}/tcp  [dim]{service_name(port)}[/]")
            except Exception:
                pass
            finally:
                q.task_done()

    n = min(max(1, concurrency), max(1, len(ports)))
    await asyncio.gather(*(asyncio.create_task(worker()) for _ in range(n)))
    return sorted(open_ports)


# ---- HTTP probe ------------------------------------------------------------
async def _probe_one(session, url, timeout):
    async with session.get(url, allow_redirects=True,
                           timeout=aiohttp.ClientTimeout(total=timeout)) as resp:
        body = await resp.content.read(200_000)
        p = urlparse(str(resp.url))
        return HttpResult(
            url=url,
            final_url=str(resp.url),
            port=p.port or (443 if p.scheme == "https" else 80),
            status=resp.status,
            server=clean_text(resp.headers.get("Server", "")),
            powered_by=clean_text(resp.headers.get("X-Powered-By", "")),
            title=extract_title(body),
            content_type=clean_text(resp.headers.get("Content-Type", "").split(";")[0]),
            length=int(resp.headers.get("Content-Length") or len(body)),
            tech=detect_tech(resp.headers, body),
            links=extract_links(body, str(resp.url)),
        )


async def probe_http(session, host, port, timeout, console):
    for url in urls_for_port(host, port):
        try:
            res = await _probe_one(session, url, timeout)
            console.print(f"  [cyan]{res.status}[/] {url}  [dim]{res.server}[/]  {res.title[:60]}")
            if res.links:
                console.print(f"  [dim]{len(res.links)} in-page link(s) extracted[/]")
            return res
        except Exception:
            continue
    return None


async def probe_url(session, url, timeout, console):
    u = url if "://" in url else "http://" + url
    try:
        res = await _probe_one(session, u, timeout)
        console.print(f"  [cyan]{res.status}[/] {u}  [dim]{res.server}[/]  {res.title[:60]}")
        if res.links:
            console.print(f"  [dim]{len(res.links)} in-page link(s) extracted[/]")
        return res
    except Exception as e:
        console.print(f"[yellow]Probe failed for {u}: {e}[/]")
        return None


# ---- content discovery -----------------------------------------------------
def _body_hash(body):
    return hashlib.sha1(body or b"").hexdigest()[:16]


async def calibrate(session, base, timeout):
    sigs = []
    for _ in range(3):
        rnd = "".join(random.choices(string.ascii_lowercase + string.digits, k=18))
        url = base + "/" + rnd
        try:
            async with session.get(url, allow_redirects=False,
                                   timeout=aiohttp.ClientTimeout(total=timeout)) as resp:
                body = await resp.content.read(4096)
                length = int(resp.headers.get("Content-Length") or len(body))
                sig = {"status": resp.status, "length": length, "hash": _body_hash(body)}
                if sig not in sigs:
                    sigs.append(sig)
        except Exception:
            pass
    return sigs


def is_fp(status, length, bhash, sigs):
    """Discard a result as a soft-404 only when it truly matches the baseline.

    On wildcard-200 sites (SPA/catch-all) every path returns the same shell, so a
    real route and a miss can share status+length; we only discard when the body
    is byte-identical. For other baseline statuses, a close size match is enough.
    """
    for sig in sigs:
        if sig["status"] != status:
            continue
        if status == 200:
            if sig["hash"] == bhash:
                return True
        elif abs(length - sig["length"]) <= 64:
            return True
    return False


async def discover_content(session, base, words, exts, match_codes,
                           concurrency, delay, timeout, console, seeds=None):
    base = base.rstrip("/")
    sigs = await calibrate(session, base, timeout)
    if sigs:
        console.print(f"  [dim]soft-404 baseline: {sigs}[/]")
    if any(s["status"] == 200 for s in sigs):
        console.print("  [yellow]wildcard 200 detected (SPA/catch-all): filtering by body "
                      "content, not just size.[/]")

    candidates, seen = [], set()
    for w in list(seeds or []) + list(words):
        w = w.strip().lstrip("/")
        if not w or w in seen:
            continue
        seen.add(w)
        candidates.append(w)
        for e in exts:
            ew = f"{w}.{e.lstrip('.')}"
            if ew not in seen:
                seen.add(ew)
                candidates.append(ew)

    q = asyncio.Queue()
    for c in candidates:
        q.put_nowait(c)
    total = len(candidates)
    hits = []
    done = {"n": 0}
    match = set(match_codes)

    async def worker():
        while True:
            try:
                path = q.get_nowait()
            except asyncio.QueueEmpty:
                return
            url = base + "/" + path
            try:
                if delay:
                    await asyncio.sleep(delay)
                async with session.get(url, allow_redirects=False,
                                       timeout=aiohttp.ClientTimeout(total=timeout)) as resp:
                    body = await resp.content.read(4096)
                    length = int(resp.headers.get("Content-Length") or len(body))
                    st = resp.status
                    if st in match and not is_fp(st, length, _body_hash(body), sigs):
                        loc = clean_text(resp.headers.get("Location", ""))
                        ct = clean_text(resp.headers.get("Content-Type", "").split(";")[0])
                        hits.append(ContentHit(url=url, status=st, length=length,
                                               content_type=ct, redirect=loc))
                        extra = f" -> {loc}" if loc else ""
                        console.print(f"  [green]{st}[/] {url} [dim]({length}b {ct})[/]{extra}")
            except Exception:
                pass
            finally:
                done["n"] += 1
                if done["n"] % 500 == 0:
                    console.print(f"  [dim]{done['n']}/{total} tested - {len(hits)} found[/]")

    n = min(max(1, concurrency), max(1, total))
    await asyncio.gather(*(asyncio.create_task(worker()) for _ in range(n)))
    return hits, sigs


# ---- vulnerability detection (opt-in; wraps external detection scanners) ---
# These shell out to battle-tested DETECTION tools (nuclei, wpscan) and parse
# their structured output. Detection only - no exploitation is performed here.
def _first_ref(v):
    refs = v.get("references") or {}
    for key in ("url", "cve", "wpvulndb"):
        val = refs.get(key)
        if isinstance(val, list) and val:
            return str(val[0])
    return ""


def parse_nuclei_line(line):
    """Parse one nuclei -jsonl line into a VulnFinding (or None)."""
    line = line.strip()
    if not line.startswith("{"):
        return None
    try:
        obj = json.loads(line)
    except Exception:
        return None
    info = obj.get("info", {}) or {}
    sev = (info.get("severity") or "info").lower()
    name = info.get("name") or obj.get("template-id", "finding")
    loc = obj.get("matched-at") or obj.get("host", "")
    refs = info.get("reference")
    ref = (refs[0] if isinstance(refs, list) and refs else (refs or "")) if refs else ""
    return VulnFinding("nuclei", name, sev, loc, ref)


def parse_wpscan_json(data, url):
    """Parse a wpscan --format json document into VulnFindings."""
    findings = []
    ver = data.get("version") or {}
    for v in (ver.get("vulnerabilities") or []):
        findings.append(VulnFinding("wpscan", f"WP core: {v.get('title', 'vuln')}",
                                    "high", url, _first_ref(v)))
    for pname, pinfo in (data.get("plugins") or {}).items():
        for v in ((pinfo or {}).get("vulnerabilities") or []):
            findings.append(VulnFinding("wpscan", f"plugin {pname}: {v.get('title', 'vuln')}",
                                        "high", url, _first_ref(v)))
    for f in (data.get("interesting_findings") or []):
        findings.append(VulnFinding("wpscan", (f.get("to_s") or f.get("type") or "interesting"),
                                    "info", f.get("url") or url, ""))
    return findings


async def _stream_subprocess(cmd, on_line, per_line_timeout=900):
    """Run cmd, invoking on_line(str) per stdout line. Returns (rc, stderr|reason)."""
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
    except FileNotFoundError:
        return None, "not-found"
    except Exception as e:
        return None, str(e)
    try:
        while True:
            line = await asyncio.wait_for(proc.stdout.readline(), timeout=per_line_timeout)
            if not line:
                break
            on_line(line.decode("utf-8", "ignore").rstrip("\n"))
        await proc.wait()
    except asyncio.TimeoutError:
        proc.kill()
        return None, "timeout"
    err = (await proc.stderr.read()).decode("utf-8", "ignore")
    return proc.returncode, err


async def run_nuclei(targets, args, cfg, console):
    d = cfg["defaults"]
    exe = shutil.which(d.get("nuclei_bin", "nuclei"))
    if not exe:
        console.print("[yellow]nuclei not found on PATH - skipping.[/] "
                      "Install: https://github.com/projectdiscovery/nuclei")
        return []
    tmp = Path(tempfile.mkdtemp(prefix="rf_nuclei_"))
    listfile = tmp / "targets.txt"
    listfile.write_text("\n".join(targets), encoding="utf-8")
    severity = args.severity or d.get("severity", "low,medium,high,critical")
    rate = str(args.nuclei_rate or d.get("nuclei_rate", 150))
    cmd = [exe, "-l", str(listfile), "-jsonl", "-silent",
           "-severity", severity, "-rate-limit", rate, "-timeout", "10"]
    console.print(f"[dim]$ {' '.join(cmd)}[/]")
    findings = []

    def on_line(line):
        vf = parse_nuclei_line(line)
        if vf:
            findings.append(vf)
            console.print(f"  [bold]{vf.severity.upper()}[/] {vf.name}  [dim]{vf.location}[/]")

    rc, reason = await _stream_subprocess(cmd, on_line)
    if reason == "timeout":
        console.print("[yellow]nuclei timed out.[/]")
    shutil.rmtree(tmp, ignore_errors=True)
    console.print(f"[bold]nuclei: {len(findings)} finding(s).[/]")
    return findings


async def run_wpscan(url, args, cfg, console):
    d = cfg["defaults"]
    exe = shutil.which(d.get("wpscan_bin", "wpscan"))
    if not exe:
        console.print("[yellow]wpscan not found on PATH - skipping.[/] Install: gem install wpscan")
        return []
    token = args.wpscan_api_token or d.get("wpscan_api_token", "")
    cmd = [exe, "--url", url, "--format", "json", "--no-banner"]
    if token:
        cmd += ["--api-token", token]
    console.print(f"[dim]$ wpscan --url {url} --format json --no-banner"
                  f"{' --api-token ***' if token else ''}[/]")
    chunks = []
    rc, reason = await _stream_subprocess(cmd, lambda l: chunks.append(l))
    try:
        data = json.loads("\n".join(chunks))
    except Exception:
        console.print("[yellow]wpscan: could not parse JSON output.[/]")
        return []
    findings = parse_wpscan_json(data, url)
    for f in findings:
        console.print(f"  [bold]{f.severity.upper()}[/] {f.name}")
    if not token:
        console.print("[dim]wpscan ran without --wpscan-api-token: enumeration only, "
                      "limited vuln data.[/]")
    console.print(f"[bold]wpscan: {len(findings)} item(s).[/]")
    return findings


# ---- subdomain enumeration (passive: certificate transparency) -------------
async def _resolve_host(host):
    try:
        infos = await asyncio.to_thread(socket.getaddrinfo, host, None)
        ips = []
        for *_, sa in infos:
            if sa[0] not in ips:
                ips.append(sa[0])
        return ips
    except Exception:
        return []


async def enumerate_subdomains(session, domain, timeout, do_resolve, console):
    subs = set()
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    console.print(f"[dim]$ crt.sh lookup for %.{domain}[/]")
    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=max(timeout, 25))) as resp:
            data = await resp.json(content_type=None)
        for row in data or []:
            for nm in str(row.get("name_value", "")).split("\n"):
                nm = nm.strip().lstrip("*.").lower()
                if nm and nm.endswith(domain) and nm != domain and " " not in nm:
                    subs.add(nm)
    except Exception as e:
        console.print(f"[yellow]crt.sh lookup failed: {e}[/]")
    subs = sorted(subs)
    results = []
    if do_resolve and subs:
        sem = asyncio.Semaphore(50)

        async def one(h):
            async with sem:
                ips = await _resolve_host(h)
            results.append({"host": h, "ips": ips})
            if ips:
                console.print(f"  [green]{h}[/] -> {', '.join(ips[:3])}")

        await asyncio.gather(*(one(s) for s in subs[:500]))
        results.sort(key=lambda r: r["host"])
        live = sum(1 for r in results if r["ips"])
        console.print(f"[bold]{len(subs)} subdomain(s) found, {live} resolve to an IP.[/]")
    else:
        results = [{"host": s, "ips": []} for s in subs]
        for s in subs:
            console.print(f"  {s}")
        console.print(f"[bold]{len(subs)} subdomain(s) found.[/]")
    return results


# ---- JS + Wayback endpoint mining ------------------------------------------
JS_PATH_RE = re.compile(rb"""["'`](/[a-zA-Z0-9_\-./]{1,120})["'`]""")
FULLURL_RE = re.compile(rb"""https?://[a-zA-Z0-9._\-]+/[a-zA-Z0-9_\-./?=&%]{0,150}""")
SECRET_RES = [
    ("AWS access key", re.compile(rb"AKIA[0-9A-Z]{16}")),
    ("Google API key", re.compile(rb"AIza[0-9A-Za-z_\-]{35}")),
    ("Slack token", re.compile(rb"xox[baprs]-[0-9A-Za-z-]{10,48}")),
    ("JWT", re.compile(rb"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{5,}")),
    ("private key block", re.compile(rb"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----")),
    ("api key/secret assignment",
     re.compile(rb"""(?i)(?:api[_-]?key|secret|access[_-]?token)["']?\s*[:=]\s*["'][0-9A-Za-z_\-]{16,}["']""")),
]


def mine_js_body(body):
    """Extract candidate paths, full URLs, and secret hits from a JS/HTML body."""
    paths, urls, secrets = set(), set(), []
    for m in JS_PATH_RE.finditer(body or b""):
        paths.add(m.group(1).decode("utf-8", "ignore").lstrip("/"))
    for m in FULLURL_RE.finditer(body or b""):
        urls.add(m.group(0).decode("utf-8", "ignore"))
    for label, rx in SECRET_RES:
        if rx.search(body or b""):
            secrets.append(label)
    return paths, urls, secrets


async def mine_endpoints(session, http_results, domain, timeout, console,
                         parallel=False, limit=10):
    paths, endpoints, secrets, js_files = set(), set(), [], []
    js_urls = []
    for r in http_results:
        base = r.final_url or r.url
        p = urlparse(base)
        origin = f"{p.scheme}://{p.netloc}"
        for lp in (r.links or []):
            low = lp.lower()
            if low.endswith(".js") or ".js?" in low:
                js_urls.append(origin + "/" + lp.lstrip("/"))
    js_urls = list(dict.fromkeys(js_urls))[:15]
    async def fetch_js(ju):
        try:
            async with session.get(ju, timeout=aiohttp.ClientTimeout(total=timeout)) as resp:
                return ju, await resp.content.read(500_000)
        except Exception:
            return ju, None

    if parallel:
        fetched = await bounded_gather([(lambda u=ju: fetch_js(u)) for ju in js_urls], limit)
    else:
        fetched = [await fetch_js(ju) for ju in js_urls]
    for ju, body in fetched:
        if body is None:
            continue
        js_files.append(ju)
        pp, uu, ss = mine_js_body(body)
        paths |= pp
        endpoints |= uu
        for label in ss:
            secrets.append({"type": label, "location": ju})
            console.print(f"  [red]possible {label}[/] in {ju}")
    wb_count = 0
    if domain:
        wb = (f"http://web.archive.org/cdx/search/cdx?url={domain}/*"
              f"&output=json&fl=original&collapse=urlkey&limit=3000")
        console.print("[dim]$ wayback (web.archive.org) lookup[/]")
        try:
            async with session.get(wb, timeout=aiohttp.ClientTimeout(total=max(timeout, 25))) as resp:
                data = await resp.json(content_type=None)
            for row in (data[1:] if isinstance(data, list) and len(data) > 1 else []):
                u = row[0] if isinstance(row, list) and row else ""
                pu = urlparse(u)
                if pu.path and len(pu.path) <= 128:
                    paths.add(pu.path.lstrip("/"))
                    wb_count += 1
        except Exception as e:
            console.print(f"[yellow]wayback lookup failed: {e}[/]")
    paths.discard("")
    console.print(f"[bold]mined: {len(js_files)} JS file(s), {len(paths)} path(s), "
                  f"{wb_count} wayback URL(s), {len(secrets)} secret hit(s).[/]")
    return {"js_files": js_files, "paths": sorted(paths)[:1000],
            "endpoints": sorted(endpoints)[:200], "secrets": secrets, "wayback_count": wb_count}


# ---- security audit (headers / cookies / CORS / TLS) -----------------------
SEC_HEADERS = {
    "content-security-policy": "CSP",
    "strict-transport-security": "HSTS",
    "x-frame-options": "X-Frame-Options",
    "x-content-type-options": "X-Content-Type-Options",
    "referrer-policy": "Referrer-Policy",
    "permissions-policy": "Permissions-Policy",
}


def cert_audit(host, port, timeout=6):
    import ssl
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ss:
                cert = ss.getpeercert()
        sans = [v for (k, v) in cert.get("subjectAltName", ()) if k == "DNS"]
        return {"trusted": True, "notAfter": cert.get("notAfter"), "sans": sans}
    except Exception as e:  # noqa: BLE001 - report untrusted/expired without a crypto dep
        return {"trusted": False, "error": type(e).__name__}


async def audit_endpoint(session, url, timeout, console):
    findings = []
    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=timeout)) as resp:
            hdrs = {k.lower(): v for k, v in resp.headers.items()}
            cookies = resp.headers.getall("Set-Cookie", []) if hasattr(resp.headers, "getall") \
                else ([resp.headers["Set-Cookie"]] if "Set-Cookie" in resp.headers else [])
    except Exception as e:
        console.print(f"[yellow]audit failed for {url}: {e}[/]")
        return findings
    missing = [label for h, label in SEC_HEADERS.items() if h not in hdrs]
    if missing:
        findings.append(VulnFinding("audit", "Missing security headers: " + ", ".join(missing),
                                    "low", url, ""))
    for c in cookies:
        cl = c.lower()
        flags = [f for f, present in (("Secure", "secure" in cl),
                                      ("HttpOnly", "httponly" in cl),
                                      ("SameSite", "samesite" in cl)) if not present]
        if flags:
            findings.append(VulnFinding("audit", f"Cookie '{c.split('=', 1)[0]}' missing: "
                                        + ", ".join(flags), "low", url, ""))
    # CORS reflection (single benign GET with a crafted Origin)
    try:
        probe = "https://recon-flow-probe.invalid"
        async with session.get(url, headers={"Origin": probe},
                               timeout=aiohttp.ClientTimeout(total=timeout)) as resp2:
            acao = resp2.headers.get("Access-Control-Allow-Origin", "")
            acac = (resp2.headers.get("Access-Control-Allow-Credentials", "") or "").lower()
        if acao == "*":
            findings.append(VulnFinding("audit", "CORS: Access-Control-Allow-Origin: * (wildcard)",
                                        "info", url, ""))
        elif acao == probe:
            with_creds = acac == "true"
            findings.append(VulnFinding(
                "audit", "CORS reflects arbitrary Origin" + (" + credentials" if with_creds else ""),
                "medium" if with_creds else "low", url, ""))
    except Exception:
        pass
    # TLS certificate (https only)
    p = urlparse(url)
    if p.scheme == "https" and p.hostname:
        info = await asyncio.to_thread(cert_audit, p.hostname, p.port or 443)
        if info and not info.get("trusted"):
            findings.append(VulnFinding("audit", f"TLS certificate not trusted ({info.get('error')})",
                                        "medium", url, ""))
        elif info and info.get("notAfter"):
            findings.append(VulnFinding("audit", f"TLS cert valid until {info['notAfter']}",
                                        "info", url, ""))
    for f in findings:
        console.print(f"  [bold]{f.severity.upper()}[/] {f.name}")
    return findings


# ---- report ----------------------------------------------------------------
def write_html(path, r):
    esc = lambda v: html.escape(str(v))
    out = [
        "<!doctype html><html><head><meta charset='utf-8'>",
        "<meta name='viewport' content='width=device-width,initial-scale=1'>",
        f"<title>ReconFlow - {esc(r['target'])}</title>",
        "<style>", CSS, "</style></head><body><div class='wrap'>",
        "<h1>ReconFlow report</h1>",
        (f"<p class='muted'>Target <b>{esc(r['target'])}</b> &middot; "
         f"{esc(', '.join(r['ips']) or 'n/a')} &middot; {esc(r['started'])} &rarr; "
         f"{esc(r['finished'])} ({esc(r['duration_sec'])}s)</p>"),
        "<h2>Open ports</h2>",
    ]
    if r["ports"]:
        out.append("<table><tr><th>Port</th><th>Service</th></tr>")
        for p in r["ports"]:
            out.append(f"<tr><td>{esc(p['port'])}/tcp</td><td>{esc(p['service'])}</td></tr>")
        out.append("</table>")
    else:
        out.append("<p class='muted'>None.</p>")

    out.append("<h2>HTTP services</h2>")
    if r["http"]:
        out.append("<table><tr><th>URL</th><th>Status</th><th>Server</th>"
                   "<th>Title</th><th>Tech</th></tr>")
        for h in r["http"]:
            target_url = h.get("final_url") or h["url"]
            out.append(
                "<tr><td><a href='%s'>%s</a></td><td>%s</td><td>%s</td>"
                "<td>%s</td><td>%s</td></tr>" % (
                    esc(target_url), esc(h["url"]), esc(h["status"]),
                    esc(h["server"]), esc(h["title"]), esc(", ".join(h["tech"])))
            )
        out.append("</table>")
    else:
        out.append("<p class='muted'>None.</p>")

    out.append("<h2>Subdomains</h2>")
    subs = r.get("subdomains") or []
    if subs:
        out.append("<table><tr><th>Subdomain</th><th>Resolves to</th></tr>")
        for s in subs:
            out.append("<tr><td>%s</td><td>%s</td></tr>" % (
                esc(s.get("host", "")), esc(", ".join(s.get("ips", [])) or "-")))
        out.append("</table>")
    else:
        out.append("<p class='muted'>Not run, or none found.</p>")

    out.append("<h2>Content discovery</h2>")
    if r["content"]:
        for sec in r["content"]:
            out.append(f"<h3>{esc(sec['base'])}</h3>")
            if sec["hits"]:
                out.append("<table><tr><th>Status</th><th>Length</th><th>Type</th>"
                           "<th>URL</th><th>Redirect</th></tr>")
                for hit in sec["hits"]:
                    out.append(
                        "<tr><td class='s%s'>%s</td><td>%s</td><td>%s</td>"
                        "<td><a href='%s'>%s</a></td><td>%s</td></tr>" % (
                            str(hit["status"])[0], esc(hit["status"]), esc(hit["length"]),
                            esc(hit["content_type"]), esc(hit["url"]), esc(hit["url"]),
                            esc(hit.get("redirect") or ""))
                    )
                out.append("</table>")
            else:
                out.append("<p class='muted'>No paths found.</p>")
    else:
        out.append("<p class='muted'>Not run.</p>")

    out.append("<h2>Mined endpoints (JS + Wayback)</h2>")
    mined = r.get("mined") or {}
    if mined:
        out.append("<p class='muted'>%s JS file(s) &middot; %s path(s) &middot; %s Wayback URL(s) "
                   "&middot; %s secret hit(s)</p>" % (
                       esc(len(mined.get("js_files", []))), esc(len(mined.get("paths", []))),
                       esc(mined.get("wayback_count", 0)), esc(len(mined.get("secrets", [])))))
        eps = mined.get("endpoints", [])
        if eps:
            out.append("<details><summary>Full URLs (%s)</summary><ul>" % esc(len(eps)))
            for e in eps[:200]:
                out.append("<li>%s</li>" % esc(e))
            out.append("</ul></details>")
    else:
        out.append("<p class='muted'>Not run.</p>")

    out.append("<h2>Findings (vuln / audit / mining)</h2>")
    vulns = r.get("vuln") or []
    if vulns:
        order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "unknown": 5}
        vulns = sorted(vulns, key=lambda v: order.get((v.get("severity") or "info").lower(), 5))
        out.append("<table><tr><th>Severity</th><th>Source</th><th>Finding</th>"
                   "<th>Location</th><th>Ref</th></tr>")
        for v in vulns:
            sev = (v.get("severity") or "info").lower()
            ref = v.get("reference") or ""
            ref_html = f"<a href='{esc(ref)}'>ref</a>" if ref else ""
            out.append(
                "<tr><td class='sev-%s'>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>" % (
                    esc(sev), esc(sev.upper()), esc(v.get("source", "")),
                    esc(v.get("name", "")), esc(v.get("location", "")), ref_html)
            )
        out.append("</table>")
    else:
        out.append("<p class='muted'>Not run, or no findings.</p>")

    out.append("<p class='foot'>Generated by ReconFlow &middot; authorized security testing only.</p>")
    out.append("</div></body></html>")
    Path(path).write_text("".join(out), encoding="utf-8")


# ---- orchestrator ----------------------------------------------------------
async def run(args, cfg, console):
    d = cfg["defaults"]
    # A service that redirects to an unresolvable host makes aiohttp raise gaierror
    # in a background task; that is benign for a scanner, so don't spam the console.
    def _quiet_handler(loop, context):
        if isinstance(context.get("exception"), socket.gaierror):
            return
        loop.default_exception_handler(context)
    try:
        asyncio.get_running_loop().set_exception_handler(_quiet_handler)
    except Exception:
        pass
    started = datetime.now(timezone.utc)
    t0 = time.time()
    phases = [p.strip() for p in args.phases.split(",") if p.strip()]
    if args.vuln and "vuln" not in phases:
        phases.append("vuln")
    for flag, name in (("subs", "subs"), ("mine", "mine"), ("audit", "audit")):
        if getattr(args, flag, False) and name not in phases:
            phases.append(name)

    ips, open_ports, http_results = [], [], []
    content_sections, vuln_findings = [], []
    subdomains, mined = [], {}

    if args.url:
        parsed = urlparse(args.url if "://" in args.url else "http://" + args.url)
        target = parsed.hostname or args.url
    else:
        target = args.target

    if not args.url and "resolve" in phases:
        console.rule("[bold]Phase 1 - Resolve")
        ips = resolve(target, console)

    if not args.url and "ports" in phases:
        console.rule("[bold]Phase 2 - Port scan")
        scan_ip = ips[0] if ips else target
        ports = parse_ports(args.ports, COMMON_PORTS)
        console.print(f"Scanning {len(ports)} port(s) on {scan_ip} ...")
        open_ports = await scan_ports(scan_ip, ports, args.port_concurrency,
                                      args.port_timeout, console)
        console.print(f"[bold]{len(open_ports)} open port(s).[/]")
        if not open_ports and str(args.ports).lower() not in ("full", "all"):
            console.print("[yellow]0 open in this set. If the host is up (try `ping`), run "
                          "--ports full — the service may be on a non-standard port.[/]")

    need_http = any(p in phases for p in ("subs", "http", "content", "vuln", "mine", "audit"))
    if need_http and aiohttp is None:
        console.print("[red]aiohttp not installed - run: pip install -r requirements.txt[/]")
    elif need_http:
        connector = aiohttp.TCPConnector(ssl=False, limit=0)
        headers = {"User-Agent": d.get("user_agent", "ReconFlow/1.0")}
        async with aiohttp.ClientSession(connector=connector, headers=headers) as session:
            if "subs" in phases:
                console.rule("[bold]Subdomain enumeration")
                if args.url:
                    dom = urlparse(args.url if "://" in args.url else "http://" + args.url).hostname
                else:
                    dom = target
                is_ip = bool(dom) and all(part.isdigit() for part in (dom or "").split("."))
                if not dom or is_ip:
                    console.print("[yellow]Subdomain enum needs a domain name; skipping for IP.[/]")
                else:
                    subdomains = await enumerate_subdomains(
                        session, dom, args.http_timeout, not args.no_subs_resolve, console)

            if any(p in phases for p in ("http", "content", "mine", "audit")):
                console.rule("[bold]Phase 3 - HTTP probe")
                if args.url:
                    res = await probe_url(session, args.url, args.http_timeout, console)
                    if res:
                        http_results.append(res)
                else:
                    web_ports = open_ports if open_ports else FALLBACK_WEB_PORTS
                    if not open_ports:
                        console.print("[dim]No port results; probing common web ports.[/]")
                    if args.mode == "parallel":
                        probed = await bounded_gather(
                            [(lambda pt=port: probe_http(session, target, pt, args.http_timeout, console))
                             for port in web_ports], args.max_parallel_hosts)
                        http_results.extend([r for r in probed if r])
                    else:
                        for port in web_ports:
                            res = await probe_http(session, target, port, args.http_timeout, console)
                            if res:
                                http_results.append(res)

            if "mine" in phases:
                console.rule("[bold]Endpoint mining (JS + Wayback)")
                if args.url:
                    dom_m = urlparse(args.url if "://" in args.url else "http://" + args.url).hostname
                elif target and not all(p.isdigit() for p in target.split(".")):
                    dom_m = target
                else:
                    dom_m = None
                mined = await mine_endpoints(session, http_results, dom_m, args.http_timeout, console,
                                             parallel=(args.mode == "parallel"),
                                             limit=args.max_parallel_hosts)
                for s in mined.get("secrets", []):
                    vuln_findings.append(VulnFinding("mine", f"Possible {s['type']} in JS",
                                                     "medium", s["location"], ""))

            if "audit" in phases:
                console.rule("[bold]Security audit (headers / CORS / cookies / TLS)")
                bases_a, skipped_a = compute_bases(args, http_results,
                                                   web_only=args.web_ports_only)
                if skipped_a:
                    console.print(f"[dim]auditing {len(bases_a)} web surface(s); skipped "
                                  f"{skipped_a} non-web-port responder(s) (--web-ports-only).[/]")
                if not bases_a:
                    console.print("[yellow]No HTTP endpoint to audit.[/]")
                if args.mode == "parallel":
                    audit_lists = await bounded_gather(
                        [(lambda b=base: audit_endpoint(session, b, args.http_timeout, console))
                         for base in bases_a], args.max_parallel_hosts)
                    for fl in audit_lists:
                        vuln_findings += fl
                else:
                    for base in bases_a:
                        console.print(f"[bold]Auditing[/] {base}")
                        vuln_findings += await audit_endpoint(session, base, args.http_timeout, console)

            if "content" in phases:
                console.rule("[bold]Phase 4 - Content discovery")
                bases, skipped_c = compute_bases(args, http_results,
                                                 web_only=args.web_ports_only)
                if skipped_c:
                    console.print(f"[dim]fuzzing {len(bases)} web surface(s); skipped {skipped_c} "
                                  f"non-web-port responder(s) (--web-ports-only).[/]")
                if not bases:
                    console.print("[yellow]No HTTP endpoint to enumerate. "
                                  "Run the http phase or pass --url.[/]")
                else:
                    words = load_words(args, cfg, console)
                    if words is not None:
                        exts_src = args.extensions.split(",") if args.extensions else d.get("extensions", [])
                        exts = [e.strip() for e in exts_src if e and e.strip()]
                        match_codes = (parse_int_list(args.match_codes)
                                       if args.match_codes else d.get("match_codes"))
                        seeds, seen_seed = [], set()
                        for r in http_results:
                            for lp in (r.links or []):
                                if lp not in seen_seed:
                                    seen_seed.add(lp)
                                    seeds.append(lp)
                        for mp in mined.get("paths", []):
                            if mp not in seen_seed:
                                seen_seed.add(mp)
                                seeds.append(mp)
                        if seeds:
                            console.print(f"[dim]{len(seeds)} path(s) seeded from in-page links.[/]")
                        async def enum_base(base):
                            console.print(f"[bold]Enumerating[/] {base}  "
                                          f"({len(words)} words + {len(seeds)} link seeds, "
                                          f"ext={exts or 'none'})")
                            hits, sigs = await discover_content(
                                session, base, words, exts, match_codes,
                                args.http_concurrency, args.delay, args.http_timeout, console,
                                seeds=seeds)
                            console.print(f"[bold]{len(hits)} path(s) found on {base}.[/]")
                            return {"base": base,
                                    "hits": [asdict(h) for h in hits],
                                    "signatures": sigs}

                        if args.mode == "parallel" and len(bases) > 1:
                            content_sections.extend(await bounded_gather(
                                [(lambda b=base: enum_base(b)) for base in bases],
                                args.max_parallel_hosts))
                        else:
                            for base in bases:
                                content_sections.append(await enum_base(base))

    if "vuln" in phases:
        console.rule("[bold]Phase 5 - Vulnerability detection (nuclei + wpscan)")
        targets, _ = compute_bases(args, http_results, web_only=args.web_ports_only)
        if not targets:
            console.print("[yellow]No live endpoint to scan. Run the http phase or pass --url.[/]")
        else:
            vuln_findings += await run_nuclei(targets, args, cfg, console)
            wp_targets = [(r.final_url or r.url) for r in http_results
                          if "wordpress" in (r.tech or [])]
            if args.wpscan_force and args.url and not wp_targets:
                wp_targets = [args.url]
            seen = set()
            for wp in wp_targets:
                if wp in seen:
                    continue
                seen.add(wp)
                vuln_findings += await run_wpscan(wp, args, cfg, console)
            if not wp_targets:
                console.print("[dim]No WordPress fingerprinted; wpscan skipped "
                              "(use --wpscan-force with --url to force).[/]")

    finished = datetime.now(timezone.utc)
    report = {
        "tool": "ReconFlow", "version": "1.0", "target": target, "ips": ips,
        "started": started.isoformat(), "finished": finished.isoformat(),
        "duration_sec": round(time.time() - t0, 1), "phases": phases,
        "ports": [{"port": p, "service": service_name(p)} for p in open_ports],
        "http": [asdict(r) for r in http_results],
        "content": content_sections,
        "subdomains": subdomains,
        "mined": mined,
        "vuln": [asdict(v) for v in vuln_findings],
    }
    report = scrub(report)  # strip any surrogate/control bytes from server responses
    outdir = Path(args.output or default_outdir(target))
    outdir.mkdir(parents=True, exist_ok=True)
    (outdir / "report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    write_html(outdir / "report.html", report)

    console.rule("[bold]Done")
    console.print(f"JSON: {outdir / 'report.json'}")
    console.print(f"HTML: {outdir / 'report.html'}")


# ---- CLI -------------------------------------------------------------------
def build_parser():
    p = argparse.ArgumentParser(
        prog="reconflow",
        description="Step-by-step recon orchestrator for authorized security testing.",
        epilog="Only scan assets you are explicitly authorized to test.",
    )
    p.add_argument("target", nargs="?", help="hostname or IP to assess")
    p.add_argument("--url", help="probe/enumerate this URL directly (skips resolve+ports)")
    p.add_argument("--ports", default=None, help="common | full | 1-1024 | 80,443,8080")
    p.add_argument("--wordlist", default=None, help="preset name(s) or file path(s), comma-separated")
    p.add_argument("--extensions", default=None, help="append extensions, e.g. php,html,txt")
    p.add_argument("--phases", default="resolve,ports,http,content",
                   help="comma list: resolve,ports,http,content")
    p.add_argument("--http-concurrency", type=int, default=None)
    p.add_argument("--port-concurrency", type=int, default=None)
    p.add_argument("--port-timeout", type=float, default=None)
    p.add_argument("--http-timeout", type=float, default=None)
    p.add_argument("--delay", type=float, default=None,
                   help="seconds between requests per worker (rate limit)")
    p.add_argument("--match-codes", default=None, help="status codes to report in content discovery")
    p.add_argument("--max-paths", type=int, default=0, help="cap wordlist size (0 = no cap)")
    p.add_argument("--seclists", default=None, help="path to SecLists base directory")
    p.add_argument("--output", default=None, help="output directory")
    p.add_argument("--config", default="config.yaml", help="config file path")
    p.add_argument("--yes", "-y", action="store_true", help="skip authorization confirmation")
    p.add_argument("--interactive", "-i", action="store_true",
                   help="interactive menu: pick target, phases, wordlist, etc.")
    p.add_argument("--no-builtin", action="store_true",
                   help="do not include the built-in high-signal path list")
    p.add_argument("--web-ports-only", action="store_true",
                   help="restrict fuzzing/audit to recognized web ports (skip HTTP on odd ports)")
    # run mode: sequential (previous, default) or parallel (faster)
    p.add_argument("--mode", choices=["sequential", "parallel"], default=None,
                   help="sequential (step-by-step, default) or parallel (faster)")
    p.add_argument("--parallel", action="store_true", help="shortcut for --mode parallel")
    p.add_argument("--max-parallel-hosts", type=int, default=None,
                   help="max hosts/endpoints processed at once in parallel mode (default 5)")
    # recon add-ons (opt-in phases)
    p.add_argument("--subs", action="store_true",
                   help="subdomain enumeration phase (crt.sh, then DNS resolve)")
    p.add_argument("--no-subs-resolve", action="store_true",
                   help="with --subs, list names without DNS-resolving them")
    p.add_argument("--mine", action="store_true",
                   help="endpoint mining phase (parse linked JS + Wayback URLs)")
    p.add_argument("--audit", action="store_true",
                   help="security audit phase (headers, CORS, cookie flags, TLS)")
    # vulnerability detection (opt-in; wraps external DETECTION scanners)
    p.add_argument("--vuln", action="store_true",
                   help="add the vuln phase (runs nuclei + wpscan, detection-only)")
    p.add_argument("--severity", default=None,
                   help="nuclei severities, e.g. medium,high,critical")
    p.add_argument("--nuclei-rate", type=int, default=None, help="nuclei max requests/sec")
    p.add_argument("--wpscan-api-token", default=None, help="WPScan API token (enables vuln DB)")
    p.add_argument("--wpscan-force", action="store_true",
                   help="run wpscan even if WordPress was not fingerprinted (with --url)")
    return p


def apply_defaults(args, cfg):
    d = cfg["defaults"]
    if args.ports is None:
        args.ports = str(d.get("ports", "common"))
    if args.wordlist is None:
        args.wordlist = str(d.get("wordlist", "common"))
    if args.http_concurrency is None:
        args.http_concurrency = int(d.get("http_concurrency", 30))
    if args.port_concurrency is None:
        args.port_concurrency = int(d.get("port_concurrency", 500))
    if args.port_timeout is None:
        args.port_timeout = float(d.get("port_timeout", 1.0))
    if args.http_timeout is None:
        args.http_timeout = float(d.get("http_timeout", 8.0))
    if args.delay is None:
        args.delay = float(d.get("delay", 0.0))
    if args.mode is None:
        args.mode = "parallel" if getattr(args, "parallel", False) else str(d.get("mode", "sequential"))
    if args.max_parallel_hosts is None:
        args.max_parallel_hosts = int(d.get("max_parallel_hosts", 5))


def interactive_setup(args, cfg, console):
    """Simple nmap-style menu: assemble a run, show the command, then proceed."""
    def ask(prompt, default=""):
        try:
            v = input(f"{prompt} " + (f"[{default}] " if default else "")).strip()
        except EOFError:
            return default
        return v or default

    console.print(f"[bold yellow]{BANNER}[/]")
    console.print("[bold]Interactive setup[/] - press Enter to accept the [default].")

    if ask("Target by (1) host/IP or (2) URL?", "1") == "2":
        args.url = ask("URL to test:", args.url or "https://example.com")
    else:
        args.target = ask("Host or IP:", args.target or "")

    console.print("Phases: 1=resolve 2=ports 3=http 4=content 5=vuln")
    sel = ask("Choose phases (comma numbers, or 'all'):", "all")
    if sel.lower() == "all":
        chosen = ["resolve", "ports", "http", "content"]
    else:
        names = {"1": "resolve", "2": "ports", "3": "http", "4": "content", "5": "vuln"}
        chosen = [names[s.strip()] for s in sel.split(",") if s.strip() in names] \
            or ["resolve", "ports", "http", "content"]
    if "vuln" in chosen:
        args.vuln = True
        chosen = [c for c in chosen if c != "vuln"]
    args.phases = ",".join(chosen)

    if not args.url and "ports" in chosen:
        args.ports = ask("Ports (common | full | 1-1024 | 80,443):", args.ports or "common")
    if "content" in chosen:
        args.wordlist = ask("Wordlist (common|small|medium|big|exposed|api|path):",
                            args.wordlist or "common")
        args.extensions = ask("Extensions (blank = none), e.g. php,txt:",
                              args.extensions or "") or None
    if args.vuln:
        args.wpscan_api_token = ask("WPScan API token (blank = skip):",
                                    args.wpscan_api_token or "") or None
        args.severity = ask("Nuclei severities:", args.severity or "low,medium,high,critical")

    args.mode = "parallel" if ask("Run mode: (1) sequential or (2) parallel?", "1") == "2" \
        else "sequential"

    tgt = f"--url {args.url}" if args.url else (args.target or "")
    cmd = f"python reconflow.py {tgt} --phases {args.phases} --mode {args.mode}"
    if not args.url and "ports" in chosen:
        cmd += f" --ports {args.ports}"
    if "content" in chosen:
        cmd += f" --wordlist {args.wordlist}"
        if args.extensions:
            cmd += f" --extensions {args.extensions}"
    if args.vuln:
        cmd += " --vuln"
        if args.severity:
            cmd += f" --severity {args.severity}"
    console.print(f"\n[bold]Equivalent command:[/]\n  {cmd}\n")


def authorization_gate(args, console):
    target = args.url or args.target
    console.print(f"[bold yellow]{BANNER}[/]")
    console.print(f"Target: [bold]{target}[/]")
    console.print(f"Phases: {args.phases}")
    console.print(f"Mode: {getattr(args, 'mode', 'sequential')}"
                  + (f" (max {args.max_parallel_hosts} parallel hosts)"
                     if getattr(args, 'mode', '') == 'parallel' else ""))
    console.print("[yellow]Proceed only against systems you are explicitly authorized to test.[/]")
    if args.yes:
        return True
    if not sys.stdin.isatty():
        console.print("[red]Non-interactive shell and no --yes: refusing to run.[/]")
        return False
    try:
        ans = input("Are you authorized to test this target? [y/N] ").strip().lower()
    except EOFError:
        return False
    return ans in ("y", "yes")


def main():
    parser = build_parser()
    args = parser.parse_args()
    cfg = load_config(args.config)
    if args.interactive:
        interactive_setup(args, cfg, _console)
    if not args.target and not args.url:
        parser.print_help()
        sys.exit(1)
    apply_defaults(args, cfg)
    if not authorization_gate(args, _console):
        _console.print("[red]Aborted.[/]")
        sys.exit(1)
    try:
        asyncio.run(run(args, cfg, _console))
    except KeyboardInterrupt:
        _console.print("\n[yellow]Interrupted.[/]")


if __name__ == "__main__":
    main()
