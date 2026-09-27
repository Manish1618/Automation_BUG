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

TITLE_RE = re.compile(rb"<title[^>]*>(.*?)</title>", re.I | re.S)

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


def extract_title(body):
    m = TITLE_RE.search(body or b"")
    if not m:
        return ""
    try:
        t = m.group(1).decode("utf-8", "ignore")
    except Exception:
        t = ""
    return " ".join(t.split())[:200]


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
    for name in names:
        path = resolve_wordlist(name, cfg, base)
        if not path:
            console.print(
                f"[red]Wordlist '{name}' not found.[/] Point --seclists / config.yaml "
                f"at your SecLists clone, or pass a direct file path."
            )
            if base is None:
                console.print("[yellow]No SecLists directory was found on this machine.[/]")
            return None
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
            console.print(f"[red]Could not read {path}: {e}[/]")
            return None
    if args.max_paths and len(words) > args.max_paths:
        words = words[: args.max_paths]
    return words


def compute_bases(args, http_results):
    if args.url:
        return [args.url.rstrip("/")]
    seen, out = set(), []
    for r in http_results:
        b = (r.final_url or r.url).rstrip("/")
        p = urlparse(b)
        origin = f"{p.scheme}://{p.netloc}"
        if origin not in seen:
            seen.add(origin)
            out.append(origin)
    return out


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
            server=resp.headers.get("Server", ""),
            powered_by=resp.headers.get("X-Powered-By", ""),
            title=extract_title(body),
            content_type=resp.headers.get("Content-Type", "").split(";")[0],
            length=int(resp.headers.get("Content-Length") or len(body)),
            tech=detect_tech(resp.headers, body),
        )


async def probe_http(session, host, port, timeout, console):
    for url in urls_for_port(host, port):
        try:
            res = await _probe_one(session, url, timeout)
            console.print(f"  [cyan]{res.status}[/] {url}  [dim]{res.server}[/]  {res.title[:60]}")
            return res
        except Exception:
            continue
    return None


async def probe_url(session, url, timeout, console):
    u = url if "://" in url else "http://" + url
    try:
        res = await _probe_one(session, u, timeout)
        console.print(f"  [cyan]{res.status}[/] {u}  [dim]{res.server}[/]  {res.title[:60]}")
        return res
    except Exception as e:
        console.print(f"[yellow]Probe failed for {u}: {e}[/]")
        return None


# ---- content discovery -----------------------------------------------------
async def calibrate(session, base, timeout):
    sigs = []
    for _ in range(3):
        rnd = "".join(random.choices(string.ascii_lowercase + string.digits, k=18))
        url = base + "/" + rnd
        try:
            async with session.get(url, allow_redirects=False,
                                   timeout=aiohttp.ClientTimeout(total=timeout)) as resp:
                body = await resp.content.read(2048)
                length = int(resp.headers.get("Content-Length") or len(body))
                sig = [resp.status, length]
                if sig not in sigs:
                    sigs.append(sig)
        except Exception:
            pass
    return sigs


def is_fp(status, length, sigs):
    for s, l in sigs:
        if s == status and abs(length - l) <= 64:
            return True
    return False


async def discover_content(session, base, words, exts, match_codes,
                           concurrency, delay, timeout, console):
    base = base.rstrip("/")
    sigs = await calibrate(session, base, timeout)
    if sigs:
        console.print(f"  [dim]soft-404 baseline: {sigs}[/]")

    candidates = []
    for w in words:
        candidates.append(w)
        for e in exts:
            candidates.append(f"{w}.{e.lstrip('.')}")

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
                    body = await resp.content.read(2048)
                    length = int(resp.headers.get("Content-Length") or len(body))
                    st = resp.status
                    if st in match and not is_fp(st, length, sigs):
                        loc = resp.headers.get("Location", "")
                        ct = resp.headers.get("Content-Type", "").split(";")[0]
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

    out.append("<h2>Vulnerability detection</h2>")
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
    started = datetime.now(timezone.utc)
    t0 = time.time()
    phases = [p.strip() for p in args.phases.split(",") if p.strip()]
    if args.vuln and "vuln" not in phases:
        phases.append("vuln")

    ips, open_ports, http_results, content_sections, vuln_findings = [], [], [], [], []

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

    need_http = any(p in phases for p in ("http", "content", "vuln"))
    if need_http and aiohttp is None:
        console.print("[red]aiohttp not installed - run: pip install -r requirements.txt[/]")
    elif need_http:
        connector = aiohttp.TCPConnector(ssl=False, limit=0)
        headers = {"User-Agent": d.get("user_agent", "ReconFlow/1.0")}
        async with aiohttp.ClientSession(connector=connector, headers=headers) as session:
            if "http" in phases:
                console.rule("[bold]Phase 3 - HTTP probe")
                if args.url:
                    res = await probe_url(session, args.url, args.http_timeout, console)
                    if res:
                        http_results.append(res)
                else:
                    web_ports = open_ports if open_ports else FALLBACK_WEB_PORTS
                    if not open_ports:
                        console.print("[dim]No port results; probing common web ports.[/]")
                    for port in web_ports:
                        res = await probe_http(session, target, port, args.http_timeout, console)
                        if res:
                            http_results.append(res)

            if "content" in phases:
                console.rule("[bold]Phase 4 - Content discovery")
                bases = compute_bases(args, http_results)
                if not bases:
                    console.print("[yellow]No HTTP endpoint to enumerate. "
                                  "Pass --url or run the http phase.[/]")
                else:
                    words = load_words(args, cfg, console)
                    if words is not None:
                        exts_src = args.extensions.split(",") if args.extensions else d.get("extensions", [])
                        exts = [e.strip() for e in exts_src if e and e.strip()]
                        match_codes = (parse_int_list(args.match_codes)
                                       if args.match_codes else d.get("match_codes"))
                        for base in bases:
                            console.print(f"[bold]Enumerating[/] {base}  "
                                          f"({len(words)} words, ext={exts or 'none'})")
                            hits, sigs = await discover_content(
                                session, base, words, exts, match_codes,
                                args.http_concurrency, args.delay, args.http_timeout, console)
                            content_sections.append({
                                "base": base,
                                "hits": [asdict(h) for h in hits],
                                "signatures": sigs,
                            })
                            console.print(f"[bold]{len(hits)} path(s) found on {base}.[/]")

    if "vuln" in phases:
        console.rule("[bold]Phase 5 - Vulnerability detection (nuclei + wpscan)")
        targets = compute_bases(args, http_results)
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
        "vuln": [asdict(v) for v in vuln_findings],
    }
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


def authorization_gate(args, console):
    target = args.url or args.target
    console.print(f"[bold yellow]{BANNER}[/]")
    console.print(f"Target: [bold]{target}[/]")
    console.print(f"Phases: {args.phases}")
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
    if not args.target and not args.url:
        parser.print_help()
        sys.exit(1)
    cfg = load_config(args.config)
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
