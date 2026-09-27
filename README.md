# ReconFlow

A one-command reconnaissance orchestrator for **authorized** security testing
(bug bounty, pentests, CTFs, your own assets). It runs the early recon phases you
normally do by hand — in order — and writes one consolidated report.

```
resolve  ->  port scan  ->  HTTP probe  ->  content/directory discovery
                                                     |
                                          report.json + report.html
```

It performs **enumeration and information gathering only**. No exploitation, no
credential testing, no detection evasion.

---

## Responsible use

- Only scan systems you are **explicitly authorized** to test (bug bounty scope or
  written permission). Unauthorized scanning is illegal in many jurisdictions.
- ReconFlow prints the target and asks you to confirm authorization before it does
  anything. `--yes` skips the prompt for automation; in a non-interactive shell it
  refuses to run without `--yes`.
- Rate limiting is available (`--delay`, `--http-concurrency`) — be a good citizen and
  stay within program rules.

---

## Requirements

- **Python 3.9+**
- Dependencies:
  ```bash
  pip install -r requirements.txt
  ```
- **SecLists** (only needed for the content-discovery presets). Clone it and point
  `config.yaml` (or `--seclists`) at it:
  ```bash
  git clone https://github.com/danielmiessler/SecLists C:/Tools/SecLists
  ```
  Any custom wordlist file path works too — SecLists is not strictly required.

---

## Quick start

Full pipeline against a host (asks for authorization confirmation):

```bash
python reconflow.py example.com
```

Interactive menu — pick target, phases, and wordlist step by step (like an nmap UI):

```bash
python reconflow.py -i
```

Skip the port scan and enumerate a known URL directly:

```bash
python reconflow.py --url https://example.com --wordlist common,exposed
```

Scan a full port range, then probe/enumerate what's open:

```bash
python reconflow.py 10.0.0.5 --ports full --wordlist medium --extensions php,txt
```

Run only specific phases:

```bash
python reconflow.py example.com --phases resolve,ports          # recon only
python reconflow.py --url https://example.com --phases content  # dir discovery only
```

Rate-limited, non-interactive run:

```bash
python reconflow.py example.com --yes --http-concurrency 10 --delay 0.1
```

---

## Phases

| Phase | What it does |
|-------|--------------|
| `resolve` | Resolves the hostname to IPv4/IPv6 addresses. |
| `ports` | Async TCP connect scan (no admin rights). Sets: `common`, `full`, ranges, lists. |
| `http` | Fetches each open web port; records status, `Server`, title, tech, redirects. |
| `content` | Directory/file discovery with SecLists wordlist(s) + soft-404 filtering. |
| `vuln` | **Opt-in** (`--vuln`). Runs Nuclei on live URLs + WPScan on any WordPress. Detection only. |

Select phases with `--phases` (default: `resolve,ports,http,content`). `--vuln` adds the vuln phase.

---

## Wordlist presets

Defined in `config.yaml`, mapped to SecLists paths. Pass a preset name, several
comma-separated names (merged + de-duplicated), or a direct file path.

| Preset | SecLists file |
|--------|---------------|
| `common` | `Discovery/Web-Content/common.txt` |
| `small` | `Discovery/Web-Content/directory-list-2.3-small.txt` |
| `medium` | `Discovery/Web-Content/directory-list-2.3-medium.txt` |
| `big` | `Discovery/Web-Content/big.txt` |
| `raft` | `Discovery/Web-Content/raft-small-directories.txt` |
| `exposed` | `Discovery/Web-Content/quickhits.txt` (.git, .env, backups) |
| `api` | `Discovery/Web-Content/api/api-endpoints.txt` |

Example: `--wordlist common,exposed`

---

## Key options

| Option | Meaning |
|--------|---------|
| `--url URL` | Probe/enumerate a URL directly (skips resolve + ports). |
| `--ports SPEC` | `common` \| `full` \| `1-1024` \| `80,443,8080`. |
| `--wordlist X` | Preset name(s) or file path(s), comma-separated. |
| `--extensions` | Append extensions, e.g. `php,html,txt`. |
| `--match-codes` | Status codes to report (default `200,204,301,302,307,401,403,405,500`). |
| `--http-concurrency` / `--port-concurrency` | Parallelism caps. |
| `--delay S` | Seconds between requests per worker (rate limit). |
| `--max-paths N` | Cap wordlist size for quick runs. |
| `--seclists PATH` | Path to your SecLists clone. |
| `--output DIR` | Report output directory. |
| `--yes` | Skip the authorization prompt. |
| `-i`, `--interactive` | Interactive menu: pick target, phases, wordlist, etc. (nmap-style). |
| `--no-builtin` | Skip the built-in high-signal path list (use only your wordlist). |

Defaults live in `config.yaml`; CLI flags override them.

---

## Output

Each run writes to `reconflow-<target>-<timestamp>/` (or `--output`):

- **`report.json`** — full structured results (feed into other tools).
- **`report.html`** — self-contained, dark-themed, one-page consolidated report.

The terminal also prints a live summary as each phase runs.

---

## How content discovery avoids false positives

Before enumerating, ReconFlow requests a few random paths to learn how the server
responds to "not found" (its status + body length). Any discovered path matching that
**soft-404 baseline** is filtered out — so servers that return `200` for everything
don't flood your results. On **wildcard/SPA sites** the filter compares response
*bodies* (hash), not just size, so real routes aren't hidden.

### Finding pages that aren't in your wordlist

Two extras catch obvious pages like `/login` and `/register` even with a small list:

- **Built-in path list** — a curated set of high-signal paths (auth, admin, api, docs,
  `.git`, `.env`, backups, …) is always tried, so you're never dependent on SecLists
  being installed. Disable with `--no-builtin`.
- **In-page link extraction** — ReconFlow reads the page it already fetched in the HTTP
  phase and seeds any same-site links (`href`/`src`/`action`) into content discovery, so
  routes linked from the homepage are found even when no wordlist contains them.

---

## Vulnerability detection (`--vuln`)

Opt-in phase that wraps two industry-standard **detection** scanners and folds their
output into the same report:

- **Nuclei** — ReconFlow writes the live URLs it found to a list and runs
  `nuclei -l <list> -jsonl -severity <sev> -rate-limit <n>`, then parses each finding.
- **WPScan** — runs **only** against endpoints fingerprinted as WordPress in the `http`
  phase (`wpscan --url <u> --format json`). Add a free API token for the vuln database.

Both are auto-skipped (with an install hint) if the binary isn't on `PATH`, so the rest
of the run still completes.

```bash
python reconflow.py example.com --vuln
python reconflow.py example.com --vuln --severity high,critical --nuclei-rate 100
python reconflow.py example.com --vuln --wpscan-api-token YOUR_TOKEN
```

**Scope note:** this phase *detects and reports* — it does not exploit. Verify each
finding manually, within your program's rules, before reporting. Automated
exploitation / privilege escalation is intentionally out of scope.

---

## Kali Linux — setup & run

Kali already ships Python 3, Nuclei, WPScan, and SecLists in most builds. Full setup:

```bash
# 1. Get the code onto Kali (copy the folder over, or git clone your repo), then:
cd reconflow

# 2. Python deps
pip install -r requirements.txt        # or: pip install --break-system-packages -r requirements.txt

# 3. Make sure the scanners + wordlists are present
sudo apt update && sudo apt install -y seclists nuclei wpscan   # most are preinstalled
nuclei -update-templates                                        # refresh template DB

# 4. SecLists on Kali lives here — matches config.yaml out of the box:
ls /usr/share/seclists/Discovery/Web-Content/common.txt
```

Run it (it asks you to confirm authorization first):

```bash
# Recon only
python3 reconflow.py target.com --phases resolve,ports

# Full recon + content discovery
python3 reconflow.py target.com --wordlist common,exposed --extensions php,txt

# Everything incl. vuln detection
python3 reconflow.py target.com --wordlist common --vuln --severity medium,high,critical
```

Then open the report:

```bash
xdg-open reconflow-target.com-*/report.html
```

If you cloned SecLists somewhere custom, point at it with `--seclists /path/to/SecLists`
(or edit `config.yaml`). Non-interactive/automated runs need `--yes`.

---

## Roadmap (v2 ideas)

- Subdomain enumeration and virtual-host discovery.
- Scope allow/deny lists enforced automatically.
- Run-to-run diffing and webhook notifications.
- Optional handoff to templated checkers (e.g. `nuclei`).

---

*For authorized security testing only.*
