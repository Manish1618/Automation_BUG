# ReconFlow — Product Requirements Document

**Version:** 1.0
**Owner:** manishkumarmeher90@gmail.com
**Status:** Draft
**Date:** 2026-09-27

---

## 1. Overview

ReconFlow is a command-line reconnaissance orchestrator for **authorized** security
testing (bug bounty programs, pentest engagements, CTFs, and your own assets). It runs
the early recon steps you normally do by hand — one after another — and produces a single
consolidated report.

It is a *thin orchestrator over standard, well-understood techniques*: TCP connect
scanning, HTTP fingerprinting, and content/directory discovery with SecLists wordlists. It
performs **enumeration and information gathering only** — it does not exploit anything,
test credentials, or attempt to evade detection.

## 2. Problem statement

At the start of every engagement you repeat the same sequence: find which ports are open,
identify the web services, and enumerate directories/files with a handful of SecLists
wordlists. Today that means running `nmap`, `httpx`, and `ffuf`/`gobuster` separately and
manually stitching their output together. ReconFlow runs the sequence for you and returns
one report.

## 3. Goals

- **G1** — Run recon phases *step by step* in one command: resolve → ports → HTTP probe → content discovery.
- **G2** — Use SecLists wordlists via friendly presets (`common`, `small`, `medium`, `big`, `raft`, `exposed`, `api`) or any custom path.
- **G3** — Produce **one consolidated output**: terminal summary + `report.json` + `report.html`.
- **G4** — Be fast (async concurrency) but a *good citizen* (rate limiting, sane defaults, honest User-Agent).
- **G5** — Be resumable/composable — each phase can run alone; JSON output feeds other tools.
- **G6** — Cross-platform (Windows / Linux / macOS), Python 3.9+.

## 4. Non-goals (v1)

- No exploitation, parameter fuzzing, or credential testing.
- No subdomain enumeration / DNS brute-force (candidate for v2).
- No detection/WAF evasion.
- No distributed scanning or scheduling.
- No GUI/web frontend (deliberate — see §6).

## 5. Target user

A bug bounty hunter / pentester comfortable on the command line who operates strictly
**within an authorized program scope**.

## 6. Design decision: CLI, not web UI

| Option | Verdict |
|---|---|
| **CLI + HTML/JSON report** (chosen) | Fits how recon is actually run (SSH, VPS, pipelines, cron). Fastest to build and extend. Still gives a single "everything in one place" HTML report. |
| Basic web UI | Adds a server + frontend to maintain, needs a browser open, harder to script/chain. No recon upside for a personal tool. Revisit only if it becomes multi-user/team. |

**Chosen: a CLI orchestrator that writes a consolidated HTML + JSON report.**

## 7. Functional requirements

### Phase 0 — Authorization gate
- On start, print the resolved target + planned actions and require explicit confirmation.
- `--yes` bypasses for automation; in a non-interactive shell without `--yes`, refuse to run.

### Phase 1 — Resolve
- Resolve hostname → IPv4/IPv6; record all A/AAAA records. Accept a raw IP too.

### Phase 2 — Port scan
- Async TCP **connect** scan (no raw sockets / admin rights needed).
- Port sets: `common` (curated ~130), `full` (1–65535), ranges (`1-1024`), lists (`80,443,8080`), or combos.
- Map open ports → service name. Configurable concurrency + timeout.

### Phase 3 — HTTP probe
- For each open web-capable port, fetch the root URL (http/https auto-detected).
- Capture: status, `Server`, `X-Powered-By`, page title, content-type, length, redirect chain.
- Lightweight tech fingerprinting from headers/cookies/body markers.

### Phase 4 — Content discovery
- Directory/file enumeration against the chosen web endpoint(s) using SecLists wordlist(s).
- Preset or custom wordlist path; merge multiple lists; optional extensions (`php,html,txt`).
- **Soft-404 calibration**: probe random paths first, filter false positives by status + length.
- Show matched status codes (default `200,204,301,302,307,401,403,405,500`), redirects, sizes.
- Concurrency cap + optional per-request delay (rate limiting).

### Phase 5 — Report
- Terminal summary tables (via `rich`).
- `report.json` — full structured results.
- `report.html` — self-contained, dark-themed, one-page consolidated report.

## 8. CLI (summary)

```
reconflow <target> [--url URL] [--ports common|full|1-1024|80,443]
                   [--wordlist common,exposed|/path/to/list.txt]
                   [--extensions php,html] [--phases resolve,ports,http,content]
                   [--http-concurrency N] [--port-concurrency N]
                   [--delay S] [--match-codes 200,301,403]
                   [--seclists /path/to/SecLists] [--output DIR] [--yes]
```

## 9. Tech stack

- **Python 3.9+**, `asyncio`
- `aiohttp` (async HTTP), `rich` (terminal UX), `PyYAML` (config)
- Standard library for TCP scanning (`asyncio.open_connection`) — no admin rights, no raw sockets.

## 10. Responsible-use requirements

- **R1** — Only scan assets you are authorized to test (program scope / written permission).
- **R2** — Rate limiting on by default; honest identifying User-Agent.
- **R3** — Recon/enumeration only — no exploitation or evasion.
- **R4** — Authorization confirmation gate before any network activity.

## 11. Roadmap (post-v1)

- Subdomain enumeration (passive sources + optional resolve).
- Virtual-host discovery.
- Scope file (in-scope / out-of-scope allow-lists) enforced automatically.
- Per-program profiles, run-to-run diffing, webhook notifications.
- Optional integration with templated checkers (e.g. `nuclei`).

## 12. Success metrics

- One command replaces the manual nmap → httpx → ffuf handoff.
- Report opens in a browser and shows all findings without extra steps.
- Runs unchanged on Windows, Linux, macOS.
