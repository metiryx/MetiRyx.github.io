---
title: "3 Recon Tricks That Consistently Find Hidden Assets"
description: "Practical recon techniques to uncover hidden hosts, endpoints, and JS insights safely and responsibly."
layout: default
image: "img/cover.png"
---

<!-- Dark mode assets + toggle button -->
<!-- <link rel="stylesheet" href="css/style.css">
<script src="js/main.js" defer></script> -->

<!-- <div style="display:flex;gap:.5rem;align-items:center;margin-bottom:1rem;">
  <button id="dark-toggle" onclick="toggleDarkMode()">Toggle Dark</button>
  <small class="muted">Toggle theme — also follows your OS by default.</small>
</div> -->

# 3 Recon Tricks That Consistently Find Hidden Assets

> Short, practical, and responsible techniques to uncover forgotten hosts, hidden endpoints, and juicy testing surfaces. Sanitize before running against third-party targets — use only against assets you own or have explicit permission.

![Cover Image](img/cover.png)
## Table of Contents

* [Overview](#overview)
* [Trick 1 — Certificate Transparency: "crt.sh: Your Subdomain Spy"](#trick-1---certificate-transparency-crtsh-your-subdomain-spy)

  * [Why it works](#why-it-works)
  * [Safe commands / POC (sanitized)](#safe-commands--poc-sanitized)
* [Trick 2 — JS Recon: "Read the Client, Find the Server"](#trick-2---js-recon-read-the-client-find-the-server)

  * [Why it works](#why-it-works-1)
  * [Safe pipeline (download → extract → probe)](#safe-pipeline-download--extract--probe)
* [Trick 3 — Historical Sources: "Wayback & GitHub — The Time Machine"](#trick-3---historical-sources-wayback--github---the-time-machine)

  * [Why it works](#why-it-works-2)
  * [Safe checks and examples](#safe-checks-and-examples)
* [Automated workflow (safe skeleton)](#automated-workflow-safe-skeleton)
* [Sanity & Safety / Legal checklist](#sanity--safety--legal-checklist)
* [Responsible disclosure & next steps](#responsible-disclosure--next-steps)
* [References](#references)

---

## Overview

This write-up expands three high-signal recon techniques into concise, reproducible steps. Each section includes:

* A brief rationale (why it helps),
* A **sanitized** proof-of-concept (commands you can safely run against permitted targets),
* A recommended follow-up to validate findings without crossing ethical/legal lines.

Key idea: combine low-noise asset discovery (CT logs) → client-side intelligence (JS) → historical traces (Wayback/GitHub) to rapidly grow an accurate attack surface map.

---

## Trick 1 — Certificate Transparency: "crt.sh: Your Subdomain Spy"

### Why it works

Certificate Transparency (CT) logs record publicly-issued TLS certificates. Many hosts receive certificates when spun up for testing or staging and those certs show up in CT logs even if DNS never did. Searching CT logs can reveal forgotten or unindexed subdomains. ([crt.sh][1])

### Safe commands / POC (sanitized)

This example queries `crt.sh` for certificates related to `example.com`, extracts names, and deduplicates them. This only fetches public CT data.

```bash
# fetch JSON from crt.sh (safe read-only)
curl -s "https://crt.sh/?q=%25.example.com&output=json" \
  | jq -r '.[].name_value' \
  | tr ',' '\n' \
  | sed 's/^\*\.//g' \
  | sort -u > crtsh-hosts.txt

# quick HTTP probe (non-destructive): check which hosts respond on common ports
cat crtsh-hosts.txt | httpx -silent -ports 80,443 -mc 200,301 -title -o crtsh-live.txt
```

Notes:

* Use `--rate-limit` or other throttling flags when probing to avoid noisy scanning.
* `jq`, `httpx` are read-only here — they only request public endpoints. ([crt.sh][1])

---

## Trick 2 — JS Recon: "Read the Client, Find the Server"

### Why it works

Developers frequently expose hard-coded endpoint URLs, parameter names, and even staging/test domains in client JS or built assets. Parsing JavaScript can reveal API paths, internal endpoints, and parameter names (e.g., `callback`, `returnTo`, `next`) that are high-value test targets. Tools like `hakrawler` and `LinkFinder` automate extraction of URLs and params from JS. ([GitHub][2])

### Safe pipeline (download → extract → probe)

A minimal and sanitized pipeline that *only downloads and parses* public JS files:

```bash
# enumerate URLs quickly (hakrawler)
hakrawler -url https://target.example -scope domain -depth 2 -plain > urls.txt

# filter JS files and download them (safe)
grep -E "\.js($|\?)" urls.txt | sort -u | xargs -n1 -P4 -I{} bash -c 'curl -s "{}" >> all-js.txt && echo "{}" >> js-list.txt'

# extract likely endpoints & parameter names (safe parse)
cat all-js.txt | grep -Eo "(/api/[A-Za-z0-9_/\-\.]+|callback|returnTo|next|admin)" | sort -u > js-endpoints.txt

# probe those endpoints non-destructively (HEAD/GET)
cat js-endpoints.txt | while read p; do
  # normalize relative paths for human review; do NOT run payloads
  echo "[check] $p"
done
```

Hints:

* Focus on strings that look like endpoint patterns (`/api/`, `/internal/`, `/admin`).
* Do manual review of `js-endpoints.txt` before any active testing.

---

## Trick 3 — Historical Sources: "Wayback & GitHub — The Time Machine"

### Why it works

Archived pages and public commits often contain old endpoints, test pages, debug endpoints, or inline credentials (rare but sometimes present). Wayback snapshots and public GitHub searches are valuable to recover these historical artifacts. The Wayback Machine provides APIs for programmatic access. ([Internet Archive][3])

### Safe checks and examples

Use Wayback's CDX API to list snapshots and grep for interesting paths:

```bash
# list snapshots via Wayback CDX API (read-only)
curl -s "http://web.archive.org/cdx/search/cdx?url=target.example&output=json&filter=statuscode:200" \
  | jq -r '.[].[]' > wayback-raw.txt

# inspect locally for candidate endpoints (no live probing)
cat wayback-raw.txt | grep -E "/admin|/test|/staging|/internal" | sort -u > wayback-candidates.txt
```

For GitHub, use `git grep`, GitHub code search, or `gh`/API queries to find references to `target.example` or endpoint patterns. Only read public commits—do not attempt to access private repositories or use exposed credentials.

---

## Automated workflow (safe skeleton)

Below is a **sanitized Python skeleton** that ties the above steps into a local pipeline that *collects* and *stores* candidate assets for later manual review. It does **not** perform destructive tests or execute payloads.

```python
#!/usr/bin/env python3
"""
safe_recon_pipeline.py - skeleton (sanitized)
Collects crt.sh results, crawls JS references, and saves candidate endpoints for manual review.
"""

import subprocess, json, os

TARGET = "example.com"
OUTDIR = "recon-output"
os.makedirs(OUTDIR, exist_ok=True)

def fetch_crtsh(domain):
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    out = subprocess.check_output(["curl","-s", url])
    data = json.loads(out)
    names = set()
    for item in data:
        nv = item.get("name_value","")
        for host in nv.split(","):
            names.add(host.strip().lstrip("*."))
    with open(os.path.join(OUTDIR,"crtsh-hosts.txt"), "w") as f:
        f.write("\n".join(sorted(names)))
    return names

def crawl_js(domain):
    # requires hakrawler installed and on PATH
    subprocess.run(["hakrawler","-url",f"https://{domain}","-scope","domain","-plain"], stdout=open(os.path.join(OUTDIR,"urls.txt"),"w"))
    # further logic: download JS, extract patterns, etc. (left for manual review)

if __name__=="__main__":
    print("[*] fetching crt.sh entries")
    hosts = fetch_crtsh(TARGET)
    print(f"[*] found {len(hosts)} hosts (saved to {OUTDIR}/crtsh-hosts.txt)")
    print("[*] crawling for JS (hakrawler)...")
    crawl_js(TARGET)
    print("[*] pipeline complete. Review files in recon-output/ before any active testing.")
```

Use this skeleton as a starting point — expand with rate-limits, logging, and manual review steps. Never add automatic exploit stages without explicit permission.

---

## Sanity & Safety / Legal checklist

Before you run any of this against a domain:

* ✅ Confirm you **own** the target or have **explicit authorization** (scope, signed engagement, bounty program with clear scope).
* ✅ Avoid automated fuzzing or payload injection without permission. The commands above are read-only by default.
* ✅ Throttle requests (`--rate-limit`) and avoid excessive parallelism to prevent DoS.
* ✅ Do not attempt to access internal metadata endpoints or private resources (e.g., cloud provider metadata) when testing third-party domains — this can cross legal/ethical lines.
* ✅ Keep an audit log of commands and timestamps for reporting and reproducibility.

---

## Responsible disclosure & next steps

If you find an issue:

1. Check for a published Vulnerability Disclosure Policy (VDP) or Bug Bounty program for that org. Follow their rules (contact method, timelines, allowed testing). ([Fortinet][4])
2. If no policy exists, follow standard responsible disclosure best practices: document your findings, provide reproducible steps, avoid publishing PoCs that enable immediate abuse, and allow a reasonable remediation window. OWASP’s Vulnerability Disclosure Cheat Sheet is a good starting point. ([OWASP Cheat Sheet Series][5])

Suggested disclosure structure (short):

* Summary of impact (non-technical)
* Affected host(s)/endpoint(s) (publicly verifiable)
* Reproduction steps (sanitized, with safe checks)
* Mitigation recommendations
* Contact details & offer to assist with verification

---

## References

* crt.sh — Certificate Transparency search interface. ([crt.sh][1])
* Why CT logs and crt.sh reveal forgotten hosts — community writeups. ([riversecurity.eu][6])
* Hakrawler — fast crawler for extracting URLs and JS files. ([GitHub][2])
* LinkFinder — JS endpoint/parameter extraction tool. ([GitHub][7])
* Wayback Machine / CDX API — programmatic access to archived snapshots. ([Internet Archive][3])
* OWASP — SSRF overview and Vulnerability Disclosure Cheat Sheet (responsible disclosure). ([OWASP Foundation][8])

---

### Final notes

* Want this as a ready GitHub Pages site (with `_config.yml` and nicer styling)? I can scaffold it (theme, header image, license).
* Want a compact 5–7 tweet mini case (with sanitized command output) to cross-post on Twitter & GitHub? I can generate that too.

[1]: https://crt.sh/?utm_source=chatgpt.com "Crt.sh"
[2]: https://github.com/hakluke/hakrawler?utm_source=chatgpt.com "hakluke/hakrawler"
[3]: https://archive.org/help/wayback_api.php?utm_source=chatgpt.com "Wayback Machine APIs"
[4]: https://www.fortinet.com/uk/resources/cyberglossary/vulnerability-disclosure?utm_source=chatgpt.com "Vulnerability Disclosure: Risks, Significance, and Best ..."
[5]: https://cheatsheetseries.owasp.org/cheatsheets/Vulnerability_Disclosure_Cheat_Sheet.html?utm_source=chatgpt.com "Vulnerability Disclosure Cheat Sheet"
[6]: https://riversecurity.eu/finding-attack-surface-and-fraudulent-domains-via-certificate-transparency-logs/?utm_source=chatgpt.com "Finding Attack Surface and Other Interesting Domains via ..."
[7]: https://github.com/GerbenJavado/LinkFinder?utm_source=chatgpt.com "GerbenJavado/LinkFinder: A python script that finds ..."
[8]: https://owasp.org/www-community/attacks/Server_Side_Request_Forgery?utm_source=chatgpt.com "Server Side Request Forgery"

