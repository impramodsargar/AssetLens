<h1 align="center">AssetLens</h1>

<p align="center">
  <b>Passive reconnaissance for a single internet-facing host. Zero packets to the target.</b>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/PowerShell-5.1%2B-5391FE?logo=powershell&logoColor=white" alt="PowerShell 5.1+">
  <img src="https://img.shields.io/badge/platform-Windows-0078D6?logo=windows&logoColor=white" alt="Windows">
  <img src="https://img.shields.io/badge/recon-passive-2ea44f" alt="Passive">
  <img src="https://img.shields.io/badge/packets%20to%20target-0-2ea44f" alt="0 packets to target">
  <img src="https://img.shields.io/badge/scope-single--host-1f6feb" alt="Single host">
</p>

<p align="center">
  <a href="#features">Features</a> •
  <a href="#installation">Installation</a> •
  <a href="#usage">Usage</a> •
  <a href="#running-assetlens">Running</a> •
  <a href="#modes">Modes</a> •
  <a href="#what-it-collects">Collects</a> •
  <a href="#output-package">Output</a> •
  <a href="#scope-discipline">Scope</a>
</p>

---

**AssetLens** is a PowerShell-native passive reconnaissance collector for a **single internet-facing host**. It runs **outside the VDI** on a stock Windows box and produces a self-contained, VDI-importable package (plain text / JSON, readable with nothing but a text editor) plus a ranked active-test worklist - everything an engagement needs to start, gathered without sending a single packet to the target.

> **The rule:** PASSIVE = zero packets to the target host. Every artifact comes from third parties that already scanned it (certificate transparency, internet-scan DBs, web archives, RDAP, OSINT APIs). All active testing is deferred to the authorized VDI.

## Features

- **Zero-touch passive** - all data from third-party sources; the target never sees you
- **Single-host discipline** - every off-host asset is auto-tagged `OUT OF SCOPE, DO NOT TEST`, never the active worklist
- **Seven phases** - scope/ownership, certs, internet-scan, origin-behind-CDN, history, JS mining, OSINT
- **Keyed or keyless** - a keyless HTTP core runs with zero config; free keys only widen coverage
- **Microsoft 365 / Azure AD** tenant mapping - tenant ID, Managed vs Federated, ADFS/IdP URL, tenant domains
- **Passive tech fingerprinting** - a bundled Wappalyzer ruleset matched against archived bodies (no live request)
- **OSINT** - AlienVault OTX threat-intel, AbuseIPDB reputation, GitHub code + commit-emails, LeakIX, breach-check
- **Self-contained report** - `Report.md` plus a `Report.html` dashboard with no CDN deps, so it opens offline inside the VDI
- **VDI bridge** - auto-zipped, SHA-256'd package and a ranked `Verify_inside_vdi.md` worklist to drive active testing
- **PowerShell-native** - no WSL, no Git Bash; the keyless core works before you install anything

## Installation

```powershell
git clone https://github.com/impramodsargar/AssetLens.git
cd AssetLens

# 1. install the toolchain (subfinder, gau, waybackurls, waymore, uro, retire.js, trufflehog, gitleaks)
.\Invoke-AssetLens.ps1 -Setup
# if Go / Python were just installed, restart the shell, then:
.\Invoke-AssetLens.ps1 -Setup -SkipBase

# 2. (optional) add your free API keys
Copy-Item .\config\keys.example.ps1 .\config\keys.ps1
notepad .\config\keys.ps1
```

> The keyless HTTP core (RDAP, crt.sh, Shodan-InternetDB, Tranco, LeakCheck, CommonCrawl, M365 mapping) runs with **zero keys**. Keys only widen coverage; anything left blank is skipped. `config\keys.ps1` is git-ignored - never commit real keys.

## Usage

```powershell
.\Invoke-AssetLens.ps1 <host> [-Strict] [-HttpOnly] [-Keyless] [-Enum] [-UatBase https://uat..]
```

| Command | What it does |
|---|---|
| `.\Invoke-AssetLens.ps1 <host>` | **RECON** -> package + `Report.md` + auto-zip |
| `.\Invoke-AssetLens.ps1 -Setup [-SkipBase]` | install the toolchain |
| `.\Invoke-AssetLens.ps1 -Report -Package <dir>` | (re)build `Report.md` - pure local, runs **inside the VDI** |
| `.\Invoke-AssetLens.ps1 -MapUat -Package <dir> -UatBase https://uat.host` | map prod URIs -> `uat_targets.txt` - pure local |
| `.\Invoke-AssetLens.ps1 -Zip -Package <dir> [-FullBodies]` | (re)zip a package for transfer; raw bodies excluded by default |
| `.\Invoke-AssetLens.ps1 -Diff -Package <new> -Against <old>` | diff two scans -> `Diff.md` (new ports/CVEs/SANs/endpoints) |
| `.\Invoke-AssetLens.ps1 -Validate` | preflight: live-check every API key + tool (hits providers + benign IPs, never a target) |

## Running AssetLens

```powershell
# full keyed pass - widest coverage
.\Invoke-AssetLens.ps1 app.target.com

# keyless pass - no API keys, no quota burn, nothing tied to your accounts
.\Invoke-AssetLens.ps1 app.target.com -Keyless

# strictest passivity - no DNS resolution at all (IP only from passive-DNS APIs)
.\Invoke-AssetLens.ps1 app.target.com -Strict

# recon, then map the harvested URIs onto a UAT host for replay
.\Invoke-AssetLens.ps1 app.target.com -UatBase https://uat.target.com
```

Output lands in `output\app.target.com_<date>\`, auto-zipped with a `.zip.sha256` ready to carry into the VDI.

## Modes

| Flag | Effect |
|---|---|
| *(default)* | Pragmatic - one DNS resolution of the target is permitted to get its IP |
| `-Strict` | No DNS resolution at all; IP comes only from passive-DNS APIs. Pick this if the RoE forbids *any* target contact. |
| `-HttpOnly` | Skip every external CLI tool; run only the HTTP core (keyless + keyed APIs) |
| `-Keyless` | Ignore `config\keys.ps1`; run only the no-key sources. Default (no flag) uses your keys for the widest coverage. |
| `-Enum` | Opt-in subdomain enumeration (subfinder). **Off by default** - single-host scope. Only for wildcard / multi-host engagements. |

The chosen mode is recorded in `Index.md`.

## What it collects

| Phase | Source | Key? |
|---|---|---|
| **P1** scope | RDAP (apex) + **DNS records (MX/TXT-SPF/DMARC/NS/CNAME)** + IP(s) + **geo-location & country flag** (ipwho.is / flagcdn) + **Microsoft 365 / Azure AD tenant mapping** (tenant ID, Managed/Federated, ADFS URL, tenant domains - queries Microsoft, not the target) + netblock owner + CDN/WAF flag | keyless |
| **P2** certs | crt.sh SANs (in-scope flagged); `subfinder` (`-Enum`) | keyless |
| **P3** scan | **Shodan-InternetDB** (ports/CPEs/CVEs, keyless!); Shodan host; Censys host; Netlas host; **AbuseIPDB** IP-reputation | InternetDB keyless |
| **P4** origin | VirusTotal + SecurityTrails passive-DNS; **CriminalIP** (+ Quake) direct cert -> IP pivot; Netlas domain | keyed |
| **P5** history | `gau` + `waybackurls` + **CommonCrawl CDX** + urlscan -> urls, params, js; **`uro`** collapses near-duplicate URL patterns | keyless core |
| **P6** js | **`waymore`** downloads archived responses -> **native regex** extracts endpoints/params/wordlist/**cloud-assets**/**tech-fingerprint** (built-in signatures + bundled Wappalyzer ruleset)/**source-maps**/**API-specs** + `trufflehog`/`gitleaks` secrets + **`retire.js`** vuln-libs (CVEs link to NVD) | keyless core |
| **P7** osint | Tranco; GitHub code search **+ commit-emails**; **AlienVault OTX** threat-pulses + passive-DNS; LeakIX; **LeakCheck** breach-check (per discovered email); SpiderFoot passive | mixed |

> Missing tool or missing key -> that step logs `SKIP` and the run continues. Coverage scales with what you have installed and configured.

## Output package

```
output/<host>_<date>/
  Report.md              <- synthesized brief: services / CVEs / origins / attack-surface / secrets / OSINT  (READ FIRST)
  Report.html            <- same, self-contained dashboard: metric tiles + host-location map + detail cards
  Index.md               <- passive-only attestation + mode + key status
  Verify_inside_vdi.md   <- ranked active-test worklist (the bridge into the VDI)
  OOS_observed.txt       <- every off-host asset, flagged DO NOT TEST
  manifest.sha256        <- integrity / chain-of-custody
  recon.log
  01_scope/  02_certs/  03_scan/  04_origin/  05_history/  06_js/  07_osint/  08_tech/
```

### Into the VDI

Each recon run **auto-creates** `output\<host>_<date>.zip` + `.zip.sha256`. Re-zip any package with:

```powershell
.\Invoke-AssetLens.ps1 -Zip -Package output\<host>_<date>
```

Transfer the zip via the client-approved channel and **verify the `.zip.sha256`** on the other side. Everything is plain text / JSON, so it is usable inside a locked-down VDI with no tools - drive `Verify_inside_vdi.md` from there.

## Scope discipline

The target is **one host**. Everything else the tools surface - SANs, subdomains, co-hosted siblings, InternetDB hostnames, passive-DNS neighbours - is written to `OOS_observed.txt` as **OUT OF SCOPE, DO NOT TEST**, never into the active worklist. The guard is automatic so a junior tester cannot drift across the line.

## Notes

- **Keys are per-tester.** `config\keys.ps1` is git-ignored. Ship only `keys.example.ps1`; rotate any key that ever lands in a log.
- **Why PowerShell, not Git Bash:** avoids MSYS path-mangling of slash args; HTTP lookups use `Invoke-RestMethod` (no curl arg-mangling).
- **Tech fingerprints:** `config\wappalyzer.json` is a slimmed, MIT-licensed Wappalyzer ruleset (via ProjectDiscovery `wappalyzergo`; see `config\wappalyzer.LICENSE`) - body-matchable patterns only, matched **passively** against archived bodies. Header/JS-only technologies (Shopify, Next.js) are invisible this way by design.
- **Do not** point a hosted online scanner at a client target - it is active-by-proxy and leaks the asset. Self-host any such tool inside the VDI.
- **Extending:** each phase is a `PhaseN-*` function in `Invoke-AssetLens.ps1`. Add a source by writing into the matching `0N_` folder and calling `Add-OOS` for anything off-host.
- `-Setup` adds Go's `%GOPATH%\bin` tools; if `subfinder` etc. read MISSING after install, add that dir to PATH and restart the shell.

---

<p align="center">
  Passive package. All active verification happens in the authorized VDI. Nothing in <code>OOS_observed.txt</code> is in scope.
</p>
