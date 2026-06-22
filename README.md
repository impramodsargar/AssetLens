<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="assets/logo-dark.svg">
    <img alt="AssetLens" src="assets/logo-light.svg" width="260">
  </picture>
</p>

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

**AssetLens** is a PowerShell-native passive reconnaissance collector for a **single internet-facing host**. It gathers everything from third-party sources - without sending a single packet to the target - and produces a self-contained report (plain text / JSON, readable with nothing but a text editor) plus a ranked worklist of suggested next checks.

> **The rule:** PASSIVE = zero packets to the target host. Every artifact comes from third parties that already scanned it: certificate transparency, internet-scan DBs, web archives, RDAP, OSINT APIs.

## Features

- **Zero-touch passive** - all data from third-party sources; the target never sees you
- **Single-host discipline** - every off-host asset is auto-tagged `OUT OF SCOPE, DO NOT TEST` and kept out of the active worklist
- **Seven phases** - scope/ownership, certs, internet-scan, origin-behind-CDN, history, JS mining, OSINT
- **Keyed or keyless** - a keyless HTTP core runs with zero config; free keys only widen coverage
- **Microsoft 365 / Azure AD** tenant mapping - tenant ID, Managed vs Federated, ADFS/IdP URL, tenant domains
- **Passive tech fingerprinting** - a bundled Wappalyzer ruleset matched against archived bodies (no live request)
- **OSINT** - AlienVault OTX threat-intel, AbuseIPDB reputation, GitHub code + commit-emails, LeakIX, breach-check
- **Self-contained report** - `Report.md` plus a `Report.html` dashboard with no CDN deps, so it opens anywhere offline
- **Packaged output** - auto-zipped and SHA-256'd, with a ranked `Verify.md` worklist of suggested next checks
- **PowerShell-native** - no WSL, no Git Bash; the keyless core works before you install anything

## Installation

```powershell
git clone https://github.com/impramodsargar/AssetLens.git
cd AssetLens

# 1. install the toolchain (subfinder, gau, waymore, uro, retire.js, trufflehog, gitleaks)
.\Invoke-AssetLens.ps1 -Setup
# if Go / Python were just installed, restart the shell, then:
.\Invoke-AssetLens.ps1 -Setup -SkipBase

# 2. (optional) add your free API keys
Copy-Item .\config\keys.example.ps1 .\config\keys.ps1
notepad .\config\keys.ps1
```

> The keyless HTTP core (RDAP, crt.sh, Shodan-InternetDB, Tranco, LeakCheck, M365 mapping) runs with **zero keys**. Keys only widen coverage; anything left blank is skipped. `config\keys.ps1` is git-ignored - never commit real keys.

## API keys

Every key is **optional** and **free-tier** (Shodan is the lone exception). The keyless core already covers RDAP, crt.sh, Shodan-InternetDB, the web archives (Wayback / CommonCrawl / OTX via `gau` + `waymore`), Tranco, urlscan search, and LeakCheck. Add keys only to widen coverage; anything left blank is skipped.

```powershell
Copy-Item .\config\keys.example.ps1 .\config\keys.ps1
notepad .\config\keys.ps1
```

| Provider | Tier | Powers | Where to get the key |
|---|---|---|---|
| **VirusTotal** | Free (4/min, 500/day) | P4 passive-DNS, reputation | https://www.virustotal.com/gui/my-apikey |
| **Censys** | Free (Platform PAT) | P3 host data | https://platform.censys.io |
| **Netlas** | Free (daily quota) | P3 host + P4 domain | https://netlas.io |
| **SecurityTrails** | Free (50/mo) | P4 passive-DNS | https://securitytrails.com/app/account/credentials |
| **URLScan** | Free (raises limits) | P5 history | https://urlscan.io/user/profile |
| **GitHub** | Free (read-only PAT) | P7 code + commit-email search | https://github.com/settings/tokens |
| **LeakIX** | Free | P7 host exposure | https://leakix.net/settings/api |
| **AlienVault OTX** | Free | P7 threat pulses + passive-DNS | https://otx.alienvault.com/api |
| **AbuseIPDB** | Free (1000/day) | P3 IP reputation | https://www.abuseipdb.com/account/api |
| **CriminalIP** | Free | P4 origin-behind-CDN pivot | https://www.criminalip.io/mypage/information |
| **Quake (360)** | Free (token) | P4 origin pivot | https://quake.360.net |
| **Shodan** | **Paid** membership | P3 host lookup (keyless InternetDB is the free fallback) | https://account.shodan.io |

> The **GitHub** token only needs read-only public access (a classic PAT with `public_repo`, or a fine-grained token with public-repository read). After signup, each key usually lives under your account or profile/API settings. Run `.\Invoke-AssetLens.ps1 -Validate` to live-check every key you added.

## Usage

```powershell
.\Invoke-AssetLens.ps1 <host> [-Strict] [-HttpOnly] [-Keyless] [-Enum] [-UatBase https://uat..]
```

| Command | What it does |
|---|---|
| `.\Invoke-AssetLens.ps1 <host>` | **RECON** -> package + `Report.md` + auto-zip |
| `.\Invoke-AssetLens.ps1 -Setup [-SkipBase]` | install the toolchain |
| `.\Invoke-AssetLens.ps1 -Report -Package <dir>` | (re)build `Report.md` - pure local, no network |
| `.\Invoke-AssetLens.ps1 -MapUat -Package <dir> -UatBase https://uat.host` | map URIs -> `uat_targets.txt` - pure local |
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

# recon, then map the harvested URIs onto another host for replay
.\Invoke-AssetLens.ps1 app.target.com -UatBase https://uat.target.com
```

Output lands in `output\app.target.com_<date>\`, auto-zipped with a `.zip.sha256` ready to transfer.

## Modes

| Flag | Effect |
|---|---|
| *(default)* | Pragmatic - one DNS resolution of the target is permitted to get its IP |
| `-Strict` | No DNS resolution at all; IP comes only from passive-DNS APIs. Pick this if the rules forbid *any* target contact. |
| `-HttpOnly` | Skip every external CLI tool; run only the HTTP core (keyless + keyed APIs) |
| `-Keyless` | Ignore `config\keys.ps1`; run only the no-key sources. Default (no flag) uses your keys for the widest coverage. |
| `-Enum` | Opt-in subdomain enumeration (subfinder). **Off by default** - single-host scope. Only for wildcard / multi-host targets. |

The chosen mode is recorded in `Index.md`.

## What it collects

| Phase | Source | Key? |
|---|---|---|
| **P1** scope | RDAP (apex) + **DNS records (MX/TXT-SPF/DMARC/NS/CNAME)** + IP(s) + **geo-location & country flag** (ipwho.is / flagcdn) + **Microsoft 365 / Azure AD tenant mapping** (tenant ID, Managed/Federated, ADFS URL, tenant domains - queries Microsoft, not the target) + netblock owner + CDN/WAF flag | keyless |
| **P2** certs | crt.sh SANs (in-scope flagged); `subfinder` (`-Enum`) | keyless |
| **P3** scan | **Shodan-InternetDB** (ports/CPEs/CVEs, keyless!); Shodan host; Censys host; Netlas host; **AbuseIPDB** IP-reputation | InternetDB keyless |
| **P4** origin | VirusTotal + SecurityTrails passive-DNS; **CriminalIP** (+ Quake) direct cert -> IP pivot; Netlas domain | keyed |
| **P5** history | **`waymore`** (`-mode B` - Wayback + CommonCrawl + OTX + URLScan + **GhostArchive**) pulls the URL list **and** downloads the response bodies in one pass; **`gau`** as an independent backstop; **`uro`** collapses near-duplicate URL patterns | keyless |
| **P6** js | mines the bodies **`waymore`** already downloaded in P5 -> **native regex** extracts endpoints/params/wordlist/**cloud-assets**/**tech-fingerprint** (built-in signatures + bundled Wappalyzer ruleset)/**source-maps**/**API-specs** + `trufflehog`/`gitleaks` secrets + **`retire.js`** vuln-libs (CVEs link to NVD) | keyless core |
| **P7** osint | Tranco; GitHub code search **+ commit-emails**; **AlienVault OTX** threat-pulses + passive-DNS; LeakIX; **LeakCheck** breach-check (per discovered email); SpiderFoot passive | mixed |

> Missing tool or missing key -> that step logs `SKIP` and the run continues. Coverage scales with what you have installed and configured.

## Output package

```
output/<host>_<date>/
  Report.md        <- synthesized brief: services / CVEs / origins / attack-surface / secrets / OSINT  (READ FIRST)
  Report.html      <- same, self-contained dashboard: metric tiles + host-location map + detail cards
  Index.md         <- passive-only attestation + mode + key status
  Verify.md        <- ranked worklist of suggested next checks
  OOS_observed.txt <- every off-host asset, flagged DO NOT TEST
  manifest.sha256  <- integrity / chain-of-custody
  recon.log
  01_scope/  02_certs/  03_scan/  04_origin/  05_history/  06_js/  07_osint/  08_tech/
```

### Packaging

Each recon run **auto-creates** `output\<host>_<date>.zip` + `.zip.sha256`. Re-zip any package with:

```powershell
.\Invoke-AssetLens.ps1 -Zip -Package output\<host>_<date>
```

Transfer the zip via your preferred channel and **verify the `.zip.sha256`** on the other side. Everything is plain text / JSON, so it is usable anywhere with nothing but a text editor - drive `Verify.md` from there.

## Scope discipline

The target is **one host**. Everything else the tools surface - SANs, subdomains, co-hosted siblings, InternetDB hostnames, passive-DNS neighbours - is written to `OOS_observed.txt` as **OUT OF SCOPE, DO NOT TEST**, never into the active worklist. The guard is automatic, so off-host assets cannot accidentally end up on the active list.

## Notes

- **Keys** live in `config\keys.ps1`, which is git-ignored. Never commit real keys; ship only `keys.example.ps1`, and rotate any key that ever lands in a log.
- **Why PowerShell, not Git Bash:** avoids MSYS path-mangling of slash args; HTTP lookups use `Invoke-RestMethod` (no curl arg-mangling).
- **Tech fingerprints:** `config\wappalyzer.json` is a slimmed, MIT-licensed Wappalyzer ruleset (via ProjectDiscovery `wappalyzergo`; see `config\wappalyzer.LICENSE`) - body-matchable patterns only, matched **passively** against archived bodies. Header/JS-only technologies (Shopify, Next.js) are invisible this way by design.
- **Do not** point a hosted online scanner at the target - it is active-by-proxy and leaks the asset.
- **Extending:** each phase is a `PhaseN-*` function in `Invoke-AssetLens.ps1`. Add a source by writing into the matching `0N_` folder and calling `Add-OOS` for anything off-host.
- `-Setup` installs Go tools to `%GOPATH%\bin`, Python tools to Python's `Scripts`, and retire.js to npm's global dir. AssetLens **adds these to PATH automatically at runtime**, so a normal run finds its tools even if they were never added to the system PATH.

## Troubleshooting

**"running scripts is disabled on this system"** - that is PowerShell's ExecutionPolicy, not AssetLens. Set it once for your user:
```powershell
Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned
```
or bypass per run (no system change):
```powershell
powershell -ExecutionPolicy Bypass -File .\Invoke-AssetLens.ps1 <host>
```
On a managed machine run `Get-ExecutionPolicy -List`: if the blocking scope is `MachinePolicy` or `UserPolicy` it is enforced by Group Policy and the above are overridden - involve IT or use an unmanaged machine.

**A tool reads `MISSING` right after `-Setup`** - winget-installed runtimes need PATH refreshed. `-Setup` now refreshes PATH in-session automatically; if anything is still missing, open a new shell and run `.\Invoke-AssetLens.ps1 -Setup -SkipBase`, then `.\Invoke-AssetLens.ps1 -Validate`.

**`waymore` / `uro` MISSING** - they install via pip into Python's `Scripts` folder, which AssetLens auto-adds at runtime, so this is usually a non-issue. If they truly failed to install (common on a brand-new Python):
```powershell
python -m pip install -U pip setuptools wheel
python -m pip install --upgrade waymore uro
```
Still failing on a bleeding-edge Python (e.g. 3.14)? Install Python 3.12 (`winget install Python.Python.3.12`) - it has prebuilt wheels for every dependency.

**Locked-down corporate laptop** - check `$ExecutionContext.SessionState.LanguageMode`. If it is `ConstrainedLanguage`, .NET one-liners like `[Environment]::SetEnvironmentVariable(...)` will fail - but AssetLens itself is Constrained-Language-Mode safe and never needs them.

---
