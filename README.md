# AssetLens

Passive-only recon collector for a **single internet-facing host**, run **outside the VDI** on Windows. It produces a self-contained, VDI-importable package (plain text / JSON, readable with nothing but a text editor) plus a ranked active-test worklist.

> **The rule:** PASSIVE = zero packets to the target host. Every artifact comes from third parties who already scanned it (certificate transparency, internet-scan DBs, web archives, RDAP, OSINT APIs). All active testing is deferred to the authorized VDI.

PowerShell-native — no WSL, no Git Bash. Runs on a stock Windows box (the keyless HTTP core works before you install anything).

---

## Quick start

```powershell
# 1. (once per machine) install the toolchain
.\Invoke-AssetLens.ps1 -Setup
# restart shell if Go/Python were just installed, then:
.\Invoke-AssetLens.ps1 -Setup -SkipBase

# 2. (once) add your API keys
Copy-Item .\config\keys.example.ps1 .\config\keys.ps1
notepad .\config\keys.ps1

# 3. run against one host
.\Invoke-AssetLens.ps1 app.target.com            # with keys (full coverage)
.\Invoke-AssetLens.ps1 app.target.com -Keyless   # without keys (no-key sources only)
```

Output lands in `output\app.target.com_<date>\`. Step 2 (keys) is optional — skip it and every run is keyless.

### One script, seven modes

| Command | What it does |
|---|---|
| `.\Invoke-AssetLens.ps1 <host>` | **RECON** → package + `Report.md` + auto-zip (add `-UatBase https://uat..` to also map URIs) |
| `.\Invoke-AssetLens.ps1 -Setup [-SkipBase]` | install the toolchain |
| `.\Invoke-AssetLens.ps1 -Report -Package <dir>` | (re)build `Report.md` on a package — pure local, runs **inside the VDI** |
| `.\Invoke-AssetLens.ps1 -MapUat -Package <dir> -UatBase https://uat.host` | map prod URIs → `uat_targets.txt` — pure local, runs **inside the VDI** |
| `.\Invoke-AssetLens.ps1 -Zip -Package <dir> [-FullBodies]` | (re)zip a package for transfer; raw response bodies excluded by default |
| `.\Invoke-AssetLens.ps1 -Diff -Package <new> -Against <old>` | diff two scans of the same host → `Diff.md` (new ports/CVEs/SANs/endpoints) — pure local |
| `.\Invoke-AssetLens.ps1 -Validate` | preflight: live-check every API key + tool (hits providers + benign IPs, never a target) |

---

## Modes

| Flag | Effect |
|---|---|
| *(default)* | Pragmatic — one DNS resolution of the target is permitted to get its IP |
| `-Strict` | No DNS resolution at all; IP comes only from passive-DNS APIs (VirusTotal/SecurityTrails). Pick this if the RoE forbids *any* target contact. |
| `-HttpOnly` | Skip every external CLI tool; run only the HTTP core (keyless + keyed APIs). Good on a machine where the tools aren't installed. |
| `-Keyless` | Ignore `config\keys.ps1` — run only the no-key sources. Default (no flag) uses your keys for the widest coverage. |
| `-Enum` | Opt-in subdomain enumeration (subfinder). **Off by default** — single-host scope. Only for wildcard / multi-host engagements. |

Set the passive boundary with the client and pick the mode to match. The chosen mode is recorded in `Index.md`.

---

## What it collects

| Phase | Source | Key? |
|---|---|---|
| **P1** scope | RDAP (apex) + **DNS records (MX/TXT-SPF/DMARC/NS/CNAME)** + IP(s) + **geo-location & country flag** (ipwho.is / flagcdn) + **Microsoft 365 / Azure AD tenant mapping** (tenant ID, Managed/Federated, ADFS URL, tenant domains — queries Microsoft, not the target), netblock owner, CDN/WAF flag | keyless |
| **P2** certs | crt.sh SANs (in-scope flagged); `subfinder` | keyless |
| **P3** scan | **Shodan-InternetDB** (ports/CPEs/CVEs, keyless!); Shodan host; Censys host; Netlas host | InternetDB keyless |
| **P4** origin | VirusTotal + SecurityTrails passive-DNS; **CriminalIP** (+ Fofa/Quake) direct cert→IP pivot; Netlas domain | keyed |
| **P5** history | `gau` + `waybackurls` + urlscan → urls, params, js; **`uro`** collapses near-duplicate URL patterns | keyless core |
| **P6** js | **`waymore`** downloads archived responses → **native regex** extracts endpoints/params/wordlist/**cloud-assets**/**tech-fingerprint (built-in signatures + bundled Wappalyzer ruleset, matched passively against the bodies)**/**source-maps**/**API-specs** + `trufflehog`/`gitleaks` secrets + **`retire.js`** vuln-libs (CVEs link to NVD) | keyless core |
| **P7** osint | Tranco; GitHub code search; IntelX; LeakIX; Hunter emails → **LeakCheck** breach-check (free/keyless); SpiderFoot passive | mixed |

Missing tool or missing key → that step logs `SKIP` and the run continues. Coverage scales with what you've installed/configured.

---

## Output package

```
output/<host>_<date>/
  Report.md             <- security scorecard + ranked findings + brief (READ THIS FIRST)
  Report.html           <- same, MobSF-style dashboard (score/grade, findings; self-contained, light/dark)
  Index.md              attestation + mode + key status
  01_scope/  02_certs/  03_scan/  04_origin/
  05_history/  06_js/  07_osint/  08_tech/
  Verify_inside_vdi.md  ← ranked active worklist (the bridge)
  OOS_observed.txt         every off-host asset, flagged DO NOT TEST
  manifest.sha256          integrity / chain-of-custody
  recon.log
  05_history/uris.txt      unique endpoint paths -> -MapUat to replay on a UAT host
```

### Into the VDI
Each recon run **auto-creates** `output\<host>_<date>.zip` + `.zip.sha256`. Re-zip any package with:
```powershell
.\Invoke-AssetLens.ps1 -Zip -Package output\<host>_<date>
```
Transfer the zip via the client-approved channel and **verify `.zip.sha256`** on the other side. Everything is plain text/JSON, so it's usable inside a locked-down VDI with no tools — drive `Verify_inside_vdi.md` from there.

---

## Scope discipline (single host)

The target is **one host**. Everything else the tools surface — SANs, subdomains, co-hosted siblings, InternetDB hostnames — is written to `OOS_observed.txt` as **OUT OF SCOPE, DO NOT TEST**, never into the active worklist. This guard is automatic so a junior tester can't drift across the line.

---

## For the team

- **Keys are per-tester.** `config\keys.ps1` is git-ignored — never commit real keys. Ship only `keys.example.ps1`.
- **Uniform output** across testers → consistent reporting and clean hand-off.
- **Don't** point a hosted online scanner (web-check.xyz, etc.) at a client target — it's active-by-proxy and leaks the asset. Self-host any such tool inside the VDI.
- **Extending:** each phase is a `PhaseN-*` function in `Invoke-AssetLens.ps1`. Add a source by writing into the matching `0N_` folder and calling `Add-OOS` for anything off-host.

## Notes / gotchas

- Why PowerShell, not Git Bash: avoids MSYS path-mangling of slash args; HTTP lookups use `Invoke-RestMethod` (no curl arg-mangling).
- `-Setup` adds Go's `%GOPATH%\bin` tools — if `subfinder` etc. read MISSING after install, add that dir to PATH and restart the shell.
- crt.sh and the archive endpoints rate-limit; a `WARN` on one lookup doesn't abort the run.
- **Tech fingerprints:** `config\wappalyzer.json` is a slimmed, MIT-licensed Wappalyzer ruleset (via ProjectDiscovery `wappalyzergo`; see `config\wappalyzer.LICENSE`) — body-matchable patterns only, matched **passively** against archived bodies (zero requests to the target). Header/JS-only technologies (e.g. Shopify, Next.js) can't be seen this way by design.
```
