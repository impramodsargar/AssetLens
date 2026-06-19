<#
.SYNOPSIS
    AssetLens : ONE script for passive recon on a SINGLE internet-facing host.
    PASSIVE = zero packets to the target; all data from third-party sources.
    Active verification is deferred to the authorized VDI.

.DESCRIPTION
    Seven modes (keys live in config\keys.ps1, git-ignored - never in this script):
      RECON  (default)  .\Invoke-AssetLens.ps1 app.target.com [-Strict] [-HttpOnly] [-Keyless] [-Enum] [-UatBase https://uat..]
                        (auto-zips the finished package + .zip.sha256; raw response bodies excluded - add -FullBodies to keep them)
      SETUP             .\Invoke-AssetLens.ps1 -Setup [-SkipBase]
      REPORT (rebuild)  .\Invoke-AssetLens.ps1 -Report -Package .\output\app.target.com_<date>
      MAP-UAT           .\Invoke-AssetLens.ps1 -MapUat -Package .\output\app.target.com_<date> -UatBase https://uat.target.com [-WithParams]
      ZIP               .\Invoke-AssetLens.ps1 -Zip -Package .\output\app.target.com_<date> [-FullBodies]
      DIFF              .\Invoke-AssetLens.ps1 -Diff -Package .\output\<host>_<new> -Against .\output\<host>_<old>
      VALIDATE          .\Invoke-AssetLens.ps1 -Validate   (live-check API keys + tools; hits providers + benign IPs, no target)

    -Report / -MapUat / -Zip / -Diff are pure-local (no network/installs) - safe to run INSIDE the VDI.
#>
#Requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Position = 0)][string]$Target,   # host to recon (RECON mode)
    [string]$OutRoot = (Join-Path $PSScriptRoot 'output'),
    [switch]$Strict,                            # no DNS resolution; passive-DNS APIs only
    [switch]$HttpOnly,                          # skip CLI tools; HTTP core only
    [switch]$Keyless,                           # RECON: ignore config\keys.ps1 - run keyless sources only (default = use keys if configured)
    [switch]$Enum,                              # opt-in subdomain enum (subfinder)
    [string]$UatBase,                           # RECON: also map URIs onto this UAT base at the end
    [switch]$Setup,                             # SETUP mode: bootstrap the toolchain
    [switch]$SkipBase,                          # SETUP: tools only (skip winget base runtimes)
    [switch]$Report,                            # REPORT mode: (re)build Report.md on -Package
    [switch]$MapUat,                            # MAP-UAT mode: map URIs onto -UatBase on -Package
    [string]$Package,                           # package dir for -Report / -MapUat
    [switch]$WithParams,                        # MAP-UAT: use path+query URIs
    [switch]$Zip,                               # ZIP mode: zip an existing -Package (recon auto-zips its own output)
    [switch]$FullBodies,                        # ZIP: also include the raw 06_js\responses\ bodies (default: excluded - already mined)
    [switch]$Diff,                              # DIFF mode: compare -Package (new) against -Against (old)
    [string]$Against,                           # DIFF: the older/baseline package to compare against
    [switch]$Validate                           # VALIDATE mode: live-check API keys + tools (no target)
)

$ErrorActionPreference = 'Continue'
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
$env:PYTHONIOENCODING = 'utf-8'   # keep Python tools (uro/waymore) from crashing on non-cp1252 stdout on Windows

# ================================================================ SETUP mode
function Invoke-Setup {
    param([switch]$SkipBase)
    function Has { param($n) [bool](Get-Command $n -ErrorAction SilentlyContinue) }
    function WG  { param($id) Write-Host "  winget: $id" -ForegroundColor DarkGray; winget install --id $id -e --accept-source-agreements --accept-package-agreements -h | Out-Null }
    function Install-GhBinary {
        param([string]$Repo, [string]$BinName, [string]$Dest, [string]$AssetPattern)
        try {
            $rel = Invoke-RestMethod "https://api.github.com/repos/$Repo/releases/latest" -Headers @{ 'User-Agent' = 'AssetLens' }
            $asset = $rel.assets | Where-Object { $_.name -match $AssetPattern } | Select-Object -First 1
            if (-not $asset) { Write-Host "  $BinName : no matching Windows asset" -ForegroundColor Yellow; return }
            $tmp = Join-Path $env:TEMP $asset.name
            Invoke-WebRequest $asset.browser_download_url -OutFile $tmp -UseBasicParsing
            $ext = Join-Path $env:TEMP "x_$BinName"
            Remove-Item $ext -Recurse -Force -ErrorAction SilentlyContinue; New-Item -ItemType Directory -Force -Path $ext | Out-Null
            if     ($asset.name -match '\.zip$')            { Expand-Archive $tmp -DestinationPath $ext -Force }
            elseif ($asset.name -match '\.tar\.gz$|\.tgz$') { tar -xf $tmp -C $ext }
            else   { Copy-Item $tmp (Join-Path $ext "$BinName.exe") }
            $exe = Get-ChildItem $ext -Recurse -Filter "$BinName.exe" | Select-Object -First 1
            if ($exe) { Copy-Item $exe.FullName (Join-Path $Dest "$BinName.exe") -Force; Write-Host "  $BinName OK" -ForegroundColor Green }
            else      { Write-Host "  $BinName : exe not found in archive" -ForegroundColor Yellow }
        } catch { Write-Host "  $BinName : $($_.Exception.Message)" -ForegroundColor Yellow }
    }
    Write-Host '== AssetLens setup ==' -ForegroundColor Cyan
    if (-not $SkipBase) {
        if (-not (Has winget)) { Write-Host 'winget not found - install "App Installer" from the Microsoft Store, then re-run.' -ForegroundColor Red; return }
        Write-Host 'Base runtimes...' -ForegroundColor Cyan
        if (-not (Has go))     { WG 'GoLang.Go' }
        if (-not (Has python)) { WG 'Python.Python.3.12' }
        if (-not (Has node))   { WG 'OpenJS.NodeJS' }
        if (-not (Has git))    { WG 'Git.Git' }
        if (-not (Has jq))     { WG 'jqlang.jq' }
        Write-Host 'If Go/Python were just installed, RESTART this shell, then run:  .\Invoke-AssetLens.ps1 -Setup -SkipBase' -ForegroundColor Yellow
    }
    $goMods = @('github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest', 'github.com/lc/gau/v2/cmd/gau@latest', 'github.com/tomnomnom/waybackurls@latest')
    $gobin = $null
    if (Has go) {
        Write-Host 'Go tools...' -ForegroundColor Cyan
        foreach ($m in $goMods) { Write-Host "  go install $m" -ForegroundColor DarkGray; go install $m }
        $gobin = Join-Path (& go env GOPATH) 'bin'
    } else { Write-Host 'go missing - skipping Go tools' -ForegroundColor Yellow }
    $binDest = if ($gobin) { $gobin } else { Join-Path $env:USERPROFILE 'go\bin' }
    New-Item -ItemType Directory -Force -Path $binDest | Out-Null
    Write-Host 'Prebuilt binaries (gitleaks / trufflehog)...' -ForegroundColor Cyan
    Install-GhBinary 'gitleaks/gitleaks'          'gitleaks'   $binDest '(?i)windows.*(x64|amd64).*\.zip$'
    Install-GhBinary 'trufflesecurity/trufflehog' 'trufflehog' $binDest '(?i)windows.*(amd64|x64).*\.(tar\.gz|zip)$'
    if (Has python) {
        Write-Host 'Python tools (waymore, uro)...' -ForegroundColor Cyan
        python -m pip install --quiet --upgrade waymore uro
    } else { Write-Host 'python missing - skipping waymore/uro' -ForegroundColor Yellow }
    if (Has npm) { Write-Host 'Node tools (retire.js)...' -ForegroundColor Cyan; npm install -g retire | Out-Null }
    Write-Host ''
    Write-Host 'Tool check:' -ForegroundColor Cyan
    foreach ($t in 'subfinder', 'gau', 'waybackurls', 'waymore', 'uro', 'retire', 'gitleaks', 'trufflehog', 'jq') {
        $ok = (Has $t) -or ($binDest -and (Test-Path (Join-Path $binDest "$t.exe")))
        Write-Host ('  {0,-14} {1}' -f $t, $(if ($ok) { 'OK' } else { 'MISSING' })) -ForegroundColor $(if ($ok) { 'Green' } else { 'DarkGray' })
    }
    Write-Host ''
    Write-Host 'Next: copy config\keys.example.ps1 -> config\keys.ps1 and add your FREE keys.' -ForegroundColor Cyan
}

# ================================================================ REPORT mode
function Build-Report {
    param([Parameter(Mandatory = $true)][string]$Package)
    if (-not (Test-Path $Package)) { throw "Package not found: $Package" }
    $u8 = New-Object System.Text.UTF8Encoding($false)
    function P     { param($rel) Join-Path $Package $rel }
    function GJson { param($rel) $p = P $rel; if (Test-Path $p) { try { return (Get-Content $p -Raw -ErrorAction Stop | ConvertFrom-Json) } catch { return $null } } return $null }
    function GLines{ param($rel) $p = P $rel; if (Test-Path $p) { return @(Get-Content $p -ErrorAction SilentlyContinue | Where-Object { $_ -and $_ -notmatch '^\s*#' }) } return @() }
    function Has   { param($rel) Test-Path (P $rel) }
    $out = New-Object System.Collections.Generic.List[string]
    function W { param($s = '') $out.Add([string]$s) }

    $host_ = (Split-Path $Package -Leaf) -replace '_\d{8}(-\d{6})?$', ''
    $ip    = if (Has '01_scope\ip.txt') { $t = @(GLines '01_scope\ip.txt'); if ($t.Count) { $t[0] } else { '' } } else { '' }
    $cdn   = if (Has '01_scope\cdn_flag.txt') { (Get-Content (P '01_scope\cdn_flag.txt') -Raw).Trim() } else { '' }
    $cdnName = if ($cdn) { ((($cdn -split ':')[-1]) -split '->')[0].Trim() } else { '' }
    $dns     = GLines '01_scope\dns_records.txt'
    $rdapIp  = GJson '01_scope\rdap_ip.json'
    $idb     = GJson '03_scan\internetdb.json'
    $shodan  = GJson '03_scan\shodan_host.json'
    $censys  = GJson '03_scan\censys_host.json'
    $sans    = GLines '02_certs\sans.txt'
    $cands   = GLines '04_origin\candidates.txt'
    $candsEnr = GLines '04_origin\candidates_enriched.txt'
    $allUrls = GLines '05_history\all_urls.txt'
    $dedupUrls = GLines '05_history\urls_deduped.txt'; if (-not @($dedupUrls).Count) { $dedupUrls = $allUrls }
    $params  = GLines '05_history\params.txt'
    $jsUrls  = GLines '05_history\js_urls.txt'
    $tranco  = GJson '07_osint\tranco.json'
    $ghHits  = GLines '07_osint\github_hits.txt'
    $emails  = GLines '07_osint\emails.txt'
    $breach  = GLines '07_osint\breach_hits.txt'
    $oos     = GLines 'OOS_observed.txt'
    $xEnd    = GLines '06_js\endpoints.txt'
    $xPar    = GLines '06_js\params.txt'
    $cloud   = GLines '06_js\cloud_assets.txt'
    # secret triage: trufflehog VERIFIED + gitleaks specific-rule = high-confidence; unverified + generic-api-key = likely-FP noise
    $thAll = @(); if (Has '06_js\trufflehog.json') { $thAll = @(GLines '06_js\trufflehog.json' | ForEach-Object { try { $_ | ConvertFrom-Json } catch {} } | Where-Object { $_ }) }
    $thVer = @($thAll | Where-Object { $_.Verified }); $thUnv = @($thAll | Where-Object { -not $_.Verified })
    $glAll = @(GJson '06_js\gitleaks.json' | Where-Object { $_ }); $glSpec = @($glAll | Where-Object { $_.RuleID -and $_.RuleID -ne 'generic-api-key' }); $glGen = @($glAll | Where-Object { $_.RuleID -eq 'generic-api-key' })
    $libs = @{}   # retire.js vuln libs (populated in section 2; pre-init so the HTML build always has it)
    $tech    = GLines '08_tech\fingerprint.txt'
    $smSrc   = GLines '06_js\sourcemap_sources.txt'
    $smRef   = GLines '06_js\sourcemap_refs.txt'
    $apiEp   = GLines '06_js\api_spec_endpoints.txt'
    $apiRefs = GLines '06_js\api_spec_refs.txt'
    $nvd     = 'https://nvd.nist.gov/vuln/detail/'
    $geo     = GJson '01_scope\geo.json'
    $m365    = GJson '01_scope\m365.json'
    $abuse   = GJson '03_scan\abuseipdb.json'
    $otx     = GJson '07_osint\otx_host.json'
    $worldPath = ''; $wpf = Join-Path $PSScriptRoot 'config\worldmap.txt'; if (Test-Path $wpf) { $worldPath = (Get-Content $wpf -Raw).Trim() }
    $flagSvg = ''; $fff = Join-Path $Package '01_scope\flag.svg'; if (Test-Path $fff) { $flagSvg = (Get-Content $fff -Raw).Trim() }

    $owner = ''
    if ($rdapIp) { $owner = [string]$rdapIp.name }
    elseif ($censys.resource.autonomous_system) { $owner = [string]$censys.resource.autonomous_system.name }

    $svc = @{}
    if ($shodan.data) { foreach ($d in $shodan.data) { if ($d.port) { $svc[[int]$d.port] = (@($d.product, $d.version) | Where-Object { $_ }) -join ' ' } } }
    if ($censys.resource.services) { foreach ($s in $censys.resource.services) { if ($s.port -and -not $svc[[int]$s.port]) { $svc[[int]$s.port] = [string]$s.extended_service_name; if (-not $svc[[int]$s.port]) { $svc[[int]$s.port] = [string]$s.service_name } } } }
    $ports = New-Object System.Collections.Generic.SortedSet[int]
    foreach ($src in @($idb.ports, $shodan.ports)) { foreach ($p in $src) { if ($p) { [void]$ports.Add([int]$p) } } }
    foreach ($k in $svc.Keys) { [void]$ports.Add([int]$k) }

    $vulns = @(); if ($idb.vulns) { $vulns = @($idb.vulns) }
    $cpes  = @(); if ($idb.cpes)  { $cpes  = @($idb.cpes) }

    $sig = '(?i)(/admin|/api|/auth|/login|/logout|/signup|/register|password|reset|token|oauth|/sso|upload|/download|/config|/setting|debug|/internal|/private|graphql|/gql|swagger|openapi|\.json|\.xml|\.env|backup|/export|/import|/payment|/invoice|/account|webhook|/callback|redirect)'
    $hot = @($dedupUrls | Where-Object { $_ -match $sig } | Sort-Object -Unique)


    W "# Recon Report - $host_"
    W ""
    W ("Generated from package ``{0}``" -f (Split-Path $Package -Leaf))
    W ""
    W ("| IP | Netblock / ASN | CDN / WAF | Tranco |")
    W ("|---|---|---|---|")
    W ("| {0} | {1} | {2} | {3} |" -f $(if ($ip) { $ip } else { 'n/a' }), $(if ($owner) { $owner } else { 'n/a' }), $(if ($cdnName) { 'YES - ' + $cdnName } else { 'none detected' }), $(if ($tranco.ranks) { $tranco.ranks[0].rank } else { 'n/a' }))
    W ""
    if ($geo) { W ("**Host location:** {0}{1} ({2}) &middot; {3} &middot; AS{4}" -f $(if ($geo.city) { $geo.city + ', ' } else { '' }), $geo.country, $geo.country_code, $geo.connection.org, $geo.connection.asn); W "" }
    if ($m365 -and $m365.isAzureAD) {
        W ("**Microsoft 365 / Azure AD:** {0}{1}{2}" -f $m365.namespaceType, $(if ($m365.tenantId) { ' &middot; tenant `' + $m365.tenantId + '`' } else { '' }), $(if ($m365.tenantRegion) { ' &middot; region ' + $m365.tenantRegion } else { '' }))
        if ($m365.namespaceType -eq 'Federated' -and $m365.federationAuthUrl) { W ("- Federated IdP / ADFS auth URL: ``{0}`` (on-prem identity surface)" -f $m365.federationAuthUrl) }
        if (@($m365.tenantDomains).Count) { W ("- {0} tenant domain(s) (off-host, see OOS): {1}" -f @($m365.tenantDomains).Count, ((@($m365.tenantDomains) | Select-Object -First 15) -join ', ')) }
        W ""
    }
    W "## Executive summary"
    $hotN = $hot.Count; $secN = ($thVer.Count + $glSpec.Count)
    W ("- **$host_** -> **$ip**" + $(if ($owner) { " ($owner)" } else { '' }) + $(if ($cdnName) { ", behind " + $cdnName } else { '' }) + ".")
    W ("- Exposed: **{0} ports**{1}, **{2} known CVE(s)** in passive scan data." -f $ports.Count, $(if ($cpes.Count) { ", " + $cpes.Count + " tech CPE(s)" } else { '' }), $vulns.Count)
    $cdnNote = if ($cdnName) { "behind $cdnName - verify they answer directly (WAF bypass)" } else { "(no CDN/WAF detected - host is served directly)" }
    W ("- **{0} origin-candidate IP(s)** recovered {1}." -f @($cands).Count, $cdnNote)
    W ("- History: **{0} URLs** ({1} after uro dedup, {2} high-signal), **{3} param(s)**, **{4} JS file(s)**." -f @($allUrls).Count, @($dedupUrls).Count, $hotN, @($params).Count, @($jsUrls).Count)
    W ("- **{0} high-confidence secret(s)**{1}; **{2} org email(s)**; **{3} OOS asset(s)** observed." -f $secN, $(if (($thUnv.Count + $glGen.Count)) { ' (' + ($thUnv.Count + $glGen.Count) + ' low-confidence / likely-FP)' } else { '' }), @($emails).Count, @($oos).Count)
    W ""
    W "## 1. Exposed services"
    if ($ports.Count) {
        W "| Port | Service / version |"; W "|---|---|"
        foreach ($p in $ports) { W ("| {0} | {1} |" -f $p, $(if ($svc[[int]$p]) { $svc[[int]$p] } else { '-' })) }
    } else { W "_No port/service data._" }
    if (@($dns).Count) {
        $spfMiss = -not ($dns | Where-Object { $_ -match 'v=spf1' }); $dmarcMiss = -not ($dns | Where-Object { $_ -match 'DMARC1' })
        W ""; W ("**DNS / mail hygiene:** " + $(if ($spfMiss) { 'SPF **MISSING**; ' } else { 'SPF ok; ' }) + $(if ($dmarcMiss) { 'DMARC **MISSING**' } else { 'DMARC ok' }) + " (full records in 01_scope\dns_records.txt)")
    }
    if (@($tech).Count) {
        $techNames = @($tech | ForEach-Object { ($_ -split '\s{2,}')[0].Trim() } | Where-Object { $_ } | Select-Object -Unique)
        W ""; W ("**Technology** (passive fingerprint): " + (($techNames | Select-Object -First 14) -join ', '))
    }
    W ""
    W "## 2. Vulnerabilities (passive)"
    if ($vulns.Count) { W ("InternetDB flags **{0}** CVE(s) on the exposed IP:" -f $vulns.Count); W ""; foreach ($v in ($vulns | Select-Object -First 40)) { W "- $v" } }
    else { W "_None flagged by InternetDB. Still version-check the services above inside the VDI._" }
    if ($cpes.Count) { W ""; W ("**Tech / CPEs:** " + (($cpes | Select-Object -First 20) -join ', ')) }
    $rj = GJson '06_js\retirejs.json'
    if ($rj -and $rj.data) {
        # map waymore response-file IDs -> original URLs (strip the web.archive.org/<ts>/ wrapper) so each lib cites a real link
        $idx = @{}
        $idxFile = P '06_js\responses\waymore_index.txt'
        if (Test-Path $idxFile) {
            foreach ($ln in (Get-Content $idxFile -ErrorAction SilentlyContinue)) {
                $parts = $ln -split ',', 3
                if ($parts.Count -ge 2) { $fid = $parts[0].Trim(); $u = ($parts[1].Trim()) -replace '^https?://web\.archive\.org/web/\w+/', ''; if ($fid -and -not $idx.ContainsKey($fid)) { $idx[$fid] = $u } }
            }
        }
        $rank = @{ 'critical' = 0; 'high' = 1; 'medium' = 2; 'low' = 3 }
        $libs = @{}
        foreach ($d in $rj.data) {
            $fid = [System.IO.Path]::GetFileNameWithoutExtension([string]$d.file)
            $src = if ($idx.ContainsKey($fid)) { $idx[$fid] } else { '' }
            foreach ($r in $d.results) {
                $key = ('{0} {1}' -f $r.component, $r.version).Trim()
                if (-not $libs.ContainsKey($key)) { $libs[$key] = @{ sev = ''; cves = (New-Object System.Collections.Generic.HashSet[string]); src = '' } }
                if (-not $libs[$key].src -and $src) { $libs[$key].src = $src }
                foreach ($v in $r.vulnerabilities) {
                    $sv = [string]$v.severity
                    if ($sv) {
                        $rNew = $(if ($rank.ContainsKey($sv)) { $rank[$sv] } else { 8 })
                        $rCur = $(if ($libs[$key].sev -and $rank.ContainsKey($libs[$key].sev)) { $rank[$libs[$key].sev] } else { 9 })
                        if ($rNew -lt $rCur) { $libs[$key].sev = $sv }
                    }
                    foreach ($cve in $v.identifiers.CVE) { if ($cve) { [void]$libs[$key].cves.Add([string]$cve) } }
                }
            }
        }
        if ($libs.Count) {
            W ""; W ("**Vulnerable JS libraries (retire.js): {0}** - confirm the live versions in the VDI:" -f $libs.Count)
            foreach ($k in ($libs.Keys | Sort-Object @{ Expression = { $s = [string]$libs[$_].sev; if ($rank.ContainsKey($s)) { $rank[$s] } else { 9 } } }, @{ Expression = { $_ } })) {
                $cv = (@($libs[$k].cves) | Sort-Object | ForEach-Object { '[{0}]({1}{0})' -f $_, $nvd }) -join ', '
                $sr = if ($libs[$k].src) { '  _' + $libs[$k].src + '_' } else { '' }
                W ("- ``{0}`` ({1}){2}{3}" -f $k, $(if ($libs[$k].sev) { $libs[$k].sev } else { '?' }), $(if ($cv) { ' - ' + $cv } else { '' }), $sr)
            }
        }
    }
    W ""
    W "## 3. Origin candidates (behind CDN)"
    if (@($cands).Count) {
        W "IPs presenting the target's cert on non-CDN addresses - **probe each from the VDI to see if it serves the app directly (WAF bypass).** InternetDB ports/CVEs shown to prioritise:"; W ""
        $cShow = if (@($candsEnr).Count) { $candsEnr } else { $cands }
        foreach ($c in $cShow) { W "- ``$c``" }
    } else { W "_No distinct origin candidates found._" }
    W ""
    W "## 4. Attack surface - high-signal endpoints"
    W ("Filtered from {0} URLs ({1} after uro pattern-dedup) down to the interesting ones (admin/api/auth/upload/config/etc.):" -f @($allUrls).Count, @($dedupUrls).Count)
    W ""
    if ($hot.Count) { foreach ($u in ($hot | Select-Object -First 60)) { W "- $u" }; if ($hot.Count -gt 60) { W ("- _...+{0} more in 05_history\all_urls.txt_" -f ($hot.Count - 60)) } }
    else { W "_No high-signal endpoints matched. Full list in 05_history\all_urls.txt._" }
    W ""
    $allParams = @(@($params) + @($xPar) | Sort-Object -Unique)
    if ($allParams.Count) { W (("**Parameters seen ({0}):** " -f $allParams.Count) + '`' + (($allParams | Select-Object -First 40) -join '`, `') + '`') }
    if (@($xEnd).Count) { W ""; W ("**Endpoints extracted from archived bodies: {0}** - see 06_js\endpoints.txt" -f @($xEnd).Count) }
    if (@($apiEp).Count) {
        W ""; W ("**API spec recovered: {0} endpoint(s)** from an archived OpenAPI/Swagger spec - the full contract (06_js\api_spec_endpoints.txt):" -f @($apiEp).Count)
        foreach ($e in (@($apiEp) | Select-Object -First 25)) { W ("- ``{0}``" -f $e.Trim()) }
        if (@($apiEp).Count -gt 25) { W ("- _...+{0} more in 06_js\api_spec_endpoints.txt_" -f (@($apiEp).Count - 25)) }
    }
    if (@($apiRefs).Count) { W ""; W ("**{0} API-spec URL(s)** referenced - fetch live in the VDI to recover the contract (06_js\api_spec_refs.txt)" -f @($apiRefs).Count) }
    $uris = GLines '05_history\uris.txt'
    if (@($uris).Count) { W ""; W ("**{0} unique URIs** (paths across all observed hosts) -> ``05_history\uris.txt``. Replay onto a UAT/staging host (never crawled) with ``Invoke-AssetLens.ps1 -MapUat -Package . -UatBase <url>`` -> uat_targets.txt." -f @($uris).Count) }
    $exts = GLines '05_history\extensions.txt'
    if (@($exts).Count) {
        W ""; W "**File types** (count / ext - full grouping in 05_history\urls_by_ext.txt):"; W ""
        foreach ($e in (@($exts) | Select-Object -First 20)) { W ("- ``{0}``" -f $e.Trim()) }
        $sens = @($exts | Where-Object { $_ -match '(?i)\.(config|bak|sql|sqlite|db|env|zip|gz|tgz|7z|rar|tar|pem|key|p12|pfx|old|swp|orig|wsdl|asmx|svc|yml|yaml|ini|conf|log|csv|xls|xlsx|git)$' })
        if ($sens.Count) { W ""; W "**Worth a look** (sensitive/interesting extensions present):"; foreach ($s in ($sens | Select-Object -First 20)) { W ("- ``{0}``" -f $s.Trim()) } }
    }
    W ""
    W "## 5. Secrets & leaks"
    $anySecret = $false
    if ($thVer.Count) { $anySecret = $true; W ("- **trufflehog: {0} VERIFIED secret(s)** - LIVE credentials, investigate now ({1})" -f $thVer.Count, ((@($thVer.DetectorName) | Sort-Object -Unique) -join ', ')) }
    if ($thUnv.Count) { W ("- trufflehog: {0} UNVERIFIED ({1}) - pattern-matches only, usually false positives on archived/minified JS; spot-check" -f $thUnv.Count, ((@($thUnv.DetectorName) | Sort-Object -Unique) -join ', ')) }
    if ($glSpec.Count) { $anySecret = $true; W ("- **gitleaks: {0} specific-rule hit(s)** (investigate): {1}" -f $glSpec.Count, ((@($glSpec.RuleID) | Sort-Object -Unique) -join ', ')) }
    if ($glGen.Count) { W ("- gitleaks: {0} generic-api-key match(es) - high-false-positive rule on minified/archived JS; triage, don't trust the count" -f $glGen.Count) }
    if (Has '07_osint\leakix_host.json') { W "- **LeakIX**: exposures captured in 07_osint\leakix_host.json (review)" }
    if (@($ghHits).Count) { W ("- **GitHub code**: {0} hit(s) referencing the host - 07_osint\github_hits.txt" -f @($ghHits).Count) }
    if (@($cloud).Count) { W ("- **Cloud storage**: {0} S3/Azure/GCS/Firebase URL(s) in archived JS - 06_js\cloud_assets.txt (check for public/listable buckets in the VDI)" -f @($cloud).Count) }
    if (@($smSrc).Count) { $anySecret = $true; W ("- **Source maps**: {0} original source path(s) recovered from archived .js.map - 06_js\sourcemap_sources.txt (internal app structure exposed)" -f @($smSrc).Count) }
    if (@($smRef).Count) { W ("- Source-map refs: {0} .map URL(s) - 06_js\sourcemap_refs.txt (fetch from the archive to recover source)" -f @($smRef).Count) }
    if (-not $anySecret -and -not $thUnv.Count -and -not $glGen.Count -and -not @($smRef).Count -and -not (Has '07_osint\leakix_host.json') -and -not @($ghHits).Count -and -not @($cloud).Count) { W "_No secrets/leaks flagged._" }
    W ""
    W "## 6. OSINT / exposure"
    W ("- Org emails: **{0}**" -f @($emails).Count) ; if (@($emails).Count) { W ("  - " + ((@($emails) | Select-Object -First 15) -join ', ')) }
    if (@($breach).Count) { W ("- Breach/infostealer hits: **{0}** (07_osint\breach_hits.txt)" -f @($breach).Count) }
    if ($tranco.ranks) { W ("- Tranco rank: **{0}**" -f $tranco.ranks[0].rank) }
    if ($otx) { W ("- OTX threat pulses: **{0}**{1}" -f [int]$otx.pulse_info.count, $(if ([int]$otx.pulse_info.count -gt 0) { ' - host referenced in threat reports (07_osint\otx_host.json)' } else { '' })) }
    if ($abuse) { W ("- AbuseIPDB (host IP): **score {0}/100**, {1} report(s), usage ``{2}``{3}" -f $abuse.abuseConfidenceScore, $abuse.totalReports, $abuse.usageType, $(if ($abuse.isTor) { ', TOR exit' } else { '' })) }
    W ""
    W "## 7. Out of scope (observed - DO NOT TEST)"
    $oosClean = @($oos)
    W ("{0} off-host asset(s) recorded in OOS_observed.txt. Not in scope." -f $oosClean.Count)
    W ""
    W "## 8. Prioritized next actions (inside VDI)"
    W "1. **Probe origin candidates** with httpx + screenshot - any that serve the app bypass the CDN/WAF."
    W ("2. **Confirm the {0} exposed ports** are open, version the services, match CVEs above." -f $ports.Count)
    W "3. **Replay prod URIs on UAT** - ``Invoke-AssetLens.ps1 -MapUat -UatBase https://<uat-host>`` -> uat_targets.txt, then ``httpx -l uat_targets.txt`` / nuclei. UAT is never crawled, so these harvested paths ARE your endpoint list."
    W "4. **Hit the high-signal endpoints** (section 4) - load uris.txt + params into Burp Intruder (payload positions); katana to crawl from there. Don't blind-fuzz."
    W "5. **Validate every secret** in section 5 (live? still valid?)."
    W "6. **Review in-scope cert SANs** for alternate names of the same app."
    W ""
    W "_Passive package. All active verification happens in the authorized VDI. Nothing in OOS_observed.txt is in scope._"
    [System.IO.File]::WriteAllText((P 'Report.md'), ($out -join "`r`n"), $u8)

    # ============ HTML report (dashboard layout; self-contained, no external deps, light/dark adaptive) ============
    function HE { param($s) ([string]$s -replace '&', '&amp;' -replace '<', '&lt;' -replace '>', '&gt;' -replace '"', '&quot;') }
    function SevS { param($s) switch -Regex ($s) { 'critical|high' { 'background:var(--dn-bg);color:var(--dn)' } 'medium' { 'background:var(--wn-bg);color:var(--wn)' } default { 'background:var(--tile);color:var(--muted)' } } }
    $rankH = @{ 'critical' = 0; 'high' = 1; 'medium' = 2; 'low' = 3 }
    $sevHi = 0; $sevMd = 0; $sevLo = 0
    foreach ($lk in $libs.Keys) { $ls = [string]$libs[$lk].sev; if ($ls -match 'critical|high') { $sevHi++ } elseif ($ls -eq 'medium') { $sevMd++ } else { $sevLo++ } }
    $h = New-Object System.Collections.Generic.List[string]
    function HW { param($s = '') $h.Add([string]$s) }
    HW '<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">'
    HW ('<title>recon - {0}</title>' -f (HE $host_))
    HW '<style>'
    HW ':root{--bg:#f6f7f9;--card:#fff;--tile:#eef1f4;--text:#1a1d21;--muted:#5c636b;--faint:#8a9099;--border:#e3e6ea;--dn:#c0392b;--dn-bg:#fbe9e7;--wn:#a96a09;--wn-bg:#f8efda;--ok:#1c7a55;--ok-bg:#e4f3ec;--info:#1f6feb;--info-bg:#e8f0fe}'
    HW '@media(prefers-color-scheme:dark){:root{--bg:#0e1116;--card:#161b22;--tile:#1c2230;--text:#e6edf3;--muted:#9aa4b2;--faint:#6b7480;--border:#2a313c;--dn:#ff6b5e;--dn-bg:#2d1714;--wn:#e0a33a;--wn-bg:#2a2110;--ok:#3fb98a;--ok-bg:#102a20;--info:#58a6ff;--info-bg:#0e1f33}}'
    HW '*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;line-height:1.6;padding:24px;font-size:15px}'
    HW '.wrap{max-width:980px;margin:0 auto}.mono{font-family:ui-monospace,"Cascadia Code",Consolas,monospace}'
    HW 'h1{font-size:24px;font-weight:600;margin:0}h2{font-size:15px;font-weight:600;margin:0 0 12px}'
    HW '.pill{font-size:12px;padding:4px 11px;border-radius:6px;font-weight:500;white-space:nowrap;display:inline-block}'
    HW '.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(115px,1fr));gap:10px;margin:18px 0}'
    HW '.tile{background:var(--tile);border-radius:8px;padding:13px 15px}.tile .l{font-size:12px;color:var(--muted)}.tile .n{font-size:26px;font-weight:600;margin-top:2px}'
    HW '.card{background:var(--card);border:1px solid var(--border);border-radius:12px;padding:17px 20px;margin-bottom:13px}'
    HW '.sev{font-size:11px;font-weight:600;padding:2px 8px;border-radius:6px;white-space:nowrap}'
    HW '.row{display:flex;justify-content:space-between;align-items:center;gap:10px;padding:9px 0;border-top:1px solid var(--border)}'
    HW '.src{font-family:ui-monospace,monospace;font-size:12px;color:var(--info);word-break:break-all}.cve{font-family:ui-monospace,monospace;font-size:12px;color:var(--muted);word-break:break-all;margin:3px 0}'
    HW '.grid2{display:grid;grid-template-columns:1fr 1fr;gap:13px}@media(max-width:680px){.grid2{grid-template-columns:1fr}}.locgrid{display:grid;grid-template-columns:1.7fr 1fr;gap:16px;align-items:start}@media(max-width:640px){.locgrid{grid-template-columns:1fr}}.flag{display:inline-block;border-radius:2px;overflow:hidden;border:0.5px solid var(--border);vertical-align:middle;line-height:0}.flag svg{width:24px;height:auto;display:block}'
    HW 'ul{margin:6px 0;padding-left:18px}li{margin:3px 0}.muted{color:var(--muted)}.bar{display:flex;height:8px;border-radius:6px;overflow:hidden;margin:2px 0 8px}a{color:var(--info);text-decoration:none}'
    HW '</style></head><body><div class="wrap">'
    HW '<div style="display:flex;justify-content:space-between;align-items:flex-start;gap:12px;flex-wrap:wrap">'
    HW ('<div><div style="font-size:11px;font-weight:600;letter-spacing:1.5px;color:var(--info)">ASSETLENS &middot; PASSIVE RECON</div><h1 style="margin-top:3px">{0}</h1><div class="mono" style="font-size:13px;color:var(--muted);margin-top:6px">{1}{2} &middot; {3}</div></div>' -f (HE $host_), $(if ($ip) { HE $ip } else { 'no IP' }), $(if ($owner) { ' &middot; ' + (HE $owner) } else { '' }), (HE (Split-Path $Package -Leaf)))
    HW $(if ($cdnName) { '<span class="pill" style="background:var(--info-bg);color:var(--info)">behind ' + (HE $cdnName) + '</span>' } else { '<span class="pill" style="background:var(--ok-bg);color:var(--ok)">passive &middot; 0 packets to target</span>' })
    HW '</div>'
    HW '<div class="tiles">'
    HW ('<div class="tile"><div class="l">ports</div><div class="n">{0}</div></div>' -f $ports.Count)
    HW ('<div class="tile"><div class="l">known CVEs</div><div class="n"{1}>{0}</div></div>' -f $vulns.Count, $(if ($vulns.Count) { ' style="color:var(--dn)"' } else { '' }))
    HW ('<div class="tile"><div class="l">vuln libraries</div><div class="n"{1}>{0}</div></div>' -f $libs.Count, $(if ($sevHi) { ' style="color:var(--dn)"' } else { '' }))
    HW ('<div class="tile"><div class="l">endpoints</div><div class="n">{0}</div></div>' -f @($xEnd).Count)
    HW ('<div class="tile"><div class="l">live secrets</div><div class="n"{1}>{0}</div></div>' -f $secN, $(if ($secN) { ' style="color:var(--dn)"' } else { '' }))
    HW ('<div class="tile"><div class="l">out-of-scope</div><div class="n">{0}</div></div>' -f $oosClean.Count)
    HW '</div>'
    if ($geo -and $worldPath -and $geo.latitude -and $geo.longitude) {
        $mpx = [Math]::Round((([double]$geo.longitude) + 180) * 1000 / 360)
        $mpy = [Math]::Round((90 - ([double]$geo.latitude)) * 500 / 180)
        HW '<div class="card"><h2>host location</h2><div class="locgrid">'
        HW '<div style="border-radius:8px;overflow:hidden;border:0.5px solid var(--border)">'
        HW ('<svg viewBox="0 14 1000 478" width="100%" style="display:block"><rect y="14" width="1000" height="478" fill="#0a0f1e"/><path d="{0}" fill="#1c2536" stroke="#2c3a52" stroke-width="0.5"/>' -f $worldPath)
        HW ('<circle cx="{0}" cy="{1}" r="28" fill="#fb7185" opacity="0.12"/><circle cx="{0}" cy="{1}" r="16" fill="#fb7185" opacity="0.2"/><circle cx="{0}" cy="{1}" fill="none" stroke="#fb7185" stroke-width="2.5"><animate attributeName="r" values="9;36" dur="2s" repeatCount="indefinite"/><animate attributeName="opacity" values="0.85;0" dur="2s" repeatCount="indefinite"/></circle><circle cx="{0}" cy="{1}" r="9" fill="#fb7185" stroke="#fff" stroke-width="1.6"/><text x="{2}" y="{3}" font-size="22" fill="#cdd6e3" font-family="system-ui" font-weight="500">{4}</text></svg></div>' -f $mpx, $mpy, ($mpx + 14), ($mpy - 12), (HE ([string]$geo.city)))
        HW '<div style="font-size:13px">'
        $flagHtml = if ($flagSvg) { '<span class="flag">' + $flagSvg + '</span>' } else { '<span style="font-family:ui-monospace,monospace;font-size:12px;font-weight:600;background:var(--tile);padding:2px 7px;border-radius:5px">' + (HE ([string]$geo.country_code)) + '</span>' }
        HW ('<div style="display:flex;align-items:center;gap:8px;margin-bottom:6px">{0}<span style="font-size:15px;font-weight:500">{1}</span><span class="muted" style="font-size:12px;font-family:ui-monospace,monospace">{2}</span></div>' -f $flagHtml, (HE ([string]$geo.country)), (HE ([string]$geo.country_code)))
        foreach ($kv in @(@('city', [string]$geo.city), @('region', [string]$geo.region), @('ISP', [string]$geo.connection.isp), @('org', [string]$geo.connection.org), @('ASN', "AS$($geo.connection.asn)"), @('type', [string]$geo.type), @('timezone', [string]$geo.timezone.id), @('coords', ('{0}, {1}' -f $geo.latitude, $geo.longitude)))) {
            if ($kv[1] -and $kv[1] -ne 'AS') { HW ('<div style="display:flex;justify-content:space-between;gap:10px;padding:4px 0;border-top:0.5px solid var(--border)"><span class="muted">{0}</span><span style="text-align:right;word-break:break-word">{1}</span></div>' -f $kv[0], (HE $kv[1])) }
        }
        HW '</div></div></div>'
    }
    if ($m365 -and $m365.isAzureAD) {
        HW '<div class="card"><h2>identity &middot; Microsoft 365 / Azure AD</h2><div style="font-size:13px">'
        foreach ($kv in @(@('namespace', [string]$m365.namespaceType), @('tenant ID', [string]$m365.tenantId), @('region', [string]$m365.tenantRegion), @('brand', [string]$m365.federationBrand), @('IdP / ADFS auth URL', [string]$m365.federationAuthUrl), @('cloud', [string]$m365.cloudInstance))) {
            if ($kv[1]) { HW ('<div style="display:flex;justify-content:space-between;gap:10px;padding:4px 0;border-top:0.5px solid var(--border)"><span class="muted">{0}</span><span class="mono" style="text-align:right;word-break:break-all">{1}</span></div>' -f $kv[0], (HE $kv[1])) }
        }
        if (@($m365.tenantDomains).Count) {
            HW ('<div style="margin-top:8px"><span class="muted" style="font-size:12px">{0} tenant domain(s) &middot; off-host, recorded in OOS:</span>' -f @($m365.tenantDomains).Count)
            HW '<div class="src" style="line-height:1.8;margin-top:3px">'; foreach ($d in (@($m365.tenantDomains) | Select-Object -First 20)) { HW ((HE $d) + '<br>') }; HW '</div></div>'
        }
        HW '</div></div>'
    }
    HW '<div class="grid2">'
    HW '<div class="card"><h2>vulnerable JS libraries</h2>'
    if ($libs.Count) {
        HW ('<div class="bar"><div style="flex:{0};background:var(--dn)"></div><div style="flex:{1};background:var(--wn)"></div><div style="flex:{2};background:var(--faint)"></div></div>' -f $sevHi, $sevMd, $sevLo)
        HW ('<div class="muted" style="font-size:12px;margin-bottom:4px">{0} high &middot; {1} medium &middot; {2} low</div>' -f $sevHi, $sevMd, $sevLo)
        $hfirst = $true
        foreach ($lk in @($libs.Keys | Sort-Object @{ Expression = { $s = [string]$libs[$_].sev; if ($rankH.ContainsKey($s)) { $rankH[$s] } else { 9 } } }, @{ Expression = { $_ } })) {
            $lsev = [string]$libs[$lk].sev; if (-not $lsev) { $lsev = '?' }
            $rtop = $(if ($hfirst) { ' style="border-top:none"' } else { '' }); $hfirst = $false
            $lsrc = $(if ($libs[$lk].src) { '<div class="src">' + (HE $libs[$lk].src) + '</div>' } else { '' })
            $lcve = $(if (@($libs[$lk].cves).Count) { '<div class="cve">' + ((@($libs[$lk].cves) | Sort-Object | ForEach-Object { '<a href="' + $nvd + (HE $_) + '">' + (HE $_) + '</a>' }) -join ', ') + '</div>' } else { '' })
            HW ('<div class="row"{0}><div style="min-width:0"><span class="mono" style="font-weight:500">{1}</span>{2}{3}</div><span class="sev" style="{4}">{5}</span></div>' -f $rtop, (HE $lk), $lcve, $lsrc, (SevS $lsev), (HE $lsev))
        }
    } else { HW '<div class="muted">none flagged.</div>' }
    HW '</div>'
    HW '<div class="card"><h2>secret triage</h2>'
    HW ('<div style="display:flex;align-items:baseline;gap:8px;margin-bottom:4px"><span style="font-size:26px;font-weight:600">{0}</span><span class="muted" style="font-size:13px">high-confidence</span></div>' -f $secN)
    if ($thVer.Count) { HW ('<div class="row" style="border-top:none"><span>trufflehog verified</span><span class="sev" style="background:var(--dn-bg);color:var(--dn)">{0} live</span></div>' -f $thVer.Count) }
    if ($glSpec.Count) { HW ('<div class="row"><span>gitleaks specific rule</span><span class="sev" style="background:var(--wn-bg);color:var(--wn)">{0}</span></div>' -f $glSpec.Count) }
    $fpN = $thUnv.Count + $glGen.Count
    if ($fpN) {
        HW '<ul class="muted" style="font-size:13px">'
        if ($thUnv.Count) { HW ('<li>{0} unverified &middot; trufflehog ({1})</li>' -f $thUnv.Count, (HE ((@($thUnv.DetectorName) | Sort-Object -Unique) -join ', '))) }
        if ($glGen.Count) { HW ('<li>{0} generic-api-key &middot; gitleaks</li>' -f $glGen.Count) }
        HW '<li>likely false positives - minified-JS / VIEWSTATE noise</li></ul>'
    }
    if (-not $secN -and -not $fpN) { HW '<div class="muted">no secrets flagged.</div>' }
    HW '</div></div>'
    HW '<div class="card"><h2>exposed services</h2>'
    if ($ports.Count) {
        HW '<div style="display:flex;flex-wrap:wrap;gap:8px;margin-bottom:8px">'
        foreach ($p in $ports) { $svv = $(if ($svc[[int]$p]) { ' &middot; ' + (HE $svc[[int]$p]) } else { '' }); HW ('<span class="pill mono" style="background:var(--tile);color:var(--text)">{0}{1}</span>' -f $p, $svv) }
        HW '</div>'
    } else { HW '<div class="muted">no port data.</div>' }
    if ($cpes.Count) { HW ('<div class="muted" style="font-size:13px">tech: {0}</div>' -f (HE (($cpes | Select-Object -First 6) -join ', '))) }
    if (@($dns).Count) {
        $spfMiss = -not ($dns | Where-Object { $_ -match 'v=spf1' }); $dmarcMiss = -not ($dns | Where-Object { $_ -match 'DMARC1' })
        HW ('<div style="font-size:13px;margin-top:6px">DNS / mail: SPF <span style="color:{0};font-weight:500">{1}</span> &middot; DMARC <span style="color:{2};font-weight:500">{3}</span></div>' -f $(if ($spfMiss) { 'var(--dn)' } else { 'var(--ok)' }), $(if ($spfMiss) { 'missing' } else { 'ok' }), $(if ($dmarcMiss) { 'var(--dn)' } else { 'var(--ok)' }), $(if ($dmarcMiss) { 'missing' } else { 'ok' }))
    }
    HW '</div>'
    if (@($tech).Count) {
        HW '<div class="card"><h2>technology</h2><div style="display:flex;flex-wrap:wrap;gap:7px">'
        $techNames = @($tech | ForEach-Object { ($_ -split '\s{2,}')[0].Trim() } | Where-Object { $_ } | Select-Object -Unique)
        foreach ($tn in ($techNames | Select-Object -First 18)) { HW ('<span class="pill" style="background:var(--tile);color:var(--text)">{0}</span>' -f (HE $tn)) }
        HW '</div></div>'
    }
    if (@($smSrc).Count -or @($smRef).Count) {
        HW '<div class="card"><h2>source maps</h2>'
        if (@($smSrc).Count) {
            HW ('<div style="font-size:13px;margin-bottom:6px"><span style="font-weight:500;color:var(--dn)">{0}</span> <span class="muted">original source path(s) recovered - internal app structure exposed</span></div>' -f @($smSrc).Count)
            HW '<div class="src" style="line-height:1.9">'; foreach ($s in (@($smSrc) | Select-Object -First 8)) { HW ((HE $s) + '<br>') }; HW '</div>'
        }
        if (@($smRef).Count) { HW ('<div class="muted" style="font-size:12px;margin-top:6px">{0} .map reference(s) in 06_js\sourcemap_refs.txt - fetch from the archive to recover source</div>' -f @($smRef).Count) }
        HW '</div>'
    }
    if (@($cands).Count) {
        HW '<div class="card"><h2>origin candidates - WAF bypass</h2>'
        $cShow = $(if (@($candsEnr).Count) { $candsEnr } else { $cands })
        $cfirst = $true
        foreach ($c in $cShow) { $rtop = $(if ($cfirst) { ' style="border-top:none"' } else { '' }); $cfirst = $false; HW ('<div class="row mono"{0}><span style="font-size:13px">{1}</span></div>' -f $rtop, (HE $c)) }
        HW '</div>'
    }
    if (@($apiEp).Count -or @($apiRefs).Count) {
        HW '<div class="card"><h2>API spec</h2>'
        if (@($apiEp).Count) {
            HW ('<div style="font-size:13px;margin-bottom:6px"><span style="font-weight:500;color:var(--dn)">{0}</span> <span class="muted">endpoint(s) recovered from an archived OpenAPI/Swagger spec - the full contract</span></div>' -f @($apiEp).Count)
            HW '<div class="src" style="line-height:1.9">'; foreach ($e in (@($apiEp) | Select-Object -First 12)) { HW ((HE $e) + '<br>') }; HW '</div>'
        }
        if (@($apiRefs).Count) { HW ('<div class="muted" style="font-size:12px;margin-top:6px">{0} spec-URL lead(s) in 06_js\api_spec_refs.txt - fetch live in the VDI</div>' -f @($apiRefs).Count) }
        HW '</div>'
    }
    HW '<div class="card"><h2>attack surface</h2>'
    HW '<div class="muted" style="display:flex;gap:18px;flex-wrap:wrap;font-size:13px">'
    HW ('<span><span style="color:var(--text);font-weight:500">{0}</span> archived URLs</span>' -f @($allUrls).Count)
    HW ('<span><span style="color:var(--text);font-weight:500">{0}</span> deduped</span>' -f @($dedupUrls).Count)
    HW ('<span><span style="color:var(--text);font-weight:500">{0}</span> high-signal</span>' -f $hot.Count)
    HW ('<span><span style="color:var(--text);font-weight:500">{0}</span> params</span>' -f $allParams.Count)
    HW ('<span><span style="color:var(--text);font-weight:500">{0}</span> URIs</span>' -f @($uris).Count)
    HW '</div>'
    if ($hot.Count) { HW '<div class="src" style="margin-top:8px;line-height:1.9">'; foreach ($u in ($hot | Select-Object -First 8)) { HW ((HE $u) + '<br>') }; HW '</div>' }
    HW '</div>'
    if (@($cloud).Count) {
        HW ('<div class="card"><h2>cloud storage - {0} URL(s)</h2>' -f @($cloud).Count)
        HW '<div class="src" style="line-height:1.9">'; foreach ($u in (@($cloud) | Select-Object -First 6)) { HW ((HE $u) + '<br>') }; HW '</div>'
        HW '<div class="muted" style="font-size:12px;margin-top:4px">check for public / listable buckets in the VDI</div></div>'
    }
    HW '<div class="card"><h2>OSINT / exposure</h2><div style="font-size:13px;line-height:1.9">'
    HW ('<div class="muted">org emails: <span style="color:var(--text);font-weight:500">{0}</span></div>' -f @($emails).Count)
    if (@($breach).Count) { HW ('<div class="muted">breach / infostealer hits: <span style="color:var(--text);font-weight:500">{0}</span></div>' -f @($breach).Count) }
    if ($tranco.ranks) { HW ('<div class="muted">Tranco rank: <span style="color:var(--text);font-weight:500">{0}</span></div>' -f $tranco.ranks[0].rank) }
    if (@($ghHits).Count) { HW ('<div class="muted">GitHub code refs: <span style="color:var(--text);font-weight:500">{0}</span></div>' -f @($ghHits).Count) }
    if ($otx) { $opc = [int]$otx.pulse_info.count; HW ('<div class="muted">OTX threat pulses: <span style="font-weight:500;color:{0}">{1}</span></div>' -f $(if ($opc -gt 0) { 'var(--dn)' } else { 'var(--text)' }), $opc) }
    if ($abuse) { HW ('<div class="muted">AbuseIPDB: <span style="font-weight:500;color:{0}">{1}/100</span> <span class="muted">({2} reports &middot; {3})</span></div>' -f $(if ([int]$abuse.abuseConfidenceScore -ge 25) { 'var(--dn)' } else { 'var(--text)' }), $abuse.abuseConfidenceScore, $abuse.totalReports, (HE ([string]$abuse.usageType))) }
    HW '</div></div>'
    HW ('<div style="font-size:12px;color:var(--faint);margin-top:4px">single host &middot; {0} out-of-scope asset(s) observed - do not test &middot; all active verification deferred to the authorised VDI</div>' -f $oosClean.Count)
    HW '</div></body></html>'
    [System.IO.File]::WriteAllText((P 'Report.html'), ($h -join "`n"), $u8)
    Write-Host "Report written: $(P 'Report.md')  +  Report.html" -ForegroundColor Green
    Write-Host ("  sections: services={0} ports, vulns={1}, origins={2}, hot-endpoints={3}, params={4}, emails={5}" -f $ports.Count, $vulns.Count, @($cands).Count, $hot.Count, $allParams.Count, @($emails).Count)
}

# ================================================================ MAP-UAT mode
function Invoke-MapUat {
    param([Parameter(Mandatory = $true)][string]$Package, [Parameter(Mandatory = $true)][string]$UatBase, [switch]$WithParams)
    if (-not (Test-Path $Package)) { throw "Package not found: $Package" }
    $u8 = New-Object System.Text.UTF8Encoding($false)
    $UatBase = $UatBase.TrimEnd('/')
    if ($UatBase -notmatch '^[a-z]+://') { $UatBase = 'https://' + $UatBase }
    $uriRel = if ($WithParams) { '05_history\uris_with_query.txt' } else { '05_history\uris.txt' }
    $src = Join-Path $Package $uriRel
    if (-not (Test-Path $src)) { throw "Not found: $src  (run a recon first)" }
    $uris = @(Get-Content $src | Where-Object { $_ })
    $targets = @($uris | ForEach-Object { $UatBase + $_ } | Sort-Object -Unique)
    $outFile = Join-Path $Package '05_history\uat_targets.txt'
    [System.IO.File]::WriteAllLines($outFile, [string[]]$targets, $u8)
    Write-Host ("Mapped {0} URIs from prod recon onto {1}" -f $targets.Count, $UatBase) -ForegroundColor Green
    Write-Host ("Wrote: {0}" -f $outFile) -ForegroundColor Green
    Write-Host ""
    Write-Host "Run these against the UAT host inside the VDI:" -ForegroundColor Cyan
    Write-Host ("  httpx  -l `"{0}`" -sc -title -mc 200,204,301,302,401,403,500" -f $outFile)
    Write-Host ("  Burp Intruder: send {0}/ to Intruder, set the path as the payload position, load `"{1}`" as the payload list (Sniper)" -f $UatBase, $src)
    Write-Host ("  nuclei -l `"{0}`" -t <templates>" -f $outFile)
}

# ================================================================ ZIP helper
function New-PackageZip {
    # Build the transfer zip. By default EXCLUDE 06_js\responses\ (raw archived bodies already mined into
    # endpoints/secrets/retire.js) - they stay on local disk. Pass -FullBodies to include them.
    param([Parameter(Mandatory = $true)][string]$Package, [switch]$FullBodies)
    if (-not (Test-Path $Package)) { throw "Package not found: $Package" }
    Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction SilentlyContinue
    Add-Type -AssemblyName System.IO.Compression -ErrorAction SilentlyContinue
    $base = (Resolve-Path $Package).Path.TrimEnd('\', '/')
    $name = Split-Path $base -Leaf
    $zip  = "$base.zip"
    if (Test-Path $zip) { Remove-Item $zip -Force }
    $respDir = Join-Path $base '06_js\responses'
    $files = Get-ChildItem $base -Recurse -File | Where-Object { $FullBodies -or -not $_.FullName.StartsWith($respDir, [System.StringComparison]::OrdinalIgnoreCase) }
    $arc = [System.IO.Compression.ZipFile]::Open($zip, 'Create')
    try { foreach ($f in $files) { $entry = ("$name/" + $f.FullName.Substring($base.Length + 1)) -replace '\\', '/'; [void][System.IO.Compression.ZipFileExtensions]::CreateEntryFromFile($arc, $f.FullName, $entry) } }
    finally { $arc.Dispose() }
    $hash = (Get-FileHash $zip -Algorithm SHA256).Hash
    [System.IO.File]::WriteAllText("$zip.sha256", "$hash  $(Split-Path $zip -Leaf)`r`n", (New-Object System.Text.UTF8Encoding($false)))
    $skipped = if ($FullBodies) { 0 } else { @(Get-ChildItem $respDir -Recurse -File -ErrorAction SilentlyContinue).Count }
    Write-Host ("Zip:    {0}  ({1:N1} MB)" -f $zip, ((Get-Item $zip).Length / 1MB)) -ForegroundColor Green
    if ($skipped) { Write-Host ("        excluded {0} raw response bodies (kept on disk in 06_js\responses\; -FullBodies to include)" -f $skipped) -ForegroundColor DarkGray }
    Write-Host ("SHA256: {0}  -> {1}.sha256  (verify after transfer into the VDI)" -f $hash, (Split-Path $zip -Leaf)) -ForegroundColor Green
}

# ================================================================ DIFF mode (compare two packages of the same host)
function Invoke-Diff {
    param([Parameter(Mandatory = $true)][string]$New, [Parameter(Mandatory = $true)][string]$Old)
    foreach ($p in $New, $Old) { if (-not (Test-Path $p)) { throw "Package not found: $p" } }
    function RL { param($dir, $rel) $p = Join-Path $dir $rel; if (Test-Path $p) { @(Get-Content $p -ErrorAction SilentlyContinue | Where-Object { $_ -and $_ -notmatch '^\s*#' }) } else { @() } }
    $sets = @(
        @{ rel = '03_scan\ports.txt';            label = 'Ports' },
        @{ rel = '08_tech\internetdb_vulns.txt'; label = 'CVEs' },
        @{ rel = '02_certs\sans.txt';            label = 'Cert SANs' },
        @{ rel = '04_origin\candidates.txt';     label = 'Origin candidates' },
        @{ rel = '05_history\uris.txt';          label = 'URIs' },
        @{ rel = '06_js\endpoints.txt';          label = 'JS endpoints' },
        @{ rel = '06_js\cloud_assets.txt';       label = 'Cloud assets' },
        @{ rel = '07_osint\emails.txt';          label = 'Org emails' },
        @{ rel = 'OOS_observed.txt';             label = 'OOS assets' }
    )
    $out = New-Object System.Collections.Generic.List[string]
    $out.Add('# Diff - ' + (Split-Path $New -Leaf))
    $out.Add('vs baseline ' + (Split-Path $Old -Leaf)); $out.Add('')
    $changed = $false
    foreach ($s in $sets) {
        $n = RL $New $s.rel; $o = RL $Old $s.rel
        $oSet = New-Object System.Collections.Generic.HashSet[string]; foreach ($x in $o) { [void]$oSet.Add($x) }
        $nSet = New-Object System.Collections.Generic.HashSet[string]; foreach ($x in $n) { [void]$nSet.Add($x) }
        $added   = @($n | Where-Object { -not $oSet.Contains($_) })
        $removed = @($o | Where-Object { -not $nSet.Contains($_) })
        if ($added.Count -or $removed.Count) {
            $changed = $true
            $out.Add(('## {0}  (+{1} / -{2})' -f $s.label, $added.Count, $removed.Count))
            foreach ($x in ($added   | Select-Object -First 60)) { $out.Add('+ ' + $x) }
            if ($added.Count -gt 60) { $out.Add(('  ...+{0} more added' -f ($added.Count - 60))) }
            foreach ($x in ($removed | Select-Object -First 20)) { $out.Add('- ' + $x) }
            $out.Add('')
        }
    }
    if (-not $changed) { $out.Add('_No changes across tracked files (ports/CVEs/SANs/origins/URIs/endpoints/cloud/emails/OOS)._') }
    $dst = Join-Path $New 'Diff.md'
    [System.IO.File]::WriteAllText($dst, ($out -join "`r`n"), (New-Object System.Text.UTF8Encoding($false)))
    Write-Host ('Diff written: {0}' -f $dst) -ForegroundColor Green
    Write-Host ''
    Write-Host (($out | Select-Object -First 70) -join "`n")
}

# ================================================================ VALIDATE mode (api keys + tools live-check; no target touched)
function Invoke-Validate {
    Write-Host '== AssetLens validation (keys + tools) ==' -ForegroundColor Cyan
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
    $Keys = @{}; $Tools = @{ Python = 'python' }
    $cfg = Join-Path $PSScriptRoot 'config\keys.ps1'
    if (Test-Path $cfg) { . $cfg } else { Write-Host 'no config\keys.ps1 (keyless run only)' -ForegroundColor Yellow }
    function Vline { param($n, $s, $c, $d = '') Write-Host ('  {0,-16} {1}{2}' -f $n, $s, $(if ($d) { "  ($d)" } else { '' })) -ForegroundColor $c }
    function Hit { param($u, $h = @{}, $m = 'Get', $b = $null)
        for ($i = 0; $i -lt 2; $i++) {
            try { $p = @{ Uri = $u; Headers = $h; Method = $m; TimeoutSec = 25; ErrorAction = 'Stop'; UserAgent = 'AssetLens' }; if ($b) { $p.Body = $b; $p.ContentType = 'application/json' }; return @{ ok = $true; obj = (Invoke-RestMethod @p) } }
            catch { $code = $(if ($_.Exception.Response) { $_.Exception.Response.StatusCode.value__ } else { $null }); if ($i -eq 0 -and ($null -eq $code -or $code -ge 500 -or $code -eq 429)) { Start-Sleep -Milliseconds 800; continue }; return @{ ok = $false; code = $(if ($null -ne $code) { $code } else { 'no-response' }) } }
        }
    }
    function Show { param($name, $present, $res, $detail = '') if (-not $present) { Vline $name 'not set' 'DarkGray' } elseif ($res.ok) { Vline $name 'VALID' 'Green' $detail } else { Vline $name ("FAIL ({0})" -f $res.code) 'Red' } }

    Write-Host "`nTools:" -ForegroundColor Cyan
    foreach ($t in 'subfinder', 'gau', 'waybackurls', 'waymore', 'uro', 'retire', 'gitleaks', 'trufflehog', 'jq', 'python') {
        if (Get-Command $t -ErrorAction SilentlyContinue) { Vline $t 'OK' 'Green' } else { Vline $t 'missing' 'DarkGray' }
    }
    Write-Host "`nKeyless sources:" -ForegroundColor Cyan
    foreach ($pr in @(@('Shodan-InternetDB', 'https://internetdb.shodan.io/8.8.8.8'), @('crt.sh', 'https://crt.sh/?q=example.com&output=json'), @('RDAP', 'https://rdap.org/domain/example.com'), @('Tranco', 'https://tranco-list.eu/api/ranks/domain/google.com'), @('LeakCheck', 'https://leakcheck.io/api/public?check=test@example.com'), @('M365 / Azure AD', 'https://login.microsoftonline.com/common/userrealm/user@example.com?api-version=1.0'))) {
        $r = Hit $pr[1]; if ($r.ok) { Vline $pr[0] 'OK' 'Green' } elseif (($r.code -is [int]) -and ($r.code -lt 500)) { Vline $pr[0] ("reachable ({0})" -f $r.code) 'Green' } else { Vline $pr[0] ("down ({0})" -f $r.code) 'Yellow' }
    }
    Write-Host "`nAPI keys:" -ForegroundColor Cyan
    Show 'VirusTotal'     $Keys.VirusTotal     (Hit 'https://www.virustotal.com/api/v3/domains/example.com' @{ 'x-apikey' = $Keys.VirusTotal })
    Show 'SecurityTrails' $Keys.SecurityTrails (Hit 'https://api.securitytrails.com/v1/ping' @{ 'APIKEY' = $Keys.SecurityTrails })
    if ($Keys.Shodan) { $r = Hit ('https://api.shodan.io/api-info?key={0}' -f $Keys.Shodan); Show 'Shodan' $true $r ("plan=$($r.obj.plan)") } else { Vline 'Shodan' 'not set' 'DarkGray' }
    Show 'Censys'         $Keys.Censys         (Hit 'https://api.platform.censys.io/v3/global/asset/host/8.8.8.8' @{ Authorization = "Bearer $($Keys.Censys)" })
    Show 'Netlas'         $Keys.Netlas         (Hit 'https://app.netlas.io/api/host/8.8.8.8/' @{ 'X-API-Key' = $Keys.Netlas })
    Show 'CriminalIP'     $Keys.CriminalIP     (Hit ('https://api.criminalip.io/v1/banner/search?query={0}&offset=0' -f [uri]::EscapeDataString('ssl_subject_common_name: example.com')) @{ 'x-api-key' = $Keys.CriminalIP })
    if ($Keys.GitHub) { $r = Hit 'https://api.github.com/rate_limit' @{ Authorization = "Bearer $($Keys.GitHub)"; 'User-Agent' = 'AssetLens' }; Show 'GitHub' $true $r ("core left $($r.obj.resources.core.remaining)") } else { Vline 'GitHub' 'not set' 'DarkGray' }
    Show 'LeakIX'         $Keys.LeakIX         (Hit 'https://leakix.net/host/8.8.8.8' @{ 'api-key' = $Keys.LeakIX; Accept = 'application/json' })
    Show 'UrlScan'        $Keys.UrlScan        (Hit 'https://urlscan.io/api/v1/search/?q=domain:example.com' @{ 'API-Key' = $Keys.UrlScan })
    Show 'OTX'            $Keys.OTX            (Hit 'https://otx.alienvault.com/api/v1/indicators/hostname/example.com/general' @{ 'X-OTX-API-KEY' = $Keys.OTX })
    if ($Keys.AbuseIPDB) { $r = Hit 'https://api.abuseipdb.com/api/v2/check?ipAddress=8.8.8.8&maxAgeInDays=90' @{ Key = $Keys.AbuseIPDB; Accept = 'application/json' }; if ($r.ok -and $r.obj.data) { Vline 'AbuseIPDB' 'VALID' 'Green' } else { Vline 'AbuseIPDB' ("FAIL ({0})" -f $r.code) 'Red' } } else { Vline 'AbuseIPDB' 'not set' 'DarkGray' }
    Show 'Quake'          $Keys.Quake          (Hit 'https://quake.360.net/api/v3/user/info' @{ 'X-QuakeToken' = $Keys.Quake })
    Write-Host ''
    Write-Host 'Run before an engagement to catch dead keys / missing tools. Probes hit the API providers + benign IPs only - never a target.' -ForegroundColor Cyan
}

# ================================================================ mode dispatch (non-recon modes return)
if ($Setup)  { Invoke-Setup -SkipBase:$SkipBase; return }
if ($Report) { if (-not $Package) { throw 'Use: -Report -Package <packageDir>' }; Build-Report -Package $Package; return }
if ($MapUat) { if (-not $Package -or -not $UatBase) { throw 'Use: -MapUat -Package <packageDir> -UatBase <url>' }; Invoke-MapUat -Package $Package -UatBase $UatBase -WithParams:$WithParams; return }
if ($Zip)    { if (-not $Package) { throw 'Use: -Zip -Package <packageDir>' }; New-PackageZip -Package $Package -FullBodies:$FullBodies; return }
if ($Diff)   { if (-not $Package -or -not $Against) { throw 'Use: -Diff -Package <newDir> -Against <oldDir>' }; Invoke-Diff -New $Package -Old $Against; return }
if ($Validate) { Invoke-Validate; return }
if (-not $Target) { throw 'Provide a target host for RECON, or use -Setup / -Report / -MapUat / -Zip / -Diff / -Validate.' }

# ---------------------------------------------------------------- config
# Default loads config\keys.ps1 (keyed run). -Keyless skips it - keyless sources only.
$Keys  = @{}
$Tools = @{ Python = 'python' }
$cfgPath = Join-Path $PSScriptRoot 'config\keys.ps1'
if ($Keyless) { Write-Warning 'Keyless run (-Keyless): config\keys.ps1 ignored.' }
elseif (Test-Path $cfgPath) { . $cfgPath }
else { Write-Warning 'No config\keys.ps1 - running keyless. Copy keys.example.ps1 -> keys.ps1 to add keys.' }
$KeyedRun = @($Keys.Values | Where-Object { $_ }).Count -gt 0

# ---------------------------------------------------------------- normalise target
$Target = ($Target -replace '^[a-z]+://', '' -replace '/.*$', '').Trim().TrimEnd('.').ToLower()
if ($Target -notmatch '^[a-z0-9.-]+\.[a-z]{2,}$') { throw "Target does not look like a hostname: '$Target'" }

# ---------------------------------------------------------------- package dirs
$stamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss zzz'
$pkg   = Join-Path $OutRoot ('{0}_{1}' -f $Target, (Get-Date -Format 'yyyyMMdd-HHmmss'))   # per-run dir - never clobber a same-day run
foreach ($d in '', '01_scope', '02_certs', '03_scan', '04_origin', '05_history', '06_js', '07_osint', '08_tech') {
    New-Item -ItemType Directory -Force -Path (Join-Path $pkg $d) | Out-Null
}
$logPath = Join-Path $pkg 'recon.log'
$utf8    = New-Object System.Text.UTF8Encoding($false)

# ---------------------------------------------------------------- helpers
function Write-Log {
    param([string]$Msg, [ValidateSet('INFO', 'WARN', 'SKIP', 'OK', 'OOS')]$Level = 'INFO')
    $line  = '{0}  [{1,-4}] {2}' -f (Get-Date -Format 'HH:mm:ss'), $Level, $Msg
    $color = @{ INFO = 'Gray'; WARN = 'Yellow'; SKIP = 'DarkGray'; OK = 'Green'; OOS = 'Magenta' }[$Level]
    Write-Host $line -ForegroundColor $color
    Add-Content -Path $logPath -Value $line -Encoding utf8
}
function Save-Text  { param($Path, $Text)  [System.IO.File]::WriteAllText($Path, [string]$Text, $utf8) }
function Save-Lines { param($Path, $Lines) [System.IO.File]::WriteAllLines($Path, [string[]]@($Lines), $utf8) }
function Save-Json  { param($Path, $Obj)   Save-Text $Path ($Obj | ConvertTo-Json -Depth 12) }

function Invoke-Json {
    param([string]$Url, [hashtable]$Headers = @{}, [int]$TimeoutSec = 30, [int]$Retries = 2)
    for ($i = 0; $i -le $Retries; $i++) {
        try { return Invoke-RestMethod -Uri $Url -Headers $Headers -TimeoutSec $TimeoutSec -UserAgent 'AssetLens' -ErrorAction Stop }
        catch {
            $code = $_.Exception.Response.StatusCode.value__
            # retry transient failures only (5xx / timeout = no response / 429 rate-limit); give up on other 4xx
            if ($i -lt $Retries -and ($null -eq $code -or $code -ge 500 -or $code -eq 429)) { Start-Sleep -Seconds (2 * ($i + 1)); continue }
            $safe = $Url -replace '(?i)([?&](key|apikey|api_key|token|access_token)=)[^&]*', '$1<redacted>'
            Write-Log "HTTP fail: $safe -- $($_.Exception.Message)" 'WARN'
            return $null
        }
    }
}
function Have-Key  { param($Name) return [bool]($Keys.ContainsKey($Name) -and $Keys[$Name]) }
function Invoke-Tool {
    # Runs an external tool under a hard timeout (Start-Job) so no single hung tool can stall the whole run.
    param([string]$Exe, [string[]]$ArgList, [int]$TimeoutSec = 300)
    if ($HttpOnly) { Write-Log "$Exe (HttpOnly mode)" 'SKIP'; return $null }
    $cmd = Get-Command $Exe -ErrorAction SilentlyContinue
    if (-not $cmd) { Write-Log "$Exe not installed" 'SKIP'; return $null }
    $job = Start-Job -ScriptBlock { param($p, $a) & $p @a } -ArgumentList $cmd.Source, $ArgList
    if (Wait-Job $job -Timeout $TimeoutSec) {
        $r = Receive-Job $job -ErrorAction SilentlyContinue
        Remove-Job $job -Force -ErrorAction SilentlyContinue
        return $r
    }
    Stop-Job $job -ErrorAction SilentlyContinue; Remove-Job $job -Force -ErrorAction SilentlyContinue
    Write-Log "$Exe timed out (${TimeoutSec}s) - killed, continuing" 'WARN'
    return $null
}
function Get-Apex {
    # registrable domain (naive PSL: handles common 2-label public suffixes)
    param($h)
    $multi = @('co.uk', 'org.uk', 'gov.uk', 'ac.uk', 'me.uk', 'com.au', 'net.au', 'org.au', 'gov.au', 'edu.au', 'co.nz', 'org.nz', 'co.in', 'net.in', 'org.in', 'gov.in', 'ac.in', 'co.jp', 'or.jp', 'ne.jp', 'com.br', 'com.mx', 'com.ar', 'com.co', 'co.za', 'com.sg', 'com.my', 'com.hk', 'com.tw', 'com.cn', 'co.kr', 'co.id', 'co.th', 'com.tr', 'com.ng', 'com.ph', 'com.pk', 'com.vn', 'com.sa', 'co.il', 'co.ke', 'com.ua')
    $p = ([string]$h).Split('.')
    if ($p.Count -le 2) { return $h }
    $last2 = ($p[-2..-1]) -join '.'
    if ($multi -contains $last2) { return ($p[-3..-1]) -join '.' }
    return $last2
}
function Get-M365Tenant {
    # PASSIVE Microsoft 365 / Azure AD tenant mapping. Queries Microsoft's OWN shared endpoints about the
    # domain (login.microsoftonline.com + autodiscover-s.outlook.com) - ZERO packets to the target host. Keyless.
    param([string]$Domain)
    $m = [ordered]@{ domain = $Domain; isAzureAD = $false; namespaceType = ''; tenantId = ''; tenantRegion = '';
                     federationBrand = ''; federationAuthUrl = ''; cloudInstance = ''; tenantDomains = @() }
    # 1) user-realm: Managed (cloud auth) vs Federated (ADFS/3rd-party IdP - exposes the on-prem auth URL)
    $ur = Invoke-Json ("https://login.microsoftonline.com/common/userrealm/user@{0}?api-version=1.0" -f $Domain)
    if ($ur) {
        $m.namespaceType     = [string]$ur.account_type
        $m.cloudInstance     = [string]$ur.cloud_instance_name
        $m.federationBrand   = [string]$ur.federation_brand_name
        $m.federationAuthUrl = [string]$ur.federation_active_auth_url
        if ($m.namespaceType -in @('Managed', 'Federated')) { $m.isAzureAD = $true }
    }
    if (-not $m.isAzureAD) { return $m }   # not a Microsoft tenant -> stop (also avoids a 400 on the openid call)
    # 2) OpenID config: tenant ID (GUID from the issuer URL) + region scope
    $oidc = Invoke-Json ("https://login.microsoftonline.com/{0}/v2.0/.well-known/openid-configuration" -f $Domain)
    if ($oidc -and $oidc.issuer) {
        if ($oidc.issuer -match '([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})') { $m.tenantId = $matches[1] }
        $m.tenantRegion = [string]$oidc.tenant_region_scope
    }
    # 3) Autodiscover GetFederationInformation (SOAP) -> every domain registered in the tenant
    try {
        $soap = '<?xml version="1.0" encoding="utf-8"?><soap:Envelope xmlns:a="http://www.w3.org/2005/08/addressing" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Header><a:Action soap:mustUnderstand="1">http://schemas.microsoft.com/exchange/2010/Autodiscover/Autodiscover/GetFederationInformation</a:Action><a:To soap:mustUnderstand="1">https://autodiscover-s.outlook.com/autodiscover/autodiscover.svc</a:To><a:ReplyTo><a:Address>http://www.w3.org/2005/08/addressing/anonymous</a:Address></a:ReplyTo></soap:Header><soap:Body><GetFederationInformationRequestMessage xmlns="http://schemas.microsoft.com/exchange/2010/Autodiscover"><Request><Domain>' + $Domain + '</Domain></Request></GetFederationInformationRequestMessage></soap:Body></soap:Envelope>'
        $hdrs = @{ SOAPAction = '"http://schemas.microsoft.com/exchange/2010/Autodiscover/Autodiscover/GetFederationInformation"'; 'User-Agent' = 'AutodiscoverClient' }
        $resp = Invoke-RestMethod -Uri 'https://autodiscover-s.outlook.com/autodiscover/autodiscover.svc' -Method Post -Body $soap -ContentType 'text/xml; charset=utf-8' -Headers $hdrs -TimeoutSec 30 -ErrorAction Stop
        $doms = @($resp.Envelope.Body.GetFederationInformationResponseMessage.Response.Domains.Domain | Where-Object { $_ })
        $m.tenantDomains = @($doms | ForEach-Object { ([string]$_).ToLower() } | Sort-Object -Unique)
    } catch {}
    return $m
}
# (uncover bridge removed - origin engines are queried directly in P4)

# ---------------------------------------------------------------- scope guard (single host)
$InScope = @($Target)
$OOS     = New-Object System.Collections.Generic.List[string]
function Test-InScope { param($h) return (([string]$h).ToLower() -in $InScope) }
function Add-OOS {
    param($Name, $Source)
    $h = ([string]$Name).Trim().ToLower().TrimStart('*').TrimStart('.')
    if (-not $h -or (Test-InScope $h)) { return }
    $entry = "$h`t$Source"
    if (-not $OOS.Contains($entry)) { $OOS.Add($entry) }
}

function Get-TargetIP {
    $script:AllIPs = @()
    if (-not $Strict) {
        try {
            $ips = @(Resolve-DnsName -Name $Target -Type A -ErrorAction Stop | Where-Object { $_.IPAddress } | ForEach-Object { $_.IPAddress })
            if ($ips.Count) {
                $script:AllIPs = $ips
                Write-Log ("Resolved $Target -> {0} (DNS, pragmatic mode)" -f ($ips -join ', ')) 'OK'
                if ($ips.Count -gt 1) { Write-Log "$($ips.Count) A records - P3/P4 scan the first; all recorded in ip.txt" 'INFO' }
                return $ips[0]
            }
        } catch { Write-Log "Resolve-DnsName failed: $($_.Exception.Message)" 'WARN' }
    }
    if (Have-Key 'VirusTotal') {
        $vt = Invoke-Json "https://www.virustotal.com/api/v3/domains/$Target" @{ 'x-apikey' = $Keys.VirusTotal }
        $as = @($vt.data.attributes.last_dns_records | Where-Object { $_.type -eq 'A' } | ForEach-Object { $_.value })
        if ($as.Count) { $script:AllIPs = $as; Write-Log ("Passive-DNS A via VirusTotal -> {0}" -f ($as -join ', ')) 'OK'; return $as[0] }
    }
    Write-Log 'No target IP (strict + no passive-DNS key). IP-based steps will skip.' 'WARN'
    return $null
}

# ---------------------------------------------------------------- phases
function Phase1-Scope {
    param($IP)
    Write-Log 'P1  scope / ownership'
    $rd = Invoke-Json ('https://rdap.org/domain/{0}' -f (Get-Apex $Target))
    if ($rd) { Save-Json (Join-Path $pkg '01_scope\rdap_domain.json') $rd; Write-Log 'RDAP domain ok' 'OK' }
    # DNS records (host A/AAAA/CNAME; apex MX/NS/TXT-SPF + _dmarc) - skipped in -Strict
    if (-not $Strict) {
        $apex = Get-Apex $Target
        $dns = New-Object System.Collections.Generic.List[string]
        function Add-Dns { param($n, $t) try { foreach ($rec in (Resolve-DnsName -Name $n -Type $t -ErrorAction Stop)) { $v = @($rec.IPAddress, $rec.NameExchange, $rec.NameHost, $rec.NameTarget, ($rec.Strings -join ' ')) | Where-Object { $_ } | Select-Object -First 1; if ($v) { $dns.Add(('{0,-7} {1,-6} {2}' -f $n, $t, $v)) } } } catch {} }
        Add-Dns $Target 'A'; Add-Dns $Target 'AAAA'; Add-Dns $Target 'CNAME'
        Add-Dns $apex 'MX'; Add-Dns $apex 'NS'; Add-Dns $apex 'TXT'; Add-Dns "_dmarc.$apex" 'TXT'
        if ($dns.Count) { Save-Lines (Join-Path $pkg '01_scope\dns_records.txt') $dns; Write-Log ('DNS records: {0} -> 01_scope\dns_records.txt' -f $dns.Count) 'OK' }
        if (-not ($dns | Where-Object { $_ -match 'v=spf1' })) { Write-Log "$apex has no SPF TXT (spoofable?)" 'WARN' }
        if (-not ($dns | Where-Object { $_ -match 'DMARC1' }))  { Write-Log "$apex has no DMARC record" 'WARN' }
    }
    Save-Lines (Join-Path $pkg '01_scope\ip.txt') @($(if (@($script:AllIPs).Count) { $script:AllIPs } else { $IP }) | Where-Object { $_ })
    if ($IP) {
        $rdip = Invoke-Json "https://rdap.org/ip/$IP"
        if ($rdip) {
            Save-Json (Join-Path $pkg '01_scope\rdap_ip.json') $rdip
            $owner = [string]$rdip.name
            Write-Log "Netblock owner: $owner" 'OK'
            if ($owner -match 'cloudflare|akamai|fastly|incapsula|imperva|cloudfront|amazon|google|azure|edgecast|sucuri') {
                Save-Text (Join-Path $pkg '01_scope\cdn_flag.txt') "LIKELY CDN/WAF: $owner  ->  origin hunt matters (see 04_origin)"
                Write-Log "Likely CDN/WAF ($owner) -> P4 origin hunt is high value" 'WARN'
            }
        }
        # IP geolocation (keyless) - hosting country/city/ASN for jurisdiction context + the report map
        $geo = Invoke-Json "https://ipwho.is/$IP"
        if ($geo -and $geo.success) {
            Save-Json (Join-Path $pkg '01_scope\geo.json') $geo
            Write-Log ("Geo: {0}, {1} ({2}) - {3} / AS{4}" -f $geo.city, $geo.country, $geo.country_code, $geo.connection.org, $geo.connection.asn) 'OK'
            # country flag SVG (keyless CDN, not the target) -> embedded in the report, works offline in the VDI
            $cc = ([string]$geo.country_code).ToLower()
            if ($cc -match '^[a-z]{2}$') { try { Invoke-WebRequest ("https://flagcdn.com/{0}.svg" -f $cc) -OutFile (Join-Path $pkg '01_scope\flag.svg') -UseBasicParsing -TimeoutSec 15 | Out-Null; Write-Log ("Country flag: {0}.svg" -f $cc) 'OK' } catch { Write-Log 'Flag fetch failed (non-fatal)' 'WARN' } }
        }
    }
    # PASSIVE Microsoft 365 / Azure AD tenant mapping (apex-level identity; queries Microsoft, never the target)
    $m365 = Get-M365Tenant (Get-Apex $Target)
    if ($m365.isAzureAD) {
        Save-Json (Join-Path $pkg '01_scope\m365.json') $m365
        Write-Log ("M365/Azure AD: {0} | tenant {1}{2}{3}" -f $m365.namespaceType, $(if ($m365.tenantId) { $m365.tenantId } else { '?' }), $(if ($m365.tenantRegion) { " | region $($m365.tenantRegion)" } else { '' }), $(if (@($m365.tenantDomains).Count) { " | $(@($m365.tenantDomains).Count) tenant domain(s)" } else { '' })) 'OK'
        if ($m365.namespaceType -eq 'Federated' -and $m365.federationAuthUrl) { Write-Log ("  Federated IdP/ADFS auth URL: {0}" -f $m365.federationAuthUrl) 'OK' }
        foreach ($d in @($m365.tenantDomains)) { if ($d -and $d -ne (Get-Apex $Target)) { Add-OOS $d 'M365 tenant domain' } }
    } else { Write-Log 'M365/Azure AD: domain not in a Microsoft tenant' 'INFO' }
}

function Phase2-Certs {
    Write-Log 'P2  certs / names (scope-gated)'
    $sans = New-Object System.Collections.Generic.HashSet[string]
    $crt  = Invoke-Json "https://crt.sh/?q=$Target&output=json"
    if ($crt) {
        Save-Json (Join-Path $pkg '02_certs\crtsh.json') $crt
        foreach ($row in $crt) {
            foreach ($n in ([string]$row.name_value -split "`n")) {
                $n = $n.Trim().TrimStart('*').TrimStart('.').ToLower()
                if ($n) { [void]$sans.Add($n) }
            }
        }
    }
    $sanList = @($sans) | Sort-Object
    Save-Lines (Join-Path $pkg '02_certs\sans.txt') $sanList
    foreach ($s in $sanList) { Add-OOS $s 'crt.sh SAN' }
    Write-Log ('CT names: {0} ({1} in-scope)' -f $sanList.Count, @($sanList | Where-Object { Test-InScope $_ }).Count) 'OK'

    if ($Enum) {
        $subs = Invoke-Tool 'subfinder' @('-d', $Target, '-all', '-silent')
        if ($subs) { Save-Lines (Join-Path $pkg '02_certs\subfinder.txt') $subs; foreach ($s in $subs) { Add-OOS $s 'subfinder' } }
    } else { Write-Log 'subfinder skipped (single-host default; pass -Enum for wildcard scope)' 'SKIP' }
}

function Phase3-Scan {
    param($IP)
    Write-Log 'P3  internet-scan data'
    if (-not $IP) { Write-Log 'no IP -> skip P3' 'SKIP'; return }
    $idb = Invoke-Json "https://internetdb.shodan.io/$IP"
    if ($idb) {
        Save-Json  (Join-Path $pkg '03_scan\internetdb.json') $idb
        Save-Lines (Join-Path $pkg '03_scan\ports.txt') (@($idb.ports) | Sort-Object { [int]$_ })
        Write-Log ('InternetDB: ports [{0}] | cpes {1} | vulns {2}' -f ($idb.ports -join ','), @($idb.cpes).Count, @($idb.vulns).Count) 'OK'
        if ($idb.cpes)  { Save-Lines (Join-Path $pkg '08_tech\cpes.txt') $idb.cpes }
        if ($idb.vulns) { Save-Lines (Join-Path $pkg '08_tech\internetdb_vulns.txt') $idb.vulns }
        foreach ($hn in $idb.hostnames) { Add-OOS $hn 'InternetDB hostname' }
    }
    if (Have-Key 'Shodan') {
        $sh = Invoke-Json ('https://api.shodan.io/shodan/host/{0}?key={1}' -f $IP, $Keys.Shodan)
        if ($sh) { Save-Json (Join-Path $pkg '03_scan\shodan_host.json') $sh; Write-Log 'Shodan host ok' 'OK' }
    }
    if (Have-Key 'Censys') {
        # Censys Platform API (Bearer PAT) - host asset endpoint. Host data is under .result.
        $cv = Invoke-Json "https://api.platform.censys.io/v3/global/asset/host/$IP" @{ Authorization = "Bearer $($Keys.Censys)" }
        if ($cv) { Save-Json (Join-Path $pkg '03_scan\censys_host.json') $cv.result; Write-Log 'Censys host ok' 'OK' }
    }
    if (Have-Key 'Netlas') {
        $nl = Invoke-Json "https://app.netlas.io/api/host/$IP/" @{ 'X-API-Key' = $Keys.Netlas }
        if ($nl) { Save-Json (Join-Path $pkg '03_scan\netlas_host.json') $nl; Write-Log 'Netlas host ok' 'OK' }
    }
    if (Have-Key 'AbuseIPDB') {
        # IP reputation (abuse score / reports / usage type / TOR) for the host's IP - free 1000 checks/day
        $ab = Invoke-Json "https://api.abuseipdb.com/api/v2/check?ipAddress=$IP&maxAgeInDays=90" @{ Key = $Keys.AbuseIPDB; Accept = 'application/json' }
        if ($ab -and $ab.data) {
            Save-Json (Join-Path $pkg '03_scan\abuseipdb.json') $ab.data
            Write-Log ('AbuseIPDB: score {0}/100, {1} report(s), usage="{2}"{3}' -f $ab.data.abuseConfidenceScore, $ab.data.totalReports, $ab.data.usageType, $(if ($ab.data.isTor) { ', TOR exit' } else { '' })) $(if ([int]$ab.data.abuseConfidenceScore -ge 25) { 'WARN' } else { 'OK' })
        }
    }
}

function Phase4-Origin {
    param($IP)
    Write-Log 'P4  origin behind CDN'
    $cand = New-Object System.Collections.Generic.List[string]
    if (Have-Key 'VirusTotal') {
        $vt = Invoke-Json "https://www.virustotal.com/api/v3/domains/$Target" @{ 'x-apikey' = $Keys.VirusTotal }
        if ($vt) {
            Save-Json (Join-Path $pkg '04_origin\vt_domain.json') $vt
            foreach ($rec in $vt.data.attributes.last_dns_records) { if ($rec.type -eq 'A') { [void]$cand.Add([string]$rec.value) } }
        }
    }
    if (Have-Key 'SecurityTrails') {
        $st = Invoke-Json "https://api.securitytrails.com/v1/history/$Target/dns/a" @{ 'APIKEY' = $Keys.SecurityTrails }
        if ($st) {
            Save-Json (Join-Path $pkg '04_origin\securitytrails_history.json') $st
            foreach ($r in $st.records) { foreach ($v in $r.values) { if ($v.ip) { [void]$cand.Add([string]$v.ip) } } }
        }
    }
    # Direct engine cert->IP origin pivot (replaces uncover). Free engines, each Have-Key gated.
    if (Have-Key 'CriminalIP') {
        $ci = Invoke-Json ('https://api.criminalip.io/v1/banner/search?query={0}&offset=0' -f [uri]::EscapeDataString('ssl_subject_common_name: ' + $Target)) @{ 'x-api-key' = $Keys.CriminalIP }
        if ($ci -and $ci.data.result) {
            Save-Json (Join-Path $pkg '04_origin\criminalip.json') $ci.data.result
            foreach ($h in $ci.data.result) { if ($h.ip_address) { [void]$cand.Add([string]$h.ip_address) } }
            Write-Log ('CriminalIP cert hits: {0}' -f @($ci.data.result).Count) 'OK'
        }
    }
    if (Have-Key 'Quake') {
        $qb = @{ query = ('cert:"' + $Target + '"'); size = 50; ignore_cache = $true } | ConvertTo-Json
        try {
            $qk = Invoke-RestMethod 'https://quake.360.net/api/v3/search/quake_service' -Method Post -Headers @{ 'X-QuakeToken' = $Keys.Quake } -ContentType 'application/json' -Body $qb -TimeoutSec 30 -ErrorAction Stop
            if ($qk.code -eq 0 -and $qk.data) {
                Save-Json (Join-Path $pkg '04_origin\quake.json') $qk.data
                foreach ($h in $qk.data) { if ($h.ip) { [void]$cand.Add([string]$h.ip) } }
                Write-Log ('Quake cert hits: {0}' -f @($qk.data).Count) 'OK'
            } else { Write-Log ('Quake: ' + $qk.message) 'WARN' }
        } catch { Write-Log "Quake error: $($_.Exception.Message)" 'WARN' }
    }

    # (Censys cert->IP pivot dropped: Platform search API is org-gated / 403 on a standard PAT.
    #  Origin still covered by VirusTotal + SecurityTrails passive-DNS + the direct engine queries below.)
    if (Have-Key 'Netlas') {
        $nd = Invoke-Json ('https://app.netlas.io/api/domains/?q=domain:{0}' -f $Target) @{ 'X-API-Key' = $Keys.Netlas }
        if ($nd) { Save-Json (Join-Path $pkg '04_origin\netlas_domain.json') $nd }
    }

    $candUniq = @($cand | Sort-Object -Unique | Where-Object { $_ -and $_ -ne $IP })
    Save-Lines (Join-Path $pkg '04_origin\candidates.txt') $candUniq
    if ($candUniq.Count) {
        # enrich EACH origin candidate with keyless InternetDB (ports/CVEs/tech) so the tester can triage which one to probe first
        $enriched = New-Object System.Collections.Generic.List[string]
        foreach ($c in ($candUniq | Select-Object -First 25)) {
            $cdb = Invoke-Json "https://internetdb.shodan.io/$c"
            if ($cdb -and $cdb.ports) {
                Save-Json (Join-Path $pkg ('04_origin\candidate_{0}.json' -f ($c -replace '[^0-9A-Fa-f.]', '_'))) $cdb
                $enriched.Add(('{0}  ports[{1}]  cves[{2}]  {3}' -f $c, (@($cdb.ports) -join ','), @($cdb.vulns).Count, ((@($cdb.cpes) | Select-Object -First 3) -join ' ')))
            } else { $enriched.Add(('{0}  (no InternetDB data)' -f $c)) }
        }
        Save-Lines (Join-Path $pkg '04_origin\candidates_enriched.txt') $enriched
        Write-Log ('origin candidates: {0} (enriched via InternetDB -> 04_origin\candidates_enriched.txt)' -f $candUniq.Count) 'OK'
    } else { Write-Log 'no distinct origin candidates' 'INFO' }
    $script:OriginCandidates = $candUniq
}

function Phase5-History {
    Write-Log 'P5  historical urls / params / endpoints'
    $urls = New-Object System.Collections.Generic.HashSet[string]
    # (raw Wayback CDX dropped - flaky timeouts; gau + waybackurls cover the same archives reliably)
    foreach ($t in 'gau', 'waybackurls') { $o = Invoke-Tool $t @($Target); if ($o) { foreach ($u in $o) { if ($u) { [void]$urls.Add([string]$u) } } } }
    # CommonCrawl CDX - more archived URLs for the host (keyless HTTP; latest crawl index)
    try {
        $ccol = Invoke-Json 'https://index.commoncrawl.org/collinfo.json'
        $ccApi = if ($ccol) { [string]$ccol[0].'cdx-api' } else { '' }
        if ($ccApi) {
            $ccN = 0
            $ccResp = Invoke-WebRequest ('{0}?url={1}/*&output=json&fl=url&limit=1000' -f $ccApi, $Target) -UseBasicParsing -TimeoutSec 60
            foreach ($ln in ($ccResp.Content -split "`n")) { if ($ln.Trim()) { try { $j = $ln | ConvertFrom-Json; if ($j.url) { [void]$urls.Add([string]$j.url); $ccN++ } } catch {} } }
            Write-Log ('CommonCrawl: {0} URLs ({1})' -f $ccN, $ccol[0].id) 'OK'
        }
    } catch { Write-Log 'CommonCrawl unreachable -> skip' 'SKIP' }
    $h = @{}; if (Have-Key 'UrlScan') { $h['API-Key'] = $Keys.UrlScan }
    $us = Invoke-Json "https://urlscan.io/api/v1/search/?q=domain:$Target" $h
    if ($us) { Save-Json (Join-Path $pkg '05_history\urlscan.json') $us; foreach ($r in $us.results) { if ($r.page.url) { [void]$urls.Add([string]$r.page.url) } } }

    # scope hygiene: archived-URL sources (esp. urlscan's domain: search) surface pages that merely REFERENCE the
    # target - keep only URLs under the target's apex; off-domain hosts go to OOS, never the attack surface.
    $apexL = Get-Apex $Target
    $inScopeUrls = New-Object System.Collections.Generic.HashSet[string]
    $offDomain = 0
    foreach ($u in $urls) {
        $uh = ''; try { $uh = ([uri][string]$u).Host.ToLower() } catch {}
        if (-not $uh) { continue }
        if ($uh -eq $apexL -or $uh.EndsWith('.' + $apexL)) { [void]$inScopeUrls.Add([string]$u) }
        else { Add-OOS $uh 'archived URL (off-domain)'; $offDomain++ }
    }
    if ($offDomain) { Write-Log ("scope filter: {0} off-domain archived URL(s) -> OOS (kept out of attack surface)" -f $offDomain) 'INFO' }
    $urls = $inScopeUrls

    $all = @($urls) | Sort-Object
    Save-Lines (Join-Path $pkg '05_history\all_urls.txt') $all
    # uro: collapse near-duplicate URL patterns into a clean representative endpoint set
    $dedup = Invoke-Tool 'uro' @('-i', (Join-Path $pkg '05_history\all_urls.txt'))
    if ($dedup) { Save-Lines (Join-Path $pkg '05_history\urls_deduped.txt') $dedup; Write-Log ('uro dedup: {0} -> {1} URL patterns' -f $all.Count, @($dedup).Count) 'OK' }
    # extract unique URIs (paths) across ALL observed hosts -> for replaying onto a UAT/staging host that was never crawled
    $uriSrc = if ($dedup) { $dedup } else { $all }
    $uris = New-Object System.Collections.Generic.HashSet[string]
    $urisQ = New-Object System.Collections.Generic.HashSet[string]
    foreach ($u in $uriSrc) {
        try { $z = [uri]([string]$u); if ($z.AbsolutePath -and $z.AbsolutePath -ne '/') { [void]$uris.Add($z.AbsolutePath) }; if ($z.PathAndQuery -and $z.PathAndQuery -ne '/') { [void]$urisQ.Add($z.PathAndQuery) } } catch {}
    }
    Save-Lines (Join-Path $pkg '05_history\uris.txt') (@($uris) | Sort-Object)
    Save-Lines (Join-Path $pkg '05_history\uris_with_query.txt') (@($urisQ) | Sort-Object)
    Write-Log ('URIs for UAT replay: {0} unique paths' -f $uris.Count) 'OK'
    $params = New-Object System.Collections.Generic.HashSet[string]
    foreach ($u in $all) {
        $q = ([string]$u -split '\?', 2)[1]
        if ($q) { foreach ($kv in ($q -split '&')) { $k = ($kv -split '=', 2)[0]; if ($k) { [void]$params.Add($k) } } }
    }
    Save-Lines (Join-Path $pkg '05_history\params.txt') (@($params) | Sort-Object)
    $js = @($all | Where-Object { $_ -match '\.js($|\?)' })
    Save-Lines (Join-Path $pkg '05_history\js_urls.txt') $js
    # group URLs by file extension (spot .config/.bak/.sql/.asmx/.svc/.json/.aspx fast)
    $extMap = @{}
    foreach ($u in $all) {
        $leaf = ((([string]$u -split '\?', 2)[0]) -split '/')[-1]
        $ext = if ($leaf -match '\.([A-Za-z][A-Za-z0-9]{0,7})$') { '.' + $matches[1].ToLower() } else { '(none)' }
        if (-not $extMap.ContainsKey($ext)) { $extMap[$ext] = New-Object System.Collections.Generic.List[string] }
        $extMap[$ext].Add([string]$u)
    }
    Save-Lines (Join-Path $pkg '05_history\extensions.txt') (@($extMap.GetEnumerator() | Sort-Object { $_.Value.Count } -Descending | ForEach-Object { '{0,7}  {1}' -f $_.Value.Count, $_.Key }))
    $byExt = New-Object System.Collections.Generic.List[string]
    foreach ($e in ($extMap.Keys | Sort-Object)) { $byExt.Add("# ===== $e ($($extMap[$e].Count)) ====="); foreach ($x in ($extMap[$e] | Sort-Object)) { $byExt.Add($x) }; $byExt.Add('') }
    Save-Lines (Join-Path $pkg '05_history\urls_by_ext.txt') $byExt
    Write-Log ('urls {0} | params {1} | js {2} | ext-types {3}' -f $all.Count, $params.Count, $js.Count, $extMap.Count) 'OK'
}

function Phase6-Js {
    Write-Log 'P6  archived responses + extraction (waymore -> native regex)'
    $jsDir = Join-Path $pkg '06_js'
    $respDir = Join-Path $jsDir 'responses'
    New-Item -ItemType Directory -Force -Path $respDir | Out-Null
    # waymore mode R: robustly download archived response bodies (incl JS) from the archives - replaces the flaky per-JS fetch
    Invoke-Tool 'waymore' @('-i', $Target, '-mode', 'R', '-oR', $respDir, '-l', '500', '-ci', 'none', '-p', '4') -TimeoutSec 600 | Out-Null
    # only real downloaded bodies are responses - exclude waymore's own bookkeeping (waymore_index.txt + *.tmp)
    $bodyFiles = @(Get-ChildItem $respDir -Recurse -File -ErrorAction SilentlyContinue | Where-Object { $_.Name -ne 'waymore_index.txt' -and $_.Name -notlike '*.tmp' })
    $cnt = $bodyFiles.Count
    if ($cnt -eq 0) { Write-Log 'waymore downloaded 0 responses -> skip extraction' 'WARN'; return }
    Write-Log "waymore downloaded $cnt archived responses" 'OK'
    # native endpoint/param/wordlist extraction from the bodies (replaced xnLinkFinder, which in v8.2 forces a
    # scope filter, writes to the console not stdout so it can't be captured, and returned 0 on real archived
    # pages; this deterministic regex recovered 3600+ endpoints it missed on a real target)
    $links = New-Object System.Collections.Generic.HashSet[string]
    $words = New-Object System.Collections.Generic.HashSet[string]
    # tech fingerprint signatures matched against archived body content
    $techSig = [ordered]@{
        'ASP.NET WebForms'   = '__VIEWSTATE|__EVENTVALIDATION|WebResource\.axd|ScriptResource\.axd'
        'ASP.NET MVC'        = '__RequestVerificationToken'
        'AjaxControlToolkit' = 'AjaxControlToolkit'
        'Vue.js'             = 'data-v-[0-9a-f]{6,}|__vue__|chunk-vendors|Vue\.config'
        'React'              = 'data-reactroot|__REACT_DEVTOOLS|_next/static'
        'Angular'            = 'ng-version=|ng-app=|\bangular\.module\b'
        'WordPress'          = 'wp-content|wp-includes|/wp-json/'
        'Drupal'             = 'Drupal\.settings|/sites/default/files'
        'Joomla'             = '/media/jui/|option=com_'
        'jQuery'             = 'jquery[.\-][0-9]'
        'Bootstrap'          = 'bootstrap(\.min)?\.(css|js)'
        'Google Analytics'   = 'google-analytics\.com|GoogleAnalyticsObject|gtag\('
        'Google Tag Manager' = 'googletagmanager\.com'
        'reCAPTCHA'          = 'recaptcha'
    }
    $techHits = @{}
    $corpus = New-Object System.Text.StringBuilder   # combined body text for Wappalyzer-style matching (capped ~6MB)
    # source maps: a body that IS a map -> original source tree; a sourceMappingURL ref -> a lead
    $smSrc = New-Object System.Collections.Generic.HashSet[string]
    $smRef = New-Object System.Collections.Generic.HashSet[string]
    # archived OpenAPI/Swagger specs: a body that IS a spec -> the full endpoint contract
    $apiEp = New-Object System.Collections.Generic.List[string]; $apiSpecN = 0
    foreach ($f in $bodyFiles) {
        $c = Get-Content $f.FullName -Raw -ErrorAction SilentlyContinue
        if (-not $c) { continue }
        if ($corpus.Length -lt 3000000) { $seg = $(if ($c.Length -gt 80000) { $c.Substring(0, 80000) } else { $c }); [void]$corpus.Append($seg).Append("`n") }
        foreach ($m in [regex]::Matches($c, 'https?://[^\s"''<>()]{6,}'))                              { [void]$links.Add(($m.Value -replace '[\\",''<>);]+$', '')) }
        foreach ($m in [regex]::Matches($c, '["''](/[a-zA-Z0-9_\-./]{2,}[a-zA-Z0-9_\-./?=&%]*)["'']')) { [void]$links.Add($m.Groups[1].Value) }
        foreach ($tk in $techSig.Keys) { if ($c -match $techSig[$tk]) { $techHits[$tk] = [int]$techHits[$tk] + 1 } }
        if ($c -match '"version"\s*:\s*3' -and $c -match '"sources"\s*:\s*\[') { try { $sm = $c | ConvertFrom-Json; foreach ($s in $sm.sources) { if ($s) { [void]$smSrc.Add([string]$s) } } } catch {} }
        foreach ($m in [regex]::Matches($c, '(?://[#@]\s*sourceMappingURL=)([^\s''"]+)')) {
            $mu = $m.Groups[1].Value
            if ($mu -match '^data:.*base64,(.+)$') { try { $dm = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($matches[1])); $sm = $dm | ConvertFrom-Json; foreach ($s in $sm.sources) { if ($s) { [void]$smSrc.Add([string]$s) } } } catch {} }
            elseif ($mu -notmatch '^data:') { [void]$smRef.Add($mu) }
        }
        # this body IS an OpenAPI/Swagger spec -> recover the full endpoint contract (method + path + params)
        if ($c -match '"(openapi|swagger)"\s*:' -and $c -match '"paths"\s*:\s*\{') {
            try {
                $spec = $c | ConvertFrom-Json
                if ($spec.paths) {
                    $apiSpecN++
                    foreach ($pp in $spec.paths.PSObject.Properties) {
                        foreach ($mm in $pp.Value.PSObject.Properties) {
                            $meth = ([string]$mm.Name).ToUpper()
                            if ($meth -notmatch '^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)$') { continue }
                            $pn = @(); if ($mm.Value.parameters) { $pn = @($mm.Value.parameters | ForEach-Object { $_.name } | Where-Object { $_ }) }
                            $line = '{0,-7} {1}' -f $meth, $pp.Name
                            if ($pn.Count) { $line += '  [' + (($pn | Select-Object -First 12) -join ', ') + ']' }
                            $apiEp.Add($line)
                        }
                    }
                }
            } catch {}
        }
    }
    # params from the extracted links' query strings only (avoids the minified-JS ?a= ternary noise a raw scan caught)
    $prm = New-Object System.Collections.Generic.HashSet[string]
    foreach ($l in $links) {
        $q = ([string]$l -split '\?', 2)[1]
        if ($q) { foreach ($kv in ($q -split '&')) { if ($kv -notmatch '=') { continue }; $k = ($kv -split '=', 2)[0]; if ($k -match '^[a-zA-Z_][a-zA-Z0-9_\-]{1,30}$') { [void]$prm.Add($k) } } }
    }
    foreach ($l in $links) { foreach ($seg in ($l -split '[/?&=.]')) { if ($seg -match '^[a-zA-Z][a-zA-Z0-9_\-]{1,30}$') { [void]$words.Add($seg.ToLower()) } } }
    # cloud-storage assets referenced in the bodies (S3/Azure/GCS/Spaces/Firebase/R2) - common prod-data carriers
    $cloud = @($links | Where-Object { $_ -match '(?i)(s3[.-][a-z0-9.-]*amazonaws\.com|\.blob\.core\.windows\.net|storage\.googleapis\.com|\.digitaloceanspaces\.com|\.firebaseio\.com|\.r2\.cloudflarestorage\.com)' } | Sort-Object -Unique)
    if ($cloud.Count) { Save-Lines (Join-Path $jsDir 'cloud_assets.txt') $cloud }
    Save-Lines (Join-Path $jsDir 'endpoints.txt') (@($links) | Sort-Object)
    Save-Lines (Join-Path $jsDir 'params.txt')    (@($prm)   | Sort-Object)
    Save-Lines (Join-Path $jsDir 'wordlist.txt')  (@($words) | Sort-Object)
    Write-Log ('extracted {0} endpoints | {1} params | {2} wordlist | {3} cloud assets from {4} bodies' -f $links.Count, $prm.Count, $words.Count, $cloud.Count, $cnt) 'OK'
    # tech fingerprint: body signatures + URL extensions + InternetDB CPEs -> 08_tech\fingerprint.txt
    $extHints = [ordered]@{ '.aspx' = 'ASP.NET'; '.asmx' = 'ASP.NET web service'; '.axd' = 'ASP.NET'; '.ashx' = 'ASP.NET handler'; '.jsp' = 'Java/JSP'; '.jspx' = 'Java/JSP'; '.do' = 'Java (Struts/Spring)'; '.action' = 'Java Struts'; '.php' = 'PHP'; '.cfm' = 'ColdFusion'; '.vue' = 'Vue.js' }
    $extsF = @(); if (Test-Path (Join-Path $pkg '05_history\extensions.txt')) { $extsF = @(Get-Content (Join-Path $pkg '05_history\extensions.txt') -ErrorAction SilentlyContinue) }
    $techOut = New-Object System.Collections.Generic.List[string]
    foreach ($tk in ($techHits.Keys | Sort-Object { $techHits[$_] } -Descending)) { $techOut.Add(('{0,-22} {1} bodies' -f $tk, $techHits[$tk])) }
    foreach ($eh in $extHints.Keys) { if ($extsF | Where-Object { $_ -match ([regex]::Escape($eh) + '$') }) { $techOut.Add(('{0,-22} (via {1} URLs)' -f $extHints[$eh], $eh)) } }
    if (Test-Path (Join-Path $pkg '08_tech\cpes.txt')) { foreach ($cp in (Get-Content (Join-Path $pkg '08_tech\cpes.txt') -ErrorAction SilentlyContinue)) { if ($cp) { $techOut.Add(('{0,-22} (InternetDB CPE)' -f $cp)) } } }
    # Wappalyzer-style passive fingerprint: match the bundled MIT ruleset (config\wappalyzer.json) against the body
    # corpus. Zero new requests - reads only the bodies waymore already pulled. Broadens beyond the curated $techSig.
    $wappaFile = Join-Path $PSScriptRoot 'config\wappalyzer.json'
    if ((Test-Path $wappaFile) -and $corpus.Length -gt 200) {
        $corpusStr = $corpus.ToString()
        $wappa = $null; try { $wappa = Get-Content $wappaFile -Raw | ConvertFrom-Json } catch { Write-Log "wappalyzer.json parse failed: $($_.Exception.Message)" 'WARN' }
        if ($wappa) {
            $already = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
            foreach ($tk in $techHits.Keys) { [void]$already.Add([string]$tk) }
            $wHits = @{}
            Write-Log ('Wappalyzer fingerprint: matching {0}-tech ruleset vs {1:N0} KB body corpus...' -f @($wappa).Count, ($corpusStr.Length / 1KB)) 'INFO'
            foreach ($t in $wappa) {
                foreach ($pat in $t.p) {
                    $ok = $false; try { $ok = [regex]::IsMatch($corpusStr, [string]$pat, [Text.RegularExpressions.RegexOptions]::IgnoreCase, [TimeSpan]::FromSeconds(2)) } catch {}
                    if ($ok) { $wHits[[string]$t.n] = (@($t.c) -join ', '); break }
                }
            }
            # fold in 'implies' (tech A present => tech B) so dependency stacks surface too
            foreach ($t in $wappa) { if ($wHits.ContainsKey([string]$t.n) -and $t.i) { foreach ($im in $t.i) { if (-not $wHits.ContainsKey([string]$im)) { $wHits[[string]$im] = '(implied)' } } } }
            $wNew = 0
            foreach ($n in ($wHits.Keys | Sort-Object)) {
                if ($already.Contains($n)) { continue }
                $det = $(if ($wHits[$n]) { $wHits[$n] + ' (Wappalyzer)' } else { '(Wappalyzer)' })
                $techOut.Add(('{0,-22} {1}' -f $n, $det)); $wNew++
            }
            Write-Log ("Wappalyzer: {0} tech(s) matched in archived bodies ({1} new beyond built-in signatures)" -f $wHits.Count, $wNew) 'OK'
        }
    }
    if ($techOut.Count) { Save-Lines (Join-Path $pkg '08_tech\fingerprint.txt') $techOut }
    # source maps: original-source disclosure (bodies that ARE maps) + .map leads (sourceMappingURL refs)
    if ($smSrc.Count) { Save-Lines (Join-Path $jsDir 'sourcemap_sources.txt') (@($smSrc) | Sort-Object) }
    if ($smRef.Count) { Save-Lines (Join-Path $jsDir 'sourcemap_refs.txt') (@($smRef) | Sort-Object) }
    # API spec discovery: parsed contract (from archived spec bodies) + spec-URL leads (to fetch live in the VDI)
    $apiRefs = @($links | Where-Object { $_ -match '(?i)(swagger|/api-docs|openapi\.json|swagger-ui|/v[0-9]+/api-docs|apispec|redoc|swagger\.(json|yaml))' } | Sort-Object -Unique)
    if ($apiEp.Count)   { Save-Lines (Join-Path $jsDir 'api_spec_endpoints.txt') (@($apiEp) | Sort-Object -Unique) }
    if ($apiRefs.Count) { Save-Lines (Join-Path $jsDir 'api_spec_refs.txt') $apiRefs }
    Write-Log ('tech: {0} signals | source maps: {1} paths / {2} refs | API spec: {3} endpoints from {4} spec(s), {5} spec-URL leads' -f $techOut.Count, $smSrc.Count, $smRef.Count, $apiEp.Count, $apiSpecN, $apiRefs.Count) 'OK'
    # secret scanners on the downloaded bodies
    $t = Invoke-Tool 'trufflehog' @('filesystem', $respDir, '--no-update', '--json'); if ($t) { Save-Lines (Join-Path $jsDir 'trufflehog.json') $t }
    Invoke-Tool 'gitleaks' @('detect', '--source', $respDir, '--no-git', '-r', (Join-Path $jsDir 'gitleaks.json')) | Out-Null
    # retire.js: flag known-vulnerable JS libraries in the archived responses
    Invoke-Tool 'retire' @('--path', $respDir, '--outputformat', 'json', '--outputpath', (Join-Path $jsDir 'retirejs.json')) | Out-Null
    if (Test-Path (Join-Path $jsDir 'retirejs.json')) { Write-Log 'retire.js -> 06_js\retirejs.json' 'OK' }
}

function Phase7-Osint {
    param($IP)
    Write-Log 'P7  OSINT / leaks / reputation'
    $emails = New-Object System.Collections.Generic.HashSet[string]

    # Tranco rank (keyless)
    $tr = Invoke-Json "https://tranco-list.eu/api/ranks/domain/$Target"
    if ($tr) { Save-Json (Join-Path $pkg '07_osint\tranco.json') $tr; if ($tr.ranks) { Write-Log ('Tranco rank: {0}' -f $tr.ranks[0].rank) 'OK' } }

    # GitHub code search - target hostname referenced in public code
    if (Have-Key 'GitHub') {
        $gh = @{ Authorization = "Bearer $($Keys.GitHub)"; Accept = 'application/vnd.github+json'; 'User-Agent' = 'AssetLens'; 'X-GitHub-Api-Version' = '2022-11-28' }
        $r = Invoke-Json ('https://api.github.com/search/code?q={0}&per_page=50' -f $Target) $gh
        if ($r) {
            Save-Json  (Join-Path $pkg '07_osint\github_code.json') $r
            Save-Lines (Join-Path $pkg '07_osint\github_hits.txt') @($r.items | ForEach-Object { '{0}  {1}  {2}' -f $_.repository.full_name, $_.path, $_.html_url })
            Write-Log ('GitHub code hits: {0}' -f $r.total_count) 'OK'
        }
        # commit-author emails matching the apex -> free org-email source (zero-FP: filtered to @apex; feeds the breach check)
        $apex = Get-Apex $Target
        $gc = Invoke-Json ('https://api.github.com/search/commits?q={0}&per_page=100' -f $apex) $gh
        if ($gc -and $gc.items) {
            $rxA = '(?i)@' + [regex]::Escape($apex) + '$'
            foreach ($it in $gc.items) { foreach ($em in @($it.commit.author.email, $it.commit.committer.email)) { if ($em -and $em -match $rxA) { [void]$emails.Add(([string]$em).ToLower()) } } }
            if ($emails.Count) { Write-Log ('GitHub commit emails (@{0}): {1}' -f $apex, @($emails).Count) 'OK' }
        }
    }

    # AlienVault OTX - threat-intel pulses (host) + passive DNS (IP -> siblings to OOS); free key
    if (Have-Key 'OTX') {
        $oh = @{ 'X-OTX-API-KEY' = $Keys.OTX }
        $og = Invoke-Json ('https://otx.alienvault.com/api/v1/indicators/hostname/{0}/general' -f $Target) $oh
        if ($og) {
            Save-Json (Join-Path $pkg '07_osint\otx_host.json') $og
            $pc = [int]$og.pulse_info.count
            Write-Log ('OTX: {0} threat pulse(s) referencing the host' -f $pc) $(if ($pc -gt 0) { 'WARN' } else { 'OK' })
        }
        if ($IP) {
            $opd = Invoke-Json ('https://otx.alienvault.com/api/v1/indicators/IPv4/{0}/passive_dns' -f $IP) $oh
            if ($opd -and $opd.passive_dns) {
                Save-Json (Join-Path $pkg '07_osint\otx_passivedns.json') $opd.passive_dns
                foreach ($pd in $opd.passive_dns) { if ($pd.hostname) { Add-OOS $pd.hostname 'OTX passive-DNS' } }
            }
        }
    }

    # LeakIX - exposures / leaks on the host IP
    if ((Have-Key 'LeakIX') -and $IP) {
        $lx = Invoke-Json "https://leakix.net/host/$IP" @{ 'api-key' = $Keys.LeakIX; Accept = 'application/json' }
        if ($lx) { Save-Json (Join-Path $pkg '07_osint\leakix_host.json') $lx; Write-Log 'LeakIX host ok' 'OK' }
    }

    # SpiderFoot passive (optional, slow)
    if (-not $HttpOnly -and $Tools.SpiderFootDir -and (Test-Path (Join-Path $Tools.SpiderFootDir 'sf.py'))) {
        Write-Log 'SpiderFoot passive (may take a while)'
        Push-Location $Tools.SpiderFootDir
        try { $sf = & $Tools.Python 'sf.py' '-s' $Target '-u' 'passive' '-o' 'json' '-q'; if ($sf) { Save-Lines (Join-Path $pkg '07_osint\spiderfoot.json') $sf; Write-Log 'SpiderFoot done' 'OK' } }
        catch { Write-Log "SpiderFoot error: $($_.Exception.Message)" 'WARN' } finally { Pop-Location }
    } else { Write-Log 'SpiderFoot not configured ($Tools.SpiderFootDir) -> skip' 'SKIP' }

    # consolidated email list -> feeds the LeakCheck breach check below
    # (emails now come from GitHub commit-authors @apex above - the free replacement for Hunter)
    if ($emails.Count) { Save-Lines (Join-Path $pkg '07_osint\emails.txt') (@($emails) | Sort-Object) }

    # Breach / infostealer exposure - FREE + KEYLESS (replaces paid HIBP)
    # (HudsonRock Cavalier domain API retired - every v2/v3 path now 404s; LeakCheck below is the keyless breach source)
    # LeakCheck public: per discovered email (keyless, rate-limited, capped)
    if ($emails.Count) {
        $out = New-Object System.Collections.Generic.List[string]
        $n = 0
        foreach ($em in (@($emails) | Sort-Object | Select-Object -First 10)) {
            $n++
            $lc = Invoke-Json ('https://leakcheck.io/api/public?check={0}' -f [uri]::EscapeDataString($em))
            if ($lc -and $lc.found -gt 0) {
                $srcs = (@($lc.sources | ForEach-Object { $_.name }) | Where-Object { $_ }) -join ', '
                $out.Add(('{0}: found={1} [{2}]' -f $em, $lc.found, $srcs))
            }
            Start-Sleep -Milliseconds 1200
        }
        if ($out.Count) { Save-Lines (Join-Path $pkg '07_osint\breach_hits.txt') $out; Write-Log ('LeakCheck: {0}/{1} emails breached' -f $out.Count, $n) 'OK' }
        else { Write-Log ('LeakCheck: checked {0} emails, no hits' -f $n) 'INFO' }
    }
}

# ---------------------------------------------------------------- deliverable docs
function Write-Index {
    param($IP)
    $modeStr = if ($Strict) { 'STRICT (no DNS resolution; passive-DNS APIs only)' } else { 'PRAGMATIC (single DNS resolution permitted)' }
    $keysOn  = @($Keys.GetEnumerator() | Where-Object { $_.Value } | ForEach-Object { $_.Key }) -join ', '
    if (-not $keysOn) { $keysOn = '(none - keyless run)' }
    Save-Text (Join-Path $pkg 'Index.md') @"
# AssetLens Package - $Target

| field | value |
|---|---|
| Target (in-scope host) | $Target |
| Resolved IP | $IP |
| Collected (local) | $stamp |
| Mode | $modeStr |
| Runtime | PowerShell-native (AssetLens) |
| API keys active | $keysOn |

## PASSIVE-ONLY ATTESTATION
Every artifact was obtained from third-party data sources (certificate
transparency, internet-scan databases, web archives, RDAP, OSINT APIs).
**No packets were sent to $Target from the collecting host.** All active
verification is deferred to the authorized VDI - see Verify_inside_vdi.md.

## SCOPE
In-scope: $Target (single host). Every other host/IP/asset discovered is in
**OOS_observed.txt** - OUT OF SCOPE, DO NOT TEST.

## CONTENTS
- Report.md   synthesized human-readable brief (read first)
- 01_scope    RDAP (apex) + DNS records (MX/TXT/NS) + IP(s) + geo + M365/Azure tenant + CDN flag
- 02_certs    CT-log SANs (in-scope flagged)
- 03_scan     Shodan-InternetDB + Shodan/Censys/Netlas host (ports / services / CVEs) + AbuseIPDB IP-reputation
- 04_origin   origin-behind-CDN candidates (verify in VDI)
- 05_history  archived URLs, uro-deduped, URIs (UAT replay), params, extensions
- 06_js       archived responses + native-regex endpoints/params/wordlist + trufflehog/gitleaks/retire.js
- 07_osint    Tranco, GitHub (code + commit-emails), OTX threat-intel, LeakIX, emails, breach exposure
- 08_tech     CPEs + InternetDB CVEs
- Verify_inside_vdi.md   ranked active-test worklist
- OOS_observed.txt   off-host assets (DO NOT TEST)
- manifest.sha256    integrity
"@
}

function Write-Worklist {
    param($IP)
    $origins = if ($script:OriginCandidates -and $script:OriginCandidates.Count) { ($script:OriginCandidates -join ', ') } else { '(none found)' }
    $ports = ''
    $pf = Join-Path $pkg '03_scan\ports.txt'
    if (Test-Path $pf) { $ports = ((Get-Content $pf) -join ', ') }
    Save-Text (Join-Path $pkg 'Verify_inside_vdi.md') @"
# Verify inside VDI - $Target

Active steps only. Run from the authorized VDI. Read Report.md first.

1. Probe host + every origin candidate with httpx; screenshot.
   - host: $Target ($IP)
   - origin candidates (does origin answer directly, bypassing any WAF?): $origins
2. Confirm the exposed ports are open from the VDI: $ports
   - cross-check 08_tech\internetdb_vulns.txt + 06_js\retirejs.json against the live versions.
3. Replay prod URIs on UAT: Invoke-AssetLens.ps1 -MapUat -Package . -UatBase https://<uat> -> uat_targets.txt, then httpx/nuclei.
4. Load 05_history\uris.txt + 06_js\wordlist.txt + params.txt into Burp Intruder (payload sets); katana to crawl. Scan 05_history\urls_by_ext.txt for sensitive file types.
5. Validate secrets in 06_js (trufflehog.json / gitleaks.json).
6. Review 02_certs\sans.txt for in-scope alternate names of the same app.

Reminder: nothing in OOS_observed.txt is in scope. Do not test it.
"@
}

# ---------------------------------------------------------------- main
Write-Host ''
Write-Log ("AssetLens  target=$Target  mode=" + $(if ($Strict) { 'strict' } else { 'pragmatic' }) + '  profile=' + $(if ($KeyedRun) { 'keyed' } else { 'keyless' }) + $(if ($HttpOnly) { '  (http-only)' } else { '' }))
$ip = Get-TargetIP

$steps = @(
    { Phase1-Scope   $ip },
    { Phase2-Certs },
    { Phase3-Scan    $ip },
    { Phase4-Origin  $ip },
    { Phase5-History },
    { Phase6-Js },
    { Phase7-Osint  $ip }
)
foreach ($s in $steps) { try { & $s } catch { Write-Log "phase failed: $($_.Exception.Message)" 'WARN' } }

Write-Index    $ip
Write-Worklist $ip
Save-Lines (Join-Path $pkg 'OOS_observed.txt') (@('# OUT OF SCOPE - observed only, DO NOT TEST', '# <host>  <tab>  <source>', '') + @($OOS))

# synthesize the human-readable report (Report.md) from the collected artifacts
try { Build-Report -Package $pkg | Out-Null; Write-Log 'report -> Report.md' 'OK' } catch { Write-Log "report failed: $($_.Exception.Message)" 'WARN' }
# optional: map URIs onto a UAT base if -UatBase was given
if ($UatBase) { try { Invoke-MapUat -Package $pkg -UatBase $UatBase | Out-Null; Write-Log 'UAT targets -> 05_history\uat_targets.txt' 'OK' } catch { Write-Log "map-uat failed: $($_.Exception.Message)" 'WARN' } }

Write-Host ''
Write-Log "DONE  package: $pkg" 'OK'
Write-Log ('OOS assets noted: {0}  (see OOS_observed.txt)' -f $OOS.Count) $(if ($OOS.Count) { 'OOS' } else { 'INFO' })

# manifest LAST (so it covers the final recon.log), then zip + hash for VDI transfer
$manifest = Get-ChildItem $pkg -Recurse -File | Where-Object { $_.Name -ne 'manifest.sha256' } |
    ForEach-Object { '{0}  {1}' -f (Get-FileHash $_.FullName -Algorithm SHA256).Hash, $_.FullName.Substring($pkg.Length + 1) }
Save-Lines (Join-Path $pkg 'manifest.sha256') $manifest
try { New-PackageZip -Package $pkg -FullBodies:$FullBodies } catch { Write-Host "zip failed: $($_.Exception.Message)" -ForegroundColor Yellow }

Write-Host ''
Write-Host '  Next: transfer the .zip into the VDI (verify .zip.sha256), then work Verify_inside_vdi.md' -ForegroundColor Cyan
Write-Host ''
