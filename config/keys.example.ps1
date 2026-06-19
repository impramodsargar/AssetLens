# ---------------------------------------------------------------------------
# AssetLens : API key + tool-path configuration  (TEMPLATE)
#
# Each tester copies this file to  config\keys.ps1  and fills in their OWN keys.
# config\keys.ps1 is git-ignored and must NEVER be committed.
#
# ALL keys below are FREE-tier. The toolkit also has a keyless HTTP core
# (RDAP, crt.sh, Shodan-InternetDB, Wayback, Tranco, urlscan search,
# LeakCheck breach data) that runs with ZERO keys.
# Keys only widen coverage. Anything left blank is skipped.
# ---------------------------------------------------------------------------

$Keys = @{
    # --- FREE keys (sign up, free tier) ---
    VirusTotal     = ''   # FREE  virustotal.com            4 req/min, 500/day - passive DNS + reputation
    Censys         = ''   # FREE  platform.censys.io        Platform PAT (single token, used as Bearer)
    Netlas         = ''   # FREE  netlas.io                 free daily quota
    SecurityTrails = ''   # FREE  securitytrails.com        50 queries / month
    UrlScan        = ''   # FREE  urlscan.io                search works keyless; key raises limits
    GitHub         = ''   # FREE  github.com/settings/tokens   read-only PAT (public_repo / read:packages)
    LeakIX         = ''   # FREE  leakix.net/settings/api
    OTX            = ''   # FREE  otx.alienvault.com   threat-intel pulses + passive DNS (free signup)
    AbuseIPDB      = ''   # FREE  abuseipdb.com        IP reputation, 1000 checks/day (free signup)

    # --- origin-pivot engines, queried DIRECTLY in P4 (free-tier reality from live testing) ---
    CriminalIP     = ''   # FREE  criminalip.io    API key   - WORKS free (primary origin engine)
    Quake          = ''   # FREE  quake.360.net    token
    # Omitted (not usefully free, so not wired): ZoomEye/HunterHow (paid/credit-gated), Fofa (paid query credits), Hunter (limited), IntelX (mostly paid).

    # --- PAID membership, optional (keyless Shodan-InternetDB is the free fallback) ---
    Shodan         = ''   # host lookup needs PAID membership; free InternetDB is used keyless instead
}

# Breach / infostealer checks are KEYLESS: LeakCheck public. No key needed.

# Optional paths to tools that are not a single .exe on PATH.
$Tools = @{
    SpiderFootDir  = ''   # e.g. C:\Users\you\tools\spiderfoot  (folder containing sf.py)
    Python         = 'python'   # python launcher on PATH
}
