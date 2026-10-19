# scanIT

**Production-grade IP reputation scanner & OSINT intelligence gatherer for cybersecurity investigations.**

`scanIT` is a single-file Bash script that automates IP reputation scanning across 3 cloud OSINT platforms. Designed for batch scanning of ~1,000 IPs/day on free-tier API keys.

---

## Why use scanIT?

- **Single file, zero install** - copy `scanIT.sh` to any Linux box with `curl` + `jq` and run.
- **3 OSINT platforms, one pipeline** - AbuseIPDB, VirusTotal, ipapi.is (all called for every IP).
- **Quota-aware** - persistent daily counters in `~/.local/state/scanIT/quota_state.json` auto-reset at midnight. Parallel-safe file-based counters protect your free-tier API keys from bans.
- **Rate-limit safe** - per-query sleep, bounded concurrency (default 2 workers), HTTP 429 retry/backoff, and automatic platform-exhaustion marking.
- **Clean output** - aligned ASCII table with 8 columns: `IP | Reputation | Country | Domain/ISP | Blacklists | Proxy/VPN | Threat Tags | Sources`.
- **Battle-tested input handling** - strict IPv4 validation, dedup, comment stripping, blank-line tolerance, atomic parallel writes, clean temp-file cleanup on signal.

---

## Quick start

Step 1 - Install dependencies (one-time):

    sudo apt-get install -y curl jq util-linux gawk        # Debian/Ubuntu/Kali
    sudo dnf install -y curl jq util-linux gawk            # RHEL/CentOS
    sudo pacman -S curl jq util-linux gawk                # Arch

Step 2 - Get free API keys (5 minutes total):
- AbuseIPDB  : https://www.abuseipdb.com/account   (1,000/day free)
- VirusTotal : https://www.virustotal.com/gui/my-apikey (500/day free)
- ipapi.is   : https://ipapi.is/                   (1,000/day free, commercial OK)

Step 3 - Edit scanIT.sh and paste your keys at the top (lines 32-34):

    ABUSEIPDB_API_KEY="your-key"
    VIRUSTOTAL_API_KEY="your-key"
    IPAPI_IS_KEY="your-key"

Step 4 - Make executable:

    chmod +x scanIT.sh

Step 5 - Run it:

    ./scanIT.sh Ip.txt -sW ScannedIp.txt

You will see output like:

    [*] Found 7 unique valid IPv4 address(es).
    [*] Capacity check: 7 IPs vs 2000/day total capacity - OK
    [*] Starting scan...
    [####################] 100% (7/7)

    [+] Scan complete.
    [*] Summary:
        MALICIOUS  : 1
        SUSPICIOUS: 0
        CLEAN     : 6
        UNKNOWN    : 0

And ScannedIp.txt will contain an aligned ASCII table:

    IP             | Reputation | Country | Domain/ISP     | Blacklists | Proxy/VPN       | Threat Tags                  | Sources
    ---------------+------------+---------+----------------+------------+-----------------+------------------------------+----------------------
    1.1.1.1        | 0%         | AU      | cloudflare.com | 0/92       | No              | CLEAN reports=143            | AbuseIPDB,VT,ipapi.is
    185.220.101.1  | 100%       | DE      | artikel10.org  | 14/92      | Yes(Tor)        | MALICIOUS abuser reports=433 | AbuseIPDB,VT,ipapi.is
    8.8.8.8        | 0%         | US      | google.com     | 0/92       | Yes(Datacenter) | CLEAN reports=239            | AbuseIPDB,VT,ipapi.is

---

## OSINT platforms

| # | Platform | Free quota | What you get | Sign-up |
|---|----------|-----------|--------------|---------|
| 1 | AbuseIPDB | 1,000/day | Abuse confidence %, reports, ISP, domain | https://www.abuseipdb.com/account |
| 2 | VirusTotal | 500/day | Multi-engine blacklist count (90+ engines) | https://www.virustotal.com/gui/my-apikey |
| 3 | ipapi.is | 1,000/day | Proxy/VPN/Tor/Datacenter + country/company | https://ipapi.is/ |

All 3 platforms are called for every IP (no fallback chain). Each gives different data:
- AbuseIPDB fills the Reputation, Country, Domain/ISP columns
- VirusTotal fills the Blacklists column
- ipapi.is fills the Proxy/VPN column and can fill Country/Domain/ISP if AbuseIPDB didn't

### Daily capacity

With all 3 keys set, you can scan up to 1,000 IPs/day with this coverage:

| IP range | Platforms active | What you get |
|---------|-------------------|--------------|
| IPs 1-500 | All 3 platforms | Full data: reputation + blacklists + proxy/VPN |
| IPs 501-1000 | AbuseIPDB + ipapi.is (VirusTotal exhausted) | Reputation + proxy/VPN (no blacklist count) |
| After 1000 | None (all exhausted) | Only verdict=UNKNOWN until midnight reset |

---

## Usage

    ./scanIT.sh <input_file> -sW <output_file>
    ./scanIT.sh --help
    ./scanIT.sh --version

### Arguments

| Arg | Description |
|-----|-------------|
| input_file | Text file with one IPv4 per line. Blank lines and lines starting with # are ignored. Invalid IPs are skipped and counted. |
| -sW | "Scan Whole" flag - runs the full pipeline across all enabled platforms. |
| output_file | Destination for the aligned ASCII table report (overwritten if it exists). |

### Environment variables

| Var | Default | Description |
|-----|---------|-------------|
| DEBUG=1 | off | Verbose debug logging to stderr. |
| NO_COLOR=1 | off | Disable ANSI color output. |

### Configuration knobs (top of scanIT.sh)

| Var | Default | Description |
|-----|---------|-------------|
| SLEEP_BETWEEN_QUERIES | 0.5 | Seconds between consecutive dispatches. |
| MAX_PARALLEL | 2 | Max concurrent background workers. Set 1 for sequential. |
| CURL_TIMEOUT | 15 | Per-request HTTP timeout in seconds. |
| HTTP_RETRY_COUNT | 2 | Retries on HTTP 429/5xx (exponential backoff). |
| LIMIT_ABUSEIPDB | 1000 | Daily quota for AbuseIPDB (bump if you upgrade). |
| LIMIT_VIRUSTOTAL | 500 | Daily quota for VirusTotal. |
| LIMIT_IPAPI_IS | 1000 | Daily quota for ipapi.is. |

---

## Input format

Ip.txt - one IPv4 per line. Comments and blanks are fine:

    # my investigation list - 2025-10-19
    8.8.8.8
    1.1.1.1

    # Tor exit nodes
    185.220.101.1
    23.94.190.107

    # Invalid lines are skipped automatically
    999.999.999.999
    not_an_ip

The script:
- Strips comments and blank lines
- Deduplicates (so you don't waste API quota)
- Validates strict IPv4 (rejects 999.x, 1.2.3, hostnames, IPv6)
- Counts and reports invalid entries (use DEBUG=1 to see them)

---

## Output format

ScannedIp.txt - pipe-delimited aligned ASCII table with 8 columns:

| Column | Source | Example |
|--------|--------|---------|
| IP | input | 185.220.101.1 |
| Reputation | AbuseIPDB abuse % / fallback score | 100% or VT:5eng or Proxy:Tor |
| Country | AbuseIPDB / ipapi.is | DE |
| Domain/ISP | AbuseIPDB domain / ISP / ipapi.is company | artikel10.org |
| Blacklists | VirusTotal engine count | 14/92 (14 of 92 engines flagged) |
| Proxy/VPN | ipapi.is | Yes(Tor), Yes(VPN), Yes(Datacenter), No |
| Threat Tags | verdict + reports + abuser flag | MALICIOUS abuser reports=433 |
| Sources | which platforms returned data | AbuseIPDB,VT,ipapi.is |

### Verdict thresholds

| Verdict | Trigger |
|---------|---------|
| MALICIOUS | AbuseIPDB score >= 75%, OR VirusTotal >= 5 engines |
| SUSPICIOUS | AbuseIPDB score 25-74%, OR VirusTotal >= 1 engine, OR ipapi.is abuser flag |
| CLEAN | AbuseIPDB score < 25%, no other flags |
| UNKNOWN | No platform returned reputation data (all exhausted) |

---

## Quota state file

Per-platform daily counters persist across script runs at:

    ~/.local/state/scanIT/quota_state.json

Auto-resets at midnight. Inspect any time:

    jq . ~/.local/state/scanIT/quota_state.json

Output:

    {
      "AbuseIPDB":  {"count": 243,  "exhausted": false, "date": "2025-10-19"},
      "VirusTotal": {"count": 500,  "exhausted": true,  "date": "2025-10-19"},
      "IPAPI_IS":   {"count": 56,   "exhausted": false, "date": "2025-10-19"}
    }

Reset manually (e.g. for testing):

    rm -rf ~/.local/state/scanIT

---

## Performance

Timing depends on your API keys, parallelism, and per-query sleep. Measured at default settings (SLEEP=0.5s, MAX_PARALLEL=2):

| Setup | ~IPs/sec | 1K estimate |
|-------|----------|-------------|
| All 3 real keys (within quota) | ~2-3 | ~10-15 min |
| After VirusTotal exhausted (IPs 501-1000) | ~3-4 | ~5-8 min |
| Sequential mode (MAX_PARALLEL=1) | ~2 | ~8-10 min |

---

## Security

- Strict IPv4 validation - regex + octet range check (0-255) prevents command injection via IP file.
- API keys never logged - keys are passed via curl headers; never written to log files, output, or stderr.
- Secure temp files - mktemp with chmod 700 on temp directory, chmod 600 on state files.
- Atomic writes - quota state file uses mktemp + mv pattern for race-free updates.
- Parallel-safe quota tracking - file-based counters and exhausted-flag files work across background workers (in-memory variables don't propagate between subshells).
- No shell injection vectors - all user-controlled variables are quoted; no eval, no backticks.
- Trap-based cleanup - temp files removed on EXIT, INT (Ctrl+C), TERM.
- set -uo pipefail - unset variables cause hard failure; pipes don't mask failures.

---

## Dependencies

| Tool | Package | Purpose |
|------|---------|---------|
| bash 4.3+ | bash | Required for wait -n parallel mode. |
| curl | curl | HTTP client. |
| jq | jq | JSON parser. |
| flock | util-linux | Atomic file locking for parallel workers. |
| awk | gawk or mawk | Input cleanup + aligned table formatter. |

Auto-checked at startup; the script tells you the install command if anything's missing.

---

## Examples

Single-shot scan:

    ./scanIT.sh suspicious_ips.txt -sW report.txt

Filter only malicious IPs after scan:

    grep MALICIOUS report.txt > malicious_only.txt

Quick test without burning API quota:

    DEBUG=1 ./scanIT.sh Ip.txt -sW ScannedIp.txt

Sequential mode (safest, slowest) - edit scanIT.sh and set MAX_PARALLEL=1.

Check remaining quota mid-day:

    jq . ~/.local/state/scanIT/quota_state.json

Reset quota counter manually:

    rm -rf ~/.local/state/scanIT

---

## Roadmap

- Web GUI (localhost): upload file, configure keys, watch live progress, filter results. Codename: findIT / authIT.
- CSV / JSON output modes (for piping into Excel / Splunk / ELK).
- Slack / Discord / Email alert when first MALICIOUS IP is found.
- IPv6 support.
- Additional OSINT platforms (IPQualityScore, Greynoise, AlienVault OTX) - currently 3 platforms for simplicity.

---

## Contributing

PRs welcome. Please:

1. Test your change with both fake and real keys.
2. Run bash -n scanIT.sh to verify syntax.
3. Don't introduce shellcheck warnings (run shellcheck scanIT.sh).
4. Don't log API keys or full URLs (which would contain keys in query strings).
5. Keep the single-file philosophy - don't split into modules.

---

## License

MIT - see LICENSE.

---

## Disclaimer

This tool is for **authorized security investigations only**. Only scan IPs you have permission to investigate, or that are listed in public threat intel feeds. Respect the terms of service of each OSINT platform - the script enforces their free-tier rate limits, but it's your responsibility to use the data lawfully.
