#!/usr/bin/env bash
# ==============================================================================
#  scanIT - IP Reputation Scanner & OSINT Intelligence Gatherer
# ==============================================================================
#  File:     scanIT.sh
#  Version:  6.0.0 (final - 3 platforms, parallel-safe, production)
#  Usage:    ./scanIT.sh Ip.txt -sW ScannedIp.txt
#  Platform: Linux only (uses flock, bash 4.3+ wait -n, awk)
#
#  Output: aligned ASCII table, 8 columns:
#    IP | Reputation | Country | Domain/ISP | Blacklists | Proxy/VPN
#       | Threat Tags | Sources
#
#  OSINT Platforms (all called for every IP):
#    1. AbuseIPDB  - abuse confidence %, reports, ISP, domain (1,000/day free)
#    2. VirusTotal - multi-engine blacklist count (500/day free)
#    3. ipapi.is   - proxy/VPN/tor/datacenter + country/company (1,000/day free)
#
#  Dependencies: bash 4.3+, curl, jq, flock (util-linux), awk
#  License: MIT
# ==============================================================================

set -uo pipefail

readonly SCRIPT_VERSION="6.0.0"

# ============================================================================
#  1.  CONFIGURATION  --- EDIT YOUR API KEYS HERE ---
# ============================================================================
ABUSEIPDB_API_KEY=""           # https://www.abuseipdb.com/account  (1,000/day free)
VIRUSTOTAL_API_KEY=""          # https://www.virustotal.com/gui/my-apikey (500/day free)
IPAPI_IS_KEY=""                # https://ipapi.is/                  (1,000/day free, commercial OK)

# ============================================================================
#  2.  RATE-LIMITING & PERFORMANCE KNOBS
# ============================================================================
SLEEP_BETWEEN_QUERIES=0.5
MAX_PARALLEL=2
CURL_TIMEOUT=15
HTTP_RETRY_COUNT=2
RETRY_BACKOFF_BASE=2
LOCK_TIMEOUT=30

LIMIT_ABUSEIPDB=1000
LIMIT_VIRUSTOTAL=500
LIMIT_IPAPI_IS=1000

# ============================================================================
#  3.  STATE FILE
# ============================================================================
STATE_DIR="${XDG_STATE_HOME:-$HOME/.local/state}/scanIT"
STATE_FILE="${STATE_DIR}/quota_state.json"

# ============================================================================
#  4.  API ENDPOINTS
# ============================================================================
readonly ABUSEIPDB_ENDPOINT="https://api.abuseipdb.com/api/v2/check"
readonly VIRUSTOTAL_ENDPOINT="https://www.virustotal.com/api/v3/ip_addresses"
readonly IPAPI_IS_ENDPOINT="https://api.ipapi.is/"

# ============================================================================
#  5.  OUTPUT FORMATTING
# ============================================================================
LOG_FILE="scan_errors.log"

# ============================================================================
#  6.  COLOR / OUTPUT
# ============================================================================
if [[ -t 1 ]] && [[ -z "${NO_COLOR:-}" ]]; then
    C_RESET="\033[0m";  C_RED="\033[31m";  C_GREEN="\033[32m"
    C_YELLOW="\033[33m"; C_CYAN="\033[36m"; C_BOLD="\033[1m";  C_DIM="\033[2m"
else
    C_RESET=""; C_RED=""; C_GREEN=""; C_YELLOW=""; C_CYAN=""; C_BOLD=""; C_DIM=""
fi

# ============================================================================
#  7.  GLOBAL STATE
# ============================================================================
INPUT_FILE=""
OUTPUT_FILE=""
SCAN_WHOLE=0
TEMP_DIR=""
TOTAL_VALID_IPS=0
PROGRESS_FILE=""
LOCK_FILE=""
RAW_TSV_FILE=""
declare -A QUOTA_STATE

# ============================================================================
#  8.  LOGGING
# ============================================================================
log_info()    { printf "${C_CYAN}[*]${C_RESET} %b\n"  "$*" >&2; }
log_success() { printf "${C_GREEN}[+]${C_RESET} %b\n" "$*" >&2; }
log_warn()    { printf "${C_YELLOW}[!]${C_RESET} %b\n" "$*" >&2; }
log_error()   { printf "${C_RED}[x]${C_RESET} %b\n"   "$*" >&2; }
log_debug()   { [[ "${DEBUG:-0}" == "1" ]] && printf "${C_DIM}[D]${C_RESET} %b\n" "$*" >&2; }

err_log() {
    printf '[%s] %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$*" >> "${LOG_FILE}" 2>/dev/null
}

die() {
    log_error "$*"
    err_log "FATAL: $*"
    cleanup
    exit 1
}

# ============================================================================
#  9.  DEPENDENCY CHECK
# ============================================================================
check_dependencies() {
    local missing=()
    command -v curl   >/dev/null 2>&1 || missing+=("curl")
    command -v jq     >/dev/null 2>&1 || missing+=("jq")
    command -v flock  >/dev/null 2>&1 || missing+=("flock (util-linux)")
    command -v awk    >/dev/null 2>&1 || missing+=("awk (gawk/mawk)")
    if (( ${#missing[@]} > 0 )); then
        die "Missing: ${missing[*]}
     Install: sudo apt-get install -y curl jq util-linux gawk"
    fi
    if (( BASH_VERSINFO[0] < 4 )) || \
       (( BASH_VERSINFO[0] == 4 && BASH_VERSINFO[1] < 3 )); then
        die "Bash 4.3+ required (you have ${BASH_VERSION})."
    fi
}

# ============================================================================
# 10.  IP VALIDATION
# ============================================================================
is_valid_ipv4() {
    local ip="$1" octet
    if [[ "$ip" =~ ^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$ ]]; then
        for octet in "${BASH_REMATCH[@]:1:4}"; do
            (( octet <= 255 )) || return 1
        done
        return 0
    fi
    return 1
}

# ============================================================================
# 11.  HELP / USAGE
# ============================================================================
print_usage() {
    cat <<USAGE
scanIT v${SCRIPT_VERSION} - IP Reputation Scanner & OSINT Intelligence Gatherer

USAGE:
    ./scanIT.sh <input_file> -sW <output_file>
    ./scanIT.sh --version
    ./scanIT.sh --help

ARGUMENTS:
    input_file     Text file with one IPv4 per line. Blank lines and lines
                   starting with '#' are ignored. Invalid IPs are skipped.
    -sW            "Scan Whole" flag - runs the full pipeline.
    output_file    Destination for the aligned ASCII table report.

EXAMPLE:
    ./scanIT.sh Ip.txt -sW ScannedIp.txt

OSINT PLATFORMS:
    AbuseIPDB  - 1,000/day free  - abuse confidence %, reports, ISP, domain
    VirusTotal - 500/day free    - multi-engine blacklist count (90+ engines)
    ipapi.is   - 1,000/day free  - proxy/VPN/tor/datacenter + country/company

DAILY CAPACITY: ~1,000 IPs/day with all 3 keys set.

QUOTA STATE: ~/.local/state/scanIT/quota_state.json (auto-resets at midnight)
USAGE
}

# ============================================================================
# 12.  ARGUMENT PARSER
# ============================================================================
parse_args() {
    if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
        print_usage
        exit 0
    fi
    if [[ "${1:-}" == "--version" || "${1:-}" == "-V" ]]; then
        printf 'scanIT v%s\n' "$SCRIPT_VERSION"
        exit 0
    fi
    if [[ $# -ne 3 ]]; then
        print_usage
        exit 1
    fi
    INPUT_FILE="$1"
    if [[ "$2" != "-sW" ]]; then
        log_error "Unknown flag: '$2' (only -sW is supported)"
        print_usage
        exit 1
    fi
    SCAN_WHOLE=1
    OUTPUT_FILE="$3"
    if [[ ! -f "$INPUT_FILE" ]]; then die "Input file not found: $INPUT_FILE"; fi
    if [[ ! -s "$INPUT_FILE" ]]; then die "Input file is empty: $INPUT_FILE"; fi
    : > "$OUTPUT_FILE" 2>/dev/null || die "Cannot write to output file: $OUTPUT_FILE"
}

# ============================================================================
# 13.  QUOTA STATE (parallel-safe via file-based counters)
# ============================================================================
load_quota_state() {
    mkdir -p "$STATE_DIR" 2>/dev/null
    local today
    today=$(date '+%Y-%m-%d')
    if [[ -f "$STATE_FILE" ]]; then
        local platform entry date count exhausted
        while IFS='|' read -r platform date count exhausted; do
            [[ -z "$platform" ]] && continue
            if [[ "$date" != "$today" ]]; then
                count=0
                exhausted="false"
            fi
            QUOTA_STATE["$platform"]="${count}|${exhausted}|${date}"
        done < <(jq -r 'to_entries[] | "\(.key)|\(.value.date)|\(.value.count)|\(.value.exhausted)"' "$STATE_FILE" 2>/dev/null)
    fi
    local platforms=("AbuseIPDB" "VirusTotal" "IPAPI_IS")
    for p in "${platforms[@]}"; do
        if [[ -z "${QUOTA_STATE[$p]:-}" ]]; then
            QUOTA_STATE["$p"]="0|false|${today}"
        fi
    done
}

save_quota_state() {
    local tmp
    tmp=$(mktemp -p "$STATE_DIR" quota_state.XXXXXX.json 2>/dev/null) || return 1
    printf '{\n' >"$tmp"
    local first=1
    for platform in "${!QUOTA_STATE[@]}"; do
        IFS='|' read -r count exhausted date <<<"${QUOTA_STATE[$platform]}"
        (( first )) || printf ',\n' >>"$tmp"
        printf '  "%s": {"count": %s, "exhausted": %s, "date": "%s"}' \
            "$platform" "$count" "$exhausted" "$date" >>"$tmp"
        first=0
    done
    printf '\n}\n' >>"$tmp"
    mv "$tmp" "$STATE_FILE"
}

platform_available() {
    local platform="$1" limit="$2"
    local exhausted_file="${TEMP_DIR}/.exhausted_${platform}"
    local counter_file="${TEMP_DIR}/.counter_${platform}"
    [[ -f "$exhausted_file" ]] && return 1
    local current=0
    [[ -f "$counter_file" ]] && current=$(<"$counter_file")
    (( current >= limit )) && return 1
    return 0
}

increment_platform() {
    local platform="$1" limit="$2"
    local counter_file="${TEMP_DIR}/.counter_${platform}"
    local exhausted_file="${TEMP_DIR}/.exhausted_${platform}"
    {
        flock -x -w "$LOCK_TIMEOUT" 200
        local current=0
        [[ -f "$counter_file" ]] && current=$(<"$counter_file")
        current=$((current+1))
        printf '%s' "$current" >"$counter_file"
        if (( current >= limit )); then
            : >"$exhausted_file"
            log_warn "$platform daily limit reached ($current/$limit) - routing to next"
            err_log "$platform daily limit reached ($current/$limit) - EXHAUSTED"
        fi
    } 200>"${counter_file}.lock"
    local state="${QUOTA_STATE[$platform]:-0|false|}"
    IFS='|' read -r count exhausted date <<<"$state"
    count=$((count+1))
    (( count >= limit )) && exhausted="true"
    QUOTA_STATE["$platform"]="${count}|${exhausted}|${date}"
}

mark_exhausted() {
    local platform="$1"
    local exhausted_file="${TEMP_DIR}/.exhausted_${platform}"
    : >"$exhausted_file"
    local state="${QUOTA_STATE[$platform]:-0|false|}"
    IFS='|' read -r count _ date <<<"$state"
    QUOTA_STATE["$platform"]="${count}|true|${date}"
    log_warn "$platform marked EXHAUSTED (HTTP 429 / quota exceeded)"
    err_log "$platform marked EXHAUSTED (HTTP 429 / quota exceeded)"
}

print_quota_status() {
    log_info "Daily quota status:"
    printf "    ${C_BOLD}%-15s %10s %10s${C_RESET}\n" "Platform" "Used" "Limit" >&2
    for platform in AbuseIPDB VirusTotal IPAPI_IS; do
        local limit_var="LIMIT_${platform^^}"
        local limit="${!limit_var:-1000}"
        local state="${QUOTA_STATE[$platform]:-0|false|}"
        IFS='|' read -r count exhausted _ <<<"$state"
        local color="$C_GREEN"
        [[ "$exhausted" == "true" ]] && color="$C_RED"
        printf "    ${color}%-15s %10s %10s${C_RESET}\n" "$platform" "$count/$limit" "$limit" >&2
    done
    printf '\n' >&2
}

# ============================================================================
# 14.  HTTP CLIENT (retry + backoff; detects quota exhaustion)
# ============================================================================
http_get_with_retry() {
    local platform="$1" url="$2"; shift 2
    local attempt=0 response http_code body
    while (( attempt <= HTTP_RETRY_COUNT )); do
        response=$(curl -sS -w "\n%{http_code}" --max-time "$CURL_TIMEOUT" \
                       -H "Accept: application/json" "$@" "$url" 2>/dev/null) \
            || response=$'\n000'
        http_code=$(printf '%s' "$response" | tail -n1)
        body=$(printf '%s' "$response" | sed '$d')
        case "$http_code" in
            200) printf '%s' "$body"; return 0 ;;
            429) err_log "$platform HTTP 429 (rate limited)"; return 99 ;;
            401|403) err_log "$platform HTTP $http_code (auth failed)"; return 99 ;;
            500|502|503|504)
                log_warn "$platform HTTP $http_code (attempt $((attempt+1)))"
                err_log "$platform HTTP $http_code"
                sleep $(( RETRY_BACKOFF_BASE ** (attempt+1) ))
                ;;
            000)
                if (( attempt >= HTTP_RETRY_COUNT )); then
                    err_log "$platform connection failed - EXHAUSTED"
                    return 99
                fi
                log_warn "$platform connection failed (attempt $((attempt+1)))"
                sleep $(( RETRY_BACKOFF_BASE ** (attempt+1) ))
                ;;
            *) log_warn "$platform HTTP $http_code"; err_log "$platform HTTP $http_code"; return 1 ;;
        esac
        attempt=$((attempt+1))
    done
    return 1
}

# ============================================================================
# 15.  PER-PLATFORM QUERIES
# ============================================================================
query_abuseipdb() {
    local ip="$1" url="${ABUSEIPDB_ENDPOINT}?ipAddress=${ip}&maxAgeInDays=90"
    [[ -z "$ABUSEIPDB_API_KEY" ]] && return 1
    if ! platform_available "AbuseIPDB" "$LIMIT_ABUSEIPDB"; then return 2; fi
    local body
    body=$(http_get_with_retry "AbuseIPDB" "$url" -H "Key: ${ABUSEIPDB_API_KEY}")
    local rc=$?
    (( rc == 99 )) && { mark_exhausted "AbuseIPDB"; return 2; }
    (( rc != 0 ))  && return 1
    increment_platform "AbuseIPDB" "$LIMIT_ABUSEIPDB"
    printf '%s' "$body" | jq -r '[
        (.data.abuseConfidenceScore // "N/A"),
        (.data.countryCode           // "N/A"),
        (.data.isp                   // "N/A"),
        (.data.domain                // "N/A"),
        (.data.totalReports          // 0),
        (.data.usageType             // "N/A")
    ] | @tsv' 2>/dev/null
}

query_virustotal() {
    local ip="$1" url="${VIRUSTOTAL_ENDPOINT}/${ip}"
    [[ -z "$VIRUSTOTAL_API_KEY" ]] && return 1
    if ! platform_available "VirusTotal" "$LIMIT_VIRUSTOTAL"; then return 2; fi
    local body
    body=$(http_get_with_retry "VirusTotal" "$url" -H "x-apikey: ${VIRUSTOTAL_API_KEY}")
    local rc=$?
    (( rc == 99 )) && { mark_exhausted "VirusTotal"; return 2; }
    (( rc != 0 ))  && return 1
    increment_platform "VirusTotal" "$LIMIT_VIRUSTOTAL"
    printf '%s' "$body" | jq -r '[
        (.data.attributes.last_analysis_stats.malicious   // 0),
        (.data.attributes.last_analysis_stats.suspicious   // 0),
        ([
            (.data.attributes.last_analysis_stats.malicious   // 0),
            (.data.attributes.last_analysis_stats.suspicious   // 0),
            (.data.attributes.last_analysis_stats.harmless     // 0),
            (.data.attributes.last_analysis_stats.undetected   // 0)
        ] | add // 0)
    ] | @tsv' 2>/dev/null
}

query_ipapi_is() {
    local ip="$1" url="${IPAPI_IS_ENDPOINT}?q=${ip}&key=${IPAPI_IS_KEY}"
    [[ -z "$IPAPI_IS_KEY" ]] && return 1
    if ! platform_available "IPAPI_IS" "$LIMIT_IPAPI_IS"; then return 2; fi
    local body
    body=$(http_get_with_retry "IPAPI_IS" "$url")
    local rc=$?
    (( rc == 99 )) && { mark_exhausted "IPAPI_IS"; return 2; }
    (( rc != 0 ))  && return 1
    increment_platform "IPAPI_IS" "$LIMIT_IPAPI_IS"
    printf '%s' "$body" | jq -r '[
        (.is_tor        // false),
        (.is_proxy      // false),
        (.is_vpn        // false),
        (.is_datacenter // false),
        (.is_abuser     // false),
        ((.company.name // "N/A") | tostring),
        ((.location.country_code // "N/A") | tostring),
        ((.company.domain // "N/A") | tostring)
    ] | @tsv' 2>/dev/null
}

# ============================================================================
# 16.  SINGLE-IP PROCESSING - all 3 platforms called for every IP
# ============================================================================
process_ip() {
    local ip="$1"
    local reputation="N/A" country="N/A" domain_isp="N/A"
    local blacklists="-" proxy_vpn="No" threat_tags="" sources=""
    local verdict="UNKNOWN" used_sources=()
    local result rc

    # --- 16a. AbuseIPDB - reputation, country, ISP, domain ---------
    local abuse_score="N/A" total_reports=0
    result=$(query_abuseipdb "$ip"); rc=$?
    if (( rc == 0 )); then
        local isp domain
        IFS=$'\t' read -r abuse_score country isp domain total_reports _ <<<"$result"
        [[ -n "$domain" && "$domain" != "null" && "$domain" != "N/A" ]] && domain_isp="$domain"
        [[ -n "$isp"    && "$isp"    != "null" && "$isp"    != "N/A" && "$domain_isp" == "N/A" ]] && domain_isp="$isp"
        used_sources+=("AbuseIPDB")
        reputation="${abuse_score}%"
    fi

    # --- 16b. VirusTotal - blacklist count (always called) ----------
    local vt_malicious=0 vt_total=0
    result=$(query_virustotal "$ip"); rc=$?
    if (( rc == 0 )); then
        IFS=$'\t' read -r vt_malicious vt_suspicious vt_total <<<"$result"
        used_sources+=("VT")
        blacklists="${vt_malicious}/${vt_total}"
        if [[ "$reputation" == "N/A" && "$vt_malicious" -gt 0 ]]; then
            reputation="VT:${vt_malicious}eng"
        fi
    fi

    # --- 16c. ipapi.is - proxy/VPN/tor/datacenter (always called) ----
    local ipapi_tor=false ipapi_proxy=false ipapi_vpn=false ipapi_dc=false ipapi_abuser=false
    local ipapi_company="" ipapi_country="" ipapi_domain=""
    result=$(query_ipapi_is "$ip"); rc=$?
    if (( rc == 0 )); then
        IFS=$'\t' read -r ipapi_tor ipapi_proxy ipapi_vpn ipapi_dc ipapi_abuser ipapi_company ipapi_country ipapi_domain <<<"$result"
        used_sources+=("ipapi.is")
        [[ "$country"    == "N/A" ]] && [[ -n "$ipapi_country" && "$ipapi_country" != "N/A" ]] && country="$ipapi_country"
        [[ "$domain_isp" == "N/A" ]] && [[ -n "$ipapi_domain"  && "$ipapi_domain"  != "N/A" ]] && domain_isp="$ipapi_domain"
        local proxy_label=""
        [[ "$ipapi_tor" == "true" ]]   && proxy_label="${proxy_label:+$proxy_label+}Tor"
        [[ "$ipapi_vpn" == "true" ]]   && proxy_label="${proxy_label:+$proxy_label+}VPN"
        [[ "$ipapi_proxy" == "true" && -z "$proxy_label" ]] && proxy_label="Proxy"
        [[ "$ipapi_dc" == "true" && -z "$proxy_label" ]] && proxy_label="Datacenter"
        if [[ -n "$proxy_label" ]]; then
            proxy_vpn="Yes(${proxy_label})"
            [[ "$reputation" == "N/A" ]] && reputation="Proxy:${proxy_label}"
        fi
        if [[ "$ipapi_abuser" == "true" && "$verdict" == "CLEAN" ]]; then
            verdict="SUSPICIOUS"
        fi
        [[ "$ipapi_abuser" == "true" ]] && threat_tags="${threat_tags}${threat_tags:+ }abuser"
    fi

    # --- 16d. Compose final verdict --------------------------------
    if [[ "$abuse_score" =~ ^[0-9]+$ ]]; then
        if   (( abuse_score >= 75 )); then verdict="MALICIOUS"
        elif (( abuse_score >= 25 )); then verdict="SUSPICIOUS"
        else                                verdict="CLEAN"
        fi
    elif [[ "$vt_malicious" =~ ^[0-9]+$ ]] && (( vt_malicious >= 5 )); then
        verdict="MALICIOUS"
    elif [[ "$vt_malicious" =~ ^[0-9]+$ ]] && (( vt_malicious >= 1 )); then
        verdict="SUSPICIOUS"
    elif [[ "$proxy_vpn" == Yes* ]]; then
        verdict="SUSPICIOUS"
    elif [[ "$reputation" == "N/A" ]]; then
        verdict="UNKNOWN"
    else
        verdict="CLEAN"
    fi

    threat_tags="${verdict}${threat_tags:+ $threat_tags}"
    [[ "$total_reports" =~ ^[0-9]+$ ]] && (( total_reports > 0 )) && \
        threat_tags="${threat_tags} reports=${total_reports}"

    sources=$(IFS=,; printf '%s' "${used_sources[*]}")
    [[ -z "$sources" ]] && sources="none"

    # --- 16e. Atomic TSV row append (parallel-safe via flock) ------
    {
        flock -x -w "$LOCK_TIMEOUT" 200
        printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
            "$ip" "$reputation" "$country" "$domain_isp" "$blacklists" \
            "$proxy_vpn" "$threat_tags" "$sources" >>"$RAW_TSV_FILE"
    } 200>"$LOCK_FILE"

    increment_progress
}

# ============================================================================
# 17.  PROGRESS TRACKING (parallel-safe via flock)
# ============================================================================
increment_progress() {
    local current=0
    {
        flock -x -w "$LOCK_TIMEOUT" 200
        current=$(<"$PROGRESS_FILE")
        current=$((current+1))
        printf '%s' "$current" >"$PROGRESS_FILE"
    } 200>"$LOCK_FILE"

    local pct=0 filled empty bar=""
    if (( TOTAL_VALID_IPS > 0 )); then
        pct=$(( current * 100 / TOTAL_VALID_IPS ))
    fi
    filled=$(( pct / 5 ))
    empty=$(( 20 - filled ))
    for ((i=0; i<filled; i++)); do bar+="#"; done
    for ((i=0; i<empty;  i++)); do bar+="-"; done
    printf "${C_DIM}\r${C_RESET}${C_BOLD}[%s]${C_RESET} %3d%% (%d/%d) " \
        "$bar" "$pct" "$current" "$TOTAL_VALID_IPS" >&2
}

# ============================================================================
# 18.  INPUT FILE PRE-PROCESSING
# ============================================================================
load_and_validate_ips() {
    local temp_all="${TEMP_DIR}/all_lines.txt"
    local temp_unique="${TEMP_DIR}/unique_ips.txt"
    : >"$temp_unique"
    awk 'NF && $1 !~ /^#/ {print $1}' "$INPUT_FILE" | sort -u >"$temp_all"
    local valid_count=0 invalid_count=0 line
    while IFS= read -r line; do
        if is_valid_ipv4 "$line"; then
            printf '%s\n' "$line" >>"$temp_unique"
            valid_count=$((valid_count+1))
        else
            invalid_count=$((invalid_count+1))
            log_debug "Skipping invalid IP: $line"
        fi
    done <"$temp_all"
    printf '%s' "$valid_count"   >"${TEMP_DIR}/.valid_count"
    printf '%s' "$invalid_count" >"${TEMP_DIR}/.invalid_count"
    if (( invalid_count > 0 )); then
        log_warn "Skipped ${invalid_count} invalid/blank IP entries (use DEBUG=1 to see them)."
    fi
    printf '%s' "$temp_unique"
}

# ============================================================================
# 19.  OUTPUT FORMATTER (TSV -> aligned ASCII table)
# ============================================================================
format_output_table() {
    local tsv_file="$1" out_file="$2"
    awk -F'\t' '
    BEGIN { ncols = 8 }
    {
        for (i = 1; i <= NF && i <= ncols; i++) {
            cell = $i
            gsub(/\t/, " ", cell)
            if (length(cell) > width[i]) width[i] = length(cell)
            if (NR == 1) {
                header[i] = cell
            } else {
                rows[NR-1, i] = cell
            }
        }
        if (NR > 1) n_rows = NR - 1
    }
    END {
        line = ""
        for (i = 1; i <= ncols; i++) {
            pad = width[i] - length(header[i])
            line = line header[i] sprintf("%*s", (pad > 0 ? pad : 0), "")
            if (i < ncols) line = line " | "
        }
        print line
        line = ""
        for (i = 1; i <= ncols; i++) {
            for (j = 0; j < width[i]; j++) line = line "-"
            if (i < ncols) line = line "-+-"
        }
        print line
        for (r = 1; r <= n_rows; r++) {
            line = ""
            for (i = 1; i <= ncols; i++) {
                cell = rows[r, i]
                pad = width[i] - length(cell)
                line = line cell sprintf("%*s", (pad > 0 ? pad : 0), "")
                if (i < ncols) line = line " | "
            }
            print line
        }
    }' "$tsv_file" >"$out_file"
}

# ============================================================================
# 20.  CLEANUP
# ============================================================================
cleanup() {
    [[ -n "${STATE_FILE:-}" ]] && save_quota_state 2>/dev/null
    [[ -n "$TEMP_DIR" && -d "$TEMP_DIR" ]] && rm -rf "$TEMP_DIR"
    [[ -f "$LOCK_FILE" ]] && rm -f "$LOCK_FILE"
    printf '\n' >&2
}

# ============================================================================
# 21.  MAIN
# ============================================================================
main() {
    trap 'cleanup' EXIT INT TERM

    parse_args "$@"
    check_dependencies

    local any_key=0
    for k in ABUSEIPDB_API_KEY VIRUSTOTAL_API_KEY IPAPI_IS_KEY; do
        [[ -n "${!k:-}" ]] && any_key=1
    done
    if (( any_key == 0 )); then
        die "No API keys configured. Edit the top of this script and set at least one of:
       ABUSEIPDB_API_KEY, VIRUSTOTAL_API_KEY, IPAPI_IS_KEY"
    fi

    log_warn "ABUSEIPDB_API_KEY     = $( [[ -n "$ABUSEIPDB_API_KEY" ]]   && echo SET || echo EMPTY)"
    log_warn "VIRUSTOTAL_API_KEY    = $( [[ -n "$VIRUSTOTAL_API_KEY" ]]  && echo SET || echo EMPTY)"
    log_warn "IPAPI_IS_KEY          = $( [[ -n "$IPAPI_IS_KEY" ]]         && echo SET || echo EMPTY)"
    printf '\n' >&2

    load_quota_state
    print_quota_status

    TEMP_DIR=$(mktemp -d -t scanIT.XXXXXX) || die "Failed to create temp directory"
    chmod 700 "$TEMP_DIR" 2>/dev/null
    LOCK_FILE="${TEMP_DIR}/.lock"
    PROGRESS_FILE="${TEMP_DIR}/.progress"
    RAW_TSV_FILE="${TEMP_DIR}/raw_rows.tsv"
    echo "0" >"$PROGRESS_FILE"
    chmod 600 "$PROGRESS_FILE" "$RAW_TSV_FILE" 2>/dev/null
    printf 'IP\tReputation\tCountry\tDomain/ISP\tBlacklists\tProxy/VPN\tThreat Tags\tSources\n' >"$RAW_TSV_FILE"

    log_info "Loading and validating IPs from: ${C_BOLD}${INPUT_FILE}${C_RESET}"
    local valid_ip_file
    valid_ip_file=$(load_and_validate_ips)
    TOTAL_VALID_IPS=$(<"${TEMP_DIR}/.valid_count")

    if (( TOTAL_VALID_IPS == 0 )); then
        die "No valid IPv4 addresses found in $INPUT_FILE"
    fi
    log_info "Found ${C_BOLD}${TOTAL_VALID_IPS}${C_RESET} unique valid IPv4 address(es)."

    local total_capacity=$(( LIMIT_ABUSEIPDB + LIMIT_IPAPI_IS ))
    if (( TOTAL_VALID_IPS > total_capacity )); then
        log_warn "Input size ${TOTAL_VALID_IPS} exceeds total capacity ${total_capacity}/day."
        log_warn "Some IPs may end up with verdict=UNKNOWN and reputation=N/A."
    else
        log_info "Capacity check: ${TOTAL_VALID_IPS} IPs vs ${total_capacity}/day total capacity - OK"
    fi

    local estimated_seconds
    estimated_seconds=$(awk -v n="$TOTAL_VALID_IPS" \
                            -v s="$SLEEP_BETWEEN_QUERIES" \
                            -v p="$MAX_PARALLEL" \
                            'BEGIN{ printf "%.0f", (n*s)/p }')
    log_info "Parallelism       : ${MAX_PARALLEL} worker(s)"
    log_info "Per-query sleep   : ${SLEEP_BETWEEN_QUERIES}s"
    log_info "Estimated runtime : ~${estimated_seconds}s ($(awk -v s="$estimated_seconds" 'BEGIN{printf "%.1f", s/60}') min)"
    log_info "Report file       : ${C_BOLD}${OUTPUT_FILE}${C_RESET}"
    log_info "Error log         : ${LOG_FILE}"
    log_info "Quota state file  : ${STATE_FILE}"
    log_info "Starting scan..."
    printf '\n' >&2

    if (( MAX_PARALLEL <= 1 )); then
        while IFS= read -r ip; do
            process_ip "$ip"
            sleep "$SLEEP_BETWEEN_QUERIES"
        done <"$valid_ip_file"
    else
        local active=0
        while IFS= read -r ip; do
            if (( active >= MAX_PARALLEL )); then
                wait -n 2>/dev/null || wait
                active=$((active-1))
            fi
            ( process_ip "$ip" ) &
            active=$((active+1))
            sleep "$SLEEP_BETWEEN_QUERIES"
        done <"$valid_ip_file"
        wait
    fi

    printf '\n\n' >&2
    log_success "Scan complete."

    format_output_table "$RAW_TSV_FILE" "$OUTPUT_FILE"

    log_info "Preview (first 20 rows):"
    head -n 22 "$OUTPUT_FILE" >&2
    printf '...\n' >&2
    printf '\n' >&2

    local n_malicious=0 n_suspicious=0 n_clean=0 n_unknown=0
    while IFS=$'\t' read -r _ _ _ _ _ _ tags _; do
        case "$tags" in
            MALICIOUS*)  n_malicious=$((n_malicious+1))  ;;
            SUSPICIOUS*) n_suspicious=$((n_suspicious+1)) ;;
            CLEAN*)      n_clean=$((n_clean+1))          ;;
            *)           n_unknown=$((n_unknown+1))      ;;
        esac
    done < <(tail -n +2 "$RAW_TSV_FILE")

    log_info "Summary:"
    printf "    ${C_RED}MALICIOUS${C_RESET}  : %d\n" "$n_malicious"   >&2
    printf "    ${C_YELLOW}SUSPICIOUS${C_RESET}: %d\n" "$n_suspicious" >&2
    printf "    ${C_GREEN}CLEAN${C_RESET}     : %d\n" "$n_clean"      >&2
    printf "    ${C_DIM}UNKNOWN${C_RESET}    : %d\n" "$n_unknown"   >&2
    printf '\n' >&2

    log_info "Report  : ${OUTPUT_FILE}"
    log_info "Errors  : ${LOG_FILE} ($([[ -s "$LOG_FILE" ]] && echo 'has entries' || echo 'empty'))"
    printf '\n' >&2
    print_quota_status
}

# ============================================================================
main "$@"
# ==============================================================================
