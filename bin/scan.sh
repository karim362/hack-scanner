#!/usr/bin/env bash
set -o pipefail

source "$(dirname "$0")/../lib/ui.sh"
source "$(dirname "$0")/../lib/utils.sh"
source "$(dirname "$0")/../lib/scan.sh"
source "$(dirname "$0")/../lib/vulns.sh"
source "$(dirname "$0")/../lib/waf.sh"

# === PARSE ARGS ===
declare -a TARGETS=()
ANALYZE_FILE=""

while [ $# -gt 0 ]; do
    case "$1" in
        --header|-H)   CUSTOM_HEADER="$2"; shift 2 ;;
        --cookie|-b)   CUSTOM_COOKIE="$2"; shift 2 ;;
        --data|-d)     CUSTOM_DATA="$2"; shift 2 ;;
        --proxy|-x)    CUSTOM_PROXY="$2"; shift 2 ;;
        --method|-X)   CUSTOM_METHOD="$2"; shift 2 ;;
        --analyze|-a)  ANALYZE_FILE="$2"; shift 2 ;;
        --vulns|-v)    VULN_MODE=1; shift ;;
        --waf|-w)      WAF_MODE=1; shift ;;
        --param|-p)    VULN_PARAM="$2"; shift 2 ;;
        --help|-h)
            cat << 'HELP'
Usage: kaha [OPTIONS] [TARGET...]

OPTIONS:
  -H, --header "Name: Value"    Add custom header
  -b, --cookie "name=value"     Add cookie
  -d, --data "key=val&k2=v2"    POST data
  -x, --proxy "socks5://..."    Use proxy
  -X, --method POST             HTTP method
  -a, --analyze FILE            Analyze local HTML file
  -v, --vulns                   Scan for LFI/XSS/SQLi/OpenRedirect/SSRF
  -w, --waf                     Detect WAF / Rate Limit / Honeypot
  -p, --param PARAM             Parameter to test (default: q)
  -h, --help                    Show this help

EXAMPLES:
  kaha --header "Authorization: Bearer X" target.com
  kaha --cookie "PHPSESSID=abc" target.com
  kaha --analyze ~/Downloads/users.html

HELP
            exit 0
            ;;
        -*) echo "Unknown option: $1 (try --help)"; exit 1 ;;
        *)  TARGETS+=("$1"); shift ;;
    esac
done

# === ANALYZE MODE ===
if [ -n "$ANALYZE_FILE" ]; then
    source "$(dirname "$0")/../lib/extract.sh"
    analyze_local_file "$ANALYZE_FILE"
    exit $?
fi

# === MAIN ===
banner

# === VULN MODE ===
if [ -n "${WAF_MODE:-}" ] && [ ${#TARGETS[@]} -gt 0 ]; then
    scan_waf "${TARGETS[0]}"
    exit $?
fi

if [ -n "${VULN_MODE:-}" ] && [ ${#TARGETS[@]} -gt 0 ]; then
    scan_vulns "$(sanitize_url "${TARGETS[0]}")" "${VULN_PARAM:-q}"
    exit $?
fi

printf "\n  ${BR}⚠ LEGAL WARNING:${N}\n"
printf "  ${Y}Use ONLY on systems you own or have written permission to test.${N}\n"
printf "  ${Y}PII found will be saved in ~/storage/shared/hack-scanner/leaks/${N}\n\n"

if [ -n "$CUSTOM_HEADER" ] || [ -n "$CUSTOM_COOKIE" ] || [ -n "$CUSTOM_DATA" ] || [ -n "$CUSTOM_PROXY" ]; then
    printf "  ${C}✓ Custom options:${N}"
    [ -n "$CUSTOM_HEADER" ] && printf " header"
    [ -n "$CUSTOM_COOKIE" ] && printf " cookie"
    [ -n "$CUSTOM_DATA" ] && printf " data"
    [ -n "$CUSTOM_PROXY" ] && printf " proxy"
    printf "\n\n"
fi

if [ ${#TARGETS[@]} -eq 0 ]; then
    printf "  ${W}➜ Enter target URL (or paste multiple URLs, one per line):${N}\n"
    printf "  ${D}Press Enter twice to start scanning.${N}\n\n"
    while IFS= read -r line; do
        [[ -z "$line" ]] && break
        TARGETS+=("$line")
    done
fi

VALID=()
for t in "${TARGETS[@]}"; do
    [ -n "$(sanitize_url "$t")" ] && VALID+=("$t")
done
TARGETS=("${VALID[@]}")
[ ${#TARGETS[@]} -eq 0 ] && die "No valid targets provided."

printf "\n  ${G}✓ Loaded ${#TARGETS[@]} target(s). Starting scan...${N}\n"

for t in "${TARGETS[@]}"; do
    scan_target "$t"
done

generate_html_report

echo ""
printf "  ${BM}${W}════════════════════════════════════════════${N}\n"
printf "  ${G}✓ All scans completed successfully.${N}\n"
printf "  ${BM}${W}════════════════════════════════════════════${N}\n\n"
