#!/usr/bin/env bash
set -o pipefail

source "$(dirname "$0")/../lib/ui.sh"
source "$(dirname "$0")/../lib/utils.sh"
source "$(dirname "$0")/../lib/scan.sh"
source "$(dirname "$0")/../lib/vulns.sh"
source "$(dirname "$0")/../lib/waf.sh"
source "$(dirname "$0")/../lib/dashboard.sh"

# === SHORTCUTS ===
if [ $# -gt 0 ]; then
    case "$1" in
        a) shift; set -- --vulns "$@" ;;
        b) shift; set -- --waf "$@" ;;
        c)
            shift
            if [ -n "${1:-}" ]; then
                set -- --analyze "$@"
            else
                printf "  Enter HTML file path: "
                read -r f
                set -- --analyze "$f"
            fi
            ;;
        d) shift; set -- --help "$@" ;;
        dashboard|menu) shift; DASHBOARD_MODE=1 ;;
        p) shift; set -- --ports "$@" ;;
    esac
fi

# === PARSE ARGS ===
declare -a TARGETS=()
ANALYZE_FILE=""
VULN_MODE=""
VULN_PARAM=""
WAF_MODE=""

while [ $# -gt 0 ]; do
    case "$1" in
        --header|-H)   CUSTOM_HEADER="$2"; shift 2 ;;
        --cookie|--ck) CUSTOM_COOKIE="$2"; shift 2 ;;
        --data|-d)     CUSTOM_DATA="$2"; shift 2 ;;
        --proxy|-x)    CUSTOM_PROXY="$2"; shift 2 ;;
        --method|-X)   CUSTOM_METHOD="$2"; shift 2 ;;
        --analyze|-an) ANALYZE_FILE="$2"; shift 2 ;;
        --vulns|-v)    VULN_MODE=1; shift ;;
        --waf|-w)      WAF_MODE=1; shift ;;
        --ports)       PORT_MODE=1; shift ;;
        --param|-p)    VULN_PARAM="$2"; shift 2 ;;
        --help|-h)
            cat << 'HELP'
Usage: kaha [OPTIONS] [TARGET...]

OPTIONS:
  -H, --header "Name: Value"    Add custom header
  --ck, --cookie "name=value"   Add cookie
  -d, --data "key=val&k2=v2"    POST data
  -x, --proxy "socks5://..."    Use proxy
  -X, --method POST             HTTP method
  -an, --analyze FILE           Analyze local HTML file
  -v, --vulns                   Scan for LFI/XSS/SQLi/OpenRedirect/SSRF
  -w, --waf                     Detect WAF / Rate Limit / Honeypot
  --ports                       Scan 60 critical ports (parallel)
  -p, --param PARAM             Parameter to test (default: q)
  -h, --help                    Show this help

SHORTCUTS:
  kaha             Interactive scan (prompts for target)
  kaha a TARGET    Vulnerability scan (--vulns)
  kaha b TARGET    WAF detection (--waf)
  kaha c [FILE]    Analyze local HTML file (--analyze)
  kaha d           Show this help (--help)
  kaha p TARGET    Port scan (60 critical ports)

EXAMPLES:
  kaha example.com
  kaha a example.com
  kaha b example.com
  kaha c ~/Downloads/users.html
  kaha --header "Authorization: Bearer X" target.com
  kaha --cookie "PHPSESSID=abc" target.com

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

# LEGAL WARNING
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

# === WAF MODE ===
if [ -n "$WAF_MODE" ] && [ ${#TARGETS[@]} -gt 0 ]; then
    scan_waf "${TARGETS[0]}"
    exit $?
fi

# === VULN MODE ===
if [ -n "$VULN_MODE" ] && [ ${#TARGETS[@]} -gt 0 ]; then
    scan_vulns "$(sanitize_url "${TARGETS[0]}")" "${VULN_PARAM:-q}"
    exit $?
fi

# === PORT MODE ===
if [ -n "${PORT_MODE:-}" ] && [ ${#TARGETS[@]} -gt 0 ]; then
    source "$(dirname "$0")/../lib/ports.sh"
    for t in "${TARGETS[@]}"; do
        scan_ports "$(sanitize_url "$t")"
    done
    GLOBAL_TARGETS_COUNT=${#TARGETS[@]}
    generate_html_report
    exit $?
fi

# === INTERACTIVE INPUT ===
if [ -n "${DASHBOARD_MODE:-}" ]; then
    run_dashboard
    exit $?
fi

if [ ${#TARGETS[@]} -eq 0 ]; then
    run_dashboard
    exit $?
fi

# === VALIDATE ===
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
