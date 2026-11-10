#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════
# Dashboard — interactive scan type selection
# ═══════════════════════════════════════════════════════════

run_dashboard() {
    clear 2>/dev/null || true
    printf "\n${BM}${W}════════════════════════════════════════════${N}\n"
    printf "${BM}${W}   🛡  HACK SCANNER — DASHBOARD${N}\n"
    printf "${BM}${W}════════════════════════════════════════════${N}\n\n"
    printf "  ${W}Select scan types (comma or space separated):${N}\n\n"
    printf "  ${G}[1]${N} Path scan        ${D}(dirsearch 691 + 25 priority + leak)${N}\n"
    printf "  ${G}[2]${N} Port scan        ${D}(60 critical ports, parallel x100)${N}\n"
    printf "  ${G}[3]${N} Vulnerabilities  ${D}(LFI/XSS/SQLi/OpenRedirect/SSRF)${N}\n"
    printf "  ${G}[4]${N} WAF detection    ${D}(Cloudflare/Akamai/Sucuri/AWS...)${N}\n"
    printf "  ${G}[5]${N} All of above     ${D}(1+2+3+4)${N}\n"
    printf "  ${G}[6]${N} Analyze file     ${D}(local HTML for PII/keys)${N}\n"
    printf "  ${R}[0]${N} Exit\n\n"
    printf "  ${W}Choice${N} ${D}(e.g., '1' or '1,3' or 'all')${N}: "
    local choice
    read -r choice
    [ -z "$choice" ] && choice="0"

    case "$choice" in
        0|exit|q|Q) printf "  ${D}Bye.${N}\n"; return 0 ;;
        all|ALL|5) choice="1,2,3,4" ;;
        6)
            printf "  ${W}Enter HTML file path${N}: "
            local f
            read -r f
            [ -z "$f" ] && { printf "  ${R}✖ Empty.${N}\n"; return 1; }
            [ ! -f "$f" ] && { printf "  ${R}✖ File not found: $f${N}\n"; return 1; }
            source "$(dirname "${BASH_SOURCE[0]}")/extract.sh"
            analyze_local_file "$f"
            return $?
            ;;
    esac

    choice="${choice// /,}"
    local -a types=()
    IFS=',' read -ra types <<< "$choice"

    printf "\n  ${W}➜ Enter target URL(s)${N} ${D}(one per line, empty line to start)${N}:\n  "
    local -a targets=()
    while IFS= read -r line; do
        [ -z "$line" ] && break
        targets+=("$line")
    done
    [ ${#targets[@]} -eq 0 ] && { printf "  ${R}✖ No target.${N}\n"; return 1; }

    local ports_lib="$(dirname "${BASH_SOURCE[0]}")/ports.sh"
    local vulns_lib="$(dirname "${BASH_SOURCE[0]}")/vulns.sh"
    local waf_lib="$(dirname "${BASH_SOURCE[0]}")/waf.sh"

    for raw_t in "${targets[@]}"; do
        local h
        h="$(sanitize_url "$raw_t")"
        [ -z "$h" ] && continue

        for t in "${types[@]}"; do
            t="${t//[[:space:]]/}"
            case "$t" in
                1) scan_target "$raw_t" ;;
                2)
                    if [ -f "$ports_lib" ]; then
                        source "$ports_lib"
                        scan_ports "$h"
                        GLOBAL_TARGETS_COUNT=$((GLOBAL_TARGETS_COUNT+1))
                    else
                        printf "  ${Y}⚠ lib/ports.sh غير موجود — تخطي فحص المنافذ.${N}\n"
                    fi
                    ;;
                3)
                    if [ -f "$vulns_lib" ]; then
                        source "$vulns_lib"
                        VULN_RESULTS=()
                        scan_vulns "$h" "q"
                        for r in "${VULN_RESULTS[@]}"; do
                            IFS='|' read -r vtype vurl vdesc <<< "$r"
                            local vpath="${vurl#https://$h}"
                            [ -z "$vpath" ] && vpath="$vurl"
                            GLOBAL_HTML_ROWS+=("${h}|CRITICAL|0|0|${vpath} 🔴 ${vtype}")
                        done
                    else
                        printf "  ${Y}⚠ lib/vulns.sh غير موجود.${N}\n"
                    fi
                    ;;
                4)
                    if [ -f "$waf_lib" ]; then
                        source "$waf_lib"
                        WAF_RESULTS=()
                        scan_waf "$h"
                        for r in "${WAF_RESULTS[@]}"; do
                            IFS='|' read -r wtype wname wtarget <<< "$r"
                            GLOBAL_HTML_ROWS+=("${h}|WARNING|0|0|/ ${wtype}: ${wname}")
                        done
                    else
                        printf "  ${Y}⚠ lib/waf.sh غير موجود.${N}\n"
                    fi
                    ;;
                *) printf "  ${Y}⚠ Choice '%s' غير معروف — تخطي.${N}\n" "$t" ;;
            esac
        done
    done

    generate_html_report
}
