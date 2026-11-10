#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════
# Vulnerability Detection (LFI, XSS, SQLi, Open Redirect, SSRF)
# ═══════════════════════════════════════════════════════════

VULN_RESULTS=()

# كشف LFI
check_lfi() {
    local base_url="$1"
    local param="$2"
    local payload="../../../../etc/passwd"
    local url="${base_url}?${param}=${payload}"
    
    local resp=$(curl -sk --max-time 10 -A "Mozilla/5.0" "$url" 2>/dev/null)
    if printf '%s' "$resp" | grep -qE 'root:.*:0:0:'; then
        VULN_RESULTS+=("LFI|$url|/etc/passwd read")
        printf "  ${BR}│ 🔴 LFI: %s${N}\n" "$url" >&2
        return 0
    fi
    return 1
}

# كشف XSS
check_xss() {
    local base_url="$1"
    local param="$2"
    local payload="<script>alert(1)</script>"
    local url="${base_url}?${param}=${payload}"
    
    local resp=$(curl -sk --max-time 10 -A "Mozilla/5.0" "$url" 2>/dev/null)
    if printf '%s' "$resp" | grep -qF "$payload"; then
        VULN_RESULTS+=("XSS|$url|payload reflected")
        printf "  ${BR}│ 🔴 XSS: %s${N}\n" "$url" >&2
        return 0
    fi
    return 1
}

# كشف SQLi
check_sqli() {
    local base_url="$1"
    local param="$2"
    local payload="1'"
    local url="${base_url}?${param}=${payload}"
    
    local resp=$(curl -sk --max-time 10 -A "Mozilla/5.0" "$url" 2>/dev/null)
    if printf '%s' "$resp" | grep -qiE "SQL syntax|mysql_fetch|ORA-[0-9]{5}|PostgreSQL.*ERROR|SQLite.*error|unclosed quotation"; then
        VULN_RESULTS+=("SQLi|$url|SQL error leaked")
        printf "  ${BR}│ 🔴 SQLi: %s${N}\n" "$url" >&2
        return 0
    fi
    return 1
}

# كشف Open Redirect
check_open_redirect() {
    local base_url="$1"
    local param="$2"
    local payload="https://evil.com"
    local url="${base_url}?${param}=${payload}"
    
    local location=$(curl -skI --max-time 10 -A "Mozilla/5.0" "$url" 2>/dev/null | grep -i '^location:' | head -1)
    if printf '%s' "$location" | grep -qF "evil.com"; then
        VULN_RESULTS+=("OpenRedirect|$url|redirects to evil.com")
        printf "  ${BR}│ 🔴 Open Redirect: %s${N}\n" "$url" >&2
        return 0
    fi
    return 1
}

# كشف SSRF (AWS metadata)
check_ssrf() {
    local base_url="$1"
    local param="$2"
    local payload="http://169.254.169.254/latest/meta-data/"
    local url="${base_url}?${param}=${payload}"
    
    local resp=$(curl -sk --max-time 10 -A "Mozilla/5.0" "$url" 2>/dev/null)
    if printf '%s' "$resp" | grep -qE "ami-id|instance-id|security-credentials|iam/"; then
        VULN_RESULTS+=("SSRF|$url|AWS metadata reachable")
        printf "  ${BR}│ 🔴 SSRF: %s${N}\n" "$url" >&2
        return 0
    fi
    return 1
}

# فحص كل الثغرات على URL
scan_vulns() {
    local target="$1"
    if [[ ! "$target" =~ ^https?:// ]]; then
        if [[ "$target" =~ ^localhost|^127\.|^192\.168\.|^10\. ]]; then
            target="http://$target"
        else
            target="https://$target"
        fi
    fi
    local param="${2:-q}"
    
    printf "\n  ${B}${C}═══ Vulnerability Scan ═══${N}\n"
    printf "  ${D}Testing %s (param: %s)${N}\n\n" "$target" "$param"
    
    check_lfi "$target" "$param"
    check_xss "$target" "$param"
    check_sqli "$target" "$param"
    check_open_redirect "$target" "$param"
    check_ssrf "$target" "$param"
    
    if [ ${#VULN_RESULTS[@]} -eq 0 ]; then
        printf "  ${G}✓ No vulnerabilities detected${N}\n"
    fi
}
