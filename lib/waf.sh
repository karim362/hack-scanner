#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════
# WAF / Rate Limit / Honeypot Detection
# ═══════════════════════════════════════════════════════════

WAF_RESULTS=()

# كشف WAF من headers
detect_waf() {
    local target="$1"
    local url="https://$target"
    [[ "$target" =~ ^https?:// ]] && url="$target"

    local headers
    headers=$(curl -skI --max-time 10 -A "Mozilla/5.0" "$url" 2>/dev/null)

    local waf=""

    # Cloudflare
    if printf '%s' "$headers" | grep -qiE "server: cloudflare|cf-ray:"; then
        waf="Cloudflare"
    # Akamai
    elif printf '%s' "$headers" | grep -qiE "server: akamai|akamai-"; then
        waf="Akamai"
    # Sucuri
    elif printf '%s' "$headers" | grep -qiE "x-sucuri-id|server: sucuri"; then
        waf="Sucuri"
    # AWS WAF
    elif printf '%s' "$headers" | grep -qiE "x-amzn-requestid|x-amz-cf-id"; then
        waf="AWS WAF/CloudFront"
    # Imperva/Incapsula
    elif printf '%s' "$headers" | grep -qiE "x-iinfo|incap_ses"; then
        waf="Imperva/Incapsula"
    # F5 BIG-IP
    elif printf '%s' "$headers" | grep -qiE "server: bigip|bigipserver"; then
        waf="F5 BIG-IP"
    # Barracuda
    elif printf '%s' "$headers" | grep -qiE "barra_counter_session|barracuda"; then
        waf="Barracuda"
    # ModSecurity
    elif printf '%s' "$headers" | grep -qiE "server:.*mod_security|modsecurity"; then
        waf="ModSecurity"
    fi

    if [ -n "$waf" ]; then
        WAF_RESULTS+=("WAF|$waf|$target")
        printf "  ${BR}│ 🛡 WAF: %s (%s)${N}\n" "$waf" "$target" >&2
        return 0
    fi
    return 1
}

# كشف Rate Limit
detect_rate_limit() {
    local target="$1"
    local url="https://$target"
    [[ "$target" =~ ^https?:// ]] && url="$target"

    local code
    code=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 10 -A "Mozilla/5.0" "$url" 2>/dev/null)

    if [ "$code" = "429" ]; then
        local retry=$(curl -skI --max-time 10 -A "Mozilla/5.0" "$url" 2>/dev/null | grep -i "retry-after:" | head -1 | tr -d '\r')
        WAF_RESULTS+=("RateLimit|429|$target|$retry")
        printf "  ${BR}│ 🚦 Rate Limit: 429 %s${N}\n" "$retry" >&2
        return 0
    fi
    return 1
}

# كشف Honeypot (صفحات وهمية بترد 200 فاضي)
detect_honeypot() {
    local target="$1"
    local url="https://$target"
    [[ "$target" =~ ^https?:// ]] && url="$target"

    # مسارات وهمية
    local fake_paths=("/admin.php" "/wp-login.php" "/.env" "/config.php")
    local honeypot_count=0

    for path in "${fake_paths[@]}"; do
        local code size
        code=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 8 -A "Mozilla/5.0" "${url}${path}" 2>/dev/null)
        size=$(curl -sk -o /dev/null -w "%{size_download}" --max-time 8 -A "Mozilla/5.0" "${url}${path}" 2>/dev/null)
        
        # لو 200 وحجم 0 → honeypot محتمل
        if [ "$code" = "200" ] && [ "$size" -eq 0 ] 2>/dev/null; then
            honeypot_count=$((honeypot_count + 1))
        fi
    done

    if [ "$honeypot_count" -ge 2 ]; then
        WAF_RESULTS+=("Honeypot|$honeypot_count/fake paths|$target")
        printf "  ${BR}│ 🍯 Honeypot: %s fake paths (200+0B)${N}\n" "$honeypot_count" >&2
        return 0
    fi
    return 1
}

# فحص شامل
scan_waf() {
    local target="$1"
    [[ "$target" != http* ]] && target="$(sanitize_url "$target")"

    printf "\n  ${B}${C}═══ WAF / Rate Limit Scan ═══${N}\n"
    printf "  ${D}Target: %s${N}\n\n" "$target"

    detect_waf "$target"
    detect_rate_limit "$target"
    detect_honeypot "$target"

    if [ ${#WAF_RESULTS[@]} -eq 0 ]; then
        printf "  ${G}✓ No WAF / Rate Limit / Honeypot detected${N}\n"
    fi
}
