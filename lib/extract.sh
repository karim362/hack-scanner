#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════
# Data Leak Detection (بدون تشفير — مؤقت)
# ═══════════════════════════════════════════════════════════

LEAKS_DIR="$HOME/storage/shared/hack-scanner/leaks"

init_leaks_dir() {
    mkdir -p "$LEAKS_DIR" 2>/dev/null
    chmod 700 "$LEAKS_DIR" 2>/dev/null
}

# كشف تسريب من URL
detect_data_leak() {
    local url="$1"
    local host="$2"
    local max_time="${3:-10}"
    local cookie_file="${4:-}"

    local html
    local tmp_resp=$(mktemp)
    if [ -n "$cookie_file" ] && [ -f "$cookie_file" ]; then
        curl -sk -b "$cookie_file" --max-time "$max_time" -A "Mozilla/5.0" "$url" -o "$tmp_resp" 2>/dev/null
    else
        curl -sk --max-time "$max_time" -A "Mozilla/5.0" "$url" -o "$tmp_resp" 2>/dev/null
    fi
    local resp_size=$(stat -c%s "$tmp_resp" 2>/dev/null || stat -f%z "$tmp_resp" 2>/dev/null)
    [ -z "$resp_size" ] || [ "$resp_size" -eq 0 ] && { rm -f "$tmp_resp"; return 1; }
    
    # لو الحجم كبير (> 10MB)، نعالج أول 5MB بس (سريع)
    if [ "$resp_size" -gt 10485760 ]; then
        printf "  ${D}  (large response: ${resp_size}B, sampling first 5MB)${N}\n" >&2
        html=$(head -c 5242880 "$tmp_resp")
    else
        html=$(cat "$tmp_resp")
    fi
    rm -f "$tmp_resp"
    [ -z "$html" ] && return 1

    # إحصائيات — نستخدم temp file للسرعة (16MB)
    local tmp_html=$(mktemp)
    printf '%s' "$html" > "$tmp_html"
    
    local emails ids rows keys cards privkeys passwords
    emails=$(grep -oE '[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}' "$tmp_html" | sort -u | wc -l | tr -d ' ')
    ids=$(grep -oE 'class="user-id"|data-user-id|id="user-[0-9]+"|user_id[=:][0-9]+' "$tmp_html" | wc -l | tr -d ' ')
    rows=$(grep -oE '<tr[ >]' "$tmp_html" | wc -l | tr -d ' ')
    keys=$(grep -oE 'AIza[0-9A-Za-z_-]{35}|sk_live_[0-9a-zA-Z]{24,}|ghp_[0-9a-zA-Z]{36}|AKIA[0-9A-Z]{16}' "$tmp_html" | wc -l | tr -d ' ')
    cards=$(grep -oE '\b[0-9]{4}[- ]?[0-9]{4}[- ]?[0-9]{4}[- ]?[0-9]{4}\b' "$tmp_html" | wc -l | tr -d ' ')
    privkeys=$(grep -cE 'BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY' "$tmp_html" 2>/dev/null | tr -d ' ')
    passwords=$(grep -oiE '"(password|passwd|pwd|secret)"\s*:\s*"[^"]{6,}"' "$tmp_html" | wc -l | tr -d ' ')
    
    # نستخدم tmp_html في استخراج البيانات
    local data_source="$tmp_html"

    local is_leak=0
    local leak_types=""
    [ "$emails" -gt 20 ] 2>/dev/null && { is_leak=1; leak_types+="${emails}emails "; }
    [ "$ids" -gt 20 ] 2>/dev/null    && { is_leak=1; leak_types+="${ids}IDs "; }
    [ "$keys" -gt 0 ] 2>/dev/null    && { is_leak=1; leak_types+="${keys}APIkeys "; }
    [ "$cards" -gt 5 ] 2>/dev/null   && { is_leak=1; leak_types+="${cards}cards "; }
    [ "$privkeys" -gt 0 ] 2>/dev/null && { is_leak=1; leak_types+="${privkeys}privkeys "; }
    [ "$passwords" -gt 0 ] 2>/dev/null && { is_leak=1; leak_types+="${passwords}passwords "; }
    [ "$rows" -gt 100 ] 2>/dev/null  && { is_leak=1; leak_types+="${rows}rows "; }

    if [ "$is_leak" -eq 1 ]; then
        init_leaks_dir
        local ts=$(date +%Y%m%d-%H%M%S)
        local safe_host=$(echo "$host" | tr '/' '_')
        local safe_path=$(echo "$url" | sed 's|https\?://||' | tr '/?&=' '____' | head -c 50)
        local out_file="$LEAKS_DIR/leak_${safe_host}_${safe_path}_${ts}.txt"

        {
            echo "═══════════════════════════════════════════════════"
            echo "LEAK SOURCE: $url"
            echo "HOST: $host"
            echo "DATE: $(date '+%Y-%m-%d %H:%M:%S')"
            echo "STATS: emails=$emails ids=$ids rows=$rows keys=$keys cards=$cards"
            echo "═══════════════════════════════════════════════════"
            echo ""
            echo "--- EMAILS (unique) ---"
            grep -oE '[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}' | sort -u
            echo ""
            echo "--- USER IDs ---"
            grep -oE 'class="user-id">#[0-9]+|data-user-id="[0-9]+"|id="user-[0-9]+"' | head -5000
            echo ""
            echo "--- POTENTIAL PASSWORDS ---"
            grep -oiE '"(password|passwd|pwd|secret)"\s*:\s*"[^"]{6,}"' | head -100
            echo ""
            echo "--- API KEYS ---"
            grep -oE 'AIza[0-9A-Za-z_-]{35}|sk_live_[0-9a-zA-Z]{24,}|ghp_[0-9a-zA-Z]{36}|AKIA[0-9A-Z]{16}'
        } > "$out_file" 2>/dev/null

        chmod 600 "$out_file" 2>/dev/null
        printf "  ${BR}│ 🔴 LEAK SAVED:${N} ${leak_types} → ${out_file}\n" >&2
        unset html
        echo "LEAK|${leak_types}|${emails}|${ids}|${keys}|${cards}|${privkeys}|${passwords}|${rows}"
        return 0
    fi

    unset html
    echo "OK|||||||"
    return 1
}

# تحليل ملف HTML محلي
analyze_local_file() {
    local file="$1"
    [ ! -f "$file" ] && { echo "✖ File not found: $file"; return 1; }

    local size=$(stat -c%s "$file" 2>/dev/null || stat -f%z "$file" 2>/dev/null)
    echo "📄 Analyzing: $file (${size}B)"

    local emails ids rows keys cards
    emails=$(grep -oE '[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}' "$file" | sort -u | wc -l | tr -d ' ')
    ids=$(grep -oE 'class="user-id"|data-user-id|id="user-[0-9]+"|user_id[=:][0-9]+' "$file" | wc -l | tr -d ' ')
    rows=$(grep -oE '<tr[ >]' "$file" | wc -l | tr -d ' ')
    keys=$(grep -oE 'AIza[0-9A-Za-z_-]{35}|sk_live_[0-9a-zA-Z]{24,}|ghp_[0-9a-zA-Z]{36}|AKIA[0-9A-Z]{16}' "$file" | wc -l | tr -d ' ')
    cards=$(grep -oE '\b[0-9]{4}[- ]?[0-9]{4}[- ]?[0-9]{4}[- ]?[0-9]{4}\b' "$file" | wc -l | tr -d ' ')

    echo "  📊 Stats: emails=$emails ids=$ids rows=$rows keys=$keys cards=$cards"

    if [ "$emails" -gt 20 ] 2>/dev/null || [ "$ids" -gt 20 ] 2>/dev/null; then
        init_leaks_dir
        local ts=$(date +%Y%m%d-%H%M%S)
        local basename=$(basename "$file" .html)
        local out_file="$LEAKS_DIR/leak_local_${basename}_${ts}.txt"

        {
            echo "═══════════════════════════════════════════════════"
            echo "LOCAL FILE: $file"
            echo "SIZE: ${size}B"
            echo "DATE: $(date '+%Y-%m-%d %H:%M:%S')"
            echo "STATS: emails=$emails ids=$ids rows=$rows keys=$keys cards=$cards"
            echo "═══════════════════════════════════════════════════"
            echo ""
            echo "--- EMAILS (unique) ---"
            grep -oE '[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}' "$file" | sort -u
            echo ""
            echo "--- USER IDs ---"
            grep -oE 'class="user-id">#[0-9]+|data-user-id="[0-9]+"|id="user-[0-9]+"' "$file" | head -5000
            echo ""
            echo "--- API KEYS ---"
            grep -oE 'AIza[0-9A-Za-z_-]{35}|sk_live_[0-9a-zA-Z]{24,}|ghp_[0-9a-zA-Z]{36}|AKIA[0-9A-Z]{16}' "$file"
        } > "$out_file" 2>/dev/null

        chmod 600 "$out_file" 2>/dev/null
        echo "  🔴 LEAK SAVED: ${emails}emails ${ids}IDs → $out_file"
        return 0
    else
        echo "  ✅ No leak (below threshold)"
        return 1
    fi
}

# ═══════════════════════════════════════════════════════════
# get_session_cookie: جلب PHPSESSID كزائر
# ═══════════════════════════════════════════════════════════
get_session_cookie() {
    local host="$1"
    local cookie_file=$(mktemp)
    curl -sk -c "$cookie_file" "https://$host/admin/login.php" -o /dev/null --max-time 10 2>/dev/null
    echo "$cookie_file"
}
