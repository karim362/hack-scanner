#!/usr/bin/env bash
set -o pipefail
HACK_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TOOLS="$HACK_DIR/tools"
WL="$HACK_DIR/wordlists/ultra500.txt"
[ -f "$WL" ] || WL="$HACK_DIR/wordlists/ultra500.txt"
DIRSEARCH="$TOOLS/dirsearch/dirsearch.py"
R='\033[0;31m'; G='\033[0;32m'; Y='\033[0;33m'; C='\033[0;36m'; M='\033[0;35m'
W='\033[1;37m'; D='\033[0;90m'; N='\033[0m'
BR='\033[1;31m'; BG='\033[1;32m'; BY='\033[1;33m'; BC='\033[1;36m'; BM='\033[1;35m'
DIM_R='\033[2;31m'; DIM_C='\033[2;36m'
HR="────────────────────────────────"
line()  { printf "${D}%s${N}\n" "$HR"; }
title() { printf "\n${M}${W}▸ %s${N}\n" "$1"; line; }
die()   { printf "${R}  ✖ %s${N}\n" "$1"; exit 1; }
banner() {
    clear
    printf "${BM}"; echo ""
    echo "  ░▒▓█▓▒░ ░▒▓█▓▒░ ░▒▓█▓▒░"
    printf "${BC}${W}"; echo ""
    echo "   ╔══════════════════════════════════════════╗"
    echo "   ║   H A C K   S C A N N E R  v28.0         ║"
    echo "   ║   ┌─ SMART AUTO SCAN ─┐                  ║"
    echo "   ║   │  ⚡ dirsearch engine ⚡ │              ║"
    echo "   ║   └──────────────────────┘               ║"
    echo "   ╚══════════════════════════════════════════╝"
    printf "${BM}"; echo "  ░▒▓█▓▒░ ░▒▓█▒░ ░▒▓█▓▒░"; printf "${N}\n\n"
}
sanitize_url() {
    local u="$1"
    u="$(printf '%s' "$u" | tr -d '\r\n\t ')"
    u="$(printf '%s' "$u" | sed 's/^\x1b\[[0-9;]*[a-zA-Z]//g')"
    [[ ! "$u" =~ ^https?:// ]] && u="https://$u"
    u="${u%%\?*}"; u="${u%%#*}"; u="${u#http://}"; u="${u#https://}"; u="${u%%/*}"
    printf '%s' "$u"
}
classify_severity() {
    local p="$1"; local code="${2:-200}"; local size="${3:-0}"
    if [[ "$code" = "308" || "$code" = "301" ]] && [ "$size" -lt 200 ] 2>/dev/null; then echo LOW; return; fi
    if [ "$size" -lt 100 ] 2>/dev/null; then echo LOW; return; fi
    echo "$p" | grep -qiE '\.(env|git|ssh|aws|docker|kube|pem|key|ppk)|config|settings|wp-config|backup|database|dump|\.sql|\.bak|\.swp|credentials|secret|password|adminer|phpmyadmin|pma|setup-config' && echo CRITICAL && return
    echo "$p" | grep -qiE 'admin|login|panel|dashboard|install|setup|api|graphql|swagger|console|manager|portal|user|account|webmail|cpanel|whm' && echo WARNING && return
    echo "$p" | grep -qiE 'robots|sitemap|favicon|\.txt|\.xml|\.ico|\.png|\.jpg|\.svg|well-known|security|ads' && echo INFO && return
    echo LOW
}
color_for() { case "$1" in CRITICAL) printf "${BR}";; WARNING) printf "${BY}";; INFO) printf "${BG}";; *) printf "${BC}";; esac; }
dim_color_for() { case "$1" in CRITICAL) printf "${DIM_R}";; *) printf "${DIM_C}";; esac; }
parse_size() {
    local s="$1"; s="${s%B}"
    if [[ "$s" == *K ]]; then echo "$s" | sed 's/K//' | awk '{printf "%.0f", $1*1024}'
    elif [[ "$s" == *M ]]; then echo "$s" | sed 's/M//' | awk '{printf "%.0f", $1*1048576}'
    elif [[ "$s" == *G ]]; then echo "$s" | sed 's/G//' | awk '{printf "%.0f", $1*1073741824}'
    else echo "$s" | awk '{printf "%.0f", $1}'; fi
}
validate_file() {
    local path="$1"
    local url="https://$HOST$path"
    local tmp=$(mktemp) hdr=$(mktemp)
    curl -sk -o "$tmp" -D "$hdr" --max-time 5 "$url" 2>/dev/null
    local ctype=$(grep -i '^content-type:' "$hdr" 2>/dev/null | head -1 | awk '{print $2}' | tr -d '\r')
    local base=$(basename "$path")
    local real="no"
    case "$base" in
        .env|.env.*|*.env) grep -qE '^[A-Z][A-Z0-9_]+=' "$tmp" 2>/dev/null && real="yes" ;;
        .git/config) grep -qE '^\[(core|remote|user|branch)' "$tmp" 2>/dev/null && real="yes" ;;
        *.sql|*.sql.*|*.dump|*.db) grep -qiE 'CREATE TABLE|INSERT INTO|-- MySQL|-- PostgreSQL' "$tmp" 2>/dev/null && real="yes" ;;
        *.pem|*.key|*.crt) grep -qE 'BEGIN (RSA |EC |OPENSSH |)PRIVATE KEY|BEGIN CERTIFICATE' "$tmp" 2>/dev/null && real="yes" ;;
        *.zip|*.tar|*.tar.*|*.gz|*.bz2|*.rar|*.7z) echo "$ctype" | grep -qiE 'text/html|application/json' && real="no" || real="yes" ;;
        *.php|*.php.*) grep -q '<?php' "$tmp" 2>/dev/null && real="yes" ;;
        *.yml|*.yaml) grep -qE '^[a-zA-Z_-]+:' "$tmp" 2>/dev/null && ! grep -qiE '<!DOCTYPE|<html' "$tmp" 2>/dev/null && real="yes" ;;
        *) echo "$ctype" | grep -qiE 'text/html' && real="no" || real="yes" ;;
    esac
    grep -qiE '<title>[^<]*(404|not found|forbidden)' "$tmp" 2>/dev/null && real="no"
    rm -f "$tmp" "$hdr"
    echo "$real"
}
detect_redirect_leak() {
    local url="$1"
    local b=$(mktemp) h=$(mktemp)
    curl -sk -o "$b" -D "$h" --max-time 15 "$url" 2>/dev/null
    local st=$(head -n1 "$h" 2>/dev/null | awk '{print $2}')
    local sz=$(wc -c < "$b" 2>/dev/null | tr -d ' ')
    local ct=$(grep -i '^content-type:' "$h" 2>/dev/null | head -1 | awk '{print $2}' | tr -d '\r')
    local leak="no"
    if [[ "$st" =~ ^(301|302|303|307|308)$ ]] && [ "${sz:-0}" -gt 5000 ]; then
        local is_spa="no"
        if echo "$ct" | grep -qi 'text/html'; then
            grep -qiE '<div id="(root|app|__next|__nuxt)"|window\.__NUXT__|window\.__NEXT_DATA__|<app-root' "$b" 2>/dev/null && is_spa="yes"
        fi
        if [ "$is_spa" = "no" ]; then
            grep -qiE 'password|secret|api_key|token|<form|admin|dashboard|smtp|mysql|username' "$b" 2>/dev/null && leak="yes"
        fi
    fi
    echo "$st|$sz|$leak"
    rm -f "$b" "$h"
}
render_bar() {
    local pct="$1" elapsed="$2"
    [ "$pct" -lt 0 ] && pct=0
    [ "$pct" -gt 100 ] && pct=100
    local filled=$((pct / 5))
    local empty=$((20 - filled))
    local bar=""
    for ((i=0; i<filled; i++)); do bar+="█"; done
    for ((i=0; i<empty; i++)); do bar+="░"; done
    printf "\r  ${C}[%s]${N} ${W}%3d%%${N} ${D}%ds${N}   " "$bar" "$pct" "$elapsed"
}
# ============ START ============
banner
printf "  ${BC}┌─ INPUT${N}\n"
printf "  ${BC}│${N} ${W}➜ Target:${N} "
read -r RAW
[ -z "$RAW" ] && die "No input."
HOST="$(sanitize_url "$RAW")"
[ -z "$HOST" ] && die "Could not parse host."
TARGET="https://$HOST"
printf "  ${BC}└─${N} ${D}Host:${N} ${W}$HOST${N}\n\n"

# Auto-install if missing
if [ ! -f "$DIRSEARCH" ]; then
    printf "  ${Y}⚠ Installing dirsearch...${N}\n"
    bash "$HACK_DIR/lib/bootstrap.sh"
    [ ! -f "$DIRSEARCH" ] && die "Installation failed"
fi
[ ! -f "$WL" ] && die "Wordlist missing"

# === QUICK CALIBRATION (5 paths, parallel) ===
title "🎯 Calibration"
CAL_DIR=$(mktemp -d); trap "rm -rf $CAL_DIR" EXIT
(
    for i in 1 2 3 4 5; do
        (
            r=$(curl -sk -w "%{http_code}|%{size_download}" --max-time 4 "https://$HOST/wp-admin/nx-$RANDOM-$i.php" 2>/dev/null)
            echo "$r" > "$CAL_DIR/$i.txt"
        ) &
    done
    wait
) 2>/dev/null
declare -a CAL_SIZES=()
for f in "$CAL_DIR"/*.txt; do
    line=$(cat "$f" 2>/dev/null)
    [ -z "$line" ] && continue
    code="${line%%|*}"; rest="${line#*|}"
    size="${rest%%|*}"
    if [ "$code" = "200" ] && [ "$size" -gt 100 ] 2>/dev/null; then
        CAL_SIZES+=("$size")
    fi
done
if [ ${#CAL_SIZES[@]} -ge 2 ]; then
    MEAN=$(printf '%s\n' "${CAL_SIZES[@]}" | awk '{s+=$1;n++} END{printf "%.0f", s/n}')
    STD=$(printf '%s\n' "${CAL_SIZES[@]}" | awk -v m="$MEAN" '{ss+=($1-m)^2;n++} END{printf "%.0f", sqrt(ss/n)}')
    RANGE_LOW=$((MEAN - 3*STD - 300))
    RANGE_HIGH=$((MEAN + 3*STD + 300))
    [ "$RANGE_LOW" -lt 0 ] && RANGE_LOW=0
    printf "  ${Y}⚠ Soft-404: ${W}${MEAN}B ± ${STD}B${N} ${D}(range ${RANGE_LOW}-${RANGE_HIGH})${N}\n"
else
    MEAN=0; STD=0; RANGE_LOW=0; RANGE_HIGH=0
    printf "  ${G}✔ No soft-404 detected${N}\n"
fi
line

# === AUTO-SCAN with dirsearch (60 threads, 3s timeout) ===
THREADS=60
TOTAL=$(wc -l < "$WL" | tr -d ' ')
printf "  ${C}ℹ Scanning ${W}${TOTAL}${N} ${C}paths @ ${W}${THREADS}${N} ${C}threads${N}\n\n"
title "⚡ Scanning"
TMP=$(mktemp); trap "rm -f $TMP; rm -rf $CAL_DIR" EXIT
cd "$TOOLS/dirsearch" 2>/dev/null || die "Cannot cd to dirsearch"
if [ -x ".venv/bin/python3" ]; then
    PYTHON=".venv/bin/python3"
else
    PYTHON="python3"
fi
$PYTHON "$DIRSEARCH" -u "$TARGET" -w "$WL" -t "$THREADS" --timeout 7 --random-agent -i 200,301,302,307,308 -x 403,404,400,405,408 > "$TMP" 2>&1 &
PID=$!
START=$(date +%s)
LAST_PCT=-1
while kill -0 $PID 2>/dev/null; do
    p=$(grep -oE '[0-9]+%' "$TMP" 2>/dev/null | tail -1 | tr -d '%')
    [ -z "$p" ] && p=0
    ELAPSED=$(( $(date +%s) - START ))
    if [ "$p" -ne "$LAST_PCT" ]; then
        render_bar "$p" "$ELAPSED"
        LAST_PCT=$p
    else
        printf "\r  ${C}[████████████░░░░░░░░]${N} ${W}%3d%%${N} ${D}%ds${N}   " "$p" "$ELAPSED"
    fi
    sleep 0.4
done
wait $PID 2>/dev/null
ELAPSED=$(( $(date +%s) - START ))
printf "\r  ${G}[████████████████████]${N} ${W}100%%${N} ${D}%ds${N} ✓        \n" "$ELAPSED"

# === SMART ANALYSIS ===
title "🔬 Analyzing"
RAW=$(mktemp); trap "rm -f $TMP $RAW; rm -rf $CAL_DIR" EXIT
# Parse dirsearch: [HH:MM:SS] CODE - SIZE - /path
while IFS= read -r l; do
    [ -z "$l" ] && continue
    c=$(printf '%s' "$l" | grep -oE '\] [0-9]+ ' | head -1 | tr -d '] ')
    p=$(printf '%s' "$l" | sed 's/.* - //' | head -1)
    rs=$(printf '%s' "$l" | grep -oE '[0-9]+(\.[0-9]+)?[KMGT]?B' | head -1)
    [ -z "$rs" ] && continue
    [ -z "$p" ] && continue
    s=$(parse_size "$rs")
    echo "$c|$s|$p"
done < "$TMP" > "$RAW"
TOTAL_RAW=$(wc -l < "$RAW" | tr -d ' ')
printf "  ${D}Raw responses: ${W}${TOTAL_RAW}${N}\n"
# Cluster detection
declare -A SIZE_BUCKETS
while IFS='|' read -r c s p; do
    [ -z "$s" ] && continue
    b=$((s / 500))
    SIZE_BUCKETS[$b]=$(( ${SIZE_BUCKETS[$b]:-0} + 1 ))
done < "$RAW"
MAX_BUCKET=0; MAX_COUNT=0
for b in "${!SIZE_BUCKETS[@]}"; do
    if [ "${SIZE_BUCKETS[$b]}" -gt "$MAX_COUNT" ]; then
        MAX_COUNT=${SIZE_BUCKETS[$b]}; MAX_BUCKET=$b
    fi
done
# === FAKE BUCKETS: any size bucket with 5+ responses ===
declare -A FAKE_BUCKETS
for b in "${!SIZE_BUCKETS[@]}"; do
    cnt="${SIZE_BUCKETS[$b]}"
    if [ "$cnt" -ge 5 ]; then
        FAKE_BUCKETS[$b]=1
        lo=$((b * 500)); hi=$((b * 500 + 499))
        printf "  ${Y}⚠ Soft-404 cluster: ${W}${lo}-${hi}B${N} (${cnt} responses)\n"
    fi
done
# Also mark calibration range buckets
if [ "$RANGE_LOW" -gt 0 ]; then
    for b in $(seq $((RANGE_LOW / 500)) $((RANGE_HIGH / 500))); do
        FAKE_BUCKETS[$b]=1
    done
    printf "  ${Y}⚠ Calibration range: ${W}${RANGE_LOW}-${RANGE_HIGH}B${N}\n"
fi
# Filter
FINAL=$(mktemp); FAKE=0; REAL=0
while IFS='|' read -r c s p; do
    [ -z "$p" ] && continue
    # Skip tiny 200s
    if [ "$c" = "200" ] && [ "$s" -lt 100 ] 2>/dev/null; then FAKE=$((FAKE+1)); continue; fi
    # Skip fake bucket
    b=$((s / 500))
    if [ -n "${FAKE_BUCKETS[$b]:-}" ]; then
        FAKE=$((FAKE+1)); continue
    fi
    sev=$(classify_severity "$p" "$c" "$s")
    echo "$sev|$c|$s|$p" >> "$FINAL"
    REAL=$((REAL+1))
done < "$RAW"
[ "$FAKE" -gt 0 ] && printf "  ${Y}✔ Filtered ${FAKE} soft-404s (${REAL} remain)${N}\n"
# Content validation for top CRITICAL (max 10)
CRIT_LIST=$(grep '^CRITICAL|' "$FINAL" 2>/dev/null | head -10)
if [ -n "$CRIT_LIST" ]; then
    printf "  ${C}ℹ Validating critical files...${N}\n"
    VALIDATED=$(mktemp)
    printf '%s\n' "$CRIT_LIST" > "$VALIDATED.in"
    while IFS='|' read -r sev c s p; do
        [ -z "$p" ] && continue
        r=$(validate_file "$p")
        [ "$r" = "yes" ] && echo "$sev|$c|$s|$p" >> "$VALIDATED"
    done < "$VALIDATED.in"
    NON_CRIT=$(grep -v '^CRITICAL|' "$FINAL" 2>/dev/null)
    { cat "$VALIDATED"; [ -n "$NON_CRIT" ] && echo "$NON_CRIT"; } > "$FINAL.new"
    mv "$FINAL.new" "$FINAL"
    rm -f "$VALIDATED" "$VALIDATED.in"
    printf "  ${G}✔ Validated${N}\n"
fi
# Sort by severity
ORD=$(mktemp)
awk -F'|' '{r=4; if($1=="CRITICAL")r=1; else if($1=="WARNING")r=2; else if($1=="INFO")r=3; print r"|"$0}' "$FINAL" | sort -t'|' -k1,1n | cut -d'|' -f2- > "$ORD"
LEAK=$(mktemp)
while IFS='|' read -r sev c s p; do
    [ -z "$p" ] && continue
    case "$c" in 301|302|307|308)
        if [ "$s" -gt 5000 ] 2>/dev/null; then
            r=$(detect_redirect_leak "https://$HOST$p")
            f="${r##*|}"
            if [ "$f" = "yes" ]; then
                rl_size="${r#*|}"; rl_size="${rl_size%%|*}"
                echo "LEAK|$c|$rl_size|$p" >> "$LEAK"
            fi
        fi
    ;; esac
done < "$ORD"
FOUND=$(wc -l < "$ORD" | tr -d ' ')
LF=$(wc -l < "$LEAK" 2>/dev/null | tr -d ' '); LF=${LF:-0}
title "🎬 Findings"
if [ "$FOUND" -eq 0 ] && [ "$LF" -eq 0 ]; then
    printf "  ${G}✔ No real findings${N}\n"
    printf "  ${D}  ${TOTAL_RAW} raw → ${FAKE} filtered → 0 real${N}\n"
else
    if [ "$LF" -gt 0 ]; then
        printf "\n  ${BR}▸ 🔥 REDIRECT LEAK${N}\n"
        while IFS='|' read -r t c s p; do
            printf "  ${BR}│${N} ${DIM_R}[${c}]${N} ${DIM_R}${s}B${N} ${BR}→${N} ${C}https://$HOST$p${N}\n"
        done < "$LEAK"
    fi
    PREV=""
    while IFS='|' read -r sev c s p; do
        [ -z "$sev" ] && continue
        if [ "$sev" != "$PREV" ]; then
            case "$sev" in
                CRITICAL) printf "\n  ${BR}▸ CRITICAL${N}\n" ;;
                WARNING)  printf "\n  ${BY}▸ WARNING${N}\n" ;;
                INFO)     printf "\n  ${BG}▸ INFO${N}\n" ;;
                *)        printf "\n  ${BC}▸ LOW${N}\n" ;;
            esac
            PREV="$sev"
        fi
        cl=$(color_for "$sev"); dm=$(dim_color_for "$sev")
        printf "  ${cl}│${N} ${dm}[${c}]${N} ${dm}${s}B${N} ${cl}→${N} ${C}https://$HOST$p${N}\n"
    done < "$ORD"
fi
echo ""; line
CR=$(grep -c '^CRITICAL|' "$ORD" 2>/dev/null | head -1); CR=${CR:-0}
WR=$(grep -c '^WARNING|' "$ORD" 2>/dev/null | head -1); WR=${WR:-0}
IN=$(grep -c '^INFO|' "$ORD" 2>/dev/null | head -1); IN=${IN:-0}
LO=$(grep -c '^LOW|' "$ORD" 2>/dev/null | head -1); LO=${LO:-0}
printf "  ${W}Summary:${N} ${BR}$CR${N} critical · ${BY}$WR${N} warning · ${BG}$IN${N} info · ${BC}$LO${N} low"
[ "$LF" -gt 0 ] && printf " · ${BR}${LF} LEAK${N}"
printf "\n"
[ "$FAKE" -gt 0 ] && printf "  ${D}Filtered: ${FAKE} soft-404 responses${N}\n"
echo ""
rm -f "$FINAL" "$ORD" "$LEAK" "$RAW"
