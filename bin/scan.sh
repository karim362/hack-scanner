#!/usr/bin/env bash
set -o pipefail
HACK_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TOOLS="$HACK_DIR/tools"
WL="$HACK_DIR/wordlists/critical.txt"
DIRSEARCH="$TOOLS/dirsearch/dirsearch.py"
GODIRB="$TOOLS/godirb"
FFUF="$TOOLS/ffuf"
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
    echo "   ║   H A C K   S C A N N E R  v27.0         ║"
    echo "   ║   ┌─ LIGHTNING EDITION ─┐                ║"
    echo "   ║   │  ⚡ FAST · SMART ⚡  │                 ║"
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
    else echo "$s" | awk '{printf "%.0f", $1}'; fi
}
# Progress bar renderer (in-place)
render_bar() {
    local pct="$1" elapsed="$2" msg="$3"
    [ "$pct" -lt 0 ] && pct=0
    [ "$pct" -gt 100 ] && pct=100
    local filled=$((pct / 5))
    local empty=$((20 - filled))
    local bar=""
    for ((i=0; i<filled; i++)); do bar+="█"; done
    for ((i=0; i<empty; i++)); do bar+="░"; done
    printf "\r  ${C}[%s]${N} ${W}%3d%%${N} ${D}%ds${N} ${msg}  " "$bar" "$pct" "$elapsed"
}
# Run tool with live progress
run_with_progress() {
    local tool="$1" logfile="$2" total="$3"
    local start=$(date +%s)
    local pct=0 last_pct=-1 elapsed=0
    # Start tool in background (cmd passed via $4 and args)
    shift 3
    "$@" > "$logfile" 2>&1 &
    local pid=$!
    while kill -0 "$pid" 2>/dev/null; do
        elapsed=$(( $(date +%s) - start ))
        case "$tool" in
            ffuf)
                local prog=$(grep -oE '\[[0-9]+/[0-9]+\]' "$logfile" 2>/dev/null | tail -1 | tr -d '[]')
                if [ -n "$prog" ]; then
                    local cur="${prog%%/*}"; local tot="${prog##*/}"
                    [ "$tot" -gt 0 ] 2>/dev/null && pct=$((cur * 100 / tot))
                fi
                ;;
            dirsearch)
                local p=$(grep -oE '[0-9]+%' "$logfile" 2>/dev/null | tail -1 | tr -d '%')
                [ -n "$p" ] && pct=$p
                ;;
            godirb)
                local done_count=$(grep -cE '^\S+\s+[0-9]+\s+[0-9]+ B ' "$logfile" 2>/dev/null)
                pct=$((done_count * 100 / total))
                [ "$pct" -gt 98 ] && pct=95
                ;;
        esac
        if [ "$pct" -ne "$last_pct" ]; then
            render_bar "$pct" "$elapsed" ""
            last_pct=$pct
        else
            printf "\r  ${C}[████████████░░░░░░░░]${N} ${W}%3d%%${N} ${D}%ds${N}            " "$pct" "$elapsed"
        fi
        sleep 0.3
    done
    wait "$pid" 2>/dev/null
    elapsed=$(( $(date +%s) - start ))
    printf "\r  ${G}[████████████████████]${N} ${W}100%%${N} ${D}%ds${N} ✓          \n" "$elapsed"
}
# Content validation (only for CRITICAL candidates, max 10 files)
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
        *.php) grep -q '<?php' "$tmp" 2>/dev/null && real="yes" ;;
        *.yml|*.yaml) grep -qE '^[a-zA-Z_-]+:' "$tmp" 2>/dev/null && ! grep -qiE '<!DOCTYPE|<html' "$tmp" 2>/dev/null && real="yes" ;;
        *) echo "$ctype" | grep -qiE 'text/html' && real="no" || real="yes" ;;
    esac
    # Detect soft-404 pages
    grep -qiE '<title>[^<]*(404|not found|forbidden)' "$tmp" 2>/dev/null && real="no"
    rm -f "$tmp" "$hdr"
    echo "$real"
}
banner
printf "  ${BC}┌─ INPUT${N}\n"
printf "  ${BC}│${N} ${W}➜ Target:${N} "
read -r RAW
[ -z "$RAW" ] && die "No input."
HOST="$(sanitize_url "$RAW")"
[ -z "$HOST" ] && die "Could not parse host."
TARGET="https://$HOST"
printf "  ${BC}└─${N} ${D}Host:${N} ${W}$HOST${N}\n\n"
if [ ! -f "$DIRSEARCH" ] || [ ! -x "$FFUF" ]; then
    printf "  ${Y}⚠ Installing tools...${N}\n"
    bash "$HACK_DIR/lib/bootstrap.sh"
fi
# Fast calibration: 5 parallel requests (2 sec max)
title "🎯 Calibration (parallel)"
CAL_DIR=$(mktemp -d); trap "rm -rf $CAL_DIR" EXIT
(
    for i in 1 2 3 4 5; do
        (
            r=$(curl -sk -w "%{http_code}|%{size_download}|%{content_type}" --max-time 4 "https://$HOST/nx-$RANDOM-$i" 2>/dev/null)
            echo "$r" > "$CAL_DIR/$i.txt"
        ) &
    done
    wait
) 2>/dev/null
# Homepage separately (not in mean!)
HOME_META=$(curl -sk -w "%{http_code}|%{size_download}" --max-time 4 "https://$HOST/" 2>/dev/null)
HOME_SIZE="${HOME_META##*|}"
# Collect wildcard sizes
declare -a CAL_SIZES=()
declare -a CAL_HASHES=()
for f in "$CAL_DIR"/*.txt; do
    line=$(cat "$f" 2>/dev/null)
    [ -z "$line" ] && continue
    code="${line%%|*}"; rest="${line#*|}"
    size="${rest%%|*}"
    if [ "$code" = "200" ] && [ "$size" -gt 50 ] 2>/dev/null; then
        CAL_SIZES+=("$size")
    fi
done
# Compute mean/stddev from wildcard only (NOT homepage)
if [ ${#CAL_SIZES[@]} -ge 2 ]; then
    MEAN=$(printf '%s\n' "${CAL_SIZES[@]}" | awk '{s+=$1;n++} END{printf "%.0f", s/n}')
    STD=$(printf '%s\n' "${CAL_SIZES[@]}" | awk -v m="$MEAN" '{ss+=($1-m)^2;n++} END{printf "%.0f", sqrt(ss/n)}')
else
    MEAN=0; STD=0
fi
RANGE_LOW=$((MEAN - 2*STD - 500))
RANGE_HIGH=$((MEAN + 2*STD + 500))
[ "$RANGE_LOW" -lt 0 ] && RANGE_LOW=0
[ "$RANGE_LOW" -gt 0 ] && printf "  ${Y}⚠ Soft-404 baseline: ${W}${MEAN}B ± ${STD}B${N} (range ${RANGE_LOW}-${RANGE_HIGH})\n"
[ "$HOME_SIZE" -gt 0 ] && printf "  ${C}ℹ Homepage: ${W}${HOME_SIZE}B${N}\n"
[ "$RANGE_LOW" -eq 0 ] && printf "  ${G}✔ No soft-404 detected${N}\n"
line
title "🛠 Choose Your Weapon"
[ -f "$DIRSEARCH" ] && printf "  ${BC}[1]${N} ${W}dirsearch${N} ${D}─ detailed, shows progress${N}\n"
[ -x "$FFUF" ] && printf "  ${BC}[2]${N} ${W}ffuf${N}      ${D}⚡ fastest (recommended)${N}\n"
[ -x "$GODIRB" ] && printf "  ${BC}[3]${N} ${W}godirb${N}    ${D}─ fast, but silent${N}\n"
printf "\n  ${W}➜${N} "
read -r TOOL_CHOICE
case "$TOOL_CHOICE" in
    1) if [ -f "$DIRSEARCH" ]; then TOOL=1; TOOL_NAME="dirsearch"; else die "dirsearch missing"; fi ;;
    3) if [ -x "$GODIRB" ]; then TOOL=3; TOOL_NAME="godirb"; else die "godirb missing"; fi ;;
    *) if [ -x "$FFUF" ]; then TOOL=2; TOOL_NAME="ffuf"; else die "ffuf missing"; fi ;;
esac
[ ! -f "$WL" ] && die "wordlist missing"
TOTAL=$(wc -l < "$WL" | tr -d ' ')
echo ""
# Speed: 100 threads for ffuf, 40 for others
case "$TOOL" in
    2) THREADS=100 ;;
    *) THREADS=40 ;;
esac
printf "  ${C}ℹ Scanning ${W}${TOTAL}${N} ${C}paths @ ${W}${THREADS}${N} ${C}threads${N}\n\n"
title "⚡ Scanning [$TOOL_NAME]"
TMP=$(mktemp); trap "rm -f $TMP; rm -rf $CAL_DIR" EXIT
if [ "$TOOL" = "2" ]; then
    run_with_progress ffuf "$TMP" "$TOTAL" \
        "$FFUF" -u "https://$HOST/FUZZ" -w "$WL" -t "$THREADS" -mc 200,301,302,307,308 -fc 403,404,400,405,408 -noninteractive
elif [ "$TOOL" = "1" ]; then
    cd "$TOOLS/dirsearch" 2>/dev/null
    if [ -x ".venv/bin/python3" ]; then
        run_with_progress dirsearch "$TMP" "$TOTAL" \
            .venv/bin/python3 "$DIRSEARCH" -u "$TARGET" -w "$WL" -t "$THREADS" --timeout 4 --random-agent -i 200,301,302,307,308 -x 403,404,400,405,408
    else
        run_with_progress dirsearch "$TMP" "$TOTAL" \
            python3 "$DIRSEARCH" -u "$TARGET" -w "$WL" -t "$THREADS" --timeout 4 --random-agent -i 200,301,302,307,308 -x 403,404,400,405,408
    fi
else
    run_with_progress godirb "$TMP" "$TOTAL" \
        "$GODIRB" -u "$TARGET" -w "$WL" -t "$THREADS" -i 403,404,400,405,408
fi
title "🔬 Analyzing (fast)"
# Parse results from tool output
RAW=$(mktemp); trap "rm -f $TMP $RAW; rm -rf $CAL_DIR" EXIT
if [ "$TOOL" = "2" ]; then
    # ffuf: <path> [Status: NNN, Size: NNN, ...]
    while IFS= read -r l; do
        [ -z "$l" ] && continue
        # Skip progress/banner/header lines
        case "$l" in
            ::*|*":: "*"Progress"*) continue ;;
            *"Progress:"*|*"Method :"*|*"URL :"*|*"Wordlist :"*|*"Threads :"*) continue ;;
            *"Matcher :"*|*"Timeout :"*|*"Duration :"*|*"Follow redirects :"*|*"Calibration :"*) continue ;;
            *"Output file :"*|*"File format :"*) continue ;;
        esac
        # Must have Status: and Size:
        [[ "$l" != *"[Status: "* ]] && continue
        [[ "$l" != *", Size: "* ]] && continue
        # Path = everything before " [Status:"
        prefix="${l%% \[Status:*}"
        p=$(printf '%s' "$prefix" | awk '{print $NF}' | tr -d '\r\n ')
        [ -z "$p" ] && continue
        [ "$p" = "::" ] && continue
        [[ "$p" == ::* ]] && continue
        [[ ! "$p" =~ ^[a-zA-Z0-9._/~-] ]] && continue
        c=$(printf '%s' "$l" | sed -n 's/.*\[Status: \([0-9]*\).*/\1/p' | head -1)
        s=$(printf '%s' "$l" | sed -n 's/.*, Size: \([0-9]*\).*/\1/p' | head -1)
        [ -n "$c" ] && [ -n "$s" ] && echo "$c|$s|/$p"
    done < "$TMP" > "$RAW"
elif [ "$TOOL" = "1" ]; then
    # dirsearch: [HH:MM:SS] 200 - 1234B - /path
    while IFS= read -r l; do
        [ -z "$l" ] && continue
        c=$(printf '%s' "$l" | grep -oE '\] [0-9]+ ' | head -1 | tr -d '] ')
        p=$(printf '%s' "$l" | sed 's/.* - //' | head -1)
        rs=$(printf '%s' "$l" | grep -oE '[0-9]+(\.[0-9]+)?[KMGT]?B' | head -1)
        [ -z "$rs" ] && continue
        s=$(parse_size "$rs")
        [ -n "$p" ] && [ -n "$c" ] && echo "$c|$s|$p"
    done < "$TMP" > "$RAW"
else
    # godirb: CODE SIZE B URL
    while IFS= read -r l; do
        [ -z "$l" ] && continue
        p=$(printf '%s' "$l" | grep -oE 'https?://[^ ]+' | sed "s|https\?://$HOST||")
        c=$(printf '%s' "$l" | awk '{print $2}')
        s=$(printf '%s' "$l" | grep -oE '[0-9]+ B' | head -1 | awk '{print $1}')
        [ -n "$p" ] && [ -n "$c" ] && [ -n "$s" ] && echo "$c|$s|$p"
    done < "$TMP" > "$RAW"
fi
TOTAL_RAW=$(wc -l < "$RAW" | tr -d ' ')
printf "  ${D}Raw responses: ${W}${TOTAL_RAW}${N}\n"
# === CLUSTER-BASED FILTER (independent of calibration) ===
# Group results by 500-byte buckets; any bucket with >5 results = soft-404
declare -A SIZE_BUCKETS
while IFS='|' read -r c s p; do
    [ -z "$s" ] && continue
    b=$((s / 500))
    SIZE_BUCKETS[$b]=$(( ${SIZE_BUCKETS[$b]:-0} + 1 ))
done < "$RAW"
# Find largest bucket
MAX_BUCKET=0
MAX_COUNT=0
for b in "${!SIZE_BUCKETS[@]}"; do
    if [ "${SIZE_BUCKETS[$b]}" -gt "$MAX_COUNT" ]; then
        MAX_COUNT=${SIZE_BUCKETS[$b]}
        MAX_BUCKET=$b
    fi
done
# Fallback: use calibration range if cluster detection weak
if [ "$MAX_COUNT" -lt 5 ] && [ "$RANGE_LOW" -gt 0 ]; then
    MAX_BUCKET=$((RANGE_LOW / 500))
    MAX_COUNT=${SIZE_BUCKETS[$MAX_BUCKET]:-0}
fi
CLUSTER_LOW=$((MAX_BUCKET * 500))
CLUSTER_HIGH=$((MAX_BUCKET * 500 + 499))
if [ "$MAX_COUNT" -ge 5 ]; then
    printf "  ${Y}⚠ Cluster baseline: ${W}${CLUSTER_LOW}-${CLUSTER_HIGH}B${N} (${MAX_COUNT} responses)\n"
fi
# Filter by cluster
FINAL=$(mktemp)
FAKE=0
REAL=0
while IFS='|' read -r c s p; do
    [ -z "$p" ] && continue
    [ "$p" = "::" ] && { FAKE=$((FAKE+1)); continue; }
    # Filter: cluster bucket
    if [ "$MAX_COUNT" -ge 5 ] && [ "$s" -ge "$CLUSTER_LOW" ] 2>/dev/null && [ "$s" -le "$CLUSTER_HIGH" ] 2>/dev/null; then
        FAKE=$((FAKE+1))
        continue
    fi
    # Filter: tiny 200s
    if [ "$s" -lt 100 ] 2>/dev/null && [ "$c" = "200" ]; then
        FAKE=$((FAKE+1))
        continue
    fi
    sev=$(classify_severity "$p" "$c" "$s")
    echo "$sev|$c|$s|$p" >> "$FINAL"
    REAL=$((REAL+1))
done < "$RAW"
printf "  ${Y}✔ Filtered ${FAKE} soft-404s (${REAL} candidates remain)${N}\n"
# === CONTENT VALIDATION (parallel, max 15 CRITICAL) ===
CRIT_LIST=$(grep '^CRITICAL|' "$FINAL" 2>/dev/null | head -15)
if [ -n "$CRIT_LIST" ]; then
    printf "  ${C}ℹ Validating top $(echo "$CRIT_LIST" | wc -l | tr -d ' ') critical files (parallel)...${N}\n"
    VALIDATED=$(mktemp)
    printf '%s\n' "$CRIT_LIST" > "$VALIDATED.in"
    # Run parallel validation
    (
        while IFS='|' read -r sev c s p; do
            [ -z "$p" ] && continue
            r=$(validate_file "$p")
            if [ "$r" = "yes" ]; then
                echo "$sev|$c|$s|$p"
            fi
        done < "$VALIDATED.in" > "$VALIDATED"
    ) &
    VAL_PID=$!
    # Show spinner while validating
    v_spin=('⠋' '⠙' '⠹' '⠸' '⠼' '⠴' '⠦' '⠧' '⠇' '⠏')
    v_i=0
    while kill -0 $VAL_PID 2>/dev/null; do
        printf "\r  ${C}${v_spin[$((v_i % 10))]}${N} validating critical files..."
        sleep 0.2
        v_i=$((v_i+1))
    done
    wait $VAL_PID 2>/dev/null
    printf "\r  ${G}✔ Critical validated${N}                    \n"
    # Replace CRITICAL entries with validated
    NON_CRIT=$(grep -v '^CRITICAL|' "$FINAL" 2>/dev/null)
    {
        cat "$VALIDATED"
        [ -n "$NON_CRIT" ] && echo "$NON_CRIT"
    } > "$FINAL.new"
    mv "$FINAL.new" "$FINAL"
    rm -f "$VALIDATED" "$VALIDATED.in"
fi
# Sort by severity
ORD=$(mktemp)
awk -F'|' '{r=4; if($1=="CRITICAL")r=1; else if($1=="WARNING")r=2; else if($1=="INFO")r=3; print r"|"$0}' "$FINAL" | sort -t'|' -k1,1n | cut -d'|' -f2- > "$ORD"
FOUND=$(wc -l < "$ORD" | tr -d ' ')
title "🎬 Findings"
if [ "$FOUND" -eq 0 ]; then
    printf "  ${Y}⚠ No real findings after filtering${N}\n"
    printf "  ${D}  Filtered ${FAKE} soft-404s | ${REAL} candidates${N}\n"
else
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
printf "  ${W}Summary:${N} ${BR}$CR${N} critical · ${BY}$WR${N} warning · ${BG}$IN${N} info · ${BC}$LO${N} low\n"
[ "$FAKE" -gt 0 ] && printf "  ${D}Filtered: ${FAKE} soft-404 responses${N}\n"
echo ""
rm -f "$FINAL" "$ORD" "$RAW"
