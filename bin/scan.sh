#!/usr/bin/env bash
set -o pipefail
HACK_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TOOLS="$HACK_DIR/tools"
WL="$HACK_DIR/wordlists/top2000.txt"
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
    echo "   ║     H A C K   S C A N N E R  v25.0       ║"
    echo "   ║     ┌─ UNIFIED INTELLIGENCE ─┐           ║"
    echo "   ║     │  ▓▒░ SYSTEM ONLINE ░▒▓  │           ║"
    echo "   ║     └───────────────────────┘           ║"
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
    local p="$1"
    local code="${2:-0}"
    local size="${3:-0}"
    if [[ "$code" == "308" || "$code" == "301" ]] && [ "$size" -lt 200 ] 2>/dev/null; then echo LOW; return; fi
    local c="$2"
    local s="$3"
    # 308/302/301 بحجم صغير (< 200B) = redirect فارغ، ليس ثغرة
    if [[ "$c" =~ ^(301|302|307|308)$ ]] && [ "${s:-0}" -lt 200 ] 2>/dev/null; then
        echo "LOW"
        return
    fi
    # 308 = Next.js trailing-slash redirect، دائماً LOW
    if [ "$c" = "308" ]; then
        echo "LOW"
        return
    fi
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
validate_content() {
    local url="$1" path="$2"
    local tmp=$(mktemp) hdr=$(mktemp)
    curl -sk -o "$tmp" -D "$hdr" --max-time 10 "$url" 2>/dev/null
    local ctype=$(grep -i '^content-type:' "$hdr" 2>/dev/null | head -1 | awk '{print $2}' | tr -d '\r')
    local base=$(basename "$path")
    local verdict="UNKNOWN"

    # Universal soft-404 markers
    if grep -qiE '<title>[^<]*(404|not[[:space:]]+found|error|access[[:space:]]+denied|forbidden)[^<]*</title>' "$tmp" 2>/dev/null; then
        verdict="FAKE"
    elif grep -qiE 'wp-die|<body[^>]*class="[^"]*error404|page[[:space:]]+not[[:space:]]+found|nothing[[:space:]]+found|<h1[^>]*>Oops' "$tmp" 2>/dev/null; then
        verdict="FAKE"
    elif grep -qiE '<h1[^>]*>[^<]*(404|not[[:space:]]+found|page[[:space:]]+not[[:space:]]+found)[^<]*</h1>' "$tmp" 2>/dev/null; then
        verdict="FAKE"
    fi

    # Extension-specific validation (only if not already FAKE)
    if [ "$verdict" = "UNKNOWN" ]; then
        case "$base" in
            .env|.env.*|*.env)
                if grep -qiE '<!DOCTYPE|<html|<head>' "$tmp" 2>/dev/null; then
                    verdict="FAKE"
                elif grep -qE '^[A-Z][A-Z0-9_]+=' "$tmp" 2>/dev/null; then
                    verdict="REAL"
                fi
                ;;
            .git/config|*/git/config)
                if grep -qE '^\[(core|remote|user|branch)' "$tmp" 2>/dev/null; then
                    verdict="REAL"
                else
                    verdict="FAKE"
                fi
                ;;
            *.sql|*.sql.gz|*.dump|*.db)
                if grep -qiE 'CREATE[[:space:]]+TABLE|INSERT[[:space:]]+INTO|DROP[[:space:]]+TABLE|-- MySQL|-- PostgreSQL' "$tmp" 2>/dev/null; then
                    verdict="REAL"
                elif grep -qiE '<!DOCTYPE|<html' "$tmp" 2>/dev/null; then
                    verdict="FAKE"
                fi
                ;;
            *.php)
                if grep -q '<?php' "$tmp" 2>/dev/null; then
                    verdict="REAL"
                else
                    verdict="FAKE"
                fi
                ;;
            *.zip|*.tar|*.tgz|*.rar|*.7z|*.gz|*.bz2)
                if echo "$ctype" | grep -qiE 'text/html|application/json' 2>/dev/null; then
                    verdict="FAKE"
                elif [ -n "$ctype" ]; then
                    verdict="REAL"
                fi
                ;;
            *.pem|*.key|*.crt|*.csr)
                if grep -qE 'BEGIN (RSA |EC |OPENSSH |)PRIVATE KEY|BEGIN CERTIFICATE' "$tmp" 2>/dev/null; then
                    verdict="REAL"
                else
                    verdict="FAKE"
                fi
                ;;
            *.json)
                if grep -qE '^\s*[\[{]' "$tmp" 2>/dev/null && ! grep -qiE '<!DOCTYPE|<html' "$tmp" 2>/dev/null; then
                    verdict="REAL"
                fi
                ;;
            *.log|*.log.bak)
                if grep -qiE '<!DOCTYPE|<html' "$tmp" 2>/dev/null; then
                    verdict="FAKE"
                fi
                ;;
        esac
    fi

    rm -f "$tmp" "$hdr"
    echo "$verdict"
}

detect_redirect_leak() {
    local url="$1"
    local b=$(mktemp) h=$(mktemp)
    curl -sk -o "$b" -D "$h" --max-time 15 "$url" 2>/dev/null
    local st=$(head -n1 "$h" 2>/dev/null | awk '{print $2}')
    local sz=$(wc -c < "$b" 2>/dev/null | tr -d ' ')
    local ct=$(grep -i '^content-type:' "$h" | head -1 | awk '{print $2}' | tr -d '\r')
    local leak="no"
    if [[ "$st" =~ ^(301|302|303|307|308)$ ]] && [ "${sz:-0}" -gt 5000 ]; then
        # Skip SPA app shells (React/Next/Vue/Angular) — huge HTML with app markers
        local is_spa="no"
        if echo "$ct" | grep -qi 'text/html'; then
            if grep -qiE '<div id="(root|app|__next|__nuxt)"|window\.__NUXT__|window\.__NEXT_DATA__|<app-root|<div id=.app.' "$b" 2>/dev/null; then
                is_spa="yes"
            fi
        fi
        if [ "$is_spa" = "no" ]; then
            if grep -qiE 'password|secret|api_key|token|<form|admin|dashboard|smtp|mysql|username|email' "$b" 2>/dev/null; then
                if ! grep -qiE 'remember.?me|sign.?in|log.?in|forgot.?password|csrf' "$b" 2>/dev/null; then
                    leak="yes"
                fi
            fi
        fi
    fi
    echo "$st|$sz|$leak"
    rm -f "$b" "$h"
}
smart_wildcard_detect() {
    local host="$1"
    local paths=("nonexistent-$(date +%s).php" "fake-$(date +%s).env" "test-$(date +%s)" "ghost-$(date +%s)/" "void-$(date +%s).log")
    local -A counts
    for p in "${paths[@]}"; do
        local r=$(curl -sk -o /dev/null -w "%{http_code}|%{size_download}" --max-time 8 "https://$host/$p" 2>/dev/null)
        if [ -n "$r" ]; then
            local s="${r##*|}"
            [ "$s" -gt 100 ] 2>/dev/null && counts[$s]=$(( ${counts[$s]:-0} + 1 ))
        fi
    done
    local out=""
    for s in "${!counts[@]}"; do [ "${counts[$s]}" -ge 2 ] && out+="${s},"; done
    printf '%s' "${out%,}"
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
    printf "  ${Y}⚠ Missing tools. Installing...${N}\n"
    bash "$HACK_DIR/lib/bootstrap.sh"
fi
title "🎯 Reconnaissance"
printf "  ${D}Scanning wildcard...${N}\n"
WC_PRE=$(smart_wildcard_detect "$HOST")
# بصمات ذكية لكشف Soft-404 بدقة
declare -A BASELINE_HASHES
declare -a BASELINE_SIZES=()
for _i in 1 2 3 4 5 6 7; do
    _res=$(curl -sk --max-time 6 "https://$HOST/nx-$RANDOM-$_i-$RANDOM" 2>/dev/null)
    _h=$(printf '%s' "$_res" | sha256sum | cut -d' ' -f1)
    _sz=$(printf '%s' "$_res" | wc -c | tr -d ' ')
    [ -n "$_h" ] && BASELINE_HASHES[$_h]=1
    [ "$_sz" -gt 100 ] 2>/dev/null && BASELINE_SIZES+=("$_sz")
done
_home=$(curl -sk --max-time 6 "https://$HOST/" 2>/dev/null)
_home_h=$(printf '%s' "$_home" | sha256sum | cut -d' ' -f1)
_home_sz=$(printf '%s' "$_home" | wc -c | tr -d ' ')
[ -n "$_home_h" ] && BASELINE_HASHES[$_home_h]=1
[ "$_home_sz" -gt 100 ] 2>/dev/null && BASELINE_SIZES+=("$_home_sz")
echo "  ${D}Baseline: ${#BASELINE_HASHES[@]} hashes | homepage ${_home_sz}B${N}"
if [ -n "$WC_PRE" ]; then
    printf "  ${Y}⚠${N} ${W}Wildcard:${N} ${Y}${WC_PRE}B${N} ${D}(auto-filtered)${N}\n"
else
    printf "  ${G}✔${N} ${W}No wildcard${N}\n"
fi
title "🛠 Choose Your Weapon"
[ -f "$DIRSEARCH" ] && printf "  ${BC}[1]${N} ${W}dirsearch${N} ${D}─ Python · unified${N}\n"
[ -x "$GODIRB" ] && printf "  ${BC}[2]${N} ${W}godirb${N}    ${D}─ Go · unified${N}\n"
[ -x "$FFUF" ] && printf "  ${BC}[3]${N} ${W}ffuf${N}      ${D}─ Go · unified${N}\n"
printf "\n  ${W}➜${N} "
read -r TOOL_CHOICE
case "$TOOL_CHOICE" in
    3) if [ -x "$FFUF" ]; then TOOL=3; TOOL_NAME="ffuf"; else die "ffuf missing"; fi ;;
    2) if [ -x "$GODIRB" ]; then TOOL=2; TOOL_NAME="godirb"; else die "godirb missing"; fi ;;
    *) if [ -f "$DIRSEARCH" ]; then TOOL=1; TOOL_NAME="dirsearch"; else die "dirsearch missing"; fi ;;
esac
[ ! -f "$WL" ] && die "wordlist missing"
echo ""
TMP=$(mktemp); trap "rm -f $TMP" EXIT
printf "  ${BC}┌─ SCANNING [%s]${N}\n" "$TOOL_NAME"
printf "  ${BC}│${N}  "
SPIN=('⠋' '⠙' '⠹' '⠸' '⠼' '⠴' '⠦' '⠧' '⠇' '⠏')
(
    if [ "$TOOL" = "3" ]; then
        "$FFUF" -u "https://$HOST/FUZZ" -w "$WL" -t 60 -mc 200,301,302,307,308 -fc 403,404,400,405,408 -s 2>/dev/null > "$TMP.paths"
        > "$TMP"
        if [ -s "$TMP.paths" ]; then
            while IFS= read -r fp; do
                [ -z "$fp" ] && continue
                fres=$(curl -sk -o /dev/null -w "%{http_code}|%{size_download}" --max-time 8 "https://$HOST/$fp" 2>/dev/null)
                [ -n "$fres" ] && echo "$fres|/$fp" >> "$TMP"
            done < "$TMP.paths"
        fi
        rm -f "$TMP.paths"
    elif [ "$TOOL" = "2" ]; then
        "$GODIRB" -u "$TARGET" -w "$WL" -t 60 -i 403,404,400,405,408 > "$TMP" 2>&1
    else
        cd "$TOOLS/dirsearch" 2>/dev/null
        if [ -x ".venv/bin/python3" ]; then
            .venv/bin/python3 "$DIRSEARCH" -u "$TARGET" -w "$WL" -t 20 --timeout 5 --random-agent -i 200,301,302,307,308 -x 403,404,400,405,408 > "$TMP" 2>&1
        else
            python3 "$DIRSEARCH" -u "$TARGET" -w "$WL" -t 20 --timeout 5 --random-agent -i 200,301,302,307,308 -x 403,404,400,405,408 > "$TMP" 2>&1
        fi
    fi
) &
PID=$!; i=0
while kill -0 $PID 2>/dev/null; do printf "\b${C}${SPIN[$((i % 10))]}${N}"; sleep 0.1; i=$((i+1)); done
wait $PID
printf "\b${G}✔${N}\n  ${BC}└─ done${N}\n"
title "🔬 Analyzing"
if [ "$TOOL" = "3" ]; then
    RAW=$(grep -E '^(200|301|302|307|308)\|' "$TMP")
    C200=$(echo "$RAW" | grep -c '^200|'); C301=$(echo "$RAW" | grep -c '^301|')
    C302=$(echo "$RAW" | grep -c '^302|'); C307=$(echo "$RAW" | grep -c '^307|')
    C308=$(echo "$RAW" | grep -c '^308|'); C403=$(grep -c '^403|' "$TMP")
    SIZES=$(echo "$RAW" | awk -F'|' '{print $2}')
elif [ "$TOOL" = "2" ]; then
    RAW=$(grep -E '^\S+\s+(200|301|302|307|308)\s+' "$TMP")
    C200=$(echo "$RAW" | grep -cE '^\S+\s+200\s+'); C301=$(echo "$RAW" | grep -cE '^\S+\s+301\s+')
    C302=$(echo "$RAW" | grep -cE '^\S+\s+302\s+'); C307=$(echo "$RAW" | grep -cE '^\S+\s+307\s+')
    C308=$(echo "$RAW" | grep -cE '^\S+\s+308\s+'); C403=$(grep -cE '^\S+\s+403\s+' "$TMP")
    SIZES=$(echo "$RAW" | grep -oE '[0-9]+ B' | awk '{print $1}')
else
    RAW=$(grep -E '\] (200|301|302|307|308) ' "$TMP")
    C200=$(echo "$RAW" | grep -c '\] 200 '); C301=$(echo "$RAW" | grep -c '\] 301 ')
    C302=$(echo "$RAW" | grep -c '\] 302 '); C307=$(echo "$RAW" | grep -c '\] 307 ')
    C308=$(echo "$RAW" | grep -c '\] 308 '); C403=$(grep -c '\] 403 ' "$TMP")
    SIZES=$(echo "$RAW" | grep -oE '\b[0-9]+(\.[0-9]+)?[KMGT]?B\b' | sed 's/B$//' | while read -r s; do parse_size "$s"; done)
fi
printf "  ${D}Status frequency:${N}\n    "
printf "${BG}200${N} ${W}%s${N}  " "${C200:-0}"
printf "${BY}301${N} ${W}%s${N}  " "${C301:-0}"
printf "${BY}302${N} ${W}%s${N}  " "${C302:-0}"
printf "${BY}307${N} ${W}%s${N}  " "${C307:-0}"
printf "${BC}308${N} ${W}%s${N}  " "${C308:-0}"
printf "${BR}403${N} ${W}%s${N}\n\n" "${C403:-0}"
declare -A SC
while read -r s; do [ -n "$s" ] && SC[$s]=$(( ${SC[$s]:-0} + 1 )); done <<< "$SIZES"
WILD=""
for s in "${!SC[@]}"; do [ "${SC[$s]}" -ge 10 ] && WILD+="$s "; done
RES=$(mktemp); trap "rm -f $TMP $RES" EXIT
if [ "$TOOL" = "3" ]; then
    while IFS='|' read -r c s p; do
        [ -z "$c" ] || [ -z "$s" ] || [ -z "$p" ] && continue
        echo "$WILD" | grep -qw "$s" || { sev=$(classify_severity "$p" "$c" "$s" "$c" "$s"); echo "$sev|$c|$s|$p" >> "$RES"; }
    done <<< "$RAW"
elif [ "$TOOL" = "2" ]; then
    while IFS= read -r l; do
        [ -z "$l" ] && continue
        p=$(echo "$l" | grep -oE 'https?://[^ ]+' | sed "s|https\?://$HOST||"); c=$(echo "$l" | awk '{print $2}'); s=$(echo "$l" | grep -oE '[0-9]+ B' | awk '{print $1}')
        [ -z "$p" ] || [ -z "$s" ] && continue
        echo "$WILD" | grep -qw "$s" || { sev=$(classify_severity "$p" "$c" "$s" "$c" "$s"); echo "$sev|$c|$s|$p" >> "$RES"; }
    done <<< "$RAW"
else
    while IFS= read -r l; do
        [ -z "$l" ] && continue
        c=$(echo "$l" | grep -oE '\] [0-9]+ ' | tr -d '] ')
        p=$(echo "$l" | sed 's/.* - //' | head -1)
        rs=$(echo "$l" | grep -oE '[0-9]+(\.[0-9]+)?[KMGT]?B' | head -1)
        [ -z "$rs" ] && continue
        s=$(parse_size "$rs")
        echo "$WILD" | grep -qw "$s" || { sev=$(classify_severity "$p" "$c" "$s" "$c" "$s"); echo "$sev|$c|$s|$p" >> "$RES"; }
    done <<< "$RAW"
fi
LEAK=$(mktemp); trap "rm -f $TMP $RES $LEAK" EXIT
while IFS='|' read -r sev c s p; do
    [ -z "$p" ] && continue
    case "$c" in 301|302|307|308)
        r=$(detect_redirect_leak "https://$HOST$p")
        f="${r##*|}"
        if [ "$f" = "yes" ]; then
            rl_size="${r#*|}"; rl_size="${rl_size%%|*}"
            echo "LEAK|$c|$rl_size|$p" >> "$LEAK"
        fi
    ;; esac
done < "$RES"

# === تحقق المحتوى: كشف Soft-404 بدقة ===
VALIDATED=$(mktemp)
V_FAKE=0
while IFS='|' read -r sev c s p; do
    [ -z "$p" ] && continue
    if [ "$c" = "200" ] && [[ "$sev" =~ ^(CRITICAL|WARNING)$ ]]; then
        _tmp=$(mktemp); _hdr=$(mktemp)
        curl -sk -o "$_tmp" -D "$_hdr" --max-time 10 "https://$HOST$p" 2>/dev/null
        _h=$(sha256sum "$_tmp" 2>/dev/null | cut -d' ' -f1)
        _ctype=$(grep -i '^content-type:' "$_hdr" 2>/dev/null | head -1 | awk '{print $2}' | tr -d '\r')
        _base=$(basename "$p")
        _real="yes"
        # (أ) تطابق بصمة SHA256 مع baseline
        [ -n "$_h" ] && [ -n "${BASELINE_HASHES[$_h]}" ] && _real="no"
        # (ب) حجم قريب من الرئيسية + HTML
        if [ "$_real" = "yes" ] && echo "$_ctype" | grep -qi 'text/html'; then
            for _bs in "${BASELINE_SIZES[@]}"; do
                if [ "$s" -ge $((_bs-500)) ] 2>/dev/null && [ "$s" -le $((_bs+500)) ] 2>/dev/null; then
                    _real="no"; break
                fi
            done
        fi
        # (ج) تحقق حسب الامتداد
        if [ "$_real" = "yes" ]; then
            case "$_base" in
                .env|.env.*|*.env) grep -qE '^[A-Z][A-Z0-9_]+=' "$_tmp" 2>/dev/null || _real="no" ;;
                .git/config) grep -qE '^\[(core|remote|user|branch)' "$_tmp" 2>/dev/null || _real="no" ;;
                *.sql|*.sql.*|*.dump|*.db|*.db.sql) grep -qiE 'CREATE TABLE|INSERT INTO|DROP TABLE|-- MySQL|-- PostgreSQL' "$_tmp" 2>/dev/null || _real="no" ;;
                *.pem|*.key|*.crt|*.csr) grep -qE 'BEGIN (RSA |EC |OPENSSH |)PRIVATE KEY|BEGIN CERTIFICATE' "$_tmp" 2>/dev/null || _real="no" ;;
                *.php.bak|*.php.txt|*.php.swp|*.php.save|*.php.old|*.php.orig|*.php~) grep -q '<?php' "$_tmp" 2>/dev/null || _real="no" ;;
                *.zip|*.tar|*.tar.*|*.tgz|*.rar|*.7z|*.gz|*.bz2) echo "$_ctype" | grep -qi 'text/html' && _real="no" ;;
                *.conf|*.cfg|*.ini|*.yml|*.yaml|*.log|*.bak|*.old|*.swp|*.xml|*.json|*.txt) echo "$_ctype" | grep -qi 'text/html' && _real="no" ;;
            esac
        fi
        # (د) علامات Soft-404
        if [ "$_real" = "yes" ]; then
            grep -qiE '<title>[^<]*(404|not[[:space:]]+found|forbidden|access[[:space:]]+denied)[^<]*</title>|<h1[^>]*>[^<]*(404|not[[:space:]]+found)[^<]*</h1>' "$_tmp" 2>/dev/null && _real="no"
        fi
        rm -f "$_tmp" "$_hdr"
        if [ "$_real" = "no" ]; then V_FAKE=$((V_FAKE+1)); continue; fi
    fi
    echo "$sev|$c|$s|$p" >> "$VALIDATED"
done < "$RES"
mv "$VALIDATED" "$RES"
[ "$V_FAKE" -gt 0 ] && echo "  ${Y}✔ Filtered $V_FAKE soft-404s (content mismatch)${N}"

ORD=$(mktemp); trap "rm -f $TMP $RES $LEAK $ORD" EXIT
awk -F'|' '{r=4; if($1=="CRITICAL")r=1; else if($1=="WARNING")r=2; else if($1=="INFO")r=3; print r"|"$0}' "$RES" | sort -t'|' -k1,1n | cut -d'|' -f2- > "$ORD"
FOUND=$(awk -F"|" '$2!="301" && $2!="302" && $2!="307" && $2!="308"' "$ORD" | wc -l); LF=$(wc -l < "$LEAK" 2>/dev/null | head -1); LF=${LF:-0}
title "🎬 Findings"
if [ "$FOUND" -eq 0 ] && [ "$LF" -eq 0 ]; then
    printf "  ${G}✔ No vulnerabilities${N}\n"
else
    if [ "$LF" -gt 0 ]; then
        printf "\n  ${BR}▸ 🔥 REDIRECT LEAK (Output Before Redirect)${N}\n"
        while IFS='|' read -r t c s p; do
            printf "  ${BR}│${N} ${DIM_R}[${c}]${N} ${DIM_R}${s}B${N} ${BR}→${N} ${C}https://$HOST$p${N}\n"
        done < "$LEAK"
    fi
    PREV=""; sleep 0.2
    while IFS='|' read -r sev c s p; do
        [ -z "$sev" ] && continue
        case "$c" in 301|302|307|308) continue ;; esac
        if [ "$sev" != "$PREV" ]; then
            case "$sev" in CRITICAL) printf "\n  ${BR}▸ CRITICAL${N}\n";; WARNING) printf "\n  ${BY}▸ WARNING${N}\n";; INFO) printf "\n  ${BG}▸ INFO${N}\n";; *) printf "\n  ${BC}▸ LOW${N}\n";; esac
            PREV="$sev"
        fi
        cl=$(color_for "$sev"); dm=$(dim_color_for "$sev")
        printf "  ${cl}│${N} ${dm}[${c}]${N} ${dm}${s}B${N} ${cl}→${N} ${C}https://$HOST$p${N}\n"
        sleep 0.05
    done < "$ORD"
fi
echo ""; line
CR=$(grep -c '^CRITICAL|' "$ORD" 2>/dev/null | head -1); CR=${CR:-0}
WR=$(grep -c '^WARNING|' "$ORD" 2>/dev/null | head -1); WR=${WR:-0}
IN=$(grep -c '^INFO|' "$ORD" 2>/dev/null | head -1); IN=${IN:-0}
LO=$(awk -F"|" '$1=="LOW" && $2!="301" && $2!="302" && $2!="307" && $2!="308"' "$ORD" | wc -l); LO=${LO:-0}
printf "  ${W}Summary:${N} ${BR}$CR${N} critical · ${BY}$WR${N} warning · ${BG}$IN${N} info · ${BC}$LO${N} low"
[ "$LF" -gt 0 ] && printf " · ${BR}${LF} LEAK${N}"
printf "\n\n"
