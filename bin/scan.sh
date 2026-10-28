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
detect_redirect_leak() {
    local url="$1"
    local b=$(mktemp) h=$(mktemp)
    curl -sk -o "$b" -D "$h" --max-time 15 "$url" 2>/dev/null
    local st=$(head -n1 "$h" 2>/dev/null | awk '{print $2}')
    local sz=$(wc -c < "$b" 2>/dev/null | tr -d ' ')
    local leak="no"
    if [[ "$st" =~ ^(301|302|303|307|308)$ ]] && [ "${sz:-0}" -gt 2000 ]; then
        leak="yes"
    fi
    if [[ "$st" =~ ^(301|302|303|307|308)$ ]] && [ "${sz:-0}" -gt 200 ]; then
        grep -qiE 'password|secret|api_key|token|<form|admin|dashboard|smtp|mysql|username|email' "$b" 2>/dev/null && leak="yes"
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
        "$FFUF" -u "https://$HOST/FUZZ" -w "$WL" -t 60 -mc 200,301,302,307,308 -fs "$WC_PRE" -s -of json -o "$TMP.json" >/dev/null 2>&1
        if [ -f "$TMP.json" ] && [ -s "$TMP.json" ]; then
            python3 -c "
import json, sys
try:
    d = json.load(open('$TMP.json'))
    for r in d.get('results', []):
        u = r.get('url', '')
        st = r.get('status', 0)
        ln = r.get('length', 0)
        p = u.split('$HOST', 1)[-1] if '$HOST' in u else '/'
        if not p.startswith('/'): p = '/' + p
        print(f'{st}|{ln}|{p}')
except Exception as e:
    pass
" > "$TMP"
            rm -f "$TMP.json"
        fi
    elif [ "$TOOL" = "2" ]; then
        "$GODIRB" -u "$TARGET" -w "$WL" -t 60 -i 403,404,400,405,408 > "$TMP" 2>&1
    else
        cd "$TOOLS/dirsearch" 2>/dev/null
        python3 "$DIRSEARCH" -u "$TARGET" -w "$WL" -t 20 --timeout 5 --random-agent -i 200,301,302,307,308 -x 403,404,400,405,408 > "$TMP" 2>&1
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
ORD=$(mktemp); trap "rm -f $TMP $RES $LEAK $ORD" EXIT
awk -F'|' '{r=4; if($1=="CRITICAL")r=1; else if($1=="WARNING")r=2; else if($1=="INFO")r=3; print r"|"$0}' "$RES" | sort -t'|' -k1,1n | cut -d'|' -f2- > "$ORD"
FOUND=$(wc -l < "$ORD" | head -1); LF=$(wc -l < "$LEAK" 2>/dev/null | head -1); LF=${LF:-0}
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
LO=$(grep -c '^LOW|' "$ORD" 2>/dev/null | head -1); LO=${LO:-0}
printf "  ${W}Summary:${N} ${BR}$CR${N} critical · ${BY}$WR${N} warning · ${BG}$IN${N} info · ${BC}$LO${N} low"
[ "$LF" -gt 0 ] && printf " · ${BR}${LF} LEAK${N}"
printf "\n\n"
