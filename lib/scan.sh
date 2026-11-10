# ═══════════════════════════════════════════════════════════
# المتغيرات العالمية لجمع النتائج (للتقرير)
# ═══════════════════════════════════════════════════════════
GLOBAL_HTML_ROWS=()
GLOBAL_TARGETS_COUNT=0
[ -f "$(dirname "${BASH_SOURCE[0]}")/extract.sh" ] && source "$(dirname "${BASH_SOURCE[0]}")/extract.sh"

# ═══════════════════════════════════════════════════════════
# generate_html_report: توليد تقرير HTML ونقله لذاكرة Android
# ═══════════════════════════════════════════════════════════
generate_html_report() {
    local ts=$(date +%Y%m%d-%H%M%S)
    local human_ts=$(date '+%Y-%m-%d %H:%M:%S')
    local total=${#GLOBAL_HTML_ROWS[@]}
    local targets=${GLOBAL_TARGETS_COUNT:-0}
    local tmp_html=$(mktemp --suffix=.html 2>/dev/null || mktemp)
    local dest_dir="$HOME/storage/shared/hack-scanner"

    # إنشاء المجلد في الذاكرة الداخلية
    if ! mkdir -p "$dest_dir" 2>/dev/null; then
        printf "  ${R}✖ فشل إنشاء مجلد الذاكرة: $dest_dir${N}\n"
        printf "  ${Y}⚠ شغّل: termux-setup-storage${N}\n"
        rm -f "$tmp_html"
        return 1
    fi

    # إحصائيات
    local cnt_crit=$(printf '%s\n' "${GLOBAL_HTML_ROWS[@]}" | grep -c '|CRITICAL|' || true)
    local cnt_warn=$(printf '%s\n' "${GLOBAL_HTML_ROWS[@]}" | grep -c '|WARNING|' || true)
    local cnt_info=$(printf '%s\n' "${GLOBAL_HTML_ROWS[@]}" | grep -c '|INFO|' || true)
    local cnt_low=$(printf '%s\n' "${GLOBAL_HTML_ROWS[@]}" | grep -c '|LOW|' || true)

    # كتابة رأس HTML
    cat > "$tmp_html" << 'HTMLEOF'
<!DOCTYPE html>
<html dir="ltr" lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Hack Scanner Report</title>
<style>
  * { box-sizing: border-box; }
  body { font-family: 'Courier New', monospace; background: #0d1117; color: #c9d1d9; margin: 0; padding: 20px; }
  h1 { color: #58a6ff; border-bottom: 2px solid #58a6ff; padding-bottom: 10px; }
  .meta { background: #161b22; padding: 15px; border-radius: 6px; margin-bottom: 20px; border-left: 4px solid #58a6ff; }
  .meta p { margin: 5px 0; }
  .stats { display: flex; gap: 15px; flex-wrap: wrap; margin-bottom: 20px; }
  .stat { padding: 15px 25px; border-radius: 6px; font-weight: bold; font-size: 18px; }
  .stat.crit { background: #da3633; color: #fff; }
  .stat.warn { background: #d29922; color: #fff; }
  .stat.info { background: #1f6feb; color: #fff; }
  .stat.low  { background: #30363d; color: #c9d1d9; }
  .stat small { display: block; font-size: 11px; font-weight: normal; opacity: 0.85; }
  table { width: 100%; border-collapse: collapse; background: #161b22; border-radius: 6px; overflow: hidden; }
  th { background: #21262d; color: #58a6ff; padding: 12px; text-align: left; border-bottom: 2px solid #30363d; }
  td { padding: 10px 12px; border-bottom: 1px solid #21262d; word-break: break-all; }
  tr.CRITICAL { background: rgba(218,54,51,0.15); }
  tr.WARNING  { background: rgba(210,153,34,0.15); }
  tr.INFO     { background: rgba(31,111,235,0.12); }
  tr.LOW      { background: rgba(48,54,61,0.4); }
  tr:hover { background: #1f2428; }
  .sev { font-weight: bold; padding: 3px 8px; border-radius: 3px; display: inline-block; font-size: 12px; }
  .sev.CRITICAL { background: #da3633; color: #fff; }
  .sev.WARNING  { background: #d29922; color: #fff; }
  .sev.INFO     { background: #1f6feb; color: #fff; }
  .sev.LOW      { background: #30363d; color: #c9d1d9; }
  .host-header { background: #0d419d; color: #fff; padding: 12px; font-weight: bold; font-size: 15px; margin-top: 20px; border-radius: 6px 6px 0 0; }
  a { color: #58a6ff; text-decoration: none; }
  a:hover { text-decoration: underline; }
  .footer { text-align: center; margin-top: 30px; color: #8b949e; font-size: 12px; }
</style>
</head>
<body>
<h1>🛡️ Hack Scanner Report</h1>
<div style="background: #3d1f00; border-left: 4px solid #d29922; padding: 12px; margin-bottom: 20px; border-radius: 6px; color: #d29922;">
  <strong>⚠️ LEGAL NOTICE:</strong> This report may contain indicators of sensitive data (PII). Encrypted PII is stored in <code>leaks/</code> directory. Handle according to GDPR/CCPA/local laws. Delete after disclosure. Do not publish.
</div>
HTMLEOF

    # إحصائيات + meta
    cat >> "$tmp_html" << HTMLEOF
<div class="meta">
  <p><strong>Date:</strong> ${human_ts}</p>
  <p><strong>Targets scanned:</strong> ${targets}</p>
  <p><strong>Total findings:</strong> ${total}</p>
</div>
<div class="stats">
  <div class="stat crit">${cnt_crit:-0}<small>CRITICAL</small></div>
  <div class="stat warn">${cnt_warn:-0}<small>WARNING</small></div>
  <div class="stat info">${cnt_info:-0}<small>INFO</small></div>
  <div class="stat low">${cnt_low:-0}<small>LOW</small></div>
</div>
HTMLEOF

    # جدول النتائج — مجمّع حسب الهدف
    echo '<table><thead><tr><th style="width:100px">Severity</th><th style="width:70px">Code</th><th style="width:100px">Size</th><th>URL</th><th style="width:200px">Data</th></tr></thead><tbody>' >> "$tmp_html"

    local current_host=""
    for row in "${GLOBAL_HTML_ROWS[@]}"; do
        IFS='|' read -r h sev c sz path <<< "$row"
        if [ "$h" != "$current_host" ]; then
            [ -n "$current_host" ] && echo '</tbody></table>' >> "$tmp_html"
            echo "<div class='host-header'>🎯 https://${h}</div><table><thead><tr><th style='width:100px'>Severity</th><th style='width:70px'>Code</th><th style='width:100px'>Size</th><th>URL</th></tr></thead><tbody>" >> "$tmp_html"
            current_host="$h"
        fi
        printf "<tr class='%s'><td><span class='sev %s'>%s</span></td><td>[%s]</td><td>%sB</td><td><a href='https://%s%s' target='_blank'>https://%s%s</a></td></tr>\n"             "$sev" "$sev" "$sev" "$c" "$sz" "$h" "$path" "$h" "$path" >> "$tmp_html"
    done
    [ -n "$current_host" ] && echo '</tbody></table>' >> "$tmp_html"

    # ذيل
    cat >> "$tmp_html" << 'HTMLEOF'
<div class="footer">
  Generated by <strong>Hack Scanner v25.2</strong> — <a href="https://github.com/karim362/hack-scanner" target="_blank">github.com/karim362/hack-scanner</a>
</div>
</body>
</html>
HTMLEOF

    # نقل (move) إلى الذاكرة الداخلية — بدون نسخة في Termux
    local dest_file="$dest_dir/report-${ts}.html"
    if mv "$tmp_html" "$dest_file"; then
        printf "\n  ${BG}${W}📄 HTML Report saved:${N}\n"
        printf "  ${C}   $dest_file${N}\n"
        printf "  ${D}   (also visible in Android Files app: Internal Storage/hack-scanner/)${N}\n\n"
        return 0
    else
        printf "  ${R}✖ فشل نقل التقرير: $dest_file${N}\n"
        rm -f "$tmp_html"
        return 1
    fi
}

scan_target() {
    local RAW="$1"
    HOST="$(sanitize_url "$RAW")"
    [ -z "$HOST" ] && return
    TARGET="https://$HOST"

    printf "\n${BM}${W}════════════════════════════════════════════${N}\n"
    printf "${BC}${W}🎯 Scanning: $TARGET${N}\n"
    printf "${BM}${W}════════════════════════════════════════════${N}\n\n"

    if [ ! -f "$DIRSEARCH" ]; then
        printf "  ${Y}⚠ Installing dirsearch...${N}\n"
        bash "$HACK_DIR/lib/bootstrap.sh"
        [ ! -f "$DIRSEARCH" ] && die "Installation failed"
    fi

    # === كشف wildcard مسبق (مسار عشوائي) ===
    RANDOM_PATH="/$(head -c 8 /dev/urandom | base64 | tr -d '/+=' | head -c 10)"
    WILDCARD_RESP=$(curl -sk -o /dev/null -w "%{http_code}|%{size_download}" "https://$HOST$RANDOM_PATH" --max-time 6 2>/dev/null)
    WILDCARD_CODE="${WILDCARD_RESP%|*}"
    WILDCARD_SIZE="${WILDCARD_RESP#*|}"
    if [ -n "$WILDCARD_CODE" ] && [ "$WILDCARD_CODE" = "200" ] && [ "$WILDCARD_SIZE" -gt 100 ] 2>/dev/null; then
        printf "  ${Y}⚠ Wildcard detected pre-scan: [%s] %sB (will filter)${N}\n" "$WILDCARD_CODE" "$WILDCARD_SIZE"
    else
        WILDCARD_CODE=""
        WILDCARD_SIZE=""
    fi

    TEMP_WL=$(mktemp)
    cp "$WL" "$TEMP_WL"
    
    # Auto-discovery (Robots & Sitemap)
    curl -sk --max-time 6 "https://$HOST/robots.txt" 2>/dev/null | grep -iE '^(Disallow|Allow):' | awk '{print $2}' | grep -vE '^$|^\*$|^/$' | sed 's|/$||' >> "$TEMP_WL" 2>/dev/null
    curl -sk --max-time 8 "https://$HOST/sitemap.xml" 2>/dev/null | grep -oE '<loc>[^<]+</loc>' | sed 's|<loc>||; s|</loc>||' | sed "s|^https\?://$HOST||" | grep -vE '^$' | head -50 >> "$TEMP_WL" 2>/dev/null

    sort -u "$TEMP_WL" -o "$TEMP_WL"

    THREADS=60
    TMP=$(mktemp)
    
    printf "  ${C}ℹ Scanning $(wc -l < "$TEMP_WL" | tr -d ' ') paths @ ${THREADS} threads...${N}\n"
    
    cd "$TOOLS/dirsearch" 2>/dev/null || exit
    if [ -x ".venv/bin/python3" ]; then PYTHON=".venv/bin/python3"; else PYTHON="python3"; fi
    
    DIRSEARCH_EXTRA=""
[ -n "$CUSTOM_HEADER" ] && DIRSEARCH_EXTRA+=" -H \"$CUSTOM_HEADER\""
[ -n "$CUSTOM_COOKIE" ] && DIRSEARCH_EXTRA+=" -H \"Cookie: $CUSTOM_COOKIE\""
[ -n "$CUSTOM_PROXY" ] && DIRSEARCH_EXTRA+=" --proxy \"$CUSTOM_PROXY\""
eval $PYTHON \"$DIRSEARCH\" -u \"$TARGET\" -w \"$TEMP_WL\" -t \"$THREADS\" --timeout 30 --random-agent -i 200,301,302,307,308 -x 403,404,400,405,408 $DIRSEARCH_EXTRA > \"$TMP\" 2>&1
    
    cd - >/dev/null

    # تحليل النتائج واستخراج البيانات
    RAW_OUT=$(mktemp)
    while IFS= read -r l; do
        [ -z "$l" ] && continue
        c=$(printf '%s' "$l" | grep -oE '\] [0-9]+ ' | head -1 | tr -d '] ')
        p=$(printf '%s' "$l" | sed 's/.* - //' | sed 's/[[:space:]]*->.*$//' | sed 's/[[:space:]]*$//')
        rs=$(printf '%s' "$l" | grep -oE '[0-9]+(\.[0-9]+)?[KMGT]?B' | head -1)
        [ -z "$rs" ] && continue
        [ -z "$p" ] && continue
        s=$(parse_size "$rs")
        echo "$c|$s|$p"
    done < "$TMP" > "$RAW_OUT"

    # === فلترة wildcard: حذف المسارات اللي عندها نفس (code+size) متكرر ===
    if [ -s "$RAW_OUT" ]; then
        FILTERED=$(mktemp)
        # حساب إجمالي عدد redirects لكل status code (لكشف catch-all)
        awk -F'|' '{
            key=$1"|"$2;
            cnt[key]++;
            line[key]=line[key] $0 "\n";
            # عدّاد إجمالي لكل status code مع redirects صغيرة
            if (($1==301||$1==302||$1==307||$1==308) && $2+0 <= 500) {
                code_cnt[$1]++;
            }
        }
        END {
            for (k in cnt) {
                split(k, parts, "|");
                code=parts[1]; size=parts[2];
                # catch-all redirect: 10+ redirects صغيرة بنفس code → حذف
                if ((code==301||code==302||code==307||code==308) && size+0 <= 500 && code_cnt[code] >= 5) {
                    printf "__CATCH_ALL__|%s|%d\n", code, cnt[k];
                    continue;
                }
                # redirect عادي صغير (≤200B) أقل من 10 مرات → اتركه
                if ((code==301||code==302||code==307||code==308) && size+0 <= 200) {
                    printf "%s", line[k];
                    continue;
                }
                # wildcard: نفس code+size تكرر 3+ مرات
                if (cnt[k] >= 3) {
                    printf "__WILDCARD__|%s|%d\n", k, cnt[k];
                    continue;
                }
                printf "%s", line[k];
            }
        }' "$RAW_OUT" > "$FILTERED"
        mv "$FILTERED" "$RAW_OUT"
    fi

    printf "\n  ${B}${C}═══ Results ═══${N}\n"
    if [ ! -s "$RAW_OUT" ]; then
        printf "  ${Y}⚠ No paths found.${N}\n"
    else
        # تجميع النتائج وتصنيفها
        SORTED_OUT=$(mktemp)
        WILDCARD_MSGS=()
        CATCH_ALL_301=0
        CATCH_ALL_302=0
        CATCH_ALL_307=0
        CATCH_ALL_308=0
        CATCH_ALL_OTHER=0
        while IFS='|' read -r c s p; do
            # __CATCH_ALL__|CODE|COUNT  (سطر نظيف بـ 3 حقول)
            if [ "$c" = "__CATCH_ALL__" ]; then
                case "$s" in
                    301) CATCH_ALL_301=$((CATCH_ALL_301 + p)) ;;
                    302) CATCH_ALL_302=$((CATCH_ALL_302 + p)) ;;
                    307) CATCH_ALL_307=$((CATCH_ALL_307 + p)) ;;
                    308) CATCH_ALL_308=$((CATCH_ALL_308 + p)) ;;
                    *)   CATCH_ALL_OTHER=$((CATCH_ALL_OTHER + p)) ;;
                esac
                continue
            fi
            # __WILDCARD__|code|size|count  (لكن IFS بيفصل على كل |، فنسحبها كـ __WILDCARD__|code|size|count = 4 حقول)
            if [ "$c" = "__WILDCARD__" ]; then
                # s = "code", p = "size|count"
                WILDCARD_MSGS+=("${s}|${p}")
                continue
            fi
            sev=$(classify_severity "$p" "$c" "$s")
            echo "$sev|$c|$s|$p" >> "$SORTED_OUT"
        done < "$RAW_OUT"

        # ترتيب حسب الخطورة
        FINAL_OUT=$(mktemp)
        awk -F'|' '{r=4; if($1=="CRITICAL")r=1; else if($1=="WARNING")r=2; else if($1=="INFO")r=3; print r"|"$0}' "$SORTED_OUT" | sort -t'|' -k1,1n | cut -d'|' -f2- > "$FINAL_OUT"

        # دمج المسارات المكررة
        DEDUP_OUT=$(mktemp)
        awk -F'|' '{
            p=$4; gsub(/\/$/, "", p);
            if (!(p in seen)) { seen[p]=1; print $0 }
        }' "$FINAL_OUT" > "$DEDUP_OUT"
        mv "$DEDUP_OUT" "$FINAL_OUT"

        # عرض النتائج
        PREV=""
        while IFS='|' read -r sev c s p; do
            [ -z "$sev" ] && continue
            [ -z "$s" ] && continue
            [ "$s" -eq 0 ] 2>/dev/null && continue
            if [ "$sev" != "$PREV" ]; then
                case "$sev" in
                    CRITICAL) printf "\n  ${BR}▸ CRITICAL${N}\n" ;;
                    WARNING)  printf "\n  ${BY}▸ WARNING${N}\n" ;;
                    INFO)     printf "\n  ${BG}▸ INFO${N}\n" ;;
                    *)        printf "\n  ${BC}▸ LOW${N}\n" ;;
                esac
                PREV="$sev"
            fi
            cl=$(color_for "$sev"); cc=$(code_color "$c")
            SUSPECT=""
            if [ "$s" -ge 1048576 ] 2>/dev/null; then
                SUSPECT=" ${Y}(⚠ truncated/1MB+ — large page or wildcard)${N}"
            fi
            printf "  ${cl}│${N} ${cc}[${c}]${N} ${s}B${SUSPECT} → ${C}https://$HOST$p${N}\n"
            # كشف Data Leak للصفحات 200 كبيرة
            LEAK_INFO=""
            if { [ "$c" = "200" ] || [ "$c" = "302" ] || [ "$c" = "301" ]; } && [ "$s" -gt 5000 ] 2>/dev/null; then
                LEAK_RESP=$(detect_data_leak "https://$HOST$p" "$HOST" 60 "" 2>/dev/null)
                if [[ "$LEAK_RESP" == LEAK* ]]; then
                    LEAK_TYPES=$(echo "$LEAK_RESP" | cut -d'|' -f2)
                    LEAK_INFO=" 🔴 LEAK:${LEAK_TYPES}"
                    [ "$sev" != "CRITICAL" ] && sev="CRITICAL"
                fi
            fi
            GLOBAL_HTML_ROWS+=("${HOST}|${sev}|${c}|${s}|${p}${LEAK_INFO}")
        done < "$FINAL_OUT"

        # عرض رسائل wildcard/catch-all
        TOTAL_CATCH_ALL=$((CATCH_ALL_301 + CATCH_ALL_302 + CATCH_ALL_307 + CATCH_ALL_308 + CATCH_ALL_OTHER))
        if [ ${#WILDCARD_MSGS[@]} -gt 0 ] || [ "$TOTAL_CATCH_ALL" -gt 0 ]; then
            printf "\n  ${Y}⚠ Wildcard/catch-all skipped:${N}\n"
            for wm in "${WILDCARD_MSGS[@]}"; do
                wc_code="${wm%%|*}"
                rest="${wm#*|}"
                wc_size="${rest%%|*}"
                wc_cnt="${rest#*|}"
                [[ "$wc_size" != *B ]] && wc_size="${wc_size}B"
                printf "  ${Y}  • [%s] %s × %s paths (same response)${N}\n" "$wc_code" "$wc_size" "$wc_cnt"
            done
            [ "$CATCH_ALL_301" -gt 0 ] && printf "  ${Y}  • [301] catch-all redirects: %s paths total${N}\n" "$CATCH_ALL_301"
            [ "$CATCH_ALL_302" -gt 0 ] && printf "  ${Y}  • [302] catch-all redirects: %s paths total${N}\n" "$CATCH_ALL_302"
            [ "$CATCH_ALL_307" -gt 0 ] && printf "  ${Y}  • [307] catch-all redirects: %s paths total${N}\n" "$CATCH_ALL_307"
            [ "$CATCH_ALL_308" -gt 0 ] && printf "  ${Y}  • [308] catch-all redirects: %s paths total${N}\n" "$CATCH_ALL_308"
            [ "$CATCH_ALL_OTHER" -gt 0 ] && printf "  ${Y}  • [3xx] catch-all redirects: %s paths total${N}\n" "$CATCH_ALL_OTHER"
        fi
        rm -f "$SORTED_OUT" "$FINAL_OUT"
    fi

    GLOBAL_TARGETS_COUNT=$((GLOBAL_TARGETS_COUNT + 1))
    rm -f "$TEMP_WL" "$TMP" "$RAW_OUT"
    printf "\n  ${G}✓ Finished scanning: $HOST${N}\n"
}
