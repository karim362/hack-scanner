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
    
    $PYTHON "$DIRSEARCH" -u "$TARGET" -w "$TEMP_WL" -t "$THREADS" --timeout 7 --random-agent -i 200,301,302,307,308 -x 403,404,400,405,408 > "$TMP" 2>&1
    
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
        done < "$FINAL_OUT"

        # عرض رسائل wildcard/catch-all
        TOTAL_CATCH_ALL=$((CATCH_ALL_301 + CATCH_ALL_302 + CATCH_ALL_307 + CATCH_ALL_308 + CATCH_ALL_OTHER))
        if [ ${#WILDCARD_MSGS[@]} -gt 0 ] || [ "$TOTAL_CATCH_ALL" -gt 0 ]; then
            printf "\n  ${Y}⚠ Wildcard/catch-all skipped:${N}\n"
            for wm in "${WILDCARD_MSGS[@]}"; do
                # wm = "code|size|count"
                wc_code="${wm%%|*}"
                rest="${wm#*|}"
                wc_size="${rest%%|*}"
                wc_cnt="${rest#*|}"
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

    rm -f "$TEMP_WL" "$TMP" "$RAW_OUT"
    printf "\n  ${G}✓ Finished scanning: $HOST${N}\n"
}
