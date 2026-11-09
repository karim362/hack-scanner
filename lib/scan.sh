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

    printf "\n  ${B}${C}═══ Results ═══${N}\n"
    if [ ! -s "$RAW_OUT" ]; then
        printf "  ${Y}⚠ No paths found.${N}\n"
    else
        # تجميع النتائج وتصنيفها
        SORTED_OUT=$(mktemp)
        while IFS='|' read -r c s p; do
            sev=$(classify_severity "$p" "$c" "$s")
            echo "$sev|$c|$s|$p" >> "$SORTED_OUT"
        done < "$RAW_OUT"
        
        # ترتيب حسب الخطورة (CRITICAL أولاً)
        FINAL_OUT=$(mktemp)
        awk -F'|' '{r=4; if($1=="CRITICAL")r=1; else if($1=="WARNING")r=2; else if($1=="INFO")r=3; print r"|"$0}' "$SORTED_OUT" | sort -t'|' -k1,1n | cut -d'|' -f2- > "$FINAL_OUT"
        
        # عرض النتائج بالألوان
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
            cl=$(color_for "$sev"); cc=$(code_color "$c")
            printf "  ${cl}│${N} ${cc}[${c}]${N} ${s}B → ${C}https://$HOST$p${N}\n"
        done < "$FINAL_OUT"
        
        rm -f "$SORTED_OUT" "$FINAL_OUT"
    fi

    rm -f "$TEMP_WL" "$TMP" "$RAW_OUT"
    printf "\n  ${G}✓ Finished scanning: $HOST${N}\n"
}
