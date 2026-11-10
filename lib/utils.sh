HACK_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TOOLS="$HACK_DIR/tools"
WL="$HACK_DIR/wordlists/ultra500_new.txt"
DIRSEARCH="$TOOLS/dirsearch/dirsearch.py"

sanitize_url() {
    local u="$1"
    u="$(printf '%s' "$u" | tr -d '\r\n\t ')"
    u="$(printf '%s' "$u" | sed 's/^\x1b\[[0-9;]*[a-zA-Z]//g')"
    [ -z "$u" ] && { printf '%s' ""; return; }
    # شيل query/fragment
    u="${u%%\?*}"; u="${u%%#*}"
    # شيل scheme لو موجود
    u="${u#http://}"; u="${u#https://}"
    # شيل المسار
    u="${u%%/*}"
    # تجاهل غير صالح (بس اسمح بـ localhost:PORT و IP:PORT)
    case "$u" in
        ""|"."|".."|*..*) printf '%s' ""; return ;;
    esac
    # اسمح بـ localhost أو IP أو نطاق فيه نقطة
    if [[ "$u" =~ ^localhost(:[0-9]+)?$ ]] || [[ "$u" =~ ^127\.0\.0\.1(:[0-9]+)?$ ]] || [[ "$u" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(:[0-9]+)?$ ]] || [[ "$u" == *.* ]]; then
        printf '%s' "$u"
    else
        printf '%s' ""
    fi
}
classify_severity() {
    local p="$1"; local code="${2:-200}"; local size="${3:-0}"

    # ملفات فارغة أو صغيرة جداً (<20B) = LOW (ردود API فارغة)
    if [ "$size" -eq 0 ] 2>/dev/null; then echo "LOW"; return; fi
    if [ "$size" -lt 20 ] 2>/dev/null; then
        echo "$p" | grep -qiE 'robots|\.txt|security\.txt|ads\.txt' || { echo LOW; return; }
    fi

    # تحويلات (3xx): أي 3xx = LOW
    if [[ "$code" =~ ^3 ]]; then echo "LOW"; return; fi

    # ملفات حساسة (CRITICAL) — فقط لو 200
    if echo "$p" | grep -qiE '\.(env|git|ssh|aws|docker|kube|pem|key|ppk)|docker-compose|Dockerfile|config|settings|wp-config|backup|database|dump|\.sql|\.bak|\.swp|credentials|secret|password|adminer|phpmyadmin|pma|setup-config'; then
        echo CRITICAL; return
    fi

    # لوحات التحكم (WARNING)
    if echo "$p" | grep -qiE 'admin|login|panel|dashboard|install|setup|api|graphql|swagger|console|manager|portal|user|account|webmail|cpanel|whm'; then
        echo WARNING; return
    fi

    # ملفات معلوماتية (INFO)
    if echo "$p" | grep -qiE 'robots|sitemap|favicon|\.txt|\.xml|\.ico|\.png|\.jpg|\.svg|well-known|security|ads'; then
        echo INFO; return
    fi

    echo LOW
}
color_for() { case "$1" in CRITICAL) printf "${BR}";; WARNING) printf "${BY}";; INFO) printf "${BG}";; *) printf "${BC}";; esac; }
dim_color_for() { case "$1" in CRITICAL) printf "${DIM_R}";; *) printf "${DIM_C}";; esac; }
code_color() {
    case "$1" in
        200)      printf "\033[1;32m" ;;
        301|302)  printf "\033[1;33m" ;;
        307|308)  printf "\033[1;36m" ;;
        400|401|403|405) printf "\033[1;31m" ;;
        *)        printf "\033[1;37m" ;;
    esac
}
parse_size() {
    local s="$1"; s="${s%B}"
    if [[ "$s" == *K ]]; then echo "$s" | sed 's/K//' | awk '{printf "%.0f", $1*1024}'
    elif [[ "$s" == *M ]]; then echo "$s" | sed 's/M//' | awk '{printf "%.0f", $1*1048576}'
    else echo "$s" | awk '{printf "%.0f", $1}'; fi
}

# ═══════════════════════════════════════════════════════════
# curl خيارات مخصصة (تُملأ من bin/scan.sh)
# ═══════════════════════════════════════════════════════════
CUSTOM_HEADER=""
CUSTOM_COOKIE=""
CUSTOM_DATA=""
CUSTOM_PROXY=""
CUSTOM_METHOD=""

# بناء args curl من الخيارات المخصصة
build_curl_opts() {
    local opts=""
    [ -n "$CUSTOM_HEADER" ] && opts+=" -H \"$CUSTOM_HEADER\""
    [ -n "$CUSTOM_COOKIE" ] && opts+=" -H \"Cookie: $CUSTOM_COOKIE\""
    [ -n "$CUSTOM_PROXY" ] && opts+=" -x \"$CUSTOM_PROXY\""
    [ -n "$CUSTOM_METHOD" ] && opts+=" -X $CUSTOM_METHOD"
    [ -n "$CUSTOM_DATA" ] && opts+=" --data \"$CUSTOM_DATA\""
    printf '%s' "$opts"
}
