HACK_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TOOLS="$HACK_DIR/tools"
WL="$HACK_DIR/wordlists/ultra500_new.txt"
DIRSEARCH="$TOOLS/dirsearch/dirsearch.py"

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
    
    # استبعاد الملفات الفارغة
    if [ "$size" -eq 0 ]; then echo "LOW"; return; fi
    
    # استبعاد التحويلات الصغيرة
    if [[ "$code" = "308" || "$code" = "301" || "$code" = "307" ]] && [ "$size" -lt 200 ] 2>/dev/null; then echo LOW; return; fi
    
    # ملفات حساسة (CRITICAL)
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
