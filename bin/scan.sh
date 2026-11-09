#!/usr/bin/env bash
set -o pipefail

# تحميل الوحدات
source "$(dirname "$0")/../lib/ui.sh"
source "$(dirname "$0")/../lib/utils.sh"
source "$(dirname "$0")/../lib/scan.sh"

# === MAIN ===
banner
declare -a TARGETS=()

if [ -n "${1:-}" ]; then
    TARGETS+=("$1")
else
    printf "  ${W}➜ Enter target URL (or paste multiple URLs, one per line):${N}\n"
    printf "  ${D}Press Enter twice to start scanning.${N}\n\n"
    while IFS= read -r line; do
        [[ -z "$line" ]] && break
        TARGETS+=("$line")
    done
fi

# فلترة الأهداف الفارغة/غير الصالحة قبل البدء
VALID=()
for t in "${TARGETS[@]}"; do
    [ -n "$(sanitize_url "$t")" ] && VALID+=("$t")
done
TARGETS=("${VALID[@]}")
[ ${#TARGETS[@]} -eq 0 ] && die "No valid targets provided."

printf "\n  ${G}✓ Loaded ${#TARGETS[@]} target(s). Starting scan...${N}\n"

for t in "${TARGETS[@]}"; do
    scan_target "$t"
done

# ═══ توليد تقرير HTML ونقله لذاكرة Android ═══
generate_html_report

echo ""
printf "  ${BM}${W}════════════════════════════════════════════${N}\n"
printf "  ${G}✓ All scans completed successfully.${N}\n"
printf "  ${BM}${W}════════════════════════════════════════════${N}\n\n"
