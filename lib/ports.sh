#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════
# Port Scanning — 60 critical ports, parallel, risk-classified
# ═══════════════════════════════════════════════════════════

PORT_META="21:CRITICAL:FTP
22:WARNING:SSH
23:CRITICAL:Telnet
25:WARNING:SMTP
53:INFO:DNS
80:INFO:HTTP
110:WARNING:POP3
111:CRITICAL:rpcbind
135:CRITICAL:MS-RPC
139:CRITICAL:NetBIOS
143:WARNING:IMAP
161:CRITICAL:SNMP
389:WARNING:LDAP
443:INFO:HTTPS
445:CRITICAL:SMB
465:INFO:SMTPS
587:INFO:SMTP-sub
636:INFO:LDAPS
873:CRITICAL:rsync
993:INFO:IMAPS
995:INFO:POP3S
1080:WARNING:SOCKS
1433:CRITICAL:MSSQL
1521:CRITICAL:Oracle
2049:CRITICAL:NFS
2375:CRITICAL:Docker
2376:CRITICAL:Docker-TLS
3000:WARNING:Node.js
3306:CRITICAL:MySQL
3389:CRITICAL:RDP
4443:INFO:HTTPS-alt
5000:WARNING:Dev-server
5432:CRITICAL:PostgreSQL
5601:WARNING:Kibana
5900:CRITICAL:VNC
6379:CRITICAL:Redis
7001:CRITICAL:WebLogic
7002:CRITICAL:WebLogic-SSL
8000:WARNING:HTTP-alt
8008:WARNING:HTTP-alt
8009:WARNING:AJP13
8080:WARNING:HTTP-alt
8081:WARNING:HTTP-alt
8088:WARNING:HTTP-alt
8089:WARNING:HTTP-alt
8443:INFO:HTTPS-alt
8888:WARNING:HTTP-alt
9000:CRITICAL:PHP-FPM
9042:CRITICAL:Cassandra
9090:WARNING:HTTP-alt
9200:CRITICAL:Elasticsearch
9300:CRITICAL:Elasticsearch
10000:WARNING:Webmin
11211:CRITICAL:Memcached
27017:CRITICAL:MongoDB
27018:CRITICAL:MongoDB
27019:CRITICAL:MongoDB
50000:WARNING:SAP"

_get_port_meta() {
    local p="$1"
    printf '%s\n' "$PORT_META" | while IFS=':' read -r mp mr ms; do
        if [ "$mp" = "$p" ]; then
            printf '%s|%s' "$mr" "$ms"
            return
        fi
    done
}

scan_ports() {
    local host="$1"
    local ports_list="21 22 23 25 53 80 110 111 135 139 143 161 389 443 445 465 587 636 873 993 995 1080 1433 1521 2049 2375 2376 3000 3306 3389 4443 5000 5432 5601 5900 6379 7001 7002 8000 8008 8009 8080 8081 8088 8089 8443 8888 9000 9042 9090 9200 9300 10000 11211 27017 27018 27019 50000"

    printf "\n  ${B}${C}═══ Port Scan ═══${N}\n"
    printf "  ${D}Scanning %s critical ports on %s (parallel x100)...${N}\n\n" "$(echo $ports_list | wc -w)" "$host"

    local scan_helper="${TMPDIR:-$HOME/tmp}/.pscan_$$.sh"
    mkdir -p "$(dirname "$scan_helper")" 2>/dev/null
    cat > "$scan_helper" << 'HELPER'
#!/bin/bash
host="$1"; port="$2"
if timeout 2 bash -c "echo >/dev/tcp/$host/$port" 2>/dev/null; then
    echo "$port"
fi
HELPER
    chmod +x "$scan_helper" 2>/dev/null

    local open_ports=""
    if command -v xargs >/dev/null 2>&1; then
        open_ports=$(printf '%s\n' $ports_list | xargs -P 100 -I{} "$scan_helper" "$host" {} 2>/dev/null | sort -n)
    else
        for port in $ports_list; do
            if timeout 2 bash -c "echo >/dev/tcp/$host/$port" 2>/dev/null; then
                open_ports+="$port"$'\n'
            fi
        done
        open_ports=$(printf '%s' "$open_ports" | sort -n)
    fi
    rm -f "$scan_helper"

    if [ -z "$open_ports" ]; then
        printf "  ${G}✓ No open ports found${N}\n"
        return
    fi

    local count=0
    for port in $open_ports; do
        [ -z "$port" ] && continue
        local meta=$(_get_port_meta "$port")
        local risk="${meta%|*}"
        local service="${meta#*|}"
        [ -z "$risk" ] && risk="INFO"
        [ -z "$service" ] && service="unknown"

        if [ "$service" = "unknown" ]; then
            local banner
            banner=$(timeout 3 bash -c "exec 3<>/dev/tcp/$host/$port 2>/dev/null; head -c 60 <&3 2>/dev/null; exec 3<&- 2>/dev/null" 2>/dev/null | tr -d '\0\r\n' | head -c 40)
            [ -n "$banner" ] && service="banner:${banner}"
        fi

        local color
        case "$risk" in
            CRITICAL) color="${BR}" ;;
            WARNING) color="${BY}" ;;
            INFO) color="${BG}" ;;
            *) color="${BC}" ;;
        esac
        printf "  ${color}│${N} ${color}[%s]${N} port %-5s ${C}%s${N}\n" "$risk" "$port" "$service"

        GLOBAL_PORT_ROWS+=("${host}|${risk}|${port}|${service}")
        count=$((count + 1))
    done

    printf "\n  ${G}✓ Found %s open port(s)${N}\n" "$count"
}
