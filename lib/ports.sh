#!/usr/bin/env bash

PORT_META="21:WARNING:FTP 22:WARNING:SSH 23:CRITICAL:Telnet 25:WARNING:SMTP 53:INFO:DNS 80:INFO:HTTP 110:WARNING:POP3 111:CRITICAL:rpcbind 135:CRITICAL:MSRPC 139:CRITICAL:NetBIOS 143:WARNING:IMAP 161:CRITICAL:SNMP 389:WARNING:LDAP 443:INFO:HTTPS 445:CRITICAL:SMB 465:INFO:SMTPS 587:INFO:SMTPsub 636:INFO:LDAPS 873:CRITICAL:rsync 993:INFO:IMAPS 995:INFO:POP3S 1080:WARNING:SOCKS 1433:CRITICAL:MSSQL 1521:CRITICAL:Oracle 2049:CRITICAL:NFS 2375:CRITICAL:Docker 2376:CRITICAL:DockerTLS 3000:WARNING:NodeJS 3306:CRITICAL:MySQL 3389:CRITICAL:RDP 4443:INFO:HTTPSalt 5000:WARNING:Dev 5432:CRITICAL:PostgreSQL 5601:WARNING:Kibana 5900:CRITICAL:VNC 6379:CRITICAL:Redis 7001:CRITICAL:WebLogic 8000:WARNING:HTTPalt 8080:WARNING:HTTPalt 8081:WARNING:HTTPalt 8443:INFO:HTTPSalt 8888:WARNING:HTTPalt 9000:CRITICAL:PHPFPM 9042:CRITICAL:Cassandra 9090:WARNING:HTTPalt 9200:CRITICAL:Elastic 11211:CRITICAL:Memcached 27017:CRITICAL:MongoDB 50000:WARNING:SAP"

_get_port_meta() {
    local p="$1"
    for pair in $PORT_META; do
        IFS=':' read -r mp mr ms <<< "$pair"
        [ "$mp" = "$p" ] && { printf '%s|%s' "$mr" "$ms"; return; }
    done
}

_verify_port() {
    local host="$1"
    local port="$2"
    local service="$3"

    # HTTP/HTTPS: curl (مؤكد)
    case "$port" in
        80|8000|8080|8081|8888|9090)
            local code=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 5 "http://$host:$port/" 2>/dev/null)
            [ -n "$code" ] && [ "$code" != "000" ] && return 0
            return 1
            ;;
        443|8443|4443)
            local code=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 5 "https://$host:$port/" 2>/dev/null)
            [ -n "$code" ] && [ "$code" != "000" ] && return 0
            return 1
            ;;
    esac

    # كل الباقي: banner إجباري (proxy مابيبعتش)
    local banner=$(timeout 3 bash -c "exec 3<>/dev/tcp/$host/$port 2>/dev/null; head -c 80 <&3 2>/dev/null; exec 3<&- 2>/dev/null" 2>/dev/null | tr -d '\0\r\n ' | head -c 60)
    [ -n "$banner" ] && return 0
    return 1
}

scan_ports() {
    local host="$1"
    local ports_list="21 22 23 25 53 80 110 111 135 139 143 161 389 443 445 465 587 636 873 993 995 1080 1433 1521 2049 2375 2376 3000 3306 3389 4443 5000 5432 5601 5900 6379 7001 8000 8080 8081 8443 8888 9000 9042 9090 9200 11211 27017 50000"

    printf "\n  ═══ Port Scan ═══\n"
    printf "  Scanning %s critical ports on %s (parallel)...\n\n" "$(echo $ports_list | wc -w)" "$host"

    # المرحلة 1: فحص سريع متوازي (background jobs)
    local tmpd
    tmpd=$(mktemp -d 2>/dev/null)
    if [ -z "$tmpd" ] || [ ! -d "$tmpd" ]; then
        tmpd="$HOME/tmp/pscan_$$"
        mkdir -p "$tmpd" 2>/dev/null
    fi
    [ -d "$tmpd" ] || { printf "  ✖ Cannot create temp dir\n"; return; }

    # توازي محدود: 10 عمليات (منع OOM على أندرويد)
    local running=0 max_parallel=10
    for port in $ports_list; do
        (
            timeout 1 bash -c "echo >/dev/tcp/$host/$port" 2>/dev/null && echo "$port" > "$tmpd/$port"
        ) &
        running=$((running + 1))
        if [ "$running" -ge "$max_parallel" ]; then
            wait -n 2>/dev/null || wait
            running=$((running - 1))
        fi
    done
    wait

    # المرحلة 2: تحقق banner + عرض
    local count=0
    for port in $ports_list; do
        [ -f "$tmpd/$port" ] || continue
        local meta=$(_get_port_meta "$port")
        local risk="${meta%|*}" service="${meta#*|}"
        [ -z "$risk" ] && risk="INFO"
        [ -z "$service" ] && service="unknown"

        # تحقق فعلي
        if ! _verify_port "$host" "$port" "$service"; then
            continue
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
        count=$((count+1))
    done
    rm -rf "$tmpd"

    printf "\n  ✓ Found %s open port(s)\n" "$count"
    printf "  ⚠ Note: ISP transparent proxy may cause false results. Use VPN/WiFi for accuracy.\n"
}
