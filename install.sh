#!/bin/bash
# ==============================================================================
# GRE / GRETAP + Backhaul / FRP  Reverse Tunnel Manager  v4.0
#
#   Iran  server : TUN_IR_IP   <== GRE or GRETAP (MTU 1400 / MSS 1240) ==>   Kharej client : TUN_KH_IP
#
# Data path
#   user -> Iran public IP:PORT --(iptables DNAT)--> TUN_IR_IP:PORT (core server)
#        -> core control + data channels travel INSIDE the GRE/GRETAP link
#        -> Kharej core client -> 127.0.0.1:TARGET_PORT on the Kharej box
#
# New in v4.0 (everything from v3.0 is kept)
#   1. Link type is chosen at setup: GRE (layer 3) or GRETAP (layer 2).
#   2. Core is chosen at setup: Backhaul or FRP (frp v0.61.1, TOML config).
#   3. Local tunnel IP pair is chosen at setup:
#        1) 10.0.0.1 (Iran)     <-> 10.0.0.2 (Kharej)      /30
#        2) 203.0.113.10 (Iran) <-> 203.0.113.20 (Kharej)  /27
#      The core server<->client connection AND all tunneled traffic use that pair.
#   4. Protocol is chosen manually, each core shows its own list:
#        Backhaul : tcp tcpmux udp ws wsmux wss wssmux
#        FRP      : tcp kcp quic websocket
#   5. Forwarded ports are handled on the Iran server exactly like before
#      (iptables DNAT to the tunnel IP + INPUT accept, tagged BHGT).
#
# Things verified against the real binaries (Backhaul v0.7.2, frp 0.61.1)
#   * Backhaul "udp" transport forwards UDP ports ONLY (no TCP listener).
#   * Backhaul accept_udp (UDP-over-TCP) works with "tcp" but NOT with "tcpmux".
#   * FRP needs the port list on BOTH sides (Iran: firewall + allowPorts,
#     Kharej: the proxies), Backhaul needs it on the Iran side only.
#   * Backhaul/FRP logs are colored: ANSI codes are stripped before matching.
#
# Upgrade note: config dir and service names of v3.x are kept on purpose, so an
# existing v3.x tunnel is still shown by Status and replaced cleanly by Setup.
# ==============================================================================

VERSION="4.0"
FRP_VERSION="0.61.1"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

CONFIG_DIR="/etc/backhaul-gretap"
CONF_FILE="$CONFIG_DIR/tunnel.conf"
CTL_SH="$CONFIG_DIR/gretap-ctl.sh"
TLS_CERT="$CONFIG_DIR/server.crt"
TLS_KEY="$CONFIG_DIR/server.key"

BACKHAUL_BIN="/usr/local/bin/backhaul-gretap"
FRPS_BIN="/usr/local/bin/frps-gretap"
FRPC_BIN="/usr/local/bin/frpc-gretap"
LEGACY_BIN="/usr/local/bin/backhaul"

UNIT_DIR="/etc/systemd/system"
LINK_SVC="gretap-tunnel.service"
BACKHAUL_SVC="backhaul-tunnel.service"
FRP_SVC="frp-tunnel.service"

MSS_VAL="1240"
MTU_VAL="1400"

# local tunnel IP pairs (index 0 = option 1, index 1 = option 2)
IPSET_IR=("10.0.0.1"  "203.0.113.10")
IPSET_KH=("10.0.0.2"  "203.0.113.20")
IPSET_PFX=("30"       "27")

# protocol lists, one per core
BH_PROTOS=(tcp tcpmux udp ws wsmux wss wssmux)
BH_DESCS=(
    "plain TCP: lowest overhead, fastest in most cases (recommended)"
    "TCP + multiplexing: many small connections over few sockets"
    "UDP transport: control over TCP, forwards UDP ports only (WireGuard, DNS, VoIP...)"
    "WebSocket over TCP"
    "WebSocket + multiplexing"
    "WebSocket + TLS (a self-signed certificate is generated on the Iran server)"
    "WebSocket + TLS + multiplexing"
)
FRP_PROTOS=(tcp kcp quic websocket)
FRP_DESCS=(
    "TCP (+TLS, multiplexed): stable, best general choice (recommended)"
    "KCP over UDP: tolerant to packet loss, uses more bandwidth"
    "QUIC over UDP: fast (re)connect, good on lossy links"
    "WebSocket over TCP"
)

# ------------------------------------------------------------------------------
# small helpers
# ------------------------------------------------------------------------------
info() { echo -e "${CYAN}[*] $*${NC}"; }
ok()   { echo -e "${GREEN}[+] $*${NC}"; }
warn() { echo -e "${YELLOW}[!] $*${NC}"; }
err()  { echo -e "${RED}[x] $*${NC}"; }
res()  { # res ok|bad|warn "message"
    case $1 in
        ok)  echo -e "  ${GREEN}[PASS]${NC} $2" ;;
        bad) echo -e "  ${RED}[FAIL]${NC} $2" ;;
        *)   echo -e "  ${YELLOW}[WARN]${NC} $2" ;;
    esac
}
pause() { read -r -p "Press Enter to continue..." _ || exit 0; }

if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}[ERROR] This script must be run as root!${NC}"
    exit 1
fi
if (( BASH_VERSINFO[0] < 4 )); then
    echo -e "${RED}[ERROR] bash >= 4 is required.${NC}"
    exit 1
fi

ask() { # ask VAR "prompt" ["default"]
    local __var=$1 __prompt=$2 __def=${3:-} __ans
    if [[ -n $__def ]]; then
        read -r -p "$__prompt [$__def]: " __ans || { echo; exit 1; }
        __ans=${__ans:-$__def}
    else
        read -r -p "$__prompt: " __ans || { echo; exit 1; }
    fi
    __ans=${__ans#"${__ans%%[![:space:]]*}"}
    __ans=${__ans%"${__ans##*[![:space:]]}"}
    printf -v "$__var" '%s' "$__ans"
}

ask_valid() { # ask_valid VAR "prompt" "default" validator "error message"
    local __v
    while true; do
        ask __v "$2" "${3:-}"
        if "$4" "$__v"; then
            printf -v "$1" '%s' "$__v"
            return 0
        fi
        err "$5"
    done
}

ask_yn() { # ask_yn "question" default(y|n)  -> exit status 0 = yes
    local def=${2:-n} a hint="y/N"
    [[ $def == y ]] && hint="Y/n"
    read -r -p "$1 [$hint]: " a || exit 1
    a=${a:-$def}
    [[ $a =~ ^[Yy] ]]
}

valid_ipv4() {
    local o
    [[ $1 =~ ^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$ ]] || return 1
    for o in "${BASH_REMATCH[@]:1}"; do
        (( 10#$o <= 255 )) || return 1
    done
    return 0
}
valid_port()  { [[ $1 =~ ^[0-9]{1,5}$ ]] && (( 10#$1 >= 1 && 10#$1 <= 65535 )); }
valid_token() { [[ $1 =~ ^[A-Za-z0-9._~@%+=-]{1,64}$ ]]; }
MENU_MAX=1
valid_menu()  { [[ $1 =~ ^[0-9]{1,2}$ ]] && (( 10#$1 >= 1 && 10#$1 <= MENU_MAX )); }

strip_ansi() { sed 's/\x1b\[[0-9;]*[A-Za-z]//g'; }

detect_ip() {
    ip -4 route get 1.1.1.1 2>/dev/null | sed -n 's/.* src \([0-9.]*\).*/\1/p' | head -n1
}

# parse_ports "1080, 443, 8443=443" -> PORT_MAP=("1080=1080" "443=443" "8443=443")
# entry "A" means public port A -> Kharej 127.0.0.1:A ; "A=B" means public A -> Kharej 127.0.0.1:B
parse_ports() {
    local raw=${1//[[:space:]]/} entry pub tgt
    local -a entries=()
    local -A seen=()
    PORT_MAP=()
    [[ -n $raw ]] || return 1
    IFS=',' read -ra entries <<< "$raw"
    for entry in "${entries[@]}"; do
        [[ -z $entry ]] && continue
        if [[ $entry == *=* ]]; then
            pub=${entry%%=*}
            tgt=${entry#*=}
        else
            pub=$entry
            tgt=$entry
        fi
        if ! valid_port "$pub" || ! valid_port "$tgt"; then
            err "Invalid port entry: '$entry' (ranges are not supported)"
            return 1
        fi
        pub=$((10#$pub))
        tgt=$((10#$tgt))
        if [[ -n ${seen[$pub]:-} ]]; then
            warn "Duplicate public port $pub ignored."
            continue
        fi
        seen[$pub]=1
        PORT_MAP+=("$pub=$tgt")
    done
    (( ${#PORT_MAP[@]} > 0 ))
}

# listeners that would clash with a core binding TUN_IR_IP:port (wildcard or same IP),
# ignoring our own tunnel processes. Prints "addr process" per clash.
listener_conflicts() { # proto port
    local flags="-ltnpH"
    [[ $1 == udp ]] && flags="-lunpH"
    local laddr proc
    ss $flags "sport = :$2" 2>/dev/null | while read -r _ _ _ laddr _ proc; do
        case ${laddr%:*} in
            "*"|0.0.0.0|"[::]"|"::"|"$TUN_IR_IP") ;;
            *) continue ;;
        esac
        case $proc in
            *'"backhaul-gretap"'*|*'"frps-gretap"'*|*'"frpc-gretap"'*) continue ;;
        esac
        echo "$laddr ${proc:-unknown-process}"
    done
}

# conflicts on the control port, depending on core + protocol
ctrl_conflicts() {
    {
        listener_conflicts tcp "$CTRL_PORT" | sed 's/^/tcp: /'
        if [[ ( $CORE == frp && ( $PROTO == kcp || $PROTO == quic ) ) || ( $CORE == backhaul && $PROTO == udp ) ]]; then
            listener_conflicts udp "$CTRL_PORT" | sed 's/^/udp: /'
        fi
    } | sed '/^$/d'
}

pick_free_port() {
    local i p
    for i in $(seq 1 60); do
        p=$(( (RANDOM % 20000) + 20000 ))
        [[ -z $(ss -H -ltn "sport = :$p" 2>/dev/null) ]] && { echo "$p"; return; }
    done
    echo 28080
}

# ------------------------------------------------------------------------------
# derived settings (single source of truth = tunnel.conf)
# ------------------------------------------------------------------------------
set_link_vars() {
    case ${LINK_TYPE:-gretap} in
        gre)    LINK_TYPE=gre;    IFACE="gretun1"; LINK_LABEL="GRE (layer 3)" ;;
        *)      LINK_TYPE=gretap; IFACE="gretap1"; LINK_LABEL="GRETAP (layer 2)" ;;
    esac
}

set_core_vars() { # needs CORE + ROLE
    case ${CORE:-backhaul} in
        frp)
            CORE=frp
            CORE_NAME="FRP v$FRP_VERSION"
            CORE_SVC=$FRP_SVC
            LOG_OK_RE='login to server success'
            LOG_ERR_RE='connect to server error|login to the server failed|\[E\]'
            if [[ $ROLE == iran ]]; then
                CORE_BIN=$FRPS_BIN; CORE_TAR_NAME="frps"; CORE_CONF="$CONFIG_DIR/frps.toml"; CORE_PROC="frps-gretap"
            else
                CORE_BIN=$FRPC_BIN; CORE_TAR_NAME="frpc"; CORE_CONF="$CONFIG_DIR/frpc.toml"; CORE_PROC="frpc-gretap"
            fi
            ;;
        *)
            CORE=backhaul
            CORE_NAME="Backhaul"
            CORE_SVC=$BACKHAUL_SVC
            LOG_OK_RE='channel established'
            LOG_ERR_RE='\[(ERROR|WARNING)\]'
            CORE_BIN=$BACKHAUL_BIN; CORE_TAR_NAME="backhaul"; CORE_CONF="$CONFIG_DIR/config.toml"; CORE_PROC="backhaul-gretap"
            ;;
    esac
}

set_role_ips() {
    if [[ $ROLE == iran ]]; then
        SELF_IP=$TUN_IR_IP
        PEER_IP=$TUN_KH_IP
    else
        SELF_IP=$TUN_KH_IP
        PEER_IP=$TUN_IR_IP
    fi
}

# which transport protocols of the forwarded ports are used (firewall + proxies)
set_fwd_flags() {
    FWD_TCP=1
    FWD_UDP=0
    case "$CORE:$PROTO" in
        backhaul:udp)       FWD_TCP=0; FWD_UDP=1 ;;
        backhaul:tcp|frp:*) FWD_UDP=${ACCEPT_UDP:-0} ;;
    esac
}

save_conf() {
    set_fwd_flags
    mkdir -p "$CONFIG_DIR"
    install -m 600 /dev/null "$CONF_FILE"
    {
        echo "# generated by gre-tunnel-manager v$VERSION - edit via the menu"
        printf 'ROLE=%q\n'       "$ROLE"
        printf 'CORE=%q\n'       "$CORE"
        printf 'LINK_TYPE=%q\n'  "$LINK_TYPE"
        printf 'IFACE=%q\n'      "$IFACE"
        printf 'LOCAL_IP=%q\n'   "$LOCAL_IP"
        printf 'REMOTE_IP=%q\n'  "$REMOTE_IP"
        printf 'TUN_IR_IP=%q\n'  "$TUN_IR_IP"
        printf 'TUN_KH_IP=%q\n'  "$TUN_KH_IP"
        printf 'PFX=%q\n'        "$PFX"
        printf 'SELF_IP=%q\n'    "$SELF_IP"
        printf 'PEER_IP=%q\n'    "$PEER_IP"
        printf 'CTRL_PORT=%q\n'  "$CTRL_PORT"
        printf 'TOKEN=%q\n'      "$TOKEN"
        printf 'PROTO=%q\n'      "$PROTO"
        printf 'ACCEPT_UDP=%q\n' "${ACCEPT_UDP:-0}"
        printf 'FWD_TCP=%q\n'    "$FWD_TCP"
        printf 'FWD_UDP=%q\n'    "$FWD_UDP"
        printf 'PORTS=%q\n'      "${PORTS:-}"
        printf 'MSS_VAL=%q\n'    "$MSS_VAL"
        printf 'MTU_VAL=%q\n'    "$MTU_VAL"
        printf 'CORE_BIN=%q\n'   "$CORE_BIN"
        printf 'CORE_CONF=%q\n'  "$CORE_CONF"
        printf 'TLS_CERT=%q\n'   "$TLS_CERT"
        printf 'TLS_KEY=%q\n'    "$TLS_KEY"
    } > "$CONF_FILE"
}

load_conf() {
    [[ -f $CONF_FILE ]] || return 1
    # shellcheck disable=SC1090
    source "$CONF_FILE" || return 1
    [[ -n ${ROLE:-} ]] || return 1
    # defaults / names used by v3.x so an old install is still understood
    CORE=${CORE:-backhaul}
    LINK_TYPE=${LINK_TYPE:-gretap}
    CTRL_PORT=${CTRL_PORT:-${BH_PORT:-}}
    TOKEN=${TOKEN:-${BH_TOKEN:-}}
    PROTO=${PROTO:-${BH_TRANS:-tcp}}
    PFX=${PFX:-30}
    TUN_IR_IP=${TUN_IR_IP:-10.10.1.1}
    TUN_KH_IP=${TUN_KH_IP:-10.10.1.2}
    set_link_vars
    set_core_vars
    set_role_ips
    set_fwd_flags
    return 0
}

# ------------------------------------------------------------------------------
# core configuration files (always regenerated from tunnel.conf)
# ------------------------------------------------------------------------------
write_backhaul_conf() {
    local m
    {
        if [[ $ROLE == iran ]]; then
            echo "[server]"
            echo "bind_addr = \"$TUN_IR_IP:$CTRL_PORT\""
            echo "transport = \"$PROTO\""
            if [[ ${ACCEPT_UDP:-0} == 1 && $PROTO == tcp ]]; then echo "accept_udp = true"; fi
            echo "token = \"$TOKEN\""
            echo "keepalive_period = 75"
            echo "nodelay = true"
            echo "heartbeat = 40"
            echo "channel_size = 2048"
            echo "sniffer = false"
            echo "log_level = \"info\""
            case $PROTO in
                *mux)
                    echo "mux_con = 8"
                    echo "mux_version = 1"
                    echo "mux_framesize = 32768"
                    echo "mux_recievebuffer = 4194304"
                    echo "mux_streambuffer = 65536"
                    ;;
            esac
            case $PROTO in
                wss|wssmux)
                    echo "tls_cert = \"$TLS_CERT\""
                    echo "tls_key = \"$TLS_KEY\""
                    ;;
            esac
            echo "ports = ["
            for m in $PORTS; do
                echo "    \"$TUN_IR_IP:${m%%=*}=${m#*=}\","
            done
            echo "]"
        else
            echo "[client]"
            echo "remote_addr = \"$TUN_IR_IP:$CTRL_PORT\""
            echo "transport = \"$PROTO\""
            echo "token = \"$TOKEN\""
            echo "connection_pool = 8"
            echo "aggressive_pool = false"
            echo "keepalive_period = 75"
            echo "dial_timeout = 10"
            echo "retry_interval = 3"
            echo "nodelay = true"
            echo "sniffer = false"
            echo "log_level = \"info\""
            case $PROTO in
                *mux)
                    echo "mux_version = 1"
                    echo "mux_framesize = 32768"
                    echo "mux_recievebuffer = 4194304"
                    echo "mux_streambuffer = 65536"
                    ;;
            esac
        fi
    } > "$CORE_CONF"
}

write_frp_conf() {
    local m pub tgt sep=""
    if [[ $ROLE == iran ]]; then
        {
            echo "# frps - generated by gre-tunnel-manager v$VERSION"
            echo "bindAddr = \"$TUN_IR_IP\""
            echo "bindPort = $CTRL_PORT"
            case $PROTO in
                kcp)  echo "kcpBindPort = $CTRL_PORT" ;;
                quic) echo "quicBindPort = $CTRL_PORT" ;;
            esac
            echo "proxyBindAddr = \"$TUN_IR_IP\""
            echo 'auth.method = "token"'
            echo "auth.token = \"$TOKEN\""
            echo 'transport.tcpMux = true'
            echo 'transport.tcpMuxKeepaliveInterval = 30'
            echo 'transport.heartbeatTimeout = 90'
            echo 'log.to = "console"'
            echo 'log.level = "info"'
            printf 'allowPorts = [ '
            for m in $PORTS; do
                printf '%s{ single = %s }' "$sep" "${m%%=*}"
                sep=", "
            done
            echo ' ]'
        } > "$CORE_CONF"
    else
        {
            echo "# frpc - generated by gre-tunnel-manager v$VERSION"
            echo "serverAddr = \"$TUN_IR_IP\""
            echo "serverPort = $CTRL_PORT"
            echo 'loginFailExit = false'
            echo 'auth.method = "token"'
            echo "auth.token = \"$TOKEN\""
            echo "transport.protocol = \"$PROTO\""
            echo 'transport.tcpMux = true'
            echo 'transport.tcpMuxKeepaliveInterval = 30'
            echo 'transport.poolCount = 5'
            echo 'transport.dialServerTimeout = 10'
            echo 'transport.heartbeatInterval = 30'
            echo 'transport.heartbeatTimeout = 90'
            echo 'log.to = "console"'
            echo 'log.level = "info"'
            for m in $PORTS; do
                pub=${m%%=*}
                tgt=${m#*=}
                printf '\n[[proxies]]\nname = "tcp-%s"\ntype = "tcp"\nlocalIP = "127.0.0.1"\nlocalPort = %s\nremotePort = %s\n' "$pub" "$tgt" "$pub"
                if [[ ${FWD_UDP:-0} == 1 ]]; then
                    printf '\n[[proxies]]\nname = "udp-%s"\ntype = "udp"\nlocalIP = "127.0.0.1"\nlocalPort = %s\nremotePort = %s\n' "$pub" "$tgt" "$pub"
                fi
            done
        } > "$CORE_CONF"
    fi
}

write_core_conf() {
    install -m 600 /dev/null "$CORE_CONF"
    if [[ $CORE == frp ]]; then write_frp_conf; else write_backhaul_conf; fi
}

# ------------------------------------------------------------------------------
# the helper that systemd runs (static content, reads tunnel.conf at runtime)
# ------------------------------------------------------------------------------
write_ctl_script() {
    mkdir -p "$CONFIG_DIR"
    {
        echo '#!/bin/bash'
        echo '# gretap-ctl.sh - managed by gre-tunnel-manager. Do not edit by hand.'
        echo '#   up | down | reload | prestart'
        printf 'CONF_FILE=%q\n' "$CONF_FILE"
        cat <<'CTL_EOF'
# shellcheck disable=SC1090
source "$CONF_FILE" || { echo "cannot read $CONF_FILE" >&2; exit 1; }

# defaults so a config written by v3.x still works
LINK_TYPE=${LINK_TYPE:-gretap}
PFX=${PFX:-30}
FWD_TCP=${FWD_TCP:-1}
FWD_UDP=${FWD_UDP:-${ACCEPT_UDP:-0}}
CORE_BIN=${CORE_BIN:-${BACKHAUL_BIN:-}}

TAG="BHGT"
if iptables -w 5 -L -n >/dev/null 2>&1; then IPT=(iptables -w 5); else IPT=(iptables); fi

# ipt_ensure <table> <chain> <match/target args...>   (idempotent, inserted at top, tagged)
ipt_ensure() {
    local t=$1 c=$2
    shift 2
    local -a pre=() post=() spec=()
    while (( $# )); do
        if [[ $1 == -j ]]; then post=("$@"); break; fi
        pre+=("$1")
        shift
    done
    spec=("${pre[@]}" -m comment --comment "$TAG" "${post[@]}")
    "${IPT[@]}" -t "$t" -C "$c" "${spec[@]}" 2>/dev/null || "${IPT[@]}" -t "$t" -I "$c" 1 "${spec[@]}"
}

# remove every rule carrying our tag, whatever the current config says
purge_rules() {
    local t line
    local -a words=()
    for t in filter nat mangle; do
        while read -r line; do
            [[ -n $line ]] || continue
            line=${line//\"/}
            line="-D${line#-A}"
            read -ra words <<< "$line"
            "${IPT[@]}" -t "$t" "${words[@]}" 2>/dev/null
        done < <("${IPT[@]}" -t "$t" -S 2>/dev/null | grep -E -- "--comment \"?$TAG\"? ")
    done
    return 0
}

apply_rules() {
    local m pub

    # --- filter: let GRE from the peer in, and everything that rides on the tunnel
    ipt_ensure filter INPUT   -p gre -s "$REMOTE_IP" -j ACCEPT
    ipt_ensure filter INPUT   -i "$IFACE" -j ACCEPT
    ipt_ensure filter FORWARD -i "$IFACE" -j ACCEPT
    ipt_ensure filter FORWARD -o "$IFACE" -j ACCEPT

    # --- mangle: MSS clamp
    ipt_ensure mangle FORWARD -o "$IFACE" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss "$MSS_VAL"
    ipt_ensure mangle FORWARD -i "$IFACE" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss "$MSS_VAL"
    ipt_ensure mangle OUTPUT  -o "$IFACE" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss "$MSS_VAL"
    ipt_ensure mangle INPUT   -i "$IFACE" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss "$MSS_VAL"

    if [[ $ROLE == iran ]]; then
        for m in $PORTS; do
            pub=${m%%=*}
            # traffic that arrives on the PUBLIC NIC and is DNATed to the tunnel IP
            # is delivered locally: it needs its own INPUT accept (NOT covered by -i $IFACE)
            if [[ $FWD_TCP == 1 ]]; then
                ipt_ensure filter INPUT -d "$TUN_IR_IP" -p tcp --dport "$pub" -j ACCEPT
                ipt_ensure nat PREROUTING ! -i "$IFACE" -m addrtype --dst-type LOCAL -p tcp --dport "$pub" -j DNAT --to-destination "$TUN_IR_IP:$pub"
            fi
            if [[ $FWD_UDP == 1 ]]; then
                ipt_ensure filter INPUT -d "$TUN_IR_IP" -p udp --dport "$pub" -j ACCEPT
                ipt_ensure nat PREROUTING ! -i "$IFACE" -m addrtype --dst-type LOCAL -p udp --dport "$pub" -j DNAT --to-destination "$TUN_IR_IP:$pub"
            fi
        done
        # tunnel traffic must never be touched by any other DNAT/REDIRECT rule on the box.
        # Inserted last on purpose so it ends up FIRST in the chain.
        ipt_ensure nat PREROUTING -i "$IFACE" -j ACCEPT
    else
        ipt_ensure nat OUTPUT -o "$IFACE" -j ACCEPT
    fi
}

has_self_ip() { ip -4 addr show dev "$IFACE" 2>/dev/null | grep -q "inet $SELF_IP/"; }

case "$1" in
    up)
        purge_rules
        modprobe ip_gre 2>/dev/null
        ip link del "$IFACE" 2>/dev/null
        case $LINK_TYPE in gre) kind=gre ;; *) kind=gretap ;; esac
        if ! ip link add "$IFACE" type "$kind" local "$LOCAL_IP" remote "$REMOTE_IP" ttl 255; then
            echo "ERROR: cannot create $IFACE (type $kind). Possible causes: GRE support (ip_gre) is missing on this VPS/kernel," >&2
            echo "       LOCAL_IP $LOCAL_IP is not an address of this host, or another $kind tunnel with the same local/remote pair already exists (another script?)." >&2
            exit 1
        fi
        ip addr add "$SELF_IP/$PFX" dev "$IFACE" || exit 1
        ip link set "$IFACE" mtu "$MTU_VAL" up || exit 1
        sysctl -qw "net.ipv4.conf.$IFACE.rp_filter=0" 2>/dev/null
        apply_rules
        ;;
    reload)
        purge_rules
        apply_rules
        ;;
    down)
        purge_rules
        ip link del "$IFACE" 2>/dev/null
        exit 0
        ;;
    prestart)
        if [[ ! -x $CORE_BIN ]]; then
            echo "ERROR: $CORE_BIN is missing or not executable (reinstall it from the menu)" >&2
            exit 1
        fi
        if [[ -n ${CORE_CONF:-} && ! -s $CORE_CONF ]]; then
            echo "ERROR: $CORE_CONF is missing or empty (run Setup again)" >&2
            exit 1
        fi
        for _ in $(seq 1 20); do has_self_ip && break; sleep 1; done
        if ! has_self_ip; then
            echo "ERROR: $IFACE has no $SELF_IP address" >&2
            exit 1
        fi
        if [[ $ROLE == kharej ]]; then
            for _ in $(seq 1 10); do ping -c1 -W1 "$PEER_IP" >/dev/null 2>&1 && break; sleep 1; done
        fi
        exit 0
        ;;
    *)
        echo "usage: $0 up|down|reload|prestart" >&2
        exit 2
        ;;
esac
CTL_EOF
    } > "$CTL_SH"
    chmod 755 "$CTL_SH"
}

write_units() {
    local s
    cat > "$UNIT_DIR/$LINK_SVC" <<EOF
[Unit]
Description=$LINK_LABEL tunnel and firewall rules (gre-tunnel-manager)
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=$CTL_SH up
ExecStop=$CTL_SH down

[Install]
WantedBy=multi-user.target
EOF

    cat > "$UNIT_DIR/$CORE_SVC" <<EOF
[Unit]
Description=$CORE_NAME reverse tunnel over $LINK_LABEL
After=$LINK_SVC
Requires=$LINK_SVC
PartOf=$LINK_SVC
StartLimitIntervalSec=0

[Service]
Type=simple
ExecStartPre=$CTL_SH prestart
ExecStart=$CORE_BIN -c $CORE_CONF
Restart=always
RestartSec=3
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF

    # the core that is NOT in use must not start at boot
    for s in "$BACKHAUL_SVC" "$FRP_SVC"; do
        [[ $s == "$CORE_SVC" ]] && continue
        systemctl disable "$s" >/dev/null 2>&1
        rm -f "$UNIT_DIR/$s"
    done
    systemctl daemon-reload
    systemctl enable "$LINK_SVC" "$CORE_SVC" >/dev/null 2>&1
}

stop_services() {
    local b
    systemctl stop "$BACKHAUL_SVC" "$FRP_SVC" "$LINK_SVC" >/dev/null 2>&1
    for b in "$BACKHAUL_BIN" "$FRPS_BIN" "$FRPC_BIN"; do
        pkill -f -- "$b -c $CONFIG_DIR/" 2>/dev/null
    done
    return 0
}

# ------------------------------------------------------------------------------
# dependencies + core binaries
# ------------------------------------------------------------------------------
ensure_deps() {
    local cmd
    local -a need=()
    for cmd in ip iptables ss curl tar sha256sum systemctl journalctl; do
        command -v "$cmd" >/dev/null 2>&1 || need+=("$cmd")
    done
    if (( ${#need[@]} > 0 )); then
        info "Missing tools: ${need[*]} - trying to install..."
        if command -v apt-get >/dev/null 2>&1; then
            apt-get update -y -qq >/dev/null 2>&1
            apt-get install -y -qq iproute2 iptables curl tar coreutils iputils-ping >/dev/null 2>&1
        elif command -v dnf >/dev/null 2>&1; then
            dnf install -y -q iproute iptables curl tar coreutils iputils >/dev/null 2>&1
        elif command -v yum >/dev/null 2>&1; then
            yum install -y -q iproute iptables curl tar coreutils iputils >/dev/null 2>&1
        elif command -v apk >/dev/null 2>&1; then
            apk add --no-cache iproute2 iptables curl tar coreutils iputils >/dev/null 2>&1
        fi
        for cmd in "${need[@]}"; do
            if ! command -v "$cmd" >/dev/null 2>&1; then
                err "Required command '$cmd' is still missing - install it manually and retry."
                return 1
            fi
        done
    fi
    command -v ping >/dev/null 2>&1 || warn "'ping' not found: diagnostics will be limited (apt install iputils-ping)."
    return 0
}

ensure_tls_cert() {
    [[ -s $TLS_CERT && -s $TLS_KEY ]] && return 0
    if ! command -v openssl >/dev/null 2>&1; then
        info "openssl is needed for wss - trying to install..."
        if command -v apt-get >/dev/null 2>&1; then apt-get install -y -qq openssl >/dev/null 2>&1
        elif command -v dnf >/dev/null 2>&1; then dnf install -y -q openssl >/dev/null 2>&1
        elif command -v yum >/dev/null 2>&1; then yum install -y -q openssl >/dev/null 2>&1
        elif command -v apk >/dev/null 2>&1; then apk add --no-cache openssl >/dev/null 2>&1
        fi
    fi
    mkdir -p "$CONFIG_DIR"
    if ! openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 3650 \
            -subj "/CN=localhost" -keyout "$TLS_KEY" -out "$TLS_CERT" >/dev/null 2>&1; then
        err "Could not generate the TLS certificate (is openssl installed?)."
        return 1
    fi
    chmod 600 "$TLS_KEY"
    ok "Self-signed TLS certificate created ($TLS_CERT)."
}

is_elf() { [[ -s $1 && "$(head -c4 "$1" 2>/dev/null | od -An -tx1 | tr -d ' \n')" == "7f454c46" ]]; }

install_binary_file() { # $1 = .tar.gz archive or raw ELF binary  (uses CORE_TAR_NAME / CORE_BIN)
    local src=$1 tmp found rc
    tmp=$(mktemp -d) || return 1
    if tar -tzf "$src" >/dev/null 2>&1; then
        tar -xzf "$src" -C "$tmp" || { rm -rf "$tmp"; return 1; }
        found=$(find "$tmp" -type f -name "$CORE_TAR_NAME" | head -n1)
        if [[ -z $found ]] || ! is_elf "$found"; then
            err "No valid '$CORE_TAR_NAME' executable inside the archive."
            rm -rf "$tmp"
            return 1
        fi
    elif is_elf "$src"; then
        found=$src
    else
        err "The file is neither a .tar.gz archive nor a Linux executable (an HTML error page?)."
        rm -rf "$tmp"
        return 1
    fi
    install -m 755 "$found" "$CORE_BIN.new" && mv -f "$CORE_BIN.new" "$CORE_BIN"
    rc=$?
    rm -rf "$tmp"
    return $rc
}

download_to() { # url file
    curl -fL --connect-timeout 15 --max-time 240 -o "$2" "$1" 2>/dev/null && [[ -s $2 ]]
}

bin_version() { timeout 3 "$CORE_BIN" -v 2>&1 | head -n1; }

show_bin_info() {
    local v
    if [[ ! -x $CORE_BIN ]]; then
        err "$CORE_NAME binary not installed ($CORE_BIN)."
        return 1
    fi
    v=$(bin_version)
    echo "    path    : $CORE_BIN"
    echo "    version : $v"
    echo "    size    : $(stat -c %s "$CORE_BIN") bytes"
    echo "    sha256  : $(sha256sum "$CORE_BIN" | cut -d' ' -f1)"
    if [[ $CORE == frp ]]; then
        [[ $v == *"$FRP_VERSION"* ]] || warn "Expected FRP $FRP_VERSION but this binary reports '$v'."
        warn "Iran (frps) and Kharej (frpc) should run the same FRP version."
    else
        warn "Iran and Kharej MUST run the same binary: compare the sha256 above on both servers."
    fi
}

fetch_core_binary() { # [force]
    local force=${1:-0} arch url tmp src
    mkdir -p "$CONFIG_DIR"
    if [[ $force != 1 ]] && [[ -x $CORE_BIN ]] && is_elf "$CORE_BIN"; then
        ok "$CORE_NAME binary already installed."
        show_bin_info
        return 0
    fi

    case "$(uname -m)" in
        x86_64|amd64)  arch="amd64" ;;
        aarch64|arm64) arch="arm64" ;;
        *) err "Unsupported architecture: $(uname -m)"; return 1 ;;
    esac
    if [[ $CORE == frp ]]; then
        url="https://github.com/fatedier/frp/releases/download/v${FRP_VERSION}/frp_${FRP_VERSION}_linux_${arch}.tar.gz"
    else
        url="https://github.com/Musixal/Backhaul/releases/latest/download/backhaul_linux_${arch}.tar.gz"
    fi

    tmp=$(mktemp) || return 1
    info "Downloading $url"
    if download_to "$url" "$tmp" && install_binary_file "$tmp"; then
        rm -f "$tmp"
        ok "$CORE_NAME installed."
        show_bin_info
        return 0
    fi
    rm -f "$tmp"
    warn "GitHub download failed (blocked / offline?)."

    if [[ $CORE == backhaul && -x $LEGACY_BIN ]] && is_elf "$LEGACY_BIN"; then
        warn "Found an existing binary at $LEGACY_BIN (probably installed by another script)."
        if ask_yn "Copy and use it for this tunnel?" n; then
            if install_binary_file "$LEGACY_BIN"; then
                ok "Copied."
                show_bin_info
                return 0
            fi
        fi
    fi

    warn "Give a direct URL or a local path of the .tar.gz release archive (or the raw '$CORE_TAR_NAME' binary). Empty = abort."
    ask src "URL or path" ""
    [[ -n $src ]] || return 1
    if [[ -f $src ]]; then
        install_binary_file "$src" || return 1
    elif [[ $src =~ ^https?:// ]]; then
        tmp=$(mktemp) || return 1
        if download_to "$src" "$tmp" && install_binary_file "$tmp"; then
            rm -f "$tmp"
        else
            rm -f "$tmp"
            err "Download/installation failed."
            return 1
        fi
    else
        err "Not a file and not an http(s) URL."
        return 1
    fi
    ok "$CORE_NAME installed."
    show_bin_info
}

# ------------------------------------------------------------------------------
# interactive choices shared by setup / update
# ------------------------------------------------------------------------------
choose_link() {
    local c
    echo
    info "Tunnel link type (must be the same on both servers):"
    echo "   1) GRE     - layer-3 point-to-point, lowest overhead"
    echo "   2) GRETAP  - layer-2 Ethernet over GRE (what v3.x used)"
    MENU_MAX=2
    ask_valid c "Select link type" "2" valid_menu "Enter 1 or 2."
    if (( 10#$c == 1 )); then LINK_TYPE=gre; else LINK_TYPE=gretap; fi
}

choose_ipset() {
    local c i
    echo
    info "Local tunnel IP pair - used by the core to connect server <-> client and to carry the tunnel traffic:"
    for i in "${!IPSET_IR[@]}"; do
        printf '   %d) Iran %-14s <->  Kharej %-14s (/%s)\n' $((i + 1)) "${IPSET_IR[i]}" "${IPSET_KH[i]}" "${IPSET_PFX[i]}"
    done
    MENU_MAX=${#IPSET_IR[@]}
    ask_valid c "Select IP pair (must be the same on both servers)" "1" valid_menu "Enter a number from 1 to $MENU_MAX."
    c=$((10#$c - 1))
    TUN_IR_IP=${IPSET_IR[c]}
    TUN_KH_IP=${IPSET_KH[c]}
    PFX=${IPSET_PFX[c]}
}

choose_core() {
    local c
    echo
    info "Tunnel core (must be the same on both servers):"
    echo "   1) Backhaul        - protocols: ${BH_PROTOS[*]}"
    echo "   2) FRP v$FRP_VERSION  - protocols: ${FRP_PROTOS[*]}"
    MENU_MAX=2
    ask_valid c "Select core" "1" valid_menu "Enter 1 or 2."
    if (( 10#$c == 2 )); then CORE=frp; else CORE=backhaul; fi
}

choose_proto() { # needs CORE
    local -a names=() descs=()
    local i c
    if [[ $CORE == frp ]]; then
        names=("${FRP_PROTOS[@]}")
        descs=("${FRP_DESCS[@]}")
    else
        names=("${BH_PROTOS[@]}")
        descs=("${BH_DESCS[@]}")
    fi
    echo
    info "$CORE_NAME protocol (must be the same on both servers):"
    for i in "${!names[@]}"; do
        printf '   %d) %-10s %s\n' $((i + 1)) "${names[i]}" "${descs[i]}"
    done
    MENU_MAX=${#names[@]}
    ask_valid c "Select protocol" "1" valid_menu "Enter a number from 1 to $MENU_MAX."
    PROTO=${names[$((10#$c - 1))]}
}

choose_role() {
    local c
    echo "   1) IRAN server    2) KHAREJ client"
    MENU_MAX=2
    ask_valid c "Role" "1" valid_menu "Enter 1 or 2."
    if (( 10#$c == 2 )); then ROLE=kharej; else ROLE=iran; fi
}

prompt_ports() {
    local raw m pub conflicts msg
    while true; do
        if [[ $ROLE == iran ]]; then
            msg="Ports to forward (e.g. 1080,443  -  use 8443=443 for public 8443 -> Kharej 443)"
        else
            msg="Ports to expose - the SAME list as on the Iran server (A=B: Iran port A -> a service on THIS server's port B)"
        fi
        ask raw "$msg" ""
        if ! parse_ports "$raw"; then
            err "Enter at least one valid port."
            continue
        fi
        [[ $ROLE == iran ]] || return 0
        conflicts=""
        for m in "${PORT_MAP[@]}"; do
            pub=${m%%=*}
            if [[ ${FWD_TCP:-1} == 1 ]]; then
                conflicts+=$(listener_conflicts tcp "$pub" | sed "s/^/tcp $pub: /")$'\n'
            fi
            if [[ ${FWD_UDP:-0} == 1 ]]; then
                conflicts+=$(listener_conflicts udp "$pub" | sed "s/^/udp $pub: /")$'\n'
            fi
        done
        conflicts=$(echo "$conflicts" | sed '/^$/d')
        [[ -z $conflicts ]] && return 0
        warn "These ports are already used by another program on this server:"
        echo "$conflicts" | sed 's/^/        /'
        warn "The core cannot bind them, and the other program would answer instead of the tunnel."
        ask_yn "Enter a different port list?" y || return 0
    done
}

print_summary() {
    echo
    echo -e "${CYAN}--------------- configuration summary ($ROLE) ---------------${NC}"
    echo "  Link      : $LINK_LABEL ($IFACE)   public IPs: this $LOCAL_IP <-> peer $REMOTE_IP"
    echo "  Tunnel IPs: Iran $TUN_IR_IP <-> Kharej $TUN_KH_IP (/$PFX)   this server: $SELF_IP"
    echo "  Core      : $CORE_NAME   protocol: $PROTO"
    echo "  Control   : $TUN_IR_IP:$CTRL_PORT (inside the tunnel)"
    echo "  Token     : $TOKEN"
    if [[ -n ${PORTS:-} ]]; then
        echo "  Ports     : ${PORTS// /, }   (TCP: $([[ ${FWD_TCP:-1} == 1 ]] && echo yes || echo no), UDP: $([[ ${FWD_UDP:-0} == 1 ]] && echo yes || echo no))"
    fi
    echo -e "${CYAN}-------------------------------------------------------------${NC}"
}

# ------------------------------------------------------------------------------
# setup
# ------------------------------------------------------------------------------
setup_tunnel() { # iran | kharej
    ROLE=$1
    local def_ip def_port c lbl_local lbl_remote start_ts
    if [[ $ROLE == iran ]]; then
        lbl_local="IRAN server"; lbl_remote="KHAREJ client"
    else
        lbl_local="KHAREJ client"; lbl_remote="IRAN server"
    fi
    echo -e "\n${CYAN}--- Configuring $lbl_local ---${NC}"

    ensure_deps || return 1

    choose_link
    choose_ipset
    choose_core
    set_link_vars
    set_core_vars
    set_role_ips
    choose_proto

    echo
    def_ip=$(detect_ip)
    ask_valid LOCAL_IP "Enter $lbl_local public IP" "$def_ip" valid_ipv4 "Not a valid IPv4 address."
    ask_valid REMOTE_IP "Enter $lbl_remote public IP" "" valid_ipv4 "Not a valid IPv4 address."
    if [[ $LOCAL_IP == "$REMOTE_IP" ]]; then
        err "Local and remote IP are identical."
        return 1
    fi

    def_port=3080
    [[ $CORE == frp ]] && def_port=7000
    while true; do
        ask_valid CTRL_PORT "$CORE_NAME control port (reached INSIDE the tunnel)" "$def_port" valid_port "Port must be 1-65535."
        [[ $ROLE == iran ]] || break
        c=$(ctrl_conflicts)
        [[ -z $c ]] && break
        err "Port $CTRL_PORT is already used on this server by:"
        echo "$c" | sed 's/^/        /'
        err "The $CORE_NAME client would connect to THAT program, which hangs up or ignores it."
        warn "Pick another port (for example $(pick_free_port))."
    done

    ask_valid TOKEN "Tunnel secret token (must be identical on both sides)" "123456" valid_token "1-64 chars from: A-Z a-z 0-9 . _ ~ @ % + = -"
    [[ $TOKEN == "123456" ]] && warn "Using the default token. The control port is only reachable inside the tunnel, but a custom token is better."

    ACCEPT_UDP=0
    PORTS=""
    if [[ $CORE == backhaul && $PROTO == tcp ]]; then
        ask_yn "Also forward UDP on those ports (Backhaul UDP-over-TCP)? (same answer on both servers)" n && ACCEPT_UDP=1
    elif [[ $CORE == frp ]]; then
        ask_yn "Also forward UDP on those ports (native FRP UDP proxies)? (same answer on both servers)" n && ACCEPT_UDP=1
    elif [[ $CORE == backhaul && $PROTO == udp ]]; then
        info "Backhaul 'udp' transport forwards UDP ports only (no TCP)."
    fi
    set_fwd_flags
    if [[ $ROLE == iran || $CORE == frp ]]; then
        if [[ $CORE == frp && $ROLE == kharej ]]; then
            warn "FRP: the Kharej client defines the proxies, so the port list is needed here too (must match the Iran server)."
        fi
        prompt_ports
        PORTS="${PORT_MAP[*]}"
    fi
    print_summary
    ask_yn "Apply this configuration now?" y || { warn "Aborted - nothing was changed."; return 1; }

    fetch_core_binary 0 || { err "Cannot continue without the $CORE_NAME binary."; return 1; }
    if [[ $ROLE == iran && ( $PROTO == wss || $PROTO == wssmux ) && $CORE == backhaul ]]; then
        ensure_tls_cert || return 1
    fi

    start_ts=$(date '+%Y-%m-%d %H:%M:%S')
    info "Stopping old services (their own stop hooks remove old firewall rules)..."
    stop_services
    rm -f "$CONFIG_DIR/gretap-up.sh" "$CONFIG_DIR/gretap-down.sh" \
          "$CONFIG_DIR/config.toml" "$CONFIG_DIR/frps.toml" "$CONFIG_DIR/frpc.toml"

    save_conf
    write_core_conf
    write_ctl_script
    write_units

    info "Starting $LINK_LABEL + $CORE_NAME..."
    if ! systemctl restart "$LINK_SVC"; then
        err "$LINK_LABEL service failed to start:"
        journalctl -u "$LINK_SVC" -n 15 --no-pager -o cat
        return 1
    fi
    systemctl restart "$CORE_SVC"

    verify_setup "$start_ts"

    echo
    echo -e "${CYAN}Enter the SAME values on the other server:${NC}"
    echo "  link type: $LINK_TYPE | IP pair: $TUN_IR_IP / $TUN_KH_IP | core: $CORE | protocol: $PROTO | control port: $CTRL_PORT | token: $TOKEN"
    if [[ $CORE == frp ]]; then
        echo "  ports (FRP needs them on BOTH servers): ${PORTS// /,}   UDP: $([[ ${FWD_UDP:-0} == 1 ]] && echo yes || echo no)"
    fi
    if [[ $ROLE == kharej ]]; then
        echo
        warn "The core forwards every tunneled port to 127.0.0.1:<target port> ON THIS (Kharej) MACHINE."
        warn "A real service (SOCKS/Xray/...) must listen there, otherwise the tunnel is up but the forwarded connection is refused."
    else
        echo
        info "Forwarded ports on this server are opened by the core only AFTER the Kharej client has connected."
    fi
}

core_log() { # n [since]
    journalctl -u "$CORE_SVC" ${2:+--since "$2"} -n "${1:-200}" --no-pager -o cat 2>/dev/null | strip_ansi
}

# is the control port really owned by our core, for the chosen protocol?
ctrl_ok() {
    local tcp udp
    tcp=$(ss -H -ltnp "sport = :$CTRL_PORT" 2>/dev/null | grep -c "$CORE_PROC")
    udp=$(ss -H -lunp "sport = :$CTRL_PORT" 2>/dev/null | grep -c "$CORE_PROC")
    case "$CORE:$PROTO" in
        frp:kcp|frp:quic)  (( tcp > 0 && udp > 0 )) ;;
        *)                 (( tcp > 0 )) ;;   # backhaul "udp": control channel is TCP, UDP listener appears after the client connects
    esac
}

# Backhaul "udp" transport: the server opens its UDP listener only AFTER the control channel is up.
# On a very fast link the client's first UDP packets can arrive too early ("connection refused") and its
# UDP workers stop. Restarting the client once (the server is ready by then) fixes it.
udp_client_settle() {
    local ts
    sleep 3
    if ! core_log 100 | grep -q "failed to receive response from server"; then
        res ok "UDP data path looks healthy"
        return 0
    fi
    warn "Backhaul udp: the client raced the server's UDP listener - restarting the client once."
    ts=$(date '+%Y-%m-%d %H:%M:%S')
    systemctl restart "$CORE_SVC"
    sleep 5
    if core_log 100 "$ts" | grep -q "failed to receive response from server"; then
        res bad "UDP data path still failing - run Diagnose, then restart the client (menu 6)"
        return 1
    fi
    res ok "UDP data path is up after the restart"
}

verify_frp_proxies() { # since
    local ts=$1 want n=0 i log bad
    want=$(( $(wc -w <<< "$PORTS") * (1 + ${FWD_UDP:-0}) ))
    for i in $(seq 1 10); do
        log=$(core_log 300 "$ts")
        n=$(grep -c "start proxy success" <<< "$log")
        (( n >= want )) && break
        sleep 1
    done
    if (( n >= want )); then
        res ok "$n/$want FRP proxies registered on the Iran server"
        return 0
    fi
    res bad "only $n/$want FRP proxies registered"
    bad=$(grep "start error" <<< "$log" | tail -n 4)
    [[ -n $bad ]] && echo "$bad" | sed 's/^/        /'
    if grep -q "port not allowed" <<< "$bad"; then
        echo "    -> 'port not allowed': the port list on the Iran server differs from this one (update ports on the IRAN server: menu 5)."
    elif grep -q "already used" <<< "$bad"; then
        echo "    -> 'already used': another program on the Iran server owns that port."
    fi
    return 1
}

verify_setup() { # start_ts
    local ts=$1 i log errs
    echo
    info "Verifying (up to 25 s)..."
    if [[ $ROLE == iran ]]; then
        for i in $(seq 1 15); do
            if systemctl is-active -q "$CORE_SVC" && ctrl_ok; then
                res ok "$CORE_NAME server is listening on $TUN_IR_IP:$CTRL_PORT ($PROTO)"
                return 0
            fi
            sleep 1
        done
        res bad "$CORE_NAME server is NOT listening on port $CTRL_PORT"
        core_log 15 "$ts" | tail -n 15
        echo "    -> run menu option 4 (Diagnose) to see who owns the port / why it exits."
        return 1
    fi

    for i in $(seq 1 25); do
        log=$(core_log 300 "$ts")
        if grep -qiE "$LOG_OK_RE" <<< "$log"; then
            res ok "Control channel established with $TUN_IR_IP:$CTRL_PORT"
            [[ $CORE == frp ]] && verify_frp_proxies "$ts"
            [[ $CORE == backhaul && $PROTO == udp ]] && udp_client_settle
            return 0
        fi
        sleep 1
    done
    errs=$(grep -cE "$LOG_ERR_RE" <<< "$log")
    if (( errs > 0 )); then
        res bad "Control channel NOT established. Last messages:"
        grep -E "$LOG_ERR_RE" <<< "$log" | tail -n 6 | sed 's/^/        /'
        if grep -qi "refused" <<< "$log"; then
            echo "    -> 'connection refused': the Iran $CORE_NAME server is not running/listening on $TUN_IR_IP:$CTRL_PORT."
        elif grep -qi "token" <<< "$log"; then
            echo "    -> token mismatch: use the same token on both servers."
        elif grep -q "EOF" <<< "$log"; then
            echo "    -> 'EOF': TCP connects but the other end hangs up at once. Most common causes:"
            echo "       a) another program owns port $CTRL_PORT on the Iran server (Diagnose on Iran shows it)"
            echo "       b) token or protocol differ between the two servers"
            echo "       c) the two servers run different binaries/versions (menu option 7)"
        elif grep -qiE "timeout|timed out" <<< "$log"; then
            echo "    -> timeouts: packets get lost inside the tunnel (MTU / GRE filtering). Run Diagnose."
        fi
        return 1
    fi
    res warn "No result yet - check again with menu option 3 / 4 in a few seconds."
    return 0
}

# ------------------------------------------------------------------------------
# status / diagnose
# ------------------------------------------------------------------------------
client_state() { # up | down | unknown (based on recent client log lines)
    local log last_ok last_err
    log=$(core_log 200)
    last_ok=$(grep -n -i -E "$LOG_OK_RE" <<< "$log" | tail -n1 | cut -d: -f1)
    last_err=$(grep -n -E "$LOG_ERR_RE" <<< "$log" | tail -n1 | cut -d: -f1)
    if [[ -n $last_ok ]] && { [[ -z $last_err ]] || (( last_ok > last_err )); }; then
        echo up
    elif [[ -n $last_err ]]; then
        echo down
    else
        echo unknown
    fi
}

show_status() {
    load_conf || { err "Not configured yet - run option 1 or 2 first."; return 1; }
    echo -e "\n${CYAN}================ TUNNEL STATUS ($ROLE) ================${NC}"
    echo "  Link       : $LINK_LABEL ($IFACE)   public: local $LOCAL_IP <-> peer $REMOTE_IP"
    echo "  Tunnel IPs : $SELF_IP <-> $PEER_IP (/$PFX)"
    echo "  Core       : $CORE_NAME   protocol: $PROTO   control: $TUN_IR_IP:$CTRL_PORT"
    if [[ -n ${PORTS:-} ]]; then
        echo "  Forwarded  : $PORTS   (TCP: $([[ $FWD_TCP == 1 ]] && echo yes || echo no), UDP: $([[ $FWD_UDP == 1 ]] && echo yes || echo no))"
    fi

    echo
    if ip link show "$IFACE" >/dev/null 2>&1 && ip -4 addr show dev "$IFACE" | grep -q "inet $SELF_IP/"; then
        echo -e "  ${GREEN}[*] $IFACE: UP ($SELF_IP, mtu $(cat /sys/class/net/$IFACE/mtu 2>/dev/null))${NC}"
        if ping -c 2 -W 2 "$PEER_IP" >/dev/null 2>&1; then
            echo -e "  ${GREEN}[*] ping $PEER_IP: SUCCESS${NC}"
        else
            echo -e "  ${RED}[x] ping $PEER_IP: FAILED${NC}"
        fi
    else
        echo -e "  ${RED}[x] $IFACE: DOWN / no $SELF_IP${NC}"
    fi

    local s
    for s in "$LINK_SVC" "$CORE_SVC"; do
        if systemctl is-active -q "$s"; then
            echo -e "  ${GREEN}[*] $s: active${NC}"
        else
            echo -e "  ${RED}[x] $s: $(systemctl is-active "$s")${NC}"
        fi
    done

    if [[ $ROLE == iran ]]; then
        echo -e "\n${CYAN}[*] Listeners (control port + forwarded ports):${NC}"
        ss -H -ltunp 2>/dev/null | grep "$CORE_PROC" | awk '{print "    " $1 "  " $5}' || true
    else
        echo -e "\n  Tunnel state (from client log): $(client_state)"
    fi

    echo -e "\n${CYAN}[*] Recent $CORE_NAME log:${NC}"
    core_log 10 | sed 's/^/    /'

    echo -e "\n${CYAN}[*] Firewall rules owned by this tunnel (tag BHGT):${NC}"
    local t
    for t in filter nat mangle; do
        iptables -t "$t" -S 2>/dev/null | grep -- "--comment" | grep BHGT | sed "s/-m comment --comment \"\\?BHGT\"\\? //; s/^/    [$t] /"
    done
    echo -e "${CYAN}===============================================${NC}\n"
}

diagnose() {
    load_conf || { err "Not configured yet - run option 1 or 2 first."; return 1; }
    echo -e "\n${CYAN}================ DIAGNOSE ($ROLE | $LINK_LABEL | $CORE_NAME/$PROTO) ================${NC}"

    echo -e "\n${CYAN}1) Binary${NC}"
    if [[ -x $CORE_BIN ]] && is_elf "$CORE_BIN"; then
        res ok "$CORE_BIN  [$(bin_version | cut -c1-50)]  sha256=$(sha256sum "$CORE_BIN" | cut -c1-16)..."
        echo "      (compare the version/sha256 with the other server)"
    else
        res bad "$CORE_NAME binary missing/invalid: $CORE_BIN  -> menu option 7"
    fi

    echo -e "\n${CYAN}2) Services${NC}"
    if systemctl is-active -q "$LINK_SVC"; then res ok "$LINK_SVC active"; else res bad "$LINK_SVC is $(systemctl is-active "$LINK_SVC")"; fi
    if systemctl is-active -q "$CORE_SVC"; then
        res ok "$CORE_SVC active (restarts so far: $(systemctl show -p NRestarts --value "$CORE_SVC" 2>/dev/null || echo '?'))"
    else
        res bad "$CORE_SVC is $(systemctl is-active "$CORE_SVC") (crash loop? see the log below)"
    fi

    echo -e "\n${CYAN}3) $LINK_LABEL link${NC}"
    if ip -4 addr show dev "$IFACE" 2>/dev/null | grep -q "inet $SELF_IP/"; then
        res ok "$IFACE has $SELF_IP (mtu $(cat /sys/class/net/$IFACE/mtu 2>/dev/null))"
        if ! ip -d link show "$IFACE" 2>/dev/null | grep -q "remote $REMOTE_IP"; then
            res warn "$IFACE does not point at remote $REMOTE_IP (wrong peer IP, or the link type differs from the other server)"
        fi
        if ping -c 2 -W 2 "$PEER_IP" >/dev/null 2>&1; then
            res ok "ping $PEER_IP works"
            local sz best=0
            for sz in 1372 1340 1300 1240 1200 1100 1000; do
                if ping -M "do" -c 1 -W 2 -s "$sz" "$PEER_IP" >/dev/null 2>&1; then best=$sz; break; fi
            done
            if (( best == 1372 )); then
                res ok "full-size packets (mtu 1400) pass without fragmentation"
            elif (( best > 0 )); then
                res warn "largest unfragmented ping payload is $best (< 1372): the real path MTU is below 1400 -> lower MTU_VAL/MSS_VAL"
            else
                res bad "even 1000-byte DF pings are lost: MTU black hole or GRE filtering for larger packets"
            fi
        else
            res bad "ping $PEER_IP fails: GRE between $LOCAL_IP and $REMOTE_IP is blocked, the peer is not running, or link type / IP pair differ between the servers"
        fi
    else
        res bad "$IFACE missing or has no $SELF_IP"
    fi

    local m pub owners proto fl
    if [[ $ROLE == iran ]]; then
        echo -e "\n${CYAN}4) Control port $CTRL_PORT on this server${NC}"
        owners=$(ss -H -ltunp "sport = :$CTRL_PORT" 2>/dev/null)
        if [[ -z $owners ]]; then
            res bad "NOTHING listens on port $CTRL_PORT -> the Kharej client gets 'connection refused'"
        elif ctrl_ok; then
            res ok "$CORE_PROC listens: $(awk '{print $1 " " $5}' <<< "$owners" | paste -sd, -)"
        elif grep -q "$CORE_PROC" <<< "$owners"; then
            res warn "$CORE_PROC listens only partly for protocol '$PROTO':"
            echo "$owners" | sed 's/^/        /'
        else
            res bad "Port $CTRL_PORT is owned by ANOTHER program (the Kharej client talks to it, not to $CORE_NAME):"
            echo "$owners" | sed 's/^/        /'
            echo "      -> stop that program or run setup again with a different control port."
        fi

        echo -e "\n${CYAN}5) Forwarded ports${NC}"
        for m in $PORTS; do
            pub=${m%%=*}
            for proto in tcp udp; do
                [[ $proto == tcp && $FWD_TCP != 1 ]] && continue
                [[ $proto == udp && $FWD_UDP != 1 ]] && continue
                fl="-ltnpH"; [[ $proto == udp ]] && fl="-lunpH"
                if iptables -t nat -S PREROUTING 2>/dev/null | grep -q -- "-p $proto .*--dport $pub .*BHGT"; then
                    res ok "$proto DNAT rule for port $pub present"
                else
                    res bad "$proto DNAT rule for port $pub missing (menu 6 to reload)"
                fi
                if ss $fl "sport = :$pub" 2>/dev/null | grep -q "$CORE_PROC"; then
                    res ok "$CORE_NAME listens on $proto port $pub"
                elif [[ -n $(ss $fl "sport = :$pub" 2>/dev/null) ]]; then
                    res bad "$proto port $pub is held by another program: $(ss $fl "sport = :$pub" | awk '{print $6}' | head -n1)"
                else
                    res warn "nothing listens on $proto $pub yet (normal until the Kharej client has connected$([[ $CORE == frp ]] && echo ' and registered this port'))"
                fi
            done
        done
    else
        echo -e "\n${CYAN}4) Reaching the Iran control port${NC}"
        local state rc
        state=$(client_state)
        if [[ $state == up ]]; then
            res ok "Tunnel is established (client log); skipping the raw probe so it cannot disturb live traffic"
        else
            timeout 3 bash -c "exec 3<>/dev/tcp/$PEER_IP/$CTRL_PORT" 2>/dev/null
            rc=$?
            case $rc in
                0)   res warn "TCP connect to $PEER_IP:$CTRL_PORT works but no tunnel is established -> the program there hangs up (port owner / token / protocol / binary mismatch). Run Diagnose on the IRAN server." ;;
                124) res bad "TCP connect to $PEER_IP:$CTRL_PORT TIMED OUT (packets dropped inside the tunnel: MTU/firewall)" ;;
                *)   res bad "TCP connect to $PEER_IP:$CTRL_PORT REFUSED: nothing listens there (Iran $CORE_NAME not running / different port)" ;;
            esac
        fi
        if [[ $CORE == frp ]]; then
            echo -e "\n${CYAN}5) FRP proxies${NC}"
            local started bad
            started=$(core_log 300 | grep -c "start proxy success")
            bad=$(core_log 300 | grep "start error" | tail -n 3)
            if [[ -n $bad ]]; then
                res bad "some proxies failed to start:"
                echo "$bad" | sed 's/^/        /'
                echo "      -> 'port not allowed' = the port list on the Iran server differs from this one."
            elif (( started > 0 )); then
                res ok "$started proxy start message(s) in the recent log"
            else
                res warn "no proxy has been started yet (not logged in?)"
            fi
        fi
        echo
        if ask_yn "Test local target ports on this Kharej server? (e.g. is your SOCKS/Xray listening)" n; then
            local raw
            ask raw "Target ports, comma separated" "${PORTS// /,}"
            if parse_ports "$raw"; then
                for m in "${PORT_MAP[@]}"; do
                    pub=${m#*=}
                    if timeout 2 bash -c "exec 3<>/dev/tcp/127.0.0.1/$pub" 2>/dev/null; then
                        res ok "127.0.0.1:$pub accepts connections"
                    else
                        res bad "127.0.0.1:$pub refuses connections: forwarded traffic to it will fail"
                    fi
                done
            fi
        fi
    fi

    echo -e "\n${CYAN}Other NAT rules that could hijack traffic${NC}"
    local foreign
    foreign=$(iptables -t nat -S 2>/dev/null | grep -E -- "-j (DNAT|REDIRECT)" | grep -v BHGT | head -n 8)
    if [[ -n $foreign ]]; then
        res warn "foreign DNAT/REDIRECT rules exist (tunnel traffic is exempted, but check them):"
        echo "$foreign" | sed 's/^/        /'
    else
        res ok "none"
    fi

    echo -e "\n${CYAN}Recent $CORE_NAME log${NC}"
    core_log 12 | sed 's/^/    /'

    echo -e "\n${CYAN}How to read common errors${NC}"
    if [[ $CORE == frp ]]; then
        echo "    'connect to server error ... refused/timeout' : frps is not reachable (service down, wrong control port, or the link is down)."
        echo "    'token in login doesn't match'                : different tokens on the two servers."
        echo "    'port not allowed'                            : the port list differs between Iran and Kharej (FRP needs it on both)."
    else
        echo "    'failed to receive response from server ... refused' (udp protocol): the client sent UDP before the Iran UDP"
        echo "    listener was ready -> restart the Kharej client (menu 6)."
        echo "    'failed to read message length ... EOF' on the Kharej client: the TCP connection worked, then the other end"
        echo "    closed it at once. With matching tokens the thing answering is not your Backhaul server (port owner, see Iran"
        echo "    step 4), uses another protocol, or is a different Backhaul build (compare sha256 in step 1 on both servers)."
    fi
    echo -e "${CYAN}======================================================${NC}\n"
}

# ------------------------------------------------------------------------------
# other menu actions
# ------------------------------------------------------------------------------
update_ports() {
    load_conf || { err "Not configured yet."; return 1; }
    if [[ $ROLE != iran && $CORE != frp ]]; then
        err "Backhaul forwarded ports are configured on the IRAN server only."
        return 1
    fi
    info "Current forwarded ports: ${PORTS:-none}"
    if [[ $CORE == frp ]]; then
        warn "FRP: enter the SAME port list on BOTH servers (Iran: firewall + allowPorts, Kharej: proxies)."
    fi
    prompt_ports
    PORTS="${PORT_MAP[*]}"
    save_conf
    write_core_conf
    "$CTL_SH" reload
    systemctl restart "$CORE_SVC"
    ok "Forwarded ports updated: $PORTS"
}

restart_services() {
    load_conf || { err "Not configured yet."; return 1; }
    systemctl restart "$LINK_SVC" "$CORE_SVC"
    ok "$LINK_LABEL and $CORE_NAME restarted."
}

binary_menu() {
    local configured=1
    if ! load_conf; then
        configured=0
        info "No tunnel configured yet - choose which binary to inspect/install."
        choose_core
        choose_role
        set_core_vars
    fi
    echo
    info "Current $CORE_NAME binary:"
    show_bin_info
    echo
    if ask_yn "Download/replace the binary now?" n; then
        fetch_core_binary 1 || return 1
        if (( configured )) && [[ -f $CORE_CONF ]]; then
            systemctl restart "$CORE_SVC"
            ok "$CORE_NAME restarted with the new binary. Do the same on the other server!"
        fi
    fi
}

follow_log() {
    load_conf || { err "Not configured yet."; return 1; }
    journalctl -u "$CORE_SVC" -f -o cat
}

uninstall_all() {
    local b
    echo
    warn "This removes the tunnel, services, firewall rules and config of THIS tunnel only."
    ask_yn "Really uninstall?" n || return 0
    systemctl stop "$BACKHAUL_SVC" "$FRP_SVC" "$LINK_SVC" >/dev/null 2>&1
    systemctl disable "$BACKHAUL_SVC" "$FRP_SVC" "$LINK_SVC" >/dev/null 2>&1
    for b in "$BACKHAUL_BIN" "$FRPS_BIN" "$FRPC_BIN"; do
        pkill -f -- "$b -c $CONFIG_DIR/" 2>/dev/null
    done
    [[ -x $CTL_SH ]] && "$CTL_SH" down
    rm -f "$UNIT_DIR/$BACKHAUL_SVC" "$UNIT_DIR/$FRP_SVC" "$UNIT_DIR/$LINK_SVC"
    systemctl daemon-reload
    ip link del gretun1 2>/dev/null
    ip link del gretap1 2>/dev/null
    rm -rf "$CONFIG_DIR"
    rm -f "$BACKHAUL_BIN" "$FRPS_BIN" "$FRPC_BIN"
    ok "Tunnel, services and firewall rules removed (the shared $LEGACY_BIN, if any, was not touched)."
}

main_menu() {
    local choice
    while true; do
        clear
        echo -e "${CYAN}========================================================${NC}"
        echo -e "${GREEN}   GRE/GRETAP + Backhaul/FRP Reverse Tunnel Manager v$VERSION  ${NC}"
        if load_conf 2>/dev/null; then
            echo -e "${CYAN}   Active: $ROLE | $LINK_LABEL | $CORE_NAME/$PROTO | $SELF_IP${NC}"
        else
            echo -e "${CYAN}   Not configured yet${NC}"
        fi
        echo -e "${CYAN}========================================================${NC}"
        echo -e " 1) Configure ${GREEN}IRAN Server${NC}   (link + core server + port forward)"
        echo -e " 2) Configure ${YELLOW}KHAREJ Client${NC} (link + core client)"
        echo -e " 3) Status & logs"
        echo -e " 4) Diagnose connection  ${CYAN}(use this when something fails)${NC}"
        echo -e " 5) Update forwarded ports (Iran; FRP: both servers)"
        echo -e " 6) Restart tunnel services"
        echo -e " 7) Check / reinstall core binary (version + sha256)"
        echo -e " 8) Follow live core log (Ctrl+C to stop)"
        echo -e " 9) ${RED}Uninstall tunnel completely${NC}"
        echo -e " 0) Exit"
        echo -e "${CYAN}========================================================${NC}"
        read -r -p "Select an option [0-9]: " choice || exit 0
        case $choice in
            1) setup_tunnel iran;   pause ;;
            2) setup_tunnel kharej; pause ;;
            3) show_status;         pause ;;
            4) diagnose;            pause ;;
            5) update_ports;        pause ;;
            6) restart_services;    pause ;;
            7) binary_menu;         pause ;;
            8) follow_log ;;
            9) uninstall_all;       pause ;;
            0) exit 0 ;;
            *) err "Invalid option!"; sleep 1 ;;
        esac
    done
}

# run the menu unless the file is being sourced (e.g. for testing)
if [[ ${BASH_SOURCE[0]} == "$0" ]]; then
    main_menu
fi
