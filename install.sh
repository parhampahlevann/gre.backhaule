#!/bin/bash
# ==============================================================================
# GRE / GRETAP / Direct + Backhaul/FRP  Reverse Tunnel Manager  v6.2
#
#   Iran  server : TUN_IR_IP   <== GRE, GRETAP or Direct (MTU/MSS fixed in GRE/GRETAP) ==>   Kharej client : TUN_KH_IP
#
# Data path
#   user (IPv4 or IPv6) -> Iran public IP:PORT (core dual-stack [::]:PORT listener)
#        -> core control + data channels travel INSIDE the GRE/GRETAP link, or straight
#           over the public IP when Direct mode is used
#        -> core client on Kharej -> 127.0.0.1:TARGET_PORT on the Kharej box
#
# Fixed in v6.2
#   1. Dual-stack IPv4+IPv6 port forwarding on Iran for BOTH Backhaul and FRP
#      across ALL link types (Direct, GRE, GRETAP):
#      - Control port stays strictly isolated on TUN_IR_IP:CTRL_PORT.
#      - Forwarded ports bind dual-stack [::]:PORT (with net.ipv6.bindv6only=0)
#        for Backhaul ("[::]:pub=127.0.0.1:tgt") and FRP (proxyBindAddr = "::"),
#        falling back to 0.0.0.0 only if IPv6 is disabled in the kernel.
#      - Both iptables and ip6tables INPUT rules are opened for forwarded ports.
#   2. IPv6 GRE/GRETAP connectivity fixes:
#      - Added `ip -6 link add ... hoplimit 255 encaplimit none` + `ip6_tunnel`
#        module so Linux does not prepend an IPv6 DSTOPS extension header that
#        breaks ip6tables GRE matching and ISP/DC filters.
#      - Adjusted IPv6 GRE/GRETAP MTU to 1360 (MSS stays fixed at 1240) to avoid
#        IPv6 outer-packet MTU black-holing (IPv6 routers never fragment).
#      - Added `net.ipv4.conf.all.rp_filter=0` (Linux uses max(all, iface)).
#      - Opened IPv6 protocol 47 (INPUT/OUTPUT) and ICMPv6 (for PMTUD/NDP).
#   3. Fixed `ipt6_filter_ensure` putting `-m comment` after `-j ACCEPT`, which
#      caused rule insertion/check/purge failures on ip6tables-nft. `purge_rules`
#      now always cleans both iptables and ip6tables tags regardless of IP_VER.
#   4. Fixed FRP `transport.tcpMux` mismatch on gaming/balance profiles (frps
#      defaulted to true while frpc set false -> instant EOF), synced
#      `transport.heartbeatTimeout`, and checked both TCP+UDP for FRP kcp/quic
#      control port conflicts.
#   5. Fixed IPv6 `prestart` (uses `ping -6`, waits for non-tentative IPv6 DAD
#      on Iran Direct mode), canonicalized IPv6 addresses (RFC 5952), improved
#      `detect_ip` IPv6 fallback, and skipped Iran-only port-conflict checks
#      when entering FRP ports on Kharej.
# ==============================================================================

VERSION="6.2"

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
LEGACY_BIN="/usr/local/bin/backhaul"
# legacy (v4.0 ini-based FRP) paths - only used to clean up a previous FRP
# install, never written again. NOT the same paths as the new FRP core below.
LEGACY_FRPS_BIN="/usr/local/bin/frps-gretap"
LEGACY_FRPC_BIN="/usr/local/bin/frpc-gretap"
LEGACY_FRP_SVC="frp-tunnel.service"

# the new, supported FRP core (v6.0+)
FRP_VERSION="0.61.1"
FRPS_BIN="/usr/local/bin/frps-core"
FRPC_BIN="/usr/local/bin/frpc-core"

UNIT_DIR="/etc/systemd/system"
LINK_SVC="gretap-tunnel.service"
BACKHAUL_SVC="backhaul-tunnel.service"
FRP_SVC="frp-tunnel.service"

# MTU/MSS are fixed per underlay IP version and NEVER change with protocol,
# profile or core, so they are always identical on Iran and Kharej. They only
# apply to GRE/GRETAP link types (Direct mode has no extra header).
MSS_VAL="1240"
MTU_VAL_V4="1400"
MTU_VAL_V6="1360"
MTU_VAL="$MTU_VAL_V4"

# local tunnel IP pairs (index 0 = option 1, index 1 = option 2) - unused in Direct mode
IPSET_IR=("10.0.0.1"  "203.0.113.10")
IPSET_KH=("10.0.0.2"  "203.0.113.20")
IPSET_PFX=("30"       "27")

# tunnel cores
CORES=(backhaul frp)
CORE_DESCS=(
    "Backhaul - lean reverse tunnel, fewest moving parts (recommended)"
    "FRP v$FRP_VERSION - fast reverse proxy, adds kcp/quic/websocket transports"
)

# Backhaul transports
BACKHAUL_PROTOS=(tcp tcpmux udp ws wsmux wss wssmux)
BACKHAUL_PROTO_DESCS=(
    "plain TCP: lowest overhead, fastest in most cases (recommended)"
    "TCP + multiplexing: many small connections over few sockets"
    "UDP transport: forwards UDP ports only (games, VoIP, DNS, WireGuard...)"
    "WebSocket over TCP"
    "WebSocket + multiplexing"
    "WebSocket + TLS (a self-signed certificate is generated on the Iran server)"
    "WebSocket + TLS + multiplexing"
)

# FRP transports
FRP_PROTOS=(tcp kcp quic websocket wss)
FRP_PROTO_DESCS=(
    "plain TCP: lowest overhead, fastest in most cases (recommended; TLS is already on by default)"
    "KCP: UDP-based, often better on lossy/high-latency links, more CPU/bandwidth"
    "QUIC: UDP-based, multiplexed, good on lossy/high-latency links"
    "WebSocket: rides as HTTP(S)-looking traffic, useful behind strict filters"
    "WebSocket + explicit TLS (wss)"
)

# connection profiles (must be the same on both servers, same menu for either core)
PROFILES=(gaming fast balance turbo)
PROFILE_DESCS=(
    "lowest ping/jitter: fast heartbeat, instant reconnect, small buffers"
    "very high speed, still low latency/jitter, light overhead (recommended)"
    "general purpose default - good all-round choice for everyday use"
    "max throughput for downloads/transfers: big buffers, more pooled connections"
)

# tunnel link types
LINK_TYPES=(gre gretap direct)
LINK_TYPE_DESCS=(
    "GRE     - layer-3 point-to-point, lowest overhead"
    "GRETAP  - layer-2 Ethernet over GRE (what older versions used)"
    "Direct  - no GRE/GRETAP: the core connects straight over the public IP (best with IPv6, skips the tunnel IP pair)"
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

valid_ipv6() {
    local ip=$1
    [[ $ip == *:* ]] || return 1
    [[ $ip =~ ^[0-9A-Fa-f:]+$ ]] || return 1
    if command -v python3 >/dev/null 2>&1; then
        python3 -c 'import ipaddress,sys
try:
    ipaddress.IPv6Address(sys.argv[1])
except Exception:
    sys.exit(1)' "$ip" 2>/dev/null
        return $?
    fi
    (( $(grep -o "::" <<< "$ip" | wc -l) <= 1 )) || return 1
    local -a groups=()
    local g
    IFS=':' read -ra groups <<< "${ip//::/: :}"
    (( ${#groups[@]} <= 8 )) || return 1
    for g in "${groups[@]}"; do
        [[ -z $g || $g == " " ]] && continue
        [[ $g =~ ^[0-9A-Fa-f]{1,4}$ ]] || return 1
    done
    return 0
}

# Canonicalize IPv6 addresses to compressed lowercase (RFC 5952) so comparisons
# against kernel/ss/ip/ip6tables output always match. IPv4 is returned as-is.
canon_ip() {
    local ip=$1
    if [[ $ip == *:* ]]; then
        if command -v python3 >/dev/null 2>&1; then
            python3 -c 'import ipaddress,sys; print(ipaddress.IPv6Address(sys.argv[1]).compressed)' "$ip" 2>/dev/null || echo "${ip,,}"
        else
            echo "${ip,,}"
        fi
    else
        echo "$ip"
    fi
}

valid_port()  { [[ $1 =~ ^[0-9]{1,5}$ ]] && (( 10#$1 >= 1 && 10#$1 <= 65535 )); }
valid_token() { [[ $1 =~ ^[A-Za-z0-9._~@%+=-]{1,64}$ ]]; }
MENU_MAX=1
valid_menu()  { [[ $1 =~ ^[0-9]{1,2}$ ]] && (( 10#$1 >= 1 && 10#$1 <= MENU_MAX )); }

strip_ansi() { sed 's/\x1b\[[0-9;]*[A-Za-z]//g'; }

# Is IPv6 enabled in the kernel on this machine?
has_ipv6() {
    [[ -f /proc/net/if_inet6 ]] && [[ $(cat /proc/sys/net/ipv6/conf/all/disable_ipv6 2>/dev/null) != 1 ]]
}

# detect this host's own outbound address for the chosen underlay IP version
detect_ip() {
    local ip=""
    if [[ ${IP_VER:-4} == 6 ]]; then
        ip=$(ip -6 route get 2606:4700:4700::1111 2>/dev/null | sed -n 's/.* src \([0-9A-Fa-f:]*\).*/\1/p' | head -n1)
        [[ -z $ip || $ip == fe80:* ]] && ip=$(ip -6 route get 2001:4860:4860::8888 2>/dev/null | sed -n 's/.* src \([0-9A-Fa-f:]*\).*/\1/p' | head -n1)
        [[ -z $ip || $ip == fe80:* ]] && ip=$(ip -6 -o addr show scope global 2>/dev/null | awk '!/temporary|deprecated/{split($4,a,"/"); print a[1]; exit}')
        [[ -n $ip ]] && canon_ip "$ip"
    else
        ip=$(ip -4 route get 1.1.1.1 2>/dev/null | sed -n 's/.* src \([0-9.]*\).*/\1/p' | head -n1)
        [[ -z $ip ]] && ip=$(ip -4 route get 8.8.8.8 2>/dev/null | sed -n 's/.* src \([0-9.]*\).*/\1/p' | head -n1)
        echo "$ip"
    fi
}

# bracket an address for a "host:port" string, only if it's IPv6 (contains ':').
bracket_addr() { [[ $1 == *:* ]] && echo "[$1]" || echo "$1"; }

# ping a peer with the right address family
ping_peer() { # target [extra ping args...]
    local tgt=$1
    shift
    local -a fam=(-4)
    [[ $tgt == *:* ]] && fam=(-6)
    ping "${fam[@]}" "$@" "$tgt"
}

# is the control-channel wire protocol UDP-based for the chosen core?
ctrl_proto_is_udp() {
    if [[ $CORE == frp ]]; then
        [[ $PROTO == kcp || $PROTO == quic ]]
    else
        [[ $PROTO == udp ]]
    fi
}

# parse_ports "1080, 443, 8443=443" -> PORT_MAP=("1080=1080" "443=443" "8443=443")
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

# listeners that would clash with a core binding a port, ignoring our own tunnel
# processes. scope=any (default for dual-stack wildcard forwarded ports) flags
# any listener on that port; scope=bind checks wildcard or TUN_IR_IP.
listener_conflicts() { # proto port [any|bind]
    local flags="-ltnpH" scope=${3:-bind}
    [[ $1 == udp ]] && flags="-lunpH"
    local laddr proc tun_ir_br host
    tun_ir_br=$(bracket_addr "${TUN_IR_IP:-}")
    ss $flags "sport = :$2" 2>/dev/null | while read -r _ _ _ laddr _ proc; do
        host=${laddr%:*}
        if [[ $scope != any ]]; then
            case $host in
                "*"|0.0.0.0|"[::]"|"::"|"$TUN_IR_IP"|"$tun_ir_br") ;;
                *) continue ;;
            esac
        fi
        case $proc in
            *'"backhaul-gretap"'*|*'"frps-gretap"'*|*'"frpc-gretap"'*|*'"frps-core"'*|*'"frpc-core"'*) continue ;;
        esac
        echo "$laddr ${proc:-unknown-process}"
    done
}

# conflicts on the control port, depending on the chosen core/protocol.
# Note: FRP always opens TCP bindPort even when kcpBindPort/quicBindPort is used.
ctrl_conflicts() {
    {
        if [[ $CORE == frp && ( $PROTO == kcp || $PROTO == quic ) ]]; then
            listener_conflicts tcp "$CTRL_PORT" bind | sed 's/^/tcp: /'
            listener_conflicts udp "$CTRL_PORT" bind | sed 's/^/udp: /'
        elif ctrl_proto_is_udp; then
            listener_conflicts udp "$CTRL_PORT" bind | sed 's/^/udp: /'
        else
            listener_conflicts tcp "$CTRL_PORT" bind | sed 's/^/tcp: /'
        fi
    } | sed '/^$/d'
}

pick_free_port() {
    local i p
    for i in $(seq 1 60); do
        p=$(( (RANDOM % 20000) + 20000 ))
        [[ -z $(ss -H -ltn "sport = :$p" 2>/dev/null) && -z $(ss -H -lun "sport = :$p" 2>/dev/null) ]] && { echo "$p"; return; }
    done
    echo 28080
}

# ------------------------------------------------------------------------------
# derived settings (single source of truth = tunnel.conf)
# ------------------------------------------------------------------------------
set_link_vars() {
    IP_VER=${IP_VER:-4}
    if [[ $IP_VER == 6 ]]; then
        MTU_VAL="$MTU_VAL_V6"
    else
        MTU_VAL="$MTU_VAL_V4"
    fi
    case ${LINK_TYPE:-gretap} in
        gre)    LINK_TYPE=gre;    IFACE="gretun1" ;;
        direct) LINK_TYPE=direct; IFACE="" ;;
        *)      LINK_TYPE=gretap; IFACE="gretap1" ;;
    esac
    if [[ $LINK_TYPE == direct ]]; then
        LINK_LABEL="Direct (no GRE/GRETAP, native IPv$IP_VER)"
    elif [[ $IP_VER == 6 ]]; then
        case $LINK_TYPE in
            gre) LINK_LABEL="GRE over IPv6 (layer 3)" ;;
            *)   LINK_LABEL="GRETAP over IPv6 (layer 2)" ;;
        esac
    else
        case $LINK_TYPE in
            gre) LINK_LABEL="GRE (layer 3)" ;;
            *)   LINK_LABEL="GRETAP (layer 2)" ;;
        esac
    fi
    if has_ipv6; then
        FWD_BIND_IP="::"
    else
        FWD_BIND_IP="0.0.0.0"
    fi
}

set_core_vars() {
    case ${CORE:-backhaul} in
        frp)
            CORE=frp
            CORE_NAME="FRP"
            CORE_SVC=$FRP_SVC
            LOG_OK_RE='login to server success|start proxy success'
            LOG_ERR_RE='\[(W|E)\]'
            CORE_TAR_NAME=$([[ $ROLE == iran ]] && echo "frps" || echo "frpc")
            CORE_BIN=$([[ $ROLE == iran ]] && echo "$FRPS_BIN" || echo "$FRPC_BIN")
            CORE_PROC=$(basename "$CORE_BIN")
            CORE_CONF="$CONFIG_DIR/frp.toml"
            ;;
        *)
            CORE=backhaul
            CORE_NAME="Backhaul"
            CORE_SVC=$BACKHAUL_SVC
            LOG_OK_RE='channel established|connected successfully|tunnel established'
            LOG_ERR_RE='(\[(ERROR|WARNING|ERR|WARN)\]|level=(error|warn))'
            CORE_BIN=$BACKHAUL_BIN
            CORE_TAR_NAME="backhaul"
            CORE_CONF="$CONFIG_DIR/config.toml"
            CORE_PROC="backhaul-gretap"
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

# which transport protocols of the forwarded ports are used (firewall)
set_fwd_flags() {
    FWD_TCP=1
    FWD_UDP=${ACCEPT_UDP:-0}
    if [[ $CORE != frp && $PROTO == udp ]]; then
        FWD_TCP=0
        FWD_UDP=1
    fi
}

# connection profile -> tuning knobs for whichever core is active.
set_profile_vars() {
    case ${PROFILE:-balance} in
        gaming)
            PROFILE=gaming;   PROFILE_LABEL="Gaming (lowest ping/jitter)"
            KEEPALIVE=20; HEARTBEAT=15; CHANNEL_SIZE=1024
            MUX_CON=4;  MUX_FRAMESIZE=16384; MUX_RECVBUF=2097152; MUX_STREAMBUF=32768
            POOL_COUNT=4;  AGGRESSIVE_POOL=false; DIAL_TIMEOUT=5;  RETRY_INTERVAL=1
            FRP_HB_INTERVAL=5;  FRP_HB_TIMEOUT=15; FRP_POOL_COUNT=4;  FRP_TCP_MUX=false
            ;;
        fast)
            PROFILE=fast;     PROFILE_LABEL="Fast (max speed, low latency)"
            KEEPALIVE=40; HEARTBEAT=25; CHANNEL_SIZE=2048
            MUX_CON=8;  MUX_FRAMESIZE=32768; MUX_RECVBUF=4194304; MUX_STREAMBUF=65536
            POOL_COUNT=8;  AGGRESSIVE_POOL=false; DIAL_TIMEOUT=8;  RETRY_INTERVAL=2
            FRP_HB_INTERVAL=10; FRP_HB_TIMEOUT=30; FRP_POOL_COUNT=8;  FRP_TCP_MUX=true
            ;;
        turbo)
            PROFILE=turbo;    PROFILE_LABEL="Turbo (max throughput)"
            KEEPALIVE=90; HEARTBEAT=60; CHANNEL_SIZE=8192
            MUX_CON=16; MUX_FRAMESIZE=65536; MUX_RECVBUF=8388608; MUX_STREAMBUF=131072
            POOL_COUNT=16; AGGRESSIVE_POOL=true;  DIAL_TIMEOUT=15; RETRY_INTERVAL=5
            FRP_HB_INTERVAL=30; FRP_HB_TIMEOUT=90; FRP_POOL_COUNT=16; FRP_TCP_MUX=true
            ;;
        *)
            PROFILE=balance;  PROFILE_LABEL="Balance (general purpose)"
            KEEPALIVE=75; HEARTBEAT=40; CHANNEL_SIZE=2048
            MUX_CON=8;  MUX_FRAMESIZE=32768; MUX_RECVBUF=4194304; MUX_STREAMBUF=65536
            POOL_COUNT=8;  AGGRESSIVE_POOL=false; DIAL_TIMEOUT=10; RETRY_INTERVAL=3
            FRP_HB_INTERVAL=30; FRP_HB_TIMEOUT=90; FRP_POOL_COUNT=8;  FRP_TCP_MUX=false
            ;;
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
        printf 'PROFILE=%q\n'    "${PROFILE:-balance}"
        printf 'IP_VER=%q\n'     "${IP_VER:-4}"
        printf 'LINK_TYPE=%q\n'  "$LINK_TYPE"
        printf 'IFACE=%q\n'      "$IFACE"
        printf 'LOCAL_IP=%q\n'   "$LOCAL_IP"
        printf 'REMOTE_IP=%q\n'  "$REMOTE_IP"
        printf 'TUN_IR_IP=%q\n'  "$TUN_IR_IP"
        printf 'TUN_KH_IP=%q\n'  "$TUN_KH_IP"
        printf 'PFX=%q\n'        "${PFX:-}"
        printf 'SELF_IP=%q\n'    "$SELF_IP"
        printf 'PEER_IP=%q\n'    "$PEER_IP"
        printf 'FWD_BIND_IP=%q\n' "${FWD_BIND_IP:-::}"
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
        printf 'FRP_HB_INTERVAL=%q\n' "${FRP_HB_INTERVAL:-30}"
        printf 'FRP_HB_TIMEOUT=%q\n'  "${FRP_HB_TIMEOUT:-90}"
        printf 'FRP_POOL_COUNT=%q\n'  "${FRP_POOL_COUNT:-8}"
        printf 'FRP_TCP_MUX=%q\n'     "${FRP_TCP_MUX:-false}"
    } > "$CONF_FILE"
}

load_conf() {
    [[ -f $CONF_FILE ]] || return 1
    # shellcheck disable=SC1090
    source "$CONF_FILE" || return 1
    [[ -n ${ROLE:-} ]] || return 1
    # defaults / names used by older versions so an old install is still understood
    LINK_TYPE=${LINK_TYPE:-gretap}
    CTRL_PORT=${CTRL_PORT:-${BH_PORT:-}}
    TOKEN=${TOKEN:-${BH_TOKEN:-}}
    PROTO=${PROTO:-${BH_TRANS:-tcp}}
    PFX=${PFX:-30}
    TUN_IR_IP=${TUN_IR_IP:-10.10.1.1}
    TUN_KH_IP=${TUN_KH_IP:-10.10.1.2}
    PROFILE=${PROFILE:-balance}
    IP_VER=${IP_VER:-4}
    CORE=${CORE:-backhaul}
    LOCAL_IP=$(canon_ip "${LOCAL_IP:-}")
    REMOTE_IP=$(canon_ip "${REMOTE_IP:-}")
    TUN_IR_IP=$(canon_ip "$TUN_IR_IP")
    TUN_KH_IP=$(canon_ip "$TUN_KH_IP")
    set_link_vars
    set_core_vars
    set_role_ips
    set_fwd_flags
    set_profile_vars
    return 0
}

# ------------------------------------------------------------------------------
# core configuration files (always regenerated from tunnel.conf)
# ------------------------------------------------------------------------------
write_backhaul_conf() {
    local m pub tgt fwd_br
    fwd_br=$(bracket_addr "${FWD_BIND_IP:-0.0.0.0}")
    {
        if [[ $ROLE == iran ]]; then
            echo "[server]"
            echo "bind_addr = \"$(bracket_addr "$TUN_IR_IP"):$CTRL_PORT\""
            echo "transport = \"$PROTO\""
            if [[ ${ACCEPT_UDP:-0} == 1 && $PROTO == tcp ]]; then echo "accept_udp = true"; fi
            echo "token = \"$TOKEN\""
            echo "keepalive_period = $KEEPALIVE"
            echo "nodelay = true"
            echo "heartbeat = $HEARTBEAT"
            echo "channel_size = $CHANNEL_SIZE"
            echo "sniffer = false"
            echo "log_level = \"info\""
            case $PROTO in
                *mux)
                    echo "mux_con = $MUX_CON"
                    echo "mux_version = 1"
                    echo "mux_framesize = $MUX_FRAMESIZE"
                    echo "mux_recievebuffer = $MUX_RECVBUF"
                    echo "mux_streambuffer = $MUX_STREAMBUF"
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
                pub=${m%%=*}
                tgt=${m#*=}
                # Bind dual-stack [::]:pub (or 0.0.0.0:pub if IPv6 is disabled) so both
                # IPv4 and IPv6 clients hitting Iran are accepted and forwarded to
                # 127.0.0.1:tgt on Kharej, while the control channel stays on TUN_IR_IP.
                echo "    \"${fwd_br}:${pub}=127.0.0.1:${tgt}\","
            done
            echo "]"
        else
            echo "[client]"
            echo "remote_addr = \"$(bracket_addr "$TUN_IR_IP"):$CTRL_PORT\""
            echo "transport = \"$PROTO\""
            echo "token = \"$TOKEN\""
            echo "connection_pool = $POOL_COUNT"
            echo "aggressive_pool = $AGGRESSIVE_POOL"
            echo "keepalive_period = $KEEPALIVE"
            echo "dial_timeout = $DIAL_TIMEOUT"
            echo "retry_interval = $RETRY_INTERVAL"
            echo "nodelay = true"
            echo "sniffer = false"
            echo "log_level = \"info\""
            case $PROTO in
                *mux)
                    echo "mux_version = 1"
                    echo "mux_framesize = $MUX_FRAMESIZE"
                    echo "mux_recievebuffer = $MUX_RECVBUF"
                    echo "mux_streambuffer = $MUX_STREAMBUF"
                    ;;
            esac
        fi
    } > "$CORE_CONF"
}

# FRP TOML config.
# Control plane binds bindAddr (TUN_IR_IP - isolated inside GRE/GRETAP or public
# IP in Direct mode). Forwarded ports bind proxyBindAddr (dual-stack "::" when
# IPv6 is enabled, or "0.0.0.0" otherwise) so BOTH IPv4 and IPv6 public traffic
# hitting Iran is forwarded cleanly across any tunnel type.
write_frp_conf() {
    local m pub tgt
    {
        if [[ $ROLE == iran ]]; then
            echo "bindAddr = \"$TUN_IR_IP\""
            echo "bindPort = $CTRL_PORT"
            echo "proxyBindAddr = \"${FWD_BIND_IP:-0.0.0.0}\""
            [[ $PROTO == kcp  ]] && echo "kcpBindPort = $CTRL_PORT"
            [[ $PROTO == quic ]] && echo "quicBindPort = $CTRL_PORT"
            echo "transport.tcpMux = ${FRP_TCP_MUX:-false}"
            echo "transport.heartbeatTimeout = ${FRP_HB_TIMEOUT:-90}"
            echo "auth.method = \"token\""
            echo "auth.token = \"$TOKEN\""
            echo "log.level = \"info\""
            if [[ -n ${PORTS:-} ]]; then
                echo "allowPorts = ["
                for m in $PORTS; do
                    pub=${m%%=*}
                    echo "  { single = $pub },"
                done
                echo "]"
            fi
        else
            echo "serverAddr = \"$TUN_IR_IP\""
            echo "serverPort = $CTRL_PORT"
            echo "transport.protocol = \"$PROTO\""
            echo "transport.heartbeatInterval = ${FRP_HB_INTERVAL:-30}"
            echo "transport.heartbeatTimeout = ${FRP_HB_TIMEOUT:-90}"
            echo "transport.poolCount = ${FRP_POOL_COUNT:-8}"
            echo "transport.tcpMux = ${FRP_TCP_MUX:-false}"
            echo "auth.method = \"token\""
            echo "auth.token = \"$TOKEN\""
            echo "log.level = \"info\""
            for m in $PORTS; do
                pub=${m%%=*}
                tgt=${m#*=}
                if [[ ${FWD_TCP:-1} == 1 ]]; then
                    echo
                    echo "[[proxies]]"
                    echo "name = \"p${pub}_tcp\""
                    echo "type = \"tcp\""
                    echo "localIP = \"127.0.0.1\""
                    echo "localPort = $tgt"
                    echo "remotePort = $pub"
                fi
                if [[ ${FWD_UDP:-0} == 1 ]]; then
                    echo
                    echo "[[proxies]]"
                    echo "name = \"p${pub}_udp\""
                    echo "type = \"udp\""
                    echo "localIP = \"127.0.0.1\""
                    echo "localPort = $tgt"
                    echo "remotePort = $pub"
                fi
            done
        fi
    } > "$CORE_CONF"
}

write_core_conf() {
    install -m 600 /dev/null "$CORE_CONF"
    case $CORE in
        frp) write_frp_conf ;;
        *)   write_backhaul_conf ;;
    esac
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

# defaults so a config written by an older version still works
LINK_TYPE=${LINK_TYPE:-gretap}
IP_VER=${IP_VER:-4}
PFX=${PFX:-30}
FWD_TCP=${FWD_TCP:-1}
FWD_UDP=${FWD_UDP:-${ACCEPT_UDP:-0}}
CORE=${CORE:-backhaul}
CORE_BIN=${CORE_BIN:-${BACKHAUL_BIN:-}}
MTU_VAL=${MTU_VAL:-$([[ $IP_VER == 6 ]] && echo 1360 || echo 1400)}

TAG="BHGT"
if iptables -w 5 -L -n >/dev/null 2>&1; then IPT4=(iptables -w 5); else IPT4=(iptables); fi
IPT6=()
if command -v ip6tables >/dev/null 2>&1; then
    if ip6tables -w 5 -L -n >/dev/null 2>&1; then IPT6=(ip6tables -w 5); else IPT6=(ip6tables); fi
fi

has_ipv6() {
    [[ -f /proc/net/if_inet6 ]] && [[ $(cat /proc/sys/net/ipv6/conf/all/disable_ipv6 2>/dev/null) != 1 ]]
}

# is the control-channel wire protocol UDP-based for the chosen core?
ctrl_is_udp() {
    if [[ $CORE == frp ]]; then
        [[ $PROTO == kcp || $PROTO == quic ]]
    else
        [[ $PROTO == udp ]]
    fi
}

# ipt_ensure <table> <chain> <match/target args...>   (idempotent, inserted at top, tagged, IPT4)
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
    "${IPT4[@]}" -t "$t" -C "$c" "${spec[@]}" 2>/dev/null || "${IPT4[@]}" -t "$t" -I "$c" 1 "${spec[@]}"
}

# ipt6_ensure <table> <chain> <match/target args...>  (idempotent, inserted at top, tagged, IPT6)
# Places -m comment BEFORE -j so ip6tables-nft / ip6tables-legacy match/check/purge cleanly.
ipt6_ensure() {
    (( ${#IPT6[@]} > 0 )) || return 0
    local t=$1 c=$2
    shift 2
    local -a pre=() post=() spec=()
    while (( $# )); do
        if [[ $1 == -j ]]; then post=("$@"); break; fi
        pre+=("$1")
        shift
    done
    spec=("${pre[@]}" -m comment --comment "$TAG" "${post[@]}")
    "${IPT6[@]}" -t "$t" -C "$c" "${spec[@]}" 2>/dev/null || "${IPT6[@]}" -t "$t" -I "$c" 1 "${spec[@]}"
}

# INPUT ACCEPT for a specific destination address ($1), auto-picking iptables or ip6tables.
fw_accept_dst_dport() { # dst proto port
    if [[ $1 == *:* ]]; then
        ipt6_ensure filter INPUT -d "$1" -p "$2" --dport "$3" -j ACCEPT
    else
        ipt_ensure filter INPUT -d "$1" -p "$2" --dport "$3" -j ACCEPT
    fi
}

# INPUT ACCEPT for a dual-stack forwarded port on both IPv4 and IPv6 (when available).
fw_accept_fwd_port() { # proto port
    ipt_ensure filter INPUT -p "$1" --dport "$2" -j ACCEPT
    if has_ipv6 && (( ${#IPT6[@]} > 0 )); then
        ipt6_ensure filter INPUT -p "$1" --dport "$2" -j ACCEPT
    fi
}

# remove every rule carrying our tag from both iptables and ip6tables
purge_rules() {
    local t line
    local -a words=()
    for t in filter nat mangle; do
        while read -r line; do
            [[ -n $line ]] || continue
            line=${line//\"/}
            line="-D${line#-A}"
            read -ra words <<< "$line"
            "${IPT4[@]}" -t "$t" "${words[@]}" 2>/dev/null
        done < <("${IPT4[@]}" -t "$t" -S 2>/dev/null | grep -E -- "--comment \"?$TAG\"?( |$)")
    done
    if (( ${#IPT6[@]} > 0 )); then
        for t in filter nat mangle; do
            while read -r line; do
                [[ -n $line ]] || continue
                line=${line//\"/}
                line="-D${line#-A}"
                read -ra words <<< "$line"
                "${IPT6[@]}" -t "$t" "${words[@]}" 2>/dev/null
            done < <("${IPT6[@]}" -t "$t" -S 2>/dev/null | grep -E -- "--comment \"?$TAG\"?( |$)")
        done
    fi
    return 0
}

apply_rules() {
    local m pub

    if [[ $LINK_TYPE == direct ]]; then
        # Direct mode: open control port on TUN_IR_IP (Iran) and allow outbound/return on Kharej.
        if [[ $ROLE == iran ]]; then
            if [[ $CORE == frp && ( $PROTO == kcp || $PROTO == quic ) ]]; then
                fw_accept_dst_dport "$TUN_IR_IP" udp "$CTRL_PORT"
                fw_accept_dst_dport "$TUN_IR_IP" tcp "$CTRL_PORT"
            elif ctrl_is_udp; then
                fw_accept_dst_dport "$TUN_IR_IP" udp "$CTRL_PORT"
            else
                fw_accept_dst_dport "$TUN_IR_IP" tcp "$CTRL_PORT"
            fi
            if [[ $IP_VER == 6 ]]; then
                ipt6_ensure filter INPUT -p icmpv6 -j ACCEPT
            fi
        else
            if [[ $IP_VER == 6 ]]; then
                ipt6_ensure filter INPUT -p icmpv6 -j ACCEPT
                if ctrl_is_udp; then
                    ipt6_ensure filter OUTPUT -d "$REMOTE_IP" -p udp --dport "$CTRL_PORT" -j ACCEPT
                    ipt6_ensure filter INPUT  -s "$REMOTE_IP" -p udp --sport "$CTRL_PORT" -j ACCEPT
                else
                    ipt6_ensure filter OUTPUT -d "$REMOTE_IP" -p tcp --dport "$CTRL_PORT" -j ACCEPT
                    ipt6_ensure filter INPUT  -s "$REMOTE_IP" -p tcp --sport "$CTRL_PORT" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
                fi
            else
                if ctrl_is_udp; then
                    ipt_ensure filter OUTPUT -d "$REMOTE_IP" -p udp --dport "$CTRL_PORT" -j ACCEPT
                    ipt_ensure filter INPUT  -s "$REMOTE_IP" -p udp --sport "$CTRL_PORT" -j ACCEPT
                else
                    ipt_ensure filter OUTPUT -d "$REMOTE_IP" -p tcp --dport "$CTRL_PORT" -j ACCEPT
                    ipt_ensure filter INPUT  -s "$REMOTE_IP" -p tcp --sport "$CTRL_PORT" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
                fi
            fi
        fi
    else
        # GRE / GRETAP mode: allow outer protocol 47 (GRE) on underlay family + inner IPv4 traffic.
        if [[ $IP_VER == 6 ]]; then
            ipt6_ensure filter INPUT  -p icmpv6 -j ACCEPT
            ipt6_ensure filter INPUT  -p 47 -s "$REMOTE_IP" -j ACCEPT
            ipt6_ensure filter OUTPUT -p 47 -d "$REMOTE_IP" -j ACCEPT
        else
            ipt_ensure filter INPUT  -p 47 -s "$REMOTE_IP" -j ACCEPT
            ipt_ensure filter OUTPUT -p 47 -d "$REMOTE_IP" -j ACCEPT
        fi
        ipt_ensure filter INPUT   -i "$IFACE" -j ACCEPT
        ipt_ensure filter FORWARD -i "$IFACE" -j ACCEPT
        ipt_ensure filter FORWARD -o "$IFACE" -j ACCEPT

        # --- mangle: MSS clamp (only meaningful with the extra GRE/GRETAP header)
        ipt_ensure mangle FORWARD -o "$IFACE" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss "$MSS_VAL"
        ipt_ensure mangle FORWARD -i "$IFACE" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss "$MSS_VAL"
        ipt_ensure mangle OUTPUT  -o "$IFACE" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss "$MSS_VAL"
        ipt_ensure mangle INPUT   -i "$IFACE" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss "$MSS_VAL"
    fi

    if [[ $ROLE == iran ]]; then
        # Forwarded ports listen dual-stack ([::]:pub or 0.0.0.0:pub) directly on the
        # core server so both IPv4 and IPv6 clients are handled natively without NAT.
        for m in $PORTS; do
            pub=${m%%=*}
            if [[ $FWD_TCP == 1 ]]; then
                fw_accept_fwd_port tcp "$pub"
            fi
            if [[ $FWD_UDP == 1 ]]; then
                fw_accept_fwd_port udp "$pub"
            fi
        done
        # tunnel traffic must never be touched by any other DNAT/REDIRECT rule on the box.
        if [[ $LINK_TYPE != direct ]]; then
            ipt_ensure nat PREROUTING -i "$IFACE" -j ACCEPT
        fi
    elif [[ $LINK_TYPE != direct ]]; then
        ipt_ensure nat OUTPUT -o "$IFACE" -j ACCEPT
    fi
}

has_self_ip() { ip -4 addr show dev "$IFACE" 2>/dev/null | grep -q "inet $SELF_IP/"; }

has_direct_self_ip() {
    if [[ $SELF_IP == *:* ]]; then
        ip -6 addr show 2>/dev/null | grep -q "inet6 ${SELF_IP}/" && \
            ! ip -6 addr show 2>/dev/null | grep "inet6 ${SELF_IP}/" | grep -q "tentative"
    else
        ip -4 addr show 2>/dev/null | grep -q "inet ${SELF_IP}/"
    fi
}

case "$1" in
    up)
        purge_rules
        # Allow dual-stack [::] sockets to accept both IPv4 and IPv6 connections.
        if has_ipv6; then
            sysctl -qw net.ipv6.bindv6only=0 2>/dev/null
            [[ $IP_VER == 6 && $LINK_TYPE == direct ]] && sysctl -qw net.ipv6.ip_nonlocal_bind=1 2>/dev/null
        fi
        if [[ $LINK_TYPE != direct ]]; then
            modprobe gre 2>/dev/null
            modprobe ip_gre 2>/dev/null
            if [[ $IP_VER == 6 ]]; then
                modprobe ip6_tunnel 2>/dev/null
                modprobe ip6_gre 2>/dev/null
            fi
            ip link del "$IFACE" 2>/dev/null
            if [[ $IP_VER == 6 ]]; then
                case $LINK_TYPE in gre) kind=ip6gre ;; *) kind=ip6gretap ;; esac
                # encaplimit none strips the IPv6 DSTOPS extension header so Next Header
                # is directly 47 (GRE) - critical for ip6tables matching and ISP firewalls.
                if ! ip -6 link add "$IFACE" type "$kind" local "$LOCAL_IP" remote "$REMOTE_IP" hoplimit 255 encaplimit none 2>/dev/null; then
                    if ! ip -6 link add "$IFACE" type "$kind" local "$LOCAL_IP" remote "$REMOTE_IP" hoplimit 255; then
                        echo "ERROR: cannot create $IFACE (type $kind). Possible causes: IPv6 GRE support (ip6_gre/ip6_tunnel) is missing on this VPS/kernel," >&2
                        echo "       LOCAL_IP $LOCAL_IP is not an address of this host, or another $kind tunnel with the same local/remote pair already exists." >&2
                        exit 1
                    fi
                fi
            else
                case $LINK_TYPE in gre) kind=gre ;; *) kind=gretap ;; esac
                if ! ip link add "$IFACE" type "$kind" local "$LOCAL_IP" remote "$REMOTE_IP" ttl 255; then
                    echo "ERROR: cannot create $IFACE (type $kind). Possible causes: GRE support (ip_gre) is missing on this VPS/kernel," >&2
                    echo "       LOCAL_IP $LOCAL_IP is not an address of this host, or another $kind tunnel with the same local/remote pair already exists." >&2
                    exit 1
                fi
            fi
            ip addr add "$SELF_IP/$PFX" dev "$IFACE" || exit 1
            ip link set "$IFACE" mtu "$MTU_VAL" up || exit 1
            # Linux uses max(all.rp_filter, iface.rp_filter) - both must be 0.
            sysctl -qw "net.ipv4.conf.all.rp_filter=0" 2>/dev/null
            sysctl -qw "net.ipv4.conf.default.rp_filter=0" 2>/dev/null
            sysctl -qw "net.ipv4.conf.$IFACE.rp_filter=0" 2>/dev/null
        fi
        apply_rules
        ;;
    reload)
        purge_rules
        apply_rules
        ;;
    down)
        purge_rules
        [[ -n $IFACE ]] && ip link del "$IFACE" 2>/dev/null
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
        if [[ $LINK_TYPE != direct ]]; then
            for _ in $(seq 1 20); do has_self_ip && break; sleep 1; done
            if ! has_self_ip; then
                echo "ERROR: $IFACE has no $SELF_IP address" >&2
                exit 1
            fi
        elif [[ $ROLE == iran ]]; then
            # Wait briefly for IPv6 DAD (tentative -> ready) on boot before binding
            for _ in $(seq 1 15); do has_direct_self_ip && break; sleep 1; done
        fi
        if [[ $ROLE == kharej ]]; then
            local tries=10
            [[ $LINK_TYPE == direct ]] && tries=3
            for _ in $(seq 1 "$tries"); do
                if [[ $PEER_IP == *:* ]]; then
                    ping -6 -c1 -W1 "$PEER_IP" >/dev/null 2>&1 && break
                else
                    ping -4 -c1 -W1 "$PEER_IP" >/dev/null 2>&1 && break
                fi
                sleep 1
            done
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
    local other_svc
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

    # clean up a leftover v4.0 (ini-based) FRP install, if any
    if [[ $CORE_SVC != "$LEGACY_FRP_SVC" ]]; then
        systemctl disable "$LEGACY_FRP_SVC" >/dev/null 2>&1
        rm -f "$UNIT_DIR/$LEGACY_FRP_SVC"
    fi

    # only one core should auto-start: disable the OTHER core's unit, if it exists
    if [[ $CORE_SVC == "$BACKHAUL_SVC" ]]; then other_svc=$FRP_SVC; else other_svc=$BACKHAUL_SVC; fi
    systemctl stop "$other_svc" >/dev/null 2>&1
    systemctl disable "$other_svc" >/dev/null 2>&1

    systemctl daemon-reload
    systemctl enable "$LINK_SVC" "$CORE_SVC" >/dev/null 2>&1
}

stop_services() {
    local b
    systemctl stop "$BACKHAUL_SVC" "$FRP_SVC" "$LEGACY_FRP_SVC" "$LINK_SVC" >/dev/null 2>&1
    for b in "$BACKHAUL_BIN" "$FRPS_BIN" "$FRPC_BIN" "$LEGACY_FRPS_BIN" "$LEGACY_FRPC_BIN"; do
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
    warn "Iran and Kharej MUST run the same binary: compare the sha256 above on both servers."
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
    case $CORE in
        frp) url="https://github.com/fatedier/frp/releases/download/v${FRP_VERSION}/frp_${FRP_VERSION}_linux_${arch}.tar.gz" ;;
        *)   url="https://github.com/Musixal/Backhaul/releases/latest/download/backhaul_linux_${arch}.tar.gz" ;;
    esac

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

    if [[ $CORE == backhaul ]] && [[ -x $LEGACY_BIN ]] && is_elf "$LEGACY_BIN"; then
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
choose_ipver() {
    local c
    echo
    info "Underlay IP version - the public IP each server uses to reach the other (must be the same on both servers):"
    echo "   1) IPv4"
    echo "   2) IPv6"
    MENU_MAX=2
    ask_valid c "Select underlay IP version" "1" valid_menu "Enter 1 or 2."
    if (( 10#$c == 2 )); then IP_VER=6; else IP_VER=4; fi
    if [[ $IP_VER == 6 ]]; then
        if ! has_ipv6; then
            err "IPv6 appears disabled in the kernel on this host - enable IPv6 first."
            return 1
        fi
        if ! command -v ip6tables >/dev/null 2>&1; then
            err "ip6tables was not found (it normally ships together with iptables) - install it and run Setup again."
            return 1
        fi
    fi
}

choose_core() {
    local i c
    echo
    info "Tunnel core (must be the same on both servers):"
    for i in "${!CORES[@]}"; do
        printf '   %d) %-9s %s\n' $((i + 1)) "${CORES[i]}" "${CORE_DESCS[i]}"
    done
    MENU_MAX=${#CORES[@]}
    ask_valid c "Select core" "1" valid_menu "Enter a number from 1 to $MENU_MAX."
    CORE=${CORES[$((10#$c - 1))]}
}

choose_link() {
    local i c
    echo
    info "Tunnel link type (must be the same on both servers):"
    for i in "${!LINK_TYPES[@]}"; do
        printf '   %d) %-8s %s\n' $((i + 1)) "${LINK_TYPES[i]}" "${LINK_TYPE_DESCS[i]}"
    done
    MENU_MAX=${#LINK_TYPES[@]}
    ask_valid c "Select link type" "2" valid_menu "Enter a number from 1 to $MENU_MAX."
    LINK_TYPE=${LINK_TYPES[$((10#$c - 1))]}
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

choose_proto() {
    local i c
    echo
    info "$CORE_NAME protocol (must be the same on both servers):"
    if [[ $CORE == frp ]]; then
        for i in "${!FRP_PROTOS[@]}"; do
            printf '   %d) %-10s %s\n' $((i + 1)) "${FRP_PROTOS[i]}" "${FRP_PROTO_DESCS[i]}"
        done
        MENU_MAX=${#FRP_PROTOS[@]}
        ask_valid c "Select protocol" "1" valid_menu "Enter a number from 1 to $MENU_MAX."
        PROTO=${FRP_PROTOS[$((10#$c - 1))]}
    else
        for i in "${!BACKHAUL_PROTOS[@]}"; do
            printf '   %d) %-10s %s\n' $((i + 1)) "${BACKHAUL_PROTOS[i]}" "${BACKHAUL_PROTO_DESCS[i]}"
        done
        MENU_MAX=${#BACKHAUL_PROTOS[@]}
        ask_valid c "Select protocol" "1" valid_menu "Enter a number from 1 to $MENU_MAX."
        PROTO=${BACKHAUL_PROTOS[$((10#$c - 1))]}
    fi
}

choose_profile() {
    local i c
    echo
    info "Connection profile (must be the same on both servers):"
    for i in "${!PROFILES[@]}"; do
        printf '   %d) %-9s %s\n' $((i + 1)) "${PROFILES[i]}" "${PROFILE_DESCS[i]}"
    done
    MENU_MAX=${#PROFILES[@]}
    ask_valid c "Select profile" "2" valid_menu "Enter a number from 1 to $MENU_MAX."
    PROFILE=${PROFILES[$((10#$c - 1))]}
    set_profile_vars
}

prompt_ports() { # entered on Iran for Backhaul; on BOTH sides for FRP
    local raw m pub conflicts msg
    while true; do
        msg="Ports to forward (e.g. 1080,443  -  use 8443=443 for public 8443 -> Kharej 443)"
        ask raw "$msg" ""
        if ! parse_ports "$raw"; then
            err "Enter at least one valid port."
            continue
        fi
        # Only Iran binds the public forwarded ports; on Kharej (FRP) the target
        # service (Xray/SOCKS/...) is supposed to already listen on those ports.
        if [[ $ROLE != iran ]]; then
            return 0
        fi
        conflicts=""
        for m in "${PORT_MAP[@]}"; do
            pub=${m%%=*}
            if [[ ${FWD_TCP:-1} == 1 ]]; then
                conflicts+=$(listener_conflicts tcp "$pub" any | sed "s/^/tcp $pub: /")$'\n'
            fi
            if [[ ${FWD_UDP:-0} == 1 ]]; then
                conflicts+=$(listener_conflicts udp "$pub" any | sed "s/^/udp $pub: /")$'\n'
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
    if [[ -n $IFACE ]]; then
        echo "  Link      : $LINK_LABEL ($IFACE)   public IPs: this $LOCAL_IP <-> peer $REMOTE_IP"
    else
        echo "  Link      : $LINK_LABEL   public IPs: this $LOCAL_IP <-> peer $REMOTE_IP"
    fi
    if [[ $LINK_TYPE == direct ]]; then
        echo "  Addressing: direct - the core binds/connects straight on the public IPs above"
    else
        echo "  Tunnel IPs: Iran $TUN_IR_IP <-> Kharej $TUN_KH_IP (/$PFX)   this server: $SELF_IP"
    fi
    echo "  Core      : $CORE_NAME   protocol: $PROTO   profile: $PROFILE_LABEL"
    if [[ $LINK_TYPE != direct ]]; then
        echo "  MTU/MSS   : $MTU_VAL / $MSS_VAL (fixed for IPv$IP_VER, same regardless of profile)"
    fi
    if [[ $LINK_TYPE == direct ]]; then
        echo "  Control   : $(bracket_addr "$TUN_IR_IP"):$CTRL_PORT"
    else
        echo "  Control   : $TUN_IR_IP:$CTRL_PORT (inside the tunnel)"
    fi
    echo "  Token     : $TOKEN"
    if [[ -n ${PORTS:-} ]]; then
        if [[ $ROLE == iran ]]; then
            echo "  Fwd bind  : $(bracket_addr "${FWD_BIND_IP:-0.0.0.0}") (dual-stack IPv4+IPv6: $([[ ${FWD_BIND_IP:-} == "::" ]] && echo yes || echo IPv4-only))"
        fi
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

    choose_ipver || return 1
    choose_core
    choose_link
    set_link_vars
    set_core_vars
    if [[ $LINK_TYPE != direct ]]; then
        choose_ipset
    else
        TUN_IR_IP=""
        TUN_KH_IP=""
        PFX=""
    fi
    set_role_ips
    choose_proto
    choose_profile

    local ip_validator="valid_ipv4"
    [[ $IP_VER == 6 ]] && ip_validator="valid_ipv6"

    echo
    def_ip=$(detect_ip)
    ask_valid LOCAL_IP "Enter $lbl_local public IP" "$def_ip" "$ip_validator" "Not a valid IPv$IP_VER address."
    ask_valid REMOTE_IP "Enter $lbl_remote public IP" "" "$ip_validator" "Not a valid IPv$IP_VER address."
    LOCAL_IP=$(canon_ip "$LOCAL_IP")
    REMOTE_IP=$(canon_ip "$REMOTE_IP")
    if [[ $LOCAL_IP == "$REMOTE_IP" ]]; then
        err "Local and remote IP are identical."
        return 1
    fi

    if [[ $LINK_TYPE == direct ]]; then
        if [[ $ROLE == iran ]]; then
            TUN_IR_IP=$LOCAL_IP
            TUN_KH_IP=$REMOTE_IP
        else
            TUN_IR_IP=$REMOTE_IP
            TUN_KH_IP=$LOCAL_IP
        fi
        PFX=""
        set_role_ips
    fi

    def_port=3080
    while true; do
        ask_valid CTRL_PORT "$CORE_NAME control port (reached INSIDE the tunnel, or directly in Direct mode)" "$def_port" valid_port "Port must be 1-65535."
        [[ $ROLE == iran ]] || break
        c=$(ctrl_conflicts)
        [[ -z $c ]] && break
        err "Port $CTRL_PORT is already used on this server by:"
        echo "$c" | sed 's/^/        /'
        err "The $CORE_NAME client would connect to THAT program, which hangs up or ignores it."
        warn "Pick another port (for example $(pick_free_port))."
    done

    ask_valid TOKEN "Tunnel secret token (must be identical on both sides)" "123456" valid_token "1-64 chars from: A-Z a-z 0-9 . _ ~ @ % + = -"
    [[ $TOKEN == "123456" ]] && warn "Using the default token. The control port is only reachable inside the tunnel (or directly, in Direct mode), but a custom token is better."

    ACCEPT_UDP=0
    PORTS=""
    if [[ $CORE == frp ]]; then
        ask_yn "Also forward UDP on those ports, besides TCP? (same answer on both servers)" n && ACCEPT_UDP=1
    else
        if [[ $PROTO == tcp ]]; then
            ask_yn "Also forward UDP on those ports (Backhaul UDP-over-TCP)? (same answer on both servers)" n && ACCEPT_UDP=1
        elif [[ $PROTO == udp ]]; then
            info "Backhaul 'udp' transport forwards UDP ports only (no TCP)."
        fi
    fi
    set_fwd_flags
    if [[ $ROLE == iran ]]; then
        prompt_ports
        PORTS="${PORT_MAP[*]}"
    elif [[ $CORE == frp ]]; then
        warn "FRP needs the port list entered again here: unlike Backhaul, frpc (the Kharej client) - not the server - is what declares each forwarded port."
        prompt_ports
        PORTS="${PORT_MAP[*]}"
    fi
    print_summary
    ask_yn "Apply this configuration now?" y || { warn "Aborted - nothing was changed."; return 1; }

    fetch_core_binary 0 || { err "Cannot continue without the $CORE_NAME binary."; return 1; }
    if [[ $ROLE == iran && $CORE == backhaul && ( $PROTO == wss || $PROTO == wssmux ) ]]; then
        ensure_tls_cert || return 1
    fi

    start_ts=$(date '+%Y-%m-%d %H:%M:%S')
    info "Stopping old services (their own stop hooks remove old firewall rules)..."
    stop_services
    # one-time cleanup of a v4.0 (ini-based) FRP install, if this box ever had one
    rm -f "$LEGACY_FRPS_BIN" "$LEGACY_FRPC_BIN"
    if [[ $CORE_SVC != "$LEGACY_FRP_SVC" ]]; then
        systemctl disable "$LEGACY_FRP_SVC" >/dev/null 2>&1
        rm -f "$UNIT_DIR/$LEGACY_FRP_SVC"
    fi
    systemctl daemon-reload
    rm -f "$CONFIG_DIR/gretap-up.sh" "$CONFIG_DIR/gretap-down.sh" \
          "$CONFIG_DIR/config.toml" "$CONFIG_DIR/frp.toml" "$CONFIG_DIR/frps.toml" "$CONFIG_DIR/frpc.toml"

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
    if [[ $LINK_TYPE == direct ]]; then
        echo "  underlay: IPv$IP_VER | core: $CORE | link type: direct | protocol: $PROTO | profile: $PROFILE | control port: $CTRL_PORT | token: $TOKEN"
    else
        echo "  underlay: IPv$IP_VER | core: $CORE | link type: $LINK_TYPE | IP pair: $TUN_IR_IP / $TUN_KH_IP | protocol: $PROTO | profile: $PROFILE | control port: $CTRL_PORT | token: $TOKEN"
    fi
    if [[ $CORE == frp ]]; then
        info "FRP needs its port list entered on BOTH servers (Iran for the allow-list, Kharej for the actual proxies) - unlike Backhaul, which only needs it on Iran."
    else
        info "The forwarded port list is only ever entered on the IRAN server - Kharej does not need it."
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
    if ctrl_proto_is_udp; then (( udp > 0 )); else (( tcp > 0 )); fi
}

# quick check without long blocking waits
verify_setup() { # start_ts
    local ts=$1 log
    sleep 1
    echo
    info "Quick check (keep an eye on menu option 3 / 4 if this isn't confirmed yet)..."
    if [[ $ROLE == iran ]]; then
        if systemctl is-active -q "$CORE_SVC" && ctrl_ok; then
            res ok "$CORE_NAME server is listening on $(bracket_addr "$TUN_IR_IP"):$CTRL_PORT ($PROTO)"
            return 0
        fi
        res warn "Not confirmed yet - the service keeps retrying in the background. Check again in a few seconds (menu 3 / 4)."
        return 0
    fi

    log=$(core_log 300 "$ts")
    if grep -qiE "$LOG_OK_RE" <<< "$log"; then
        res ok "Control channel established with $(bracket_addr "$TUN_IR_IP"):$CTRL_PORT"
        return 0
    fi
    if grep -qE "$LOG_ERR_RE" <<< "$log"; then
        res warn "Last log line(s) below - the client keeps retrying automatically:"
        grep -E "$LOG_ERR_RE" <<< "$log" | tail -n 3 | sed 's/^/        /'
        if grep -qi "refused" <<< "$log"; then
            echo "    -> 'connection refused': the Iran $CORE_NAME server is not running/listening on $(bracket_addr "$TUN_IR_IP"):$CTRL_PORT."
        elif grep -qi "token" <<< "$log"; then
            echo "    -> token mismatch: use the same token on both servers."
        elif grep -q "EOF" <<< "$log"; then
            echo "    -> 'EOF': TCP connects but the other end hangs up at once. Most common causes:"
            echo "       a) another program owns port $CTRL_PORT on the Iran server (Diagnose on Iran shows it)"
            echo "       b) token, profile, or protocol differ between the two servers"
            echo "       c) the two servers run different binaries/versions (menu option 7)"
        elif grep -qiE "timeout|timed out" <<< "$log"; then
            echo "    -> timeouts: packets get lost inside the tunnel (MTU / GRE filtering, or a blocked path in Direct mode). Run Diagnose."
        fi
    else
        res warn "No result yet - check again with menu option 3 / 4 in a few seconds."
    fi
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
    if [[ -n $IFACE ]]; then
        echo "  Link       : $LINK_LABEL ($IFACE)   public: local $LOCAL_IP <-> peer $REMOTE_IP"
    else
        echo "  Link       : $LINK_LABEL   public: local $LOCAL_IP <-> peer $REMOTE_IP"
    fi
    if [[ $LINK_TYPE == direct ]]; then
        echo "  Addressing : direct (public IPs used as-is): $SELF_IP <-> $PEER_IP"
    else
        echo "  Tunnel IPs : $SELF_IP <-> $PEER_IP (/$PFX)"
    fi
    echo "  Core       : $CORE_NAME   protocol: $PROTO   profile: $PROFILE_LABEL"
    if [[ $LINK_TYPE == direct ]]; then
        echo "  Control    : $(bracket_addr "$TUN_IR_IP"):$CTRL_PORT   (direct mode: no MTU/MSS clamp applied)"
    else
        echo "  Control    : $TUN_IR_IP:$CTRL_PORT   MTU/MSS: $MTU_VAL/$MSS_VAL (fixed for IPv$IP_VER)"
    fi
    if [[ -n ${PORTS:-} ]]; then
        echo "  Forwarded  : $PORTS   (bind: $(bracket_addr "${FWD_BIND_IP:-0.0.0.0}"), TCP: $([[ $FWD_TCP == 1 ]] && echo yes || echo no), UDP: $([[ $FWD_UDP == 1 ]] && echo yes || echo no))"
    fi

    echo
    if [[ $LINK_TYPE == direct ]]; then
        echo -e "  ${CYAN}[*] Direct mode: no virtual interface is used; the public IP ($SELF_IP) is used as-is${NC}"
        if ping_peer "$PEER_IP" -c 2 -W 2 >/dev/null 2>&1; then
            echo -e "  ${GREEN}[*] ping $PEER_IP: SUCCESS${NC}"
        else
            echo -e "  ${RED}[x] ping $PEER_IP: FAILED${NC}"
        fi
    elif ip link show "$IFACE" >/dev/null 2>&1 && ip -4 addr show dev "$IFACE" | grep -q "inet $SELF_IP/"; then
        echo -e "  ${GREEN}[*] $IFACE: UP ($SELF_IP, mtu $(cat /sys/class/net/$IFACE/mtu 2>/dev/null))${NC}"
        if ping_peer "$PEER_IP" -c 2 -W 2 >/dev/null 2>&1; then
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
    if command -v ip6tables >/dev/null 2>&1; then
        for t in filter nat mangle; do
            ip6tables -t "$t" -S 2>/dev/null | grep -- "--comment" | grep BHGT | sed "s/-m comment --comment \"\\?BHGT\"\\? //; s/^/    [ip6 $t] /"
        done
    fi
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
    if [[ $LINK_TYPE == direct ]]; then
        res ok "Direct mode: no virtual interface is used; $SELF_IP (this host's own public IP) is used as-is"
        if ping_peer "$PEER_IP" -c 2 -W 2 >/dev/null 2>&1; then
            res ok "ping $PEER_IP works"
        else
            res bad "ping $PEER_IP fails: check that $CTRL_PORT (and the forwarded ports) are reachable; the peer may simply block ICMP even if the tunnel itself works"
        fi
    elif ip -4 addr show dev "$IFACE" 2>/dev/null | grep -q "inet $SELF_IP/"; then
        local cur_mtu max_pl
        cur_mtu=$(cat "/sys/class/net/$IFACE/mtu" 2>/dev/null || echo "$MTU_VAL")
        max_pl=$((cur_mtu - 28))
        res ok "$IFACE has $SELF_IP (mtu $cur_mtu)"
        if ! ip -d link show "$IFACE" 2>/dev/null | grep -q "remote $REMOTE_IP"; then
            res warn "$IFACE does not point at remote $REMOTE_IP (wrong peer IP, or the link type differs from the other server)"
        fi
        if ping_peer "$PEER_IP" -c 2 -W 2 >/dev/null 2>&1; then
            res ok "ping $PEER_IP works"
            local sz best=0
            for sz in "$max_pl" 1340 1300 1240 1200 1100 1000; do
                (( sz > max_pl )) && continue
                if ping -4 -M "do" -c 1 -W 2 -s "$sz" "$PEER_IP" >/dev/null 2>&1; then best=$sz; break; fi
            done
            if (( best == max_pl )); then
                res ok "full-size packets (mtu $cur_mtu) pass without fragmentation"
            elif (( best > 0 )); then
                res warn "largest unfragmented ping payload is $best (< $max_pl): real path MTU is below $cur_mtu -> lower MTU_VAL"
            else
                res bad "even 1000-byte DF pings are lost: MTU black hole or GRE filtering for larger packets"
            fi
        else
            res bad "ping $PEER_IP fails: GRE between $LOCAL_IP and $REMOTE_IP is blocked, the peer is not running, or link type / IP pair differ between the servers"
        fi
    else
        res bad "$IFACE missing or has no $SELF_IP"
    fi

    local m pub owners proto fl bind_list
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

        echo -e "\n${CYAN}5) Forwarded ports (dual-stack IPv4 + IPv6)${NC}"
        for m in $PORTS; do
            pub=${m%%=*}
            for proto in tcp udp; do
                [[ $proto == tcp && $FWD_TCP != 1 ]] && continue
                [[ $proto == udp && $FWD_UDP != 1 ]] && continue
                fl="-ltnpH"; [[ $proto == udp ]] && fl="-lunpH"
                if iptables -t filter -S INPUT 2>/dev/null | grep -q -- "-p $proto .*--dport $pub .*BHGT"; then
                    res ok "IPv4 firewall ACCEPT rule for $proto port $pub present"
                else
                    res bad "IPv4 firewall ACCEPT rule for $proto port $pub missing (menu 6 to reload)"
                fi
                if has_ipv6 && command -v ip6tables >/dev/null 2>&1; then
                    if ip6tables -t filter -S INPUT 2>/dev/null | grep -q -- "-p $proto .*--dport $pub .*BHGT"; then
                        res ok "IPv6 firewall ACCEPT rule for $proto port $pub present"
                    else
                        res bad "IPv6 firewall ACCEPT rule for $proto port $pub missing (menu 6 to reload)"
                    fi
                fi
                bind_list=$(ss $fl "sport = :$pub" 2>/dev/null | grep "$CORE_PROC" | awk '{print $4}' | paste -sd, -)
                if [[ -n $bind_list ]]; then
                    res ok "$CORE_NAME listens on $proto port $pub ($bind_list)"
                elif [[ -n $(ss $fl "sport = :$pub" 2>/dev/null) ]]; then
                    res bad "$proto port $pub is held by another program: $(ss $fl "sport = :$pub" | awk '{print $6}' | head -n1)"
                else
                    res warn "nothing listens on $proto $pub yet (normal until the Kharej client has connected)"
                fi
            done
        done
    else
        echo -e "\n${CYAN}4) Reaching the Iran control port${NC}"
        local state rc
        state=$(client_state)
        if [[ $state == up ]]; then
            res ok "Tunnel is established (client log); skipping the raw probe so it cannot disturb live traffic"
        elif ctrl_proto_is_udp; then
            res warn "UDP-based transport ($PROTO) cannot be probed with a plain TCP connect - read the client log below"
        else
            timeout 3 bash -c "exec 3<>/dev/tcp/$PEER_IP/$CTRL_PORT" 2>/dev/null
            rc=$?
            case $rc in
                0)   res warn "TCP connect to $(bracket_addr "$PEER_IP"):$CTRL_PORT works but no tunnel is established -> the program there hangs up (port owner / token / protocol / profile / binary mismatch). Run Diagnose on the IRAN server." ;;
                124) res bad "TCP connect to $(bracket_addr "$PEER_IP"):$CTRL_PORT TIMED OUT (packets dropped: MTU/firewall, or a blocked path in Direct mode)" ;;
                *)   res bad "TCP connect to $(bracket_addr "$PEER_IP"):$CTRL_PORT REFUSED: nothing listens there (Iran $CORE_NAME not running / different port)" ;;
            esac
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
    echo "    'failed to read message length ... EOF' on the Kharej client: the TCP connection worked, then the other end"
    echo "    closed it at once. With matching tokens the thing answering is not your core server (port owner, see Iran"
    echo "    step 4), uses another protocol/profile, or is a different build (compare sha256 in step 1 on both servers)."
    echo -e "${CYAN}======================================================${NC}\n"
}

# ------------------------------------------------------------------------------
# other menu actions
# ------------------------------------------------------------------------------
update_ports() {
    load_conf || { err "Not configured yet."; return 1; }
    if [[ $ROLE != iran && $CORE != frp ]]; then
        err "Forwarded ports are configured on the IRAN server only for $CORE_NAME - nothing to update here on Kharej."
        return 1
    fi
    if [[ $ROLE != iran ]]; then
        info "FRP: updating the port list on the KHAREJ client (frpc owns the proxy definitions)."
    fi
    info "Current forwarded ports: ${PORTS:-none}"
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
    local b t line
    local -a words=()
    echo
    warn "This removes the tunnel, services, firewall rules and config of THIS tunnel only."
    ask_yn "Really uninstall?" n || return 0
    systemctl stop "$BACKHAUL_SVC" "$FRP_SVC" "$LEGACY_FRP_SVC" "$LINK_SVC" >/dev/null 2>&1
    systemctl disable "$BACKHAUL_SVC" "$FRP_SVC" "$LEGACY_FRP_SVC" "$LINK_SVC" >/dev/null 2>&1
    for b in "$BACKHAUL_BIN" "$FRPS_BIN" "$FRPC_BIN" "$LEGACY_FRPS_BIN" "$LEGACY_FRPC_BIN"; do
        pkill -f -- "$b -c $CONFIG_DIR/" 2>/dev/null
    done
    [[ -x $CTL_SH ]] && "$CTL_SH" down
    # fallback firewall cleanup in case tunnel.conf was missing/corrupt
    for t in filter nat mangle; do
        while read -r line; do
            [[ -n $line ]] || continue
            line=${line//\"/}
            line="-D${line#-A}"
            read -ra words <<< "$line"
            iptables -t "$t" "${words[@]}" 2>/dev/null
        done < <(iptables -t "$t" -S 2>/dev/null | grep -E -- "--comment \"?BHGT\"?( |$)")
        if command -v ip6tables >/dev/null 2>&1; then
            while read -r line; do
                [[ -n $line ]] || continue
                line=${line//\"/}
                line="-D${line#-A}"
                read -ra words <<< "$line"
                ip6tables -t "$t" "${words[@]}" 2>/dev/null
            done < <(ip6tables -t "$t" -S 2>/dev/null | grep -E -- "--comment \"?BHGT\"?( |$)")
        fi
    done
    rm -f "$UNIT_DIR/$BACKHAUL_SVC" "$UNIT_DIR/$FRP_SVC" "$UNIT_DIR/$LEGACY_FRP_SVC" "$UNIT_DIR/$LINK_SVC"
    systemctl daemon-reload
    ip link del gretun1 2>/dev/null
    ip link del gretap1 2>/dev/null
    rm -rf "$CONFIG_DIR"
    rm -f "$BACKHAUL_BIN" "$FRPS_BIN" "$FRPC_BIN" "$LEGACY_FRPS_BIN" "$LEGACY_FRPC_BIN"
    ok "Tunnel, services and firewall rules removed (the shared $LEGACY_BIN, if any, was not touched)."
}

main_menu() {
    local choice
    while true; do
        clear
        echo -e "${CYAN}========================================================${NC}"
        echo -e "${GREEN}   GRE/GRETAP/Direct + Backhaul/FRP Tunnel Manager v$VERSION  ${NC}"
        if load_conf 2>/dev/null; then
            echo -e "${CYAN}   Active: $ROLE | $CORE_NAME | $LINK_LABEL | $PROTO/$PROFILE | $SELF_IP${NC}"
        else
            echo -e "${CYAN}   Not configured yet${NC}"
        fi
        echo -e "${CYAN}========================================================${NC}"
        echo -e " 1) Configure ${GREEN}IRAN Server${NC}   (link + core server + port forward)"
        echo -e " 2) Configure ${YELLOW}KHAREJ Client${NC} (link + core client)"
        echo -e " 3) Status & logs"
        echo -e " 4) Diagnose connection  ${CYAN}(use this when something fails)${NC}"
        echo -e " 5) Update forwarded ports"
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
