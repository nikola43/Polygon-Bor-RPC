#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────
#  Terminal Server Dashboard  —  like Grafana, but in bash
#  Usage:  ./server-status.sh            (one-shot)
#          ./server-status.sh --live     (auto-refresh every 2s)
#          ./server-status.sh --live 5   (auto-refresh every 5s)
# ──────────────────────────────────────────────────────────

set -uo pipefail

# ── colours & symbols ─────────────────────────────────────
R='\033[0;31m'; G='\033[0;32m'; Y='\033[0;33m'; B='\033[0;34m'
C='\033[0;36m'; M='\033[0;35m'; W='\033[1;37m'; D='\033[0;90m'
RESET='\033[0m'; BOLD='\033[1m'; DIM='\033[2m'

BAR_FULL="█"; BAR_EMPTY="░"

# ── helpers ───────────────────────────────────────────────
bar() {
    local pct=$1 width=${2:-30} colour=""
    if   (( pct >= 90 )); then colour=$R
    elif (( pct >= 70 )); then colour=$Y
    else                       colour=$G
    fi
    local filled=$(( pct * width / 100 ))
    local empty=$(( width - filled ))
    local bar_str=""
    for (( i=0; i<filled; i++ )); do bar_str+="$BAR_FULL"; done
    local empty_str=""
    for (( i=0; i<empty; i++ )); do empty_str+="$BAR_EMPTY"; done
    printf "${colour}%s${D}%s${RESET}" "$bar_str" "$empty_str"
}

divider() {
    printf "${D}─%.0s${RESET}" $(seq 1 60)
    echo
}

section() {
    echo
    printf "  ${BOLD}${C}▎ %s${RESET}\n" "$1"
    divider
}

# ── build dashboard ───────────────────────────────────────
render() {
    local cols=$(tput cols 2>/dev/null || echo 80)

    # HEADER
    echo
    printf "  ${BOLD}${W}╔══════════════════════════════════════════════════════════╗${RESET}\n"
    printf "  ${BOLD}${W}║${RESET}${BOLD}${C}           ⚡  SERVER DASHBOARD  ⚡                     ${RESET}${BOLD}${W}║${RESET}\n"
    printf "  ${BOLD}${W}╚══════════════════════════════════════════════════════════╝${RESET}\n"

    # SYSTEM INFO
    section "SYSTEM"
    local hostname=$(hostname)
    local kernel=$(uname -r)
    local uptime_str=$(uptime -p 2>/dev/null || uptime | sed 's/.*up/up/')
    local datetime=$(date '+%Y-%m-%d %H:%M:%S %Z')
    local load=$(awk '{print $1" "$2" "$3}' /proc/loadavg)
    local cpu_model=$(grep -m1 'model name' /proc/cpuinfo | cut -d: -f2 | xargs)
    local cpu_cores=$(nproc)

    printf "  ${W}Hostname :${RESET} %-20s ${W}Kernel :${RESET} %s\n" "$hostname" "$kernel"
    printf "  ${W}CPU      :${RESET} %s ${D}(%s cores)${RESET}\n" "$cpu_model" "$cpu_cores"
    printf "  ${W}Uptime   :${RESET} %-20s ${W}Time   :${RESET} %s\n" "$uptime_str" "$datetime"
    printf "  ${W}Load Avg :${RESET} %s\n" "$load"

    # CPU
    section "CPU USAGE"
    # read from /proc/stat  (two snapshots 0.3s apart for accuracy)
    read -r _ u1 n1 s1 i1 w1 _ _ _ _ < /proc/stat
    sleep 0.3
    read -r _ u2 n2 s2 i2 w2 _ _ _ _ < /proc/stat
    local total_d=$(( (u2+n2+s2+i2+w2) - (u1+n1+s1+i1+w1) ))
    local idle_d=$(( i2 - i1 ))
    local cpu_pct=0
    if (( total_d > 0 )); then
        cpu_pct=$(( 100 * (total_d - idle_d) / total_d ))
    fi
    printf "  $(bar $cpu_pct 40)  ${BOLD}%3d%%${RESET}\n" "$cpu_pct"

    # per-core (top 8)
    if command -v mpstat &>/dev/null; then
        mpstat -P ALL 0 1 2>/dev/null | awk '/^[0-9]/ || /^Average.*[0-9]+$/' | tail -n +2 | head -8 | while read -r _ _ core _ _ _ _ _ _ _ _ idle; do
            local pct=$(awk "BEGIN{printf \"%d\", 100-$idle}")
            printf "  ${D}Core %-2s${RESET} $(bar $pct 20) %3d%%\n" "$core" "$pct"
        done
    fi

    # MEMORY
    section "MEMORY"
    read -r mem_total mem_avail mem_used mem_pct <<< $(free -m | awk '/^Mem:/{used=$3; pct=int(used/$2*100); printf "%s %s %s %s", $2, $7, used, pct}')
    printf "  ${W}RAM ${RESET} $(bar $mem_pct 35) ${BOLD}%3d%%${RESET}  ${D}(%s / %s MB)${RESET}\n" "$mem_pct" "$mem_used" "$mem_total"

    # swap
    read -r swap_total swap_used swap_pct <<< $(free -m | awk '/^Swap:/{pct=($2>0)?int($3/$2*100):0; printf "%s %s %s", $2, $3, pct}')
    if (( swap_total > 0 )); then
        printf "  ${W}SWAP${RESET} $(bar $swap_pct 35) ${BOLD}%3d%%${RESET}  ${D}(%s / %s MB)${RESET}\n" "$swap_pct" "$swap_used" "$swap_total"
    else
        printf "  ${W}SWAP${RESET} ${D}(none)${RESET}\n"
    fi

    # DISK
    section "DISK USAGE"
    df -h --output=source,size,used,avail,pcent,target -x tmpfs -x devtmpfs -x squashfs 2>/dev/null | tail -n +2 | while read -r src size used avail pct mount; do
        local pct_num=${pct%%%}
        printf "  ${W}%-12s${RESET} $(bar $pct_num 25) %4s  ${D}%s used / %s total  →  %s${RESET}\n" \
            "$src" "$pct" "$used" "$size" "$mount"
    done

    # DISK I/O (if iostat available)
    if command -v iostat &>/dev/null; then
        section "DISK I/O"
        iostat -dh 1 1 2>/dev/null | awk 'NR>3 && NF>=6 {printf "  %-10s  Read: %-8s  Write: %-8s\n", $1, $3, $4}'
    fi

    # NETWORK
    section "NETWORK"
    for iface in /sys/class/net/*/; do
        iface_name=$(basename "$iface")
        [[ "$iface_name" == "lo" ]] && continue
        local state=$(cat "$iface/operstate" 2>/dev/null || echo "unknown")
        local rx_bytes=$(cat "$iface/statistics/rx_bytes" 2>/dev/null || echo 0)
        local tx_bytes=$(cat "$iface/statistics/tx_bytes" 2>/dev/null || echo 0)
        local rx_h=$(numfmt --to=iec "$rx_bytes" 2>/dev/null || echo "${rx_bytes}B")
        local tx_h=$(numfmt --to=iec "$tx_bytes" 2>/dev/null || echo "${tx_bytes}B")

        local ip_addr=$(ip -4 addr show "$iface_name" 2>/dev/null | awk '/inet /{print $2}' | head -1)
        [[ -z "$ip_addr" ]] && ip_addr="—"

        local state_colour=$G
        [[ "$state" != "up" ]] && state_colour=$R

        printf "  ${W}%-10s${RESET} ${state_colour}%-5s${RESET}  IP: %-18s  ↓ %-8s  ↑ %-8s\n" \
            "$iface_name" "$state" "$ip_addr" "$rx_h" "$tx_h"
    done

    # CONNECTIONS SUMMARY
    if command -v ss &>/dev/null; then
        local established=$(ss -tun state established 2>/dev/null | tail -n +2 | wc -l)
        local listening=$(ss -tln 2>/dev/null | tail -n +2 | wc -l)
        local time_wait=$(ss -tun state time-wait 2>/dev/null | tail -n +2 | wc -l)
        printf "\n  ${W}Connections:${RESET}  ESTABLISHED: ${G}%d${RESET}  LISTENING: ${C}%d${RESET}  TIME_WAIT: ${Y}%d${RESET}\n" \
            "$established" "$listening" "$time_wait"
    fi

    # TOP PROCESSES by CPU
    section "TOP PROCESSES  (by CPU)"
    printf "  ${D}%-7s %-12s %6s %6s  %s${RESET}\n" "PID" "USER" "CPU%" "MEM%" "COMMAND"
    ps aux --sort=-%cpu | awk 'NR>1 && NR<=8 {printf "  %-7s %-12s %5s%% %5s%%  %s\n", $2, $1, $3, $4, $11}' | head -7

    # TOP PROCESSES by MEM
    section "TOP PROCESSES  (by MEM)"
    printf "  ${D}%-7s %-12s %6s %6s  %s${RESET}\n" "PID" "USER" "CPU%" "MEM%" "COMMAND"
    ps aux --sort=-%mem | awk 'NR>1 && NR<=8 {printf "  %-7s %-12s %5s%% %5s%%  %s\n", $2, $1, $3, $4, $11}' | head -7

    # DOCKER (if running)
    if command -v docker &>/dev/null && docker info &>/dev/null 2>&1; then
        section "DOCKER CONTAINERS"
        docker stats --no-stream --format "  {{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}\t{{.NetIO}}\t{{.BlockIO}}" 2>/dev/null | \
            (printf "  ${D}%-25s %8s  %-20s  %-20s  %-20s${RESET}\n" "NAME" "CPU%" "MEM" "NET I/O" "BLOCK I/O"; cat) || true
    fi

    # SYSTEMD FAILED UNITS
    if command -v systemctl &>/dev/null; then
        local failed=$(systemctl --failed --no-legend 2>/dev/null | wc -l)
        if (( failed > 0 )); then
            section "FAILED SERVICES"
            printf "  ${R}${BOLD}%d failed unit(s):${RESET}\n" "$failed"
            systemctl --failed --no-legend 2>/dev/null | while read -r unit load active sub desc; do
                printf "  ${R}✗${RESET} %s  ${D}(%s)${RESET}\n" "$unit" "$desc"
            done
        fi
    fi

    # FOOTER
    echo
    divider
    printf "  ${D}Refreshed: %s${RESET}\n\n" "$(date '+%H:%M:%S')"
}

# ── main ──────────────────────────────────────────────────
if [[ "${1:-}" == "--live" ]]; then
    interval=${2:-2}
    while true; do
        clear
        render
        sleep "$interval"
    done
else
    render
fi
