#!/bin/bash

TUNNEL_BASE_NAME="l2tpeth"
GRE_BASE_NAME="gre"
CRON_FILE="/etc/cron.d/l2tp_tunnels"

function install_dependencies() {
    echo "[+] Installing required kernel modules..."
    sudo apt install -y linux-modules-extra-$(uname -r)
    sudo modprobe l2tp_eth
    sudo modprobe l2tp_ip
    sudo modprobe ip_gre
}

function generate_unique_name() {
    local base=$1
    local index=0
    while ip link show "$base$index" &>/dev/null; do
        ((index++))
    done
    echo "${base}${index}"
}

function add_tunnel() {
    echo "[+] Creating new L2TP tunnel"

    read -p "Local IP: " LOCAL_IP
    read -p "Remote IP: " REMOTE_IP
    read -p "Tunnel ID: " TUN_ID
    read -p "Session ID: " SES_ID
    read -p "IP range for L2TP interface (e.g., 10.10.1.1/30): " L2TP_IP
    read -p "GRE local IP (usually same as L2TP local): " GRE_LOCAL
    read -p "GRE remote IP (usually same as L2TP remote): " GRE_REMOTE
    read -p "GRE IP range (e.g., 10.20.1.1/30): " GRE_TUN_IP

    L2TP_NAME=$(generate_unique_name "$TUNNEL_BASE_NAME")
    GRE_NAME=$(generate_unique_name "$GRE_BASE_NAME")

    echo "[*] Creating L2TP tunnel: $L2TP_NAME"

    sudo ip l2tp add tunnel tunnel_id "$TUN_ID" peer_tunnel_id "$TUN_ID" \
        encap ip local "$LOCAL_IP" remote "$REMOTE_IP" udp_sport 1701 udp_dport 1701

    sudo ip l2tp add session tunnel_id "$TUN_ID" session_id "$SES_ID" peer_session_id "$SES_ID" \
        name "$L2TP_NAME"

    sudo ip link set "$L2TP_NAME" up
    sudo ip addr add "$L2TP_IP" dev "$L2TP_NAME"

    echo "[*] Creating GRE tunnel: $GRE_NAME"

    sudo ip tunnel add "$GRE_NAME" mode gre local "$GRE_LOCAL" remote "$GRE_REMOTE"
    sudo ip link set "$GRE_NAME" up
    sudo ip addr add "$GRE_TUN_IP" dev "$GRE_NAME"

    echo "[*] Saving startup script"
    STARTUP_SCRIPT="/usr/local/bin/start-${L2TP_NAME}.sh"
    echo "#!/bin/bash" > "$STARTUP_SCRIPT"
    echo "ip l2tp add tunnel tunnel_id $TUN_ID peer_tunnel_id $TUN_ID encap ip local $LOCAL_IP remote $REMOTE_IP udp_sport 1701 udp_dport 1701" >> "$STARTUP_SCRIPT"
    echo "ip l2tp add session tunnel_id $TUN_ID session_id $SES_ID peer_session_id $SES_ID name $L2TP_NAME" >> "$STARTUP_SCRIPT"
    echo "ip link set $L2TP_NAME up" >> "$STARTUP_SCRIPT"
    echo "ip addr add $L2TP_IP dev $L2TP_NAME" >> "$STARTUP_SCRIPT"
    echo "ip tunnel add $GRE_NAME mode gre local $GRE_LOCAL remote $GRE_REMOTE" >> "$STARTUP_SCRIPT"
    echo "ip link set $GRE_NAME up" >> "$STARTUP_SCRIPT"
    echo "ip addr add $GRE_TUN_IP dev $GRE_NAME" >> "$STARTUP_SCRIPT"
    chmod +x "$STARTUP_SCRIPT"

    echo "@reboot root bash $STARTUP_SCRIPT" | sudo tee -a "$CRON_FILE" > /dev/null

    echo "[+] Tunnel $L2TP_NAME and GRE $GRE_NAME created and added to boot."
}

function delete_tunnel() {
    echo "[!] Existing tunnels:"
    ip l | grep -oP '^.*: \K(l2tpeth[0-9]+)' | sort -u
    read -p "Enter L2TP tunnel name to delete (e.g., l2tpeth0): " L2TP_NAME

    GRE_NAME="gre${L2TP_NAME//l2tpeth/}"

    echo "[*] Removing interfaces"
    sudo ip link del "$GRE_NAME" &>/dev/null
    sudo ip link del "$L2TP_NAME" &>/dev/null

    echo "[*] Removing startup script and cron"
    STARTUP_SCRIPT="/usr/local/bin/start-${L2TP_NAME}.sh"
    sudo rm -f "$STARTUP_SCRIPT"
    sudo sed -i "\|$STARTUP_SCRIPT|d" "$CRON_FILE"

    echo "[+] Tunnel $L2TP_NAME and $GRE_NAME removed."
}

function delete_all_tunnels() {
    echo "[!] Removing all L2TP and GRE tunnels..."

    for i in $(ip l | grep -oP '^.*: \K(l2tpeth[0-9]+)' | sort -u); do
        sudo ip link del "$i" &>/dev/null
        GRE_NAME="gre${i//l2tpeth/}"
        sudo ip link del "$GRE_NAME" &>/dev/null
        sudo rm -f "/usr/local/bin/start-${i}.sh"
        sudo sed -i "\|start-${i}.sh|d" "$CRON_FILE"
    done

    echo "[+] All tunnels removed."
}

function menu() {
    echo ""
    echo "===== L2TP Tunnel Manager ====="
    echo "1. Install dependencies"
    echo "2. Add new L2TP + GRE tunnel"
    echo "3. Delete a tunnel"
    echo "4. Delete all tunnels"
    echo "0. Exit"
    echo "================================"
    read -p "Choose option: " OPT

    case "$OPT" in
        1) install_dependencies ;;
        2) add_tunnel ;;
        3) delete_tunnel ;;
        4) delete_all_tunnels ;;
        0) exit 0 ;;
        *) echo "Invalid option";;
    esac
}

while true; do
    menu
done
