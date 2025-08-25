#!/bin/bash
# start_polish_vpn.sh
# VPS + OpenVPN clients via Surfshark VPN (Polish IP)
# SSH (port 22) bypasses VPN

OVPN_FILE="/root/ovpn/polishclient/poland_openvpn_udp.ovpn"
CRED_FILE="/root/ovpn/polishclient/cred.txt"
SSH_PORT=22
OVPN_SERVER_PORT=1194
VPN_TABLE=200
BACKUP_BASE="/root/network_backups"

mkdir -p "$BACKUP_BASE"

# --- Step 0: Clean previous tun100 interface ---
if ip link show tun100 &>/dev/null; then
    echo "[*] Removing existing tun100 interface..."
    ip link set tun100 down
    ip link delete tun100
fi

# --- Step 1: Backup current network ---
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_DIR="$BACKUP_BASE/backup_$TIMESTAMP"
mkdir -p "$BACKUP_DIR"

echo "[*] Backing up routing table..."
ip route show > "$BACKUP_DIR/routes.txt"

echo "[*] Backing up iptables..."
iptables-save > "$BACKUP_DIR/iptables-filter.txt"
iptables-save -t nat > "$BACKUP_DIR/iptables-nat.txt"
iptables-save -t mangle > "$BACKUP_DIR/iptables-mangle.txt"

echo "[*] Backing up interfaces and links..."
ip addr show > "$BACKUP_DIR/interfaces.txt"
ip link show > "$BACKUP_DIR/links.txt"

echo "[*] Backing up OpenVPN interfaces and processes..."
ip link show type tun > "$BACKUP_DIR/tun_interfaces.txt"
ps aux | grep openvpn | grep -v grep > "$BACKUP_DIR/openvpn_processes.txt"

ln -sfn "$BACKUP_DIR" "$BACKUP_BASE/latest"
echo "[*] Backup complete: $BACKUP_DIR"

# --- Step 2: Ensure dev tun100 and auth-user-pass in OVPN file ---
if ! grep -q "^dev tun100" "$OVPN_FILE"; then
    sed -i '/^dev /d' "$OVPN_FILE"
    echo "dev tun100" | cat - "$OVPN_FILE" > temp && mv temp "$OVPN_FILE"
fi

if ! grep -q "^auth-user-pass $CRED_FILE" "$OVPN_FILE"; then
    if grep -q '^auth-user-pass' "$OVPN_FILE"; then
        sed -i "s|^auth-user-pass.*|auth-user-pass $CRED_FILE|" "$OVPN_FILE"
    else
        echo "auth-user-pass $CRED_FILE" >> "$OVPN_FILE"
    fi
fi

# --- Step 3: Start Surfshark client ---
echo "[*] Starting Surfshark client..."
openvpn --config "$OVPN_FILE" --daemon

# Wait for tun100 to come up
for i in {1..10}; do
    sleep 2
    if ip addr show tun100 &>/dev/null; then
        break
    fi
done

if ! ip addr show tun100 &>/dev/null; then
    echo "[!] ERROR: tun100 did not appear. Check OpenVPN logs."
    exit 1
fi
echo "[*] Surfshark client running on tun100."

# --- Step 4: Policy routing and NAT ---
VPN_GW=$(ip addr show tun100 | grep 'inet ' | awk '{print $2}' | cut -d/ -f1)

sysctl -w net.ipv4.ip_forward=1

# Create VPN table if not exists
if ! ip route show table $VPN_TABLE &>/dev/null; then
    ip route add default via "$VPN_GW" dev tun100 table $VPN_TABLE
fi

# Flush old rules for table
ip rule del fwmark 0x1 table $VPN_TABLE 2>/dev/null

# Mark all outgoing traffic EXCEPT SSH and OpenVPN server port
iptables -t mangle -F OUTPUT 2>/dev/null
iptables -t mangle -A OUTPUT -o ens6 ! -p tcp --dport $SSH_PORT -j MARK --set-mark 0x1
iptables -t mangle -A OUTPUT -o ens6 ! -p udp --dport $OVPN_SERVER_PORT -j MARK --set-mark 0x1

# Add rule to route marked packets via VPN table
ip rule add fwmark 0x1 table $VPN_TABLE

# MASQUERADE traffic going out tun100
iptables -t nat -C POSTROUTING -o tun100 -j MASQUERADE &>/dev/null || \
    iptables -t nat -A POSTROUTING -o tun100 -j MASQUERADE

echo "[*] VPS and OpenVPN clients routed via tun100 (Polish IP)."
echo "[*] SSH on port $SSH_PORT bypasses VPN."
echo "[*] OpenVPN server on tun1 remains active for clients."
echo "[*] Backup at $BACKUP_DIR. Restore with network-backup-restore.sh if needed."
