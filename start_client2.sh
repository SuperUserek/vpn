#!/bin/bash
# start_polish_vpn.sh
# VPS runs OpenVPN server (tun0) + OpenVPN client (Surfshark via tun100)
# Safe: backup first, exit if backup fails

OVPN_FILE="/root/ovpn/polishclient/poland_openvpn_udp.ovpn"
CRED_FILE="/root/ovpn/polishclient/cred.txt"
SSH_PORT=22
OVPN_SERVER_PORT=1194
VPN_TABLE=200
SERVER_NET="10.8.0.0/24"
SERVER_DEV="tun0"   # your OpenVPN server device
CLIENT_DEV="tun100" # Surfshark client device
BACKUP_BASE="/root/network_backups"

mkdir -p "$BACKUP_BASE"

# --- Step 0: Clean old VPN client device ---
if ip link show $CLIENT_DEV &>/dev/null; then
    echo "[*] Removing old $CLIENT_DEV ..."
    ip link set $CLIENT_DEV down
    ip link delete $CLIENT_DEV
fi

# --- Step 1: Backup current state ---
TS=$(date +%Y%m%d_%H%M%S)
BKP="$BACKUP_BASE/backup_$TS"
mkdir -p "$BKP"

echo "[*] Backing up routing table..."
if ! ip route show > "$BKP/routes.txt"; then
    echo "[!] ERROR: Failed to backup routing table. Exiting."
    exit 1
fi

echo "[*] Backing up iptables..."
if ! iptables-save > "$BKP/iptables-filter.txt"; then
    echo "[!] ERROR: Failed to backup iptables filter table. Exiting."
    exit 1
fi
if ! iptables-save -t nat > "$BKP/iptables-nat.txt"; then
    echo "[!] ERROR: Failed to backup iptables NAT table. Exiting."
    exit 1
fi
if ! iptables-save -t mangle > "$BKP/iptables-mangle.txt"; then
    echo "[!] ERROR: Failed to backup iptables mangle table. Exiting."
    exit 1
fi

echo "[*] Backing up interfaces..."
if ! ip addr show > "$BKP/interfaces.txt"; then
    echo "[!] ERROR: Failed to backup interfaces. Exiting."
    exit 1
fi
if ! ip link show > "$BKP/links.txt"; then
    echo "[!] ERROR: Failed to backup links. Exiting."
    exit 1
fi

echo "[*] Backing up OpenVPN tun devices and processes..."
if ! ip link show type tun > "$BKP/tun_interfaces.txt"; then
    echo "[!] ERROR: Failed to backup tun interfaces. Exiting."
    exit 1
fi
if ! ps aux | grep openvpn | grep -v grep > "$BKP/openvpn_processes.txt"; then
    echo "[!] ERROR: Failed to backup OpenVPN processes. Exiting."
    exit 1
fi

ln -sfn "$BKP" "$BACKUP_BASE/latest"
echo "[*] Backup complete: $BKP"

# --- Step 2: Ensure tun100 + credentials in OVPN config ---
if ! grep -q "^dev $CLIENT_DEV" "$OVPN_FILE"; then
    sed -i '/^dev /d' "$OVPN_FILE"
    echo "dev $CLIENT_DEV" | cat - "$OVPN_FILE" > tmp && mv tmp "$OVPN_FILE"
fi
if ! grep -q "^auth-user-pass $CRED_FILE" "$OVPN_FILE"; then
    sed -i '/^auth-user-pass/d' "$OVPN_FILE"
    echo "auth-user-pass $CRED_FILE" >> "$OVPN_FILE"
fi

# --- Step 3: Start Surfshark client ---
echo "[*] Starting Surfshark OpenVPN client..."
openvpn --config "$OVPN_FILE" --daemon

# Wait for tun100 to appear
for i in {1..10}; do
    sleep 2
    if ip addr show $CLIENT_DEV &>/dev/null; then
        break
    fi
done
if ! ip addr show $CLIENT_DEV &>/dev/null; then
    echo "[!] ERROR: $CLIENT_DEV did not come up"
    exit 1
fi
echo "[*] Surfshark client running on $CLIENT_DEV"

# --- Step 4: Routing + NAT ---
sysctl -w net.ipv4.ip_forward=1

# Setup routing table for VPN
ip route flush table $VPN_TABLE
ip route add default dev $CLIENT_DEV table $VPN_TABLE

# Flush fwmark rules and mangle
ip rule del fwmark 0x1 table $VPN_TABLE 2>/dev/null
iptables -t mangle -F OUTPUT

# Exempt SSH
iptables -t mangle -A OUTPUT -p tcp --sport $SSH_PORT -j RETURN
# Exempt OpenVPN server
iptables -t mangle -A OUTPUT -p udp --sport $OVPN_SERVER_PORT -j RETURN
iptables -t mangle -A OUTPUT -p tcp --sport $OVPN_SERVER_PORT -j RETURN
# Exempt VPN server subnet
iptables -t mangle -A OUTPUT -d $SERVER_NET -j RETURN
# Everything else gets marked
iptables -t mangle -A OUTPUT -j MARK --set-mark 0x1

# Apply fwmark rule
ip rule add fwmark 0x1 table $VPN_TABLE

# NAT for clients: MASQUERADE on tun100
iptables -t nat -C POSTROUTING -s $SERVER_NET -o $CLIENT_DEV -j MASQUERADE 2>/dev/null || \
iptables -t nat -A POSTROUTING -s $SERVER_NET -o $CLIENT_DEV -j MASQUERADE

echo "[*] Config complete"
echo "    - SSH ($SSH_PORT/tcp) via provider IP"
echo "    - OpenVPN server ($OVPN_SERVER_PORT/tcp+udp) via provider IP"
echo "    - Local VPN subnet $SERVER_NET accessible"
echo "    - All other traffic goes out $CLIENT_DEV (Surfshark Polish IP)"

curl -4 ifconfig.io
