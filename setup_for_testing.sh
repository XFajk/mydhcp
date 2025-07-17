#!/bin/bash
# Usage: SET_FOR_TESTING=1 ./test-net.sh SSID PASSWORD INTERFACE
#        SET_FOR_TESTING=0 ./test-net.sh

SSID=$1
PASS=$2
IFACE=$3

RESOLV_SYMLINK="/etc/resolv.conf"
RESOLV_TARGET="/run/systemd/resolve/stub-resolv.conf"

# Simple sanity check for required params when SET_FOR_TESTING=1
if [ "$SET_FOR_TESTING" = "1" ]; then
    if [ -z "$SSID" ] || [ -z "$PASS" ] || [ -z "$IFACE" ]; then
        echo "Usage: SET_FOR_TESTING=1 $0 SSID PASSWORD INTERFACE"
        exit 1
    fi
fi

if [ "$SET_FOR_TESTING" = "1" ]; then
    echo "Setting up testing environment..."

    # Stop NetworkManager (you might need sudo)
    sudo systemctl stop NetworkManager
    sudo systemctl stop systemd-resolved

    # Remove /etc/resolv.conf if it's a symlink
    if [ -L "$RESOLV_SYMLINK" ]; then
        echo "Removing /etc/resolv.conf symlink..."
        sudo rm "$RESOLV_SYMLINK"
    fi

    # Create new empty resolv.conf file
    echo "Creating standalone /etc/resolv.conf..."
    echo "# Created by mydhcp/setup_for_testing.sh for manual DNS control" | sudo tee "$RESOLV_SYMLINK" > /dev/null

    # Kill any running wpa_supplicant on the interface (cleanup)
    sudo pkill -f "wpa_supplicant.*$IFACE"

    # Bring interface down
    sudo ip link set "$IFACE" down

    # Create temporary wpa_supplicant config file
    WPA_CONF=$(mktemp)
    cat > "$WPA_CONF" <<EOF
network={
    ssid="$SSID"
    psk="$PASS"
}
EOF

    # Start wpa_supplicant manually in background
    sudo wpa_supplicant -B -i "$IFACE" -c "$WPA_CONF" -C /run/wpa_supplicant
    # Bring interface up
    sudo ip link set "$IFACE" up

    echo "Environment ready. Now you can run your DHCP client on $IFACE."

elif [ "$SET_FOR_TESTING" = "0" ]; then
    echo "Restoring normal environment..."

    # Kill any running wpa_supplicant on the interface
    if [ -n "$IFACE" ]; then
        sudo pkill -f "wpa_supplicant.*$IFACE"
    else
        sudo pkill wpa_supplicant
    fi

    # Bring interface down and up to reset
    if [ -n "$IFACE" ]; then
        sudo ip link set "$IFACE" down
        sudo ip link set "$IFACE" up
    fi

    # Remove custom /etc/resolv.conf if it exists
    if [ -f "$RESOLV_SYMLINK" ] && [ ! -L "$RESOLV_SYMLINK" ]; then
        echo "Removing temporary /etc/resolv.conf..."
        sudo rm "$RESOLV_SYMLINK"
    fi

    # Restore systemd's symlink
    if [ ! -L "$RESOLV_SYMLINK" ]; then
        echo "Restoring /etc/resolv.conf symlink..."
        sudo ln -s "$RESOLV_TARGET" "$RESOLV_SYMLINK"
    fi

    # Restart NetworkManager and systemd-resolved
    sudo systemctl start systemd-resolved
    sudo systemctl start NetworkManager

    echo "NetworkManager restarted, normal operation resumed."

else
    echo "Please set SET_FOR_TESTING to 1 or 0"
    exit 1
fi
