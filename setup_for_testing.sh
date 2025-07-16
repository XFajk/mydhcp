#!/bin/bash
# Usage: SET_FOR_TESTING=1 ./test-net.sh SSID PASSWORD INTERFACE
#        SET_FOR_TESTING=0 ./test-net.sh

SSID=$1
PASS=$2
IFACE=$3

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

    # Start and start NetworkManager again
    sudo systemctl start NetworkManager

    echo "NetworkManager restarted, normal operation resumed."

else
    echo "Please set SET_FOR_TESTING to 1 or 0"
    exit 1
fi
