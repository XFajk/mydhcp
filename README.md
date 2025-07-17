
# MyDHCP

A basic DHCP client written in Rust.

---

## 🚀 Overview

`mydhcp` is a standalone DHCP client made build out of curiosity of how DHCP and low level networking works it only supports linux because it used AF_PACKET socket's for total control over what gets set.

## ⚙️ Features

`mydhcp` is intentionally minimal and only supports IPv4 DHCP on Linux. Current capabilities include:

- Completes the standard DHCP handshake:  
  `DHCPDISCOVER → DHCPOFFER → DHCPREQUEST → DHCPACK`
- Automatically renews the lease based on the server-provided time
- Sends a `DHCPRELEASE` on `SIGINT` or panic (cleanup logic included)
- Configures received parameters using shell commands (for now)
  - IP address
  - Subnet mask
  - Gateway (via `ip route add default`)
  - DNS (via editing `/etc/resolv.conf`)

## 🫆 Security

The project tries to use Rust safely, but it does contain some `unsafe` code due to use of `libc`. Notably:

- `ManualDrop` is used in the `keep_track` method to manage lease state cleanup
- Care was taken, but memory safety is not guaranteed — especially in `keep_track`

If you're concerned about security, treat this as an educational reference, not production code.

## 💼 Usage

This project is primarily for learning and exploration. It's not production-ready and may contain memory safety bugs or rough edges.

You may find it useful as:

- A starting point for writing your own DHCP client
- A reference for low-level networking in Rust
- A personal experiment to study packet formats and system integration


## 🌐 Installation

For now you can only build from source with cargo.

```bash
git clone https://github.com/XFajk/mydhcp.git
cd mydhcp
cargo build --release
```

## 🏃‍➡️ Running

Before running, note:

- This is not a daemon (yet) — you'll need to daemonize it yourself if needed
- If you're using NetworkManager or systemd-resolved, stop them to avoid conflicts

You can use the setup_for_testing.sh script to configure your environment safely. Review what it does before running:

```bash
SET_FOR_TESTING=1 ./test-net.sh [SSID] [PASSWORD] [INTERFACE]
sudo RUST_LOG=info ./target/release/mydhcp [INTERFACE]
```

To clean up:

```bash
SET_FOR_TESTING=0 ./setup_for_testing.sh
```

## 📋 Documentation

Full integration design and internals are described in DESIGN.md (coming soon).

You can also view code-level documentation using:

```bash
cargo doc --open
```

## 📝 TODO

- Add full code documentation via docstrings
- Write unit tests where usefull
- Turn into a proper daemo
- Replace shell commands with Netlink API (for route + interface setup)
- Add support for IPv6
