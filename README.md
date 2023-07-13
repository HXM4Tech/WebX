# WebX
WebX is peer-to-peer network carring signed IPv6 packages between peers.

## How it works?
When you launch WebX daemon, the TUN interface is created on your system. It automatically gets assigned a WebX IPv6 address, MTU of 1500 bytes and is brought up. Each peer can operate as both server and client. You can enable/disable server and set port in the confing file (either system-wide at `/etc/webx/config.toml` or user's personal at `~/.config/webx/config.toml`) along with initial peers, which daemon will try to connect to as soon as it's launched.

### WebX IPv6 address assignment
Each peer has its own "wallet" which is an ECDSA Secp256k1 keypair and timezone offset from GMT-12 + a 2 letter country code (these are associated with the timezone set on the system, where the wallet was generated and are used to designate "a region" in P2P network, which helps to find a route to peer).

The WebX IPv6 address consists of 3 parts:
1. Constant prefix colliding with neither public nor private IPv6 addresses. The `4c00::/8` was picked for this purpose.
2. Information about the peer's region (timezone offset + country code). Timezone offset takes 1 byte (it is raw uint8 value from 0 to 26) and country code takes 2 bytes (represented as 2 ASCII characters). This way, the Germany (GMT+1) will have `0x0d` (13 in hexadecimal) as timezone offset and `0x4445` (`DE` encoded in ASCII) as country code.
3. The last 12 bytes (96 bits) are the first 12 bytes of xxHash128 hash of the public key in compressed form (SEC1).

It is important to note, that the WebX IPv6 address is not the public key itself, but rather a hash of it. This way, the public key is not exposed to the network, but can be easily "recovered" from the packet signature (which is a part of the packet itself). The recovery would return invalid public key when packet is corrupted or modified, but that is not the problem since the hash of valid public key is embedded in source address and there are still pretty low chances of a hash collision. That's exactly how WebX packets are verified.

### Routing
Each peer in WebX network stores a tree of peers it knows about (3 levels deep; neighbors of neighbors of neighbors). The tree is updated evert time peer connects to/disconnects from another peer or gets information that some peer from its tree connected to/disconnected from another peer. The tree is used to determine which neighbor to forward packet to in order to get to the destination peer. If the tree does not contain the destination peer, the peer form the same country (and in the next step timezone) is picked. If there are still no such peers, the packet is forwarded to the first neighbor in the tree. If there are no neighbors, the packet is dropped.

To prevent infinite routes and routing loops, a Hop Limit field of IPv6 (equivalent of IPv4's TTL field) heder is limited to 16. This way, the packet can travel at most 16 hops before it is dropped. Also a packet is dropped when it would be routed back to the source peer.

## How to build and run it?
### Dependencies
You will need to have a rust toolchain instaled along with `build-essential` package on Debian-based distros, `base-devel` on Arch-based distros or corresponding packages on other distros to build WebX.

WebX itself also depends on `libcap`, `python3`, `findutils`, `iproute2` and `coreutils` packages, but those are usually preinstalled on most distros.

You can get rust toolchain from [rustup.rs](https://rustup.rs/).

### Building
If you're running Arch-based distro (including Arch Linux itself) or Debian-based distro (including Debian itself) it is recommended to build the package and install it using a package manager. Detailed instructions bellow.

**Arch-based distros:**
```sh
git clone https://github.com/HXM4Tech/webx.git
cd webx
makepkg -si
```

**Debian-based distros:**
```sh
cargo install cargo-deb
git clone https://github.com/HXM4Tech/webx.git
cd webx
cargo deb
sudo dpkg -i target/debian/webx_*.deb
```

For other distros you will need to build and install WebX manually. Detailed instructions for user installation bellow:

```sh
git clone https://github.com/HXM4Tech/webx.git
cd webx
cargo build --release

install install -Dm755 "target/release/webx" "$HOME/.local/bin/webxd"
sudo setcap CAP_NET_ADMIN+eip "$HOME/.local/bin/webx"
install -Dm755 "py-src/cli.py" "$HOME/.local/bin/webx-cli"
install -Dm644 "config.toml" "$HOME/.config/webx/config.toml"
```
After completing, ensure that `$HOME/.local/bin` is in your `$PATH`.

### Configuration
If you used a package manager to install WebX, you can find the config file at `/etc/webx/config.toml`. You can override it by creating a config file at `~/.config/webx/config.toml`.

If you built WebX manually, you can find the config file at `~/.config/webx/config.toml`.

### Running
If you used a package manager to install WebX, you can start daemon using systemd:
```sh
sudo systemctl start webx@$USER
```
You can also enable it to start on boot:
```sh
sudo systemctl enable webx@$USER
```

If you built WebX manually, you can start daemon using:
```sh
webxd
```
If you want to run it in background, you can use `screen`.

## How to use it?

If the daemon has started succesfully and connected to network you can start accessing WebX addresses right away.

### Using `webx-cli`
You can also use `webx-cli` to check what is your WebX address, how many packets have you sent/received/forwarded and what peers are in your peer's tree.
