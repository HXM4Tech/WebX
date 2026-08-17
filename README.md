# WebX
WebX is decentralized peer-to-peer overlay network with cryptographic IPv6 addressing and packet verification.

## How it works?
When launched, WebX daemon generates you a wallet (if not already present under `.webx/wallet`) and opens a TUN interface on your system. The interface is then assigned a WebX IPv6 address corresponding to your wallet, MTU of 1280 bytes (temporarily to avoid IP fragmentation issues until inner TCP SYN interception and WebX message fragmentation are implemented) and is brought up.

Each peer can operate as both server and client. You can enable/disable server and set port in the config file (either system-wide at `/etc/webx/config.toml` or user's personal at `~/.webx/config.toml`) along with initial peers, which daemon will try to connect to as soon as it's launched.

### WebX IPv6 address assignment

Each peer has its own "wallet" which is an ECDSA Secp256k1 keypair used to assign WebX IPv6 address and sign packets.

The WebX IPv6 address consists of 2 parts:
1. 1-byte constant prefix `d400::/8` ensuring no collision with actively used address space. Although officially falling into [range reserved by IETF](https://www.iana.org/assignments/ipv6-address-space), it has not been assigned for any specific purpose. 
2. The last 15 bytes (120 bits) are 15-byte Blake3 XOF hash of the public key in compressed form (SEC1).

Note that the WebX IPv6 address is not the public key itself, but rather embeds a hash of it. This way, the public key is not directly exposed to the network, but can be easily "recovered" from the packet signature (which is a part of the packet itself). The recovery would return invalid public key when packet was corrupted or modified leading to a mismatch between its hash and source WebX IPv6 address. That's how WebX packets are verified.

### Routing

> [!WARNING]  
> Currently this is at work-in-progress stage. Routing based on XOR distance between WebX IPv6 addresses is implemented, but packets are dropped if they reach local minimum distance to the destination peer and the destination peer is not a direct neighbor. The peer discovery mechanism is needed to find new neighbors and route packets to them. This is planned to be implemented in the future.

The routing is based on XOR distance between WebX IPv6 addresses. Each peer maintains a list of its direct neighbors and their WebX IPv6 addresses. When a packet is received, the peer checks if it is the destination. If not, it calculates the XOR distances between its neighbors and the packet'sdestination address. The packet is forwarded to the neighbor with the closest address, unless the peer itself is closer to the destination than any of its neighbors. In that case, the packet is dropped.

To prevent too long routes, a Hop Limit field of IPv6 (equivalent of IPv4's TTL field) header is limited to 16. This way, the packet can travel at most 16 hops before it is dropped. Also a packet is dropped when it would be routed back to the source peer.

## How to build and run it?
### Dependencies
You will need to have a rust toolchain installed along with `build-essential` package on Debian-based distros, `base-devel` on Arch-based distros or corresponding packages on other distros to build WebX.

WebX itself also depends on `glibc`, `libcap`, and `python3`, but those are usually preinstalled on most systems.
`systemd` is required to run WebX daemon as a [system service](conf/webx@.service).

You can get rust toolchain from [rustup.rs](https://rustup.rs/).

### Building
If you're running Arch Linux or Debian-based distro (including Debian itself) it is recommended to build the package and install it using a package manager. Detailed instructions below.

**Arch Linux:**
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

For other distros you will need to build and install WebX manually. Detailed commands for user-wide installation below:

```sh
git clone https://github.com/HXM4Tech/WebX.git
cd webx
cargo build --release

install -Dm755 "target/release/webx" "$HOME/.local/bin/webxd"
sudo setcap CAP_NET_ADMIN+eip "$HOME/.local/bin/webxd"
install -Dm755 "py-src/cli.py" "$HOME/.local/bin/webx-cli"
install -Dm644 "config.toml" "$HOME/.webx/config.toml"
```
After completing, ensure that `$HOME/.local/bin` is in your `$PATH`.

The `setcap` command is used to grant WebX daemon capability necessary to set up the TUN interface. After the interface is set up, `CAP_NET_ADMIN` capability is dropped form the permitted set right away to prevent exploitation.

### Configuration
If you used a package manager to install WebX, you can find the config file at `/etc/webx/config.toml`. You can override it by creating a config file at `~/.webx/config.toml`.

If you built WebX manually, you can find the config file at `~/.webx/config.toml`.

### Running
If you used a package manager to install WebX, you can start daemon using systemd:
```sh
sudo systemctl start webx@$USER
```
You can also enable it to start on boot:
```sh
sudo systemctl enable webx@$USER
```
If you prefer running WebX as different user, replace `$USER` with desired username.

If you built WebX manually, you can start daemon by directly launching daemon binary:
```sh
webxd
```
If you want to run it in background, you can use `screen`.

## How to use it?

If the daemon has started successfully and connected to network you can start accessing WebX addresses right away.

### Using `webx-cli`
You can also use `webx-cli` to check what is your WebX address, how many packets have you sent/received/forwarded and what peers are your direct neighbors.
