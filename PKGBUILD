# Maintainer: Krzysztof Stefańczyk <krzys.stefanczyk@gmail.com>

pkgname="webx"
url="https://github.com/HXM4Tech/WebX"
pkgver=0.1.0
pkgrel=1
pkgdesc="A decentralized P2P overlay network with cryptographic IPv6 addressing and packet verification"
arch=("x86_64" "i686" "aarch64" "armv6h" "armv7h" "riscv64" "loong64")
license=("MIT")
depends=("glibc" "libgcc" "libcap" "findutils" "python3")
optdepends=("systemd: to run as a system service")
install="package-archlinux/install.sh"
backup=("etc/webx/config.toml")

build() {
    cd "$startdir"
    cargo build --release
}

package() {
    cd "$startdir"
    install -Dm755 "target/release/webx" "$pkgdir/usr/bin/webxd"
    install -Dm755 "src/cli.py" "$pkgdir/usr/bin/webx-cli"
    install -Dm644 "conf/webx@.service" "$pkgdir/usr/lib/systemd/system/webx@.service"
    install -Dm644 "conf/config.toml" "$pkgdir/etc/webx/config.toml"
    install -Dm644 "LICENSE" "$pkgdir/usr/share/licenses/$pkgname/LICENSE"
    install -Dm644 "README.md" "$pkgdir/usr/share/doc/$pkgname/README.md"
}
