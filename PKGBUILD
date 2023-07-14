# Maintainer: Krzysztof Stefańczyk <krzysztof.stefanczyk@hxm4tech.tk>
# Contributor: Krzysztof Stefańczyk <krzysztof.stefanczyk@hxm4tech.tk>

pkgname=webx
pkgver=$(grep -m1 "version" Cargo.toml | cut -d '"' -f2)
pkgrel=1
pkgdesc=$(grep -m1 "description" Cargo.toml | cut -d '"' -f2)
arch=("x86_64" "i686" "armv7h" "aarch64")
license=($(grep -m1 "license" Cargo.toml | cut -d '"' -f2))
depends=("base" "libcap" "python")
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
}
