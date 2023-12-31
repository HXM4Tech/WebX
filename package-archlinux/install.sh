post_install() {
        setcap CAP_NET_ADMIN+eip /usr/bin/webxd
        systemctl daemon-reload 2> /dev/null || /bin/true

        printf "\n"
        printf "\033[32;1mWebX has been installed successfully!\033[0m\n"
        printf "System-wide configuration file is located at /etc/webx/config.toml\n"
        printf "You can start WebX by running 'systemctl start webx@{user}' as root\n"
        printf "User provided as argument will, along with root, have access to WebX CLI (command 'webx-cli')\n"
        printf "\n"
}

post_upgrade() {
        setcap CAP_NET_ADMIN+eip /usr/bin/webxd
        systemctl daemon-reload 2> /dev/null || /bin/true
        systemctl restart webx@\* --all 2> /dev/null || /bin/true
}

pre_remove() {
        systemctl stop --now webx@\* --all 2> /dev/null || /bin/true
        find -L /etc/systemd/ -samefile /usr/lib/systemd/system/webx@.service -delete
}

post_remove() {
        systemctl daemon-reload 2> /dev/null || /bin/true
}
