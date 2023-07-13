post_install() {
        setcap CAP_NET_ADMIN+eip /usr/bin/webxd
        systemctl daemon-reload

        printf "\n"
        printf "\033[32;1mWebX has been installed successfully!\033[0m\n"
        printf "System-wide configuration file is located at /etc/webx/config.toml\n"
        printf "You can start WebX by running 'systemctl start webx@{user}' as root\n"
        printf "User provided as argument will, along with root, have access to WebX CLI (command 'webx-cli')\n"
        printf "\n"
}

post_upgrade() {
        setcap CAP_NET_ADMIN+eip /usr/bin/webxd
        systemctl daemon-reload
        systemctl restart webx@\* --all
}

pre_remove() {
        systemctl stop --now webx@\* --all
        find -L /etc/systemd/ -samefile /usr/lib/systemd/system/webx@.service -delete
}

post_remove() {
        systemctl daemon-reload
}
