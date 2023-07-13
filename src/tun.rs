use colored::Colorize;
use std::net::Ipv6Addr;
use tun_tap::{Iface, Mode};

use crate::wallet::IPV6_PREFIX;

#[derive(Clone)]
pub struct TunKanal {
    tx: kanal::AsyncSender<Vec<u8>>,
    rx: kanal::AsyncReceiver<Vec<u8>>,
}

impl TunKanal {
    pub fn new() -> (Self, kanal::Sender<Vec<u8>>, kanal::Receiver<Vec<u8>>) {
        let (tx_front, rx_back) = kanal::unbounded_async();
        let (tx_back, rx_front) = kanal::unbounded_async();

        (Self {
            tx: tx_front,
            rx: rx_front,
        }, tx_back.to_sync(), rx_back.to_sync())
    }

    pub async fn send(&mut self, data: Vec<u8>) -> Result<(), kanal::SendError> {
        self.tx.send(data).await
    }

    pub async fn recv(&mut self) -> Result<Vec<u8>, kanal::ReceiveError> {
        self.rx.recv().await
    }
}


pub struct Tun {
    iface: Option<Iface>,
    setup_finished: bool,
    name: String,
}

impl Tun {
    pub fn new() -> Self {
        let Ok(iface) = Iface::without_packet_info("webx%d", Mode::Tun) else {
            eprintln!();
            log_error!("You do not have CAP_NET_ADMIN capability! Cannot create TUN interface.");
            eprintln!("Hints:");
            eprintln!("  1) Run this program as root, or");
            eprintln!("  2) {} Add CAP_NET_ADMIN capability to this program by running as root:", "(RECOMMENDED)".green().bold());
            eprintln!("       {}{}{}", "setcap CAP_NET_ADMIN+eip \"".bold(), std::env::current_exe().unwrap().to_str().unwrap().bold(), "\"".bold());
            eprintln!();
            std::process::exit(1);
        };

        // bring the interface up
        std::process::Command::new("ip")
            .arg("link")
            .arg("set")
            .arg("dev")
            .arg(iface.name())
            .arg("up")
            .output()
            .unwrap_or_else(|_| panic!("failed to bring up {} interface", iface.name()));

        std::process::Command::new("ip")
            .arg("link")
            .arg("set")
            .arg("dev")
            .arg(iface.name())
            .arg("mtu")
            .arg("1500")
            .output()
            .unwrap_or_else(|_| panic!("failed to set MTU of {} interface", iface.name()));

        let name = iface.name().to_string();
        Self {
            iface: Some(iface),
            setup_finished: false,
            name,
        }
    }

    pub fn setup_ipv6(&mut self, ipv6: &Ipv6Addr) {
        // add ipv6 address to interface
        std::process::Command::new("ip")
            .arg("-6")
            .arg("addr")
            .arg("add")
            .arg(format!("{ipv6}/8"))
            .arg("dev")
            .arg(&self.name)
            .output()
            .unwrap_or_else(|_| panic!("failed to add ipv6 address to {} interface", self.name));

        // setup route
        std::process::Command::new("ip")
            .arg("-6")
            .arg("route")
            .arg("add")
            .arg(format!("{IPV6_PREFIX:x}00::/8"))
            .arg("dev")
            .arg(&self.name)
            .output()
            .unwrap_or_else(|_| panic!("failed to add route to {} interface", self.name));

        self.setup_finished = true;
    }

    pub fn name(&self) -> String {
        self.name.clone()
    }

    pub fn open_kanal(&mut self) -> TunKanal {
        let (k, back_tx, back_rx) = TunKanal::new();

        use std::os::fd::{AsRawFd, FromRawFd};

        let iface = self.iface.take().unwrap();
        let mut iface_reader = unsafe { std::fs::File::from_raw_fd(iface.as_raw_fd()) };

        tokio::task::spawn_blocking(move || {
            use std::io::Read;
            let mut buf = [0u8; 1504];

            loop {
                if let Ok(n) = iface_reader.read(&mut buf[..]) {
                    let _ = back_tx.send(buf[..n].to_vec());
                }
            }
        });

        tokio::task::spawn_blocking(move || {
            loop {
                if let Ok(data) = back_rx.recv() {
                    let _ = iface.send(&data);
                }
            }
        });

        k
    }
}
