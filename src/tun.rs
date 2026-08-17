use colored::Colorize;
use std::net::Ipv6Addr;
use tun_tap::{Iface, Mode};
use tokio::io::unix::AsyncFd;

#[derive(Clone)]
pub struct TunKanal {
    tx: kanal::AsyncSender<Vec<u8>>,
    rx: kanal::AsyncReceiver<Vec<u8>>,
}

impl TunKanal {
    pub fn new() -> (Self, kanal::AsyncSender<Vec<u8>>, kanal::AsyncReceiver<Vec<u8>>) {
        let (tx_front, rx_back) = kanal::bounded_async(2048);
        let (tx_back, rx_front) = kanal::bounded_async(2048);

        (
            Self {
                tx: tx_front,
                rx: rx_front,
            },
            tx_back,
            rx_back,
        )
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
    if_index: libc::c_uint,
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
            eprintln!("     To prevent exploitation the capability will be dropped from permitted set just after the TUN interface is set up.");
            eprintln!();
            std::process::exit(1);
        };

        let name = iface.name().to_string();
        
        let c_name = std::ffi::CString::new(name.as_str()).unwrap();
        let if_index = unsafe { libc::if_nametoindex(c_name.as_ptr()) };

        assert_ne!(if_index, 0, "Failed to deterine index of the TUN interface");

        Self {
            iface: Some(iface),
            setup_finished: false,
            if_index,
            name,
        }
    }

    pub async fn setup(&mut self, ipv6: &Ipv6Addr) {
        if let Err(_) = async {
            use netlink_packet_route::link::{LinkFlags, LinkMessage};
            use netlink_packet_route::link::LinkAttribute;

            let (connection, handle, _) = rtnetlink::new_connection()?;
            tokio::spawn(connection);

            // Set MTU to 1280 (temporairly to avoid fragmentation issues) and bring interface UP
            // TODO: implement inner TCP SYN interception and WebX message fragmentation
            let mut msg = LinkMessage::default();
            msg.header.index = self.if_index;
            msg.attributes.push(LinkAttribute::Mtu(1280));
            msg.header.flags |= LinkFlags::Up;
            msg.header.change_mask |= LinkFlags::Up;

            handle.link().set(msg).execute().await?;

            // Add IPv6 address (/8 prefix)
            handle
                .address()
                .add(self.if_index, std::net::IpAddr::V6(*ipv6), 8)
                .execute()
                .await?;

            Ok::<(), Box<dyn std::error::Error>>(())
        }.await {
            panic!("Unable to configure TUN interface")
        };

        self.setup_finished = true;
    }

    pub fn name(&self) -> String {
        self.name.clone()
    }

    pub fn open_kanal(&mut self) -> TunKanal {
        use std::os::fd::{IntoRawFd, FromRawFd};
        use std::fs::File;
        use std::io::Write;
        use std::sync::Arc;

        let (k, back_tx, back_rx) = TunKanal::new();

        let iface = self.iface.take().unwrap();
        let fd = iface.into_raw_fd();

        let fd = unsafe {
            let f = libc::fcntl(fd, libc::F_GETFL);
            if f < 0 || libc::fcntl(fd, libc::F_SETFL, f | libc::O_NONBLOCK) < 0 {
                panic!("Could not set O_NONBLOCK on TUN file descriptor");
            }

            File::from_raw_fd(fd)
        };

        let fd_1 = Arc::new(
            AsyncFd::new(fd).expect("Could not create AsyncFd for TUN")
        );
        let fd_2 = fd_1.clone();

        tokio::task::spawn(async move {
            use std::io::Read;
            let mut buf = [0u8; 65535];

            loop {
                if let Ok(mut guard) = fd_1.readable().await {
                    match guard.try_io(|inner| inner.get_ref().read(&mut buf)) {
                        Ok(Ok(n)) => {
                            let _ = back_tx.send(buf[..n].to_vec()).await;
                        },
                        _ => continue
                    }
                }
            }
        });

        tokio::task::spawn(async move {
            while let Ok(data) = back_rx.recv().await {
                if let Ok(mut guard) = fd_2.writable().await {
                    let _ =  guard.try_io(|inner| inner.get_ref().write(&data));
                }
            }
        });

        k
    }
}
