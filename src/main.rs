use colored::Colorize;
use serde::{Deserialize, Deserializer};
use std::net::{Ipv6Addr, SocketAddr};
use std::process;
use std::sync::Arc;
use std::collections::HashSet;
use tokio::sync::{Mutex, RwLock};

#[macro_use]
extern crate lazy_static;

#[macro_use]
mod logging_macros;

mod cli_socket;
mod udp_handler;
mod p2p_network;
mod tun;
mod wallet;

const LOOPBACK_ADDR: [u8; 16] = [
    wallet::IPV6_PREFIX,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    1,
];

fn panic_hook(info: &std::panic::PanicHookInfo) {
    use colored::Colorize;
    let now = now!();

    eprintln!("\n");
    eprintln!("{} {} {}", now.dimmed(), "[FATAL]".red().bold(), "Fatal error occurred! Cannot continue operation.".red().bold());

    info.to_string().split("\n").into_iter().for_each(|line| {
        eprintln!("{} {} {}", now.dimmed(), "[FATAL]".red().bold(), line.red());
    });

    process::exit(1);
}

fn drop_all_caps_except_net_admin() {
    let caps = caps::read(None, caps::CapSet::Permitted).unwrap();

    for cap in caps {
        if cap != caps::Capability::CAP_NET_ADMIN {
            let _ = caps::drop(None, caps::CapSet::Effective, cap);
            let _ = caps::drop(None, caps::CapSet::Permitted, cap);
        }

        let _ = caps::drop(None, caps::CapSet::Ambient, cap);
        let _ = caps::drop(None, caps::CapSet::Inheritable, cap);
    }
}

fn with_onetime_cap_net_admin<F, T>(f: F) -> T
where
    F: AsyncFnOnce() -> T
{
    let caps_raised = if matches!(
        caps::has_cap(
            None,
            caps::CapSet::Permitted,
            caps::Capability::CAP_NET_ADMIN,
        ),
        Ok(true)
    ) {
        caps::raise(None, caps::CapSet::Effective, caps::Capability::CAP_NET_ADMIN).unwrap();
        true
    } else {
        false
    };

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();

    let t = rt.block_on(f());

    if caps_raised {
        caps::drop(None, caps::CapSet::Effective, caps::Capability::CAP_NET_ADMIN).unwrap();
        caps::drop(None, caps::CapSet::Permitted, caps::Capability::CAP_NET_ADMIN).unwrap();
    }

    t
}

#[derive(Deserialize)]
struct Config {
    bind_addr: Option<SocketAddr>,

    #[serde(deserialize_with = "initial_peers_deserialize")]
    initial_peers: HashSet<SocketAddr>,
}

fn initial_peers_deserialize<'de, D>(de: D) -> Result<HashSet<SocketAddr>, D::Error>
where
    D: Deserializer<'de>,
{
    use std::net::ToSocketAddrs;

    let unresolved = Vec::<String>::deserialize(de)?;
    let mut resolved = HashSet::new();

    for curr in unresolved {
        let a = match curr.to_socket_addrs() {
            Ok(mut a) => match a.next() {
                Some(addr) => addr,
                None => return Err(serde::de::Error::custom(format!("Unable to resolve address \"{}\"", curr))),
            },
            Err(e) => {
                let a = format!("{}:4760", curr);
                
                match a.to_socket_addrs() {
                    Ok(mut b) => match b.next() {
                        Some(addr) => addr,
                        None => return Err(serde::de::Error::custom(format!("Unable to resolve address \"{}\"", curr))),
                    },
                    Err(_e1) => return Err(serde::de::Error::custom(e)),
                }
            }
        };

        resolved.insert(a);
    }
    Ok(resolved)
}

pub struct Stats {
    pub total_packets_sent: Mutex<u128>,
    pub total_packets_received: Mutex<u128>,
    pub total_packets_forwarded: Mutex<u128>,
}

lazy_static! {
    static ref STATS: Stats = Stats {
        total_packets_sent: Mutex::new(0),
        total_packets_received: Mutex::new(0),
        total_packets_forwarded: Mutex::new(0),
    };
}

fn main() {
    std::panic::set_hook(Box::new(panic_hook));
    drop_all_caps_except_net_admin();

    let (home_dir, user_uid) = {
        use users::os::unix::UserExt;
        let mut sudo_user = std::env::var("SUDO_USER").ok();

        // check for --sudo-is-root flag
        let sudo_is_root = std::env::args().any(|arg| arg == "--sudo-is-root");

        if sudo_is_root {
            if sudo_user.is_none() {
                log_warn!(
                    "The --sudo-is-root flag was passed, but daemon was not started with `sudo`. Ignoring the flag."
                );
            }

            sudo_user = None; // fall back to root's home directory and uid
        }

        let u;

        if users::get_current_uid() == 0 {
            log_warn!(
                "WebX daemon was started as root. This is not recommended; consider using libcap-ng to grant the binary CAP_NET_ADMIN instead."
            );

            if let Some(sudo_user) = sudo_user {
                u = users::get_user_by_name(&sudo_user).unwrap();

                log_warn!(
                    "The configuration and wallet of user `{}` will be used instead of root. To load root's configuration and wallet, pass `--sudo-is-root` to the command line.",
                    sudo_user
                );
            } else {
                u = users::get_user_by_uid(0).unwrap();
            }
        } else {
            u = users::get_user_by_uid(users::get_current_uid()).unwrap();
        }

        (u.home_dir().display().to_string(), u.uid())
    };

    let (peer_config, wlt) = {
        use std::io::Read;

        let mut config_file_path = format!("{home_dir}/.webx/config.toml");

        // if config file doesn't exist, load from /etc/webx/config.toml
        if !std::path::Path::new(&config_file_path).exists() {
            if std::fs::create_dir_all(format!("{home_dir}/.webx")).is_err() {
                log_error!("Failed to create ~/.webx directory!");
                process::exit(1);
            }

            config_file_path = "/etc/webx/config.toml".to_string();
        }

        let mut config_file = std::fs::File::open(&config_file_path)
            .unwrap_or_else(|_| panic!("Config file not found or unreadable!"));

        let mut config_str = String::new();
        config_file.read_to_string(&mut config_str).unwrap();

        match toml::from_str::<Config>(&config_str) {
            Ok(c) => {
                // load a wallet from ~/.webx/wallet
                // or generate a new one if it doesn't exist and save it
                let wlt =
                    match wallet::Wallet::from_file(&format!("{home_dir}/.webx/wallet")) {
                        Ok(wlt) => {
                            log_ok!("Wallet has been loaded!");
                            wlt
                        }
                        Err(_) => {
                            let wlt = wallet::Wallet::new();
                            log_warn!("New wallet has been generated!");
                            wlt.save_to_file(&format!("{home_dir}/.webx/wallet"))
                                .unwrap_or_else(|e| {
                                    log_error!("Cannot save wallet to file: {e}");
                                    process::exit(1);
                                });
                            wlt
                        }
                    };

                use std::os::unix::fs::PermissionsExt;

                let mut perms = std::fs::metadata(format!("{home_dir}/.webx/wallet"))
                    .unwrap()
                    .permissions();

                perms.set_mode(0o600);
                std::fs::set_permissions(format!("{home_dir}/.webx/wallet"), perms)
                    .unwrap_or_else(|e| {
                        log_error!("Cannot set permissions on wallet file: {e}");
                    });

                let user_gid = users::get_user_by_uid(user_uid).unwrap().primary_group_id();
                let wallet_path = format!("{home_dir}/.webx/wallet");

                if let Err(e) = std::os::unix::fs::chown(&wallet_path, Some(user_uid), Some(user_gid)) {
                    log_error!("Cannot set ownership on wallet file `{wallet_path}`: {e}");
                }

                (c, wlt)
            }
            Err(e) => {
                log_error!("Cannot process the config file at {config_file_path}:\n{e}");
                process::exit(1);
            }
        }
    };

    log_info!("Public key: {}", wlt.string_public_key());
    log_info!("IPv6: {}", wlt.ipv6);

    let tun_if = with_onetime_cap_net_admin(|| async {
        let mut t = tun::Tun::new();
        t.setup(&wlt.ipv6).await;

        log_ok!("TUN interface has been set up!");
        log_info!("The interface has name: {}", t.name());

        t
    });

    let tokio_rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("Failed to build Tokio runtime");

    tokio_rt.block_on(async_main(peer_config, wlt, tun_if, user_uid));
}


async fn async_main(
    peer_config: Config,
    wlt: wallet::Wallet,
    mut tun_if: tun::Tun,
    user_uid: u32,
) {
    log_ok!("Entered asynchronous runtime!");

    let neighbors_db: Arc<RwLock<p2p_network::NeighborsDb>> =
        Arc::new(RwLock::new(p2p_network::NeighborsDb::new(wlt.ipv6)));

    let mut tun_channel = tun_if.open_kanal();
    let mut cli_sock = cli_socket::CliSocket::new(user_uid, neighbors_db.clone(), wlt.clone());

    cli_sock.start();

    let (sock, udp_inbound_rx) = udp_handler::UdpHandler::bind(
        peer_config.bind_addr.unwrap_or(SocketAddr::from((Ipv6Addr::UNSPECIFIED, 4760)))
    ).await.unwrap();

    
    let sock_signalhandler = sock.clone();
    tokio::task::spawn(async move {
        use tokio::signal::unix::{signal, SignalKind};

        let mut sigterm = signal(SignalKind::terminate()).unwrap();
        let mut sigint = signal(SignalKind::interrupt()).unwrap();

        tokio::select! {
            _ = sigterm.recv() => eprintln!("\n{}", "SIGTERM received, exiting...".yellow().bold()),
            _ = sigint.recv() => eprintln!("\n{}", "SIGINT received, exiting...".yellow().bold()),
        }

        sock_signalhandler.close_all().await;
        process::exit(0);
    });


    let net_wlt = wlt.clone();
    let net_neighbors_db = neighbors_db.clone();
    let net_tun_channel = tun_channel.clone();
    let net_sock = sock.clone();

    tokio::task::spawn(async move {
        loop {
            if let Ok(mut packet) = tun_channel.recv().await {
                if packet.len() < 40 {
                    continue;
                }

                let dst: [u8; 16] = (&packet[24..40]).try_into().unwrap();

                if dst[0] != wallet::IPV6_PREFIX {
                    continue;
                }

                if dst == LOOPBACK_ADDR || dst == wlt.ipv6.octets() {
                    packet[24..40].copy_from_slice(&wlt.ipv6.octets());
                    packet[8..24].copy_from_slice(&LOOPBACK_ADDR);

                    let result = tun_channel.send(packet).await;
                    if result.is_err() {
                        log_error!(
                            "Failed to send packet to TUN interface: {}",
                            result.err().unwrap()
                        );
                    }

                    continue;
                }

                let packet_for_p2p = p2p_network::PacketForP2P::new(packet, &wlt);
                let route_to = neighbors_db
                    .read()
                    .await
                    .get_sockaddr_to_route_to(Ipv6Addr::from(dst));

                if route_to == SocketAddr::from(([0, 0, 0, 0], 0)) {
                    continue;
                }

                let mut msg = vec![crate::p2p_network::MsgType::Packet as u8];
                msg.extend_from_slice(&packet_for_p2p.to_bytes());

                if sock.send_to(&msg, route_to).await.is_err() {
                    log_error!("Failed to forward packet to {}", crate::p2p_network::socketaddr_formatter(route_to));
                    continue;
                }

                *STATS.total_packets_sent.lock().await += 1;
            }
        }
    });

    p2p_network::p2p_job(
        net_sock,
        udp_inbound_rx,
        net_wlt,
        net_neighbors_db,
        net_tun_channel,
        peer_config.initial_peers,
    ).await;
}
