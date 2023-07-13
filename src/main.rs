use colored::Colorize;
use serde::{Deserialize, Deserializer};
use signal_hook::{
    consts::{SIGINT, SIGTERM},
    iterator::Signals,
};
use std::collections::HashMap;
use std::net::Ipv6Addr;
use std::process;
use std::sync::Arc;
use tokio::sync::{Mutex, RwLock};

#[macro_use]
extern crate lazy_static;

#[macro_use]
mod logging_macros;

mod cli_socket;
mod loc;
mod p2p_network;
mod tun;
mod wallet;

const PSEUDOROUTER_ADDR: [u8; 16] = [
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

fn panic_hook(info: &core::panic::PanicInfo) {
    eprintln!(
        "{} {}",
        "Fatal error:".red().bold(),
        info.to_string().red().bold()
    );
    process::exit(1);
}

fn with_ambient_cap_net_admin<F, T>(f: F) -> T
where
    F: FnOnce() -> T,
{
    let caps_raised = if matches!(
        caps::has_cap(
            None,
            caps::CapSet::Permitted,
            caps::Capability::CAP_NET_ADMIN,
        ),
        Ok(true)
    ) && caps::raise(
        None,
        caps::CapSet::Inheritable,
        caps::Capability::CAP_NET_ADMIN,
    )
    .is_ok()
    {
        caps::raise(None, caps::CapSet::Ambient, caps::Capability::CAP_NET_ADMIN).unwrap();
        true
    } else {
        false
    };

    let t: T = f();

    if caps_raised {
        caps::drop(None, caps::CapSet::Ambient, caps::Capability::CAP_NET_ADMIN).unwrap();
        caps::drop(
            None,
            caps::CapSet::Inheritable,
            caps::Capability::CAP_NET_ADMIN,
        )
        .unwrap();
    }

    t
}

fn setup() {
    std::panic::set_hook(Box::new(panic_hook));

    let mut signals = Signals::new([SIGINT, SIGTERM]).unwrap();
    tokio::task::spawn_blocking(move || {
        for signal in signals.forever() {
            match signal {
                SIGINT => {
                    eprintln!("\n{}", "SIGINT received, exiting...".yellow().bold());
                }
                SIGTERM => {
                    eprintln!("\n{}", "SIGTERM received, exiting...".yellow().bold());
                }
                _ => unreachable!(),
            }

            process::exit(0);
        }
    });
}

#[derive(Deserialize)]
struct Config {
    server_enabled: bool,
    server_port: Option<u16>,
    #[serde(deserialize_with = "initial_peers_deserialize")]
    initial_peers: Vec<Vec<std::net::SocketAddr>>,
}

fn initial_peers_deserialize<'de, D>(de: D) -> Result<Vec<Vec<std::net::SocketAddr>>, D::Error>
where
    D: Deserializer<'de>,
{
    use std::net::ToSocketAddrs;

    let unresolved = Vec::<String>::deserialize(de)?;
    let mut resolved = vec![];
    for a in unresolved {
        let a = match a.to_socket_addrs() {
            Ok(a) => a,
            Err(e) => {
                let a = format!("{}:4760", a);
                a.to_socket_addrs()
                    .map_err(|_| serde::de::Error::custom(e))?
            }
        };

        resolved.push(a.collect::<Vec<_>>());
    }
    Ok(resolved)
}

lazy_static! {
    static ref STATS: cli_socket::Stats = cli_socket::Stats {
        total_packets_sent: Mutex::new(0),
        total_packets_received: Mutex::new(0),
        total_packets_forwarded: Mutex::new(0),
    };
}

#[tokio::main]
async fn main() {
    setup();

    let (home_dir, user_uid) = {
        use users::os::unix::UserExt;
        let sudo_user = std::env::var("SUDO_USER").ok();

        match sudo_user {
            Some(sudo_user) => {
                let u = users::get_user_by_name(&sudo_user).unwrap();
                (u.home_dir().display().to_string(), u.uid())
            }
            None => {
                let u = users::get_user_by_uid(users::get_current_uid()).unwrap();
                (u.home_dir().display().to_string(), u.uid())
            }
        }
    };

    let (peer_config, wlt) = {
        use std::io::Read;

        let mut config_file_path = format!("{home_dir}/.config/webx/config.toml");

        // if config file doesn't exist, get a copy from /etc/webx/config.toml
        if !std::path::Path::new(&config_file_path).exists() {
            if std::fs::create_dir_all(format!("{home_dir}/.config/webx")).is_err() {
                log_error!("Failed to create ~/.config/webx directory!");
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
                // load a wallet from ~/.config/webx/wallet
                // or generate a new one if it doesn't exist and save it
                let wlt =
                    match wallet::Wallet::from_file(&format!("{home_dir}/.config/webx/wallet")) {
                        Ok(wlt) => {
                            log_ok!("Wallet has been loaded!");
                            wlt
                        }
                        Err(_) => {
                            let wlt = wallet::Wallet::new();
                            log_warn!("New wallet has been generated!");
                            wlt.save_to_file(&format!("{home_dir}/.config/webx/wallet"))
                                .unwrap_or_else(|e| {
                                    log_error!("Cannot save wallet to file: {e}");
                                    process::exit(1);
                                });
                            wlt
                        }
                    };

                use std::os::unix::fs::PermissionsExt;

                let mut perms = std::fs::metadata(format!("{home_dir}/.config/webx/wallet"))
                    .unwrap()
                    .permissions();

                perms.set_mode(0o600);
                std::fs::set_permissions(format!("{home_dir}/.config/webx/wallet"), perms)
                    .unwrap_or_else(|e| {
                        log_error!("Cannot set permissions on wallet file: {e}");
                    });

                let user_gid = users::get_user_by_uid(user_uid).unwrap().primary_group_id();

                match std::process::Command::new("chown")
                    .arg(format!("{user_uid}:{user_gid}"))
                    .arg(&format!("{home_dir}/.config/webx/wallet"))
                    .spawn()
                {
                    Ok(mut child) => match child.wait() {
                        Ok(status) => {
                            if !status.success() {
                                log_error!("Cannot set ownership on wallet file: {status}");
                            }
                        }
                        Err(e) => {
                            log_error!("Cannot set ownership on wallet file: {e}");
                        }
                    },
                    Err(e) => {
                        log_error!("Cannot set ownership on wallet file: {e}");
                    }
                }

                (c, wlt)
            }
            Err(e) => {
                log_error!("Cannot parse config file at {config_file_path}:\n{e}");
                process::exit(1);
            }
        }
    };

    log_info!("Public key: {}", wlt.string_public_key());
    log_info!("IPv6: {}", wlt.ipv6);

    let mut tun_if = with_ambient_cap_net_admin(|| {
        let mut t = tun::Tun::new();
        t.setup_ipv6(&wlt.ipv6);
        t
    });

    log_ok!("TUN interface has been set up!");
    log_info!("The interface has name: {}", tun_if.name());

    let peers_tree: Arc<RwLock<p2p_network::PeerTree>> =
        Arc::new(RwLock::new(p2p_network::PeerTree::new(wlt.ipv6)));
    let send_queue: Arc<RwLock<HashMap<Ipv6Addr, kanal::AsyncSender<p2p_network::PacketForP2P>>>> =
        Arc::new(RwLock::new(HashMap::new()));
    let mut tun_channel = tun_if.open_kanal();

    let mut cli_sock = cli_socket::CliSocket::new(user_uid, peers_tree.clone(), wlt.clone());

    cli_sock.start();

    let net_wlt = wlt.clone();
    let net_peers_tree = peers_tree.clone();
    let net_send_queue = send_queue.clone();
    let net_tun_channel = tun_channel.clone();

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

                if dst == PSEUDOROUTER_ADDR {
                    packet[24..40].copy_from_slice(&wlt.ipv6.octets());
                    packet[8..24].copy_from_slice(&PSEUDOROUTER_ADDR);

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
                let route_to = peers_tree
                    .read()
                    .await
                    .get_ipv6_to_route_to(Ipv6Addr::from(dst));

                if route_to == Ipv6Addr::UNSPECIFIED {
                    continue;
                }

                if let Some(queue_inner) = send_queue.read().await.get(&route_to) {
                    let _ = queue_inner.send(packet_for_p2p).await;
                }
                *STATS.total_packets_sent.lock().await += 1;
            }
        }
    });

    p2p_network::p2p_job(
        net_wlt,
        peer_config.server_enabled,
        peer_config.server_port.unwrap_or(4760),
        net_peers_tree,
        net_send_queue,
        net_tun_channel,
        peer_config.initial_peers,
    )
    .await;
}
