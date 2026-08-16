use crate::STATS;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixListener;
use tokio::sync::Mutex;
use tokio::sync::RwLock;

pub struct Stats {
    pub total_packets_sent: Mutex<u128>,
    pub total_packets_received: Mutex<u128>,
    pub total_packets_forwarded: Mutex<u128>,
}

#[repr(u8)]
enum CliMsgType {
    StatsRequest = 0,
    StatsResponse = 1,
    NeighborsRequest = 2,
    NeighborsResponse = 3,
    WalletInfoRequest = 4,
    WalletInfoResponse = 5,

    Unknown = 255,
}

impl CliMsgType {
    pub fn from_byte(n: u8) -> Self {
        match n {
            0 => Self::StatsRequest,
            1 => Self::StatsResponse,
            2 => Self::NeighborsRequest,
            3 => Self::NeighborsResponse,
            4 => Self::WalletInfoRequest,
            5 => Self::WalletInfoResponse,
            _ => Self::Unknown,
        }
    }
}

pub struct CliSocket {
    neighbors_db: Option<Arc<RwLock<crate::p2p_network::NeighborsDb>>>,
    wallet: Option<crate::wallet::Wallet>,
    pub unix_socket_path: String,
    uid: u32,
}

impl CliSocket {
    pub fn new(
        uid: u32,
        neighbors_db: Arc<RwLock<crate::p2p_network::NeighborsDb>>,
        wallet: crate::wallet::Wallet,
    ) -> Self {
        let unix_socket_path = format!("/tmp/webx-{}.sock", uid);

        Self {
            neighbors_db: Some(neighbors_db),
            wallet: Some(wallet),
            unix_socket_path,
            uid,
        }
    }

    pub fn start(&mut self) {
        if std::path::Path::new(&self.unix_socket_path).exists() {
            let _ = std::fs::remove_file(&self.unix_socket_path);
        }

        if let Ok(listener) = UnixListener::bind(&self.unix_socket_path) {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(
                &self.unix_socket_path,
                std::fs::Permissions::from_mode(0o600),
            );
            let _ = std::process::Command::new("chown")
                .arg(format!("{}", self.uid))
                .arg(&self.unix_socket_path)
                .spawn();

            let neighbors_db = self.neighbors_db.take().unwrap();
            let wallet = self.wallet.take().unwrap();

            tokio::task::spawn(async move {
                loop {
                    let (mut socket, _) = listener.accept().await.unwrap();
                    let t_neighbors_db = neighbors_db.clone();

                    tokio::task::spawn(async move {
                        let mut buf = [0u8; 1];
                        loop {
                            if socket.read_exact(&mut buf).await.is_ok() {
                                match CliMsgType::from_byte(buf[0]) {
                                    CliMsgType::StatsRequest => {
                                        let mut msg = vec![CliMsgType::StatsResponse as u8];
                                        msg.extend_from_slice(
                                            &STATS.total_packets_sent.lock().await.to_be_bytes(),
                                        );
                                        msg.extend_from_slice(
                                            &STATS
                                                .total_packets_received
                                                .lock()
                                                .await
                                                .to_be_bytes(),
                                        );
                                        msg.extend_from_slice(
                                            &STATS
                                                .total_packets_forwarded
                                                .lock()
                                                .await
                                                .to_be_bytes(),
                                        );
                                        if socket.write_all(&msg).await.is_err() {
                                            return;
                                        }
                                    }
                                    CliMsgType::NeighborsRequest => {
                                        let mut msg = vec![CliMsgType::NeighborsResponse as u8];
                                        let neighbors_db = t_neighbors_db.read().await;
                                        let neighbors: std::collections::HashMap<
                                            std::net::Ipv6Addr,
                                            std::net::SocketAddr,
                                        > = neighbors_db.get_neighbors_hashmap();

                                        msg.extend_from_slice(&(neighbors.len() as u16).to_be_bytes());

                                        for (peer, socketaddr) in neighbors {
                                            msg.extend_from_slice(&peer.octets());
                                            
                                            match socketaddr {
                                                std::net::SocketAddr::V4(addr) => {
                                                    msg.push(0);
                                                    msg.extend_from_slice(&addr.ip().octets());
                                                    msg.extend_from_slice(&addr.port().to_be_bytes());
                                                }
                                                std::net::SocketAddr::V6(addr) => {
                                                    msg.push(1);
                                                    msg.extend_from_slice(&addr.ip().octets());
                                                    msg.extend_from_slice(&addr.port().to_be_bytes());
                                                }
                                            }
                                        }

                                        if socket.write_all(&msg).await.is_err() {
                                            return;
                                        }
                                    }
                                    CliMsgType::WalletInfoRequest => {
                                        let mut msg = vec![CliMsgType::WalletInfoResponse as u8];
                                        msg.extend_from_slice(&wallet.public_key.to_sec1_bytes());
                                        msg.extend_from_slice(&wallet.ipv6.octets());

                                        if socket.write_all(&msg).await.is_err() {
                                            return;
                                        }
                                    }
                                    _ => {
                                        continue;
                                    }
                                }
                            } else {
                                return;
                            }
                        }
                    });
                }
            });
        } else {
            log_error!("Failed to bind to unix socket {}", self.unix_socket_path);
        }
    }
}
