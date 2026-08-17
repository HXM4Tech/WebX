use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::RwLock;

#[derive(Clone)]
pub struct UdpHandler {
    socket: Arc<UdpSocket>,
    peers: Arc<RwLock<HashMap<SocketAddr, kanal::AsyncSender<Vec<u8>>>>>,
}

impl UdpHandler {
    pub async fn bind(addr: SocketAddr) -> std::io::Result<(Self, kanal::AsyncReceiver<(SocketAddr, Vec<u8>)>)> {
        let socket = Arc::new(UdpSocket::bind(addr).await?);
        let peers = Arc::new(RwLock::new(HashMap::<SocketAddr, kanal::AsyncSender<Vec<u8>>>::new()));

        let (inbound_tx, inbound_rx) = kanal::unbounded_async::<(SocketAddr, Vec<u8>)>();

        let s = Arc::clone(&socket);
        let p = Arc::clone(&peers);

        tokio::spawn(async move {
            let mut buf = [0u8; 65535];
            while let Ok((len, src)) = s.recv_from(&mut buf).await {
                let data = buf[..len].to_vec();
                let src = Self::normalize_addr(src);

                let tx = {
                    let map = p.read().await;
                    map.get(&src).cloned()
                };

                if let Some(tx) = tx {
                    let _ = tx.send(data).await;
                } else {
                    let _ = inbound_tx.send((src, data)).await;
                }
            }
        });

        Ok((Self { socket, peers }, inbound_rx))
    }

    pub async fn connect(&self, target: SocketAddr) -> kanal::AsyncReceiver<Vec<u8>> {
        let target = Self::normalize_addr(target);
        let (tx, rx) = kanal::unbounded_async::<Vec<u8>>();
        self.peers.write().await.insert(target, tx);

        rx
    }

    pub async fn send_to(&self, buf: &[u8], target: SocketAddr) -> std::io::Result<usize> {
        self.socket.send_to(buf, target).await
    }

    pub async fn close(&self, target: SocketAddr) {
        self.peers.write().await.remove(&target);
        self.socket.send_to(&[crate::p2p_network::MsgType::Disconnect as u8], target).await.ok();
    }

    pub async fn close_all(&self) {
        let mut peers = self.peers.write().await;

        for (peer, _tx) in peers.drain() {
            self.socket.send_to(&[crate::p2p_network::MsgType::Disconnect as u8], peer).await.ok();
        }
    }

    fn normalize_addr(addr: SocketAddr) -> SocketAddr {
        match addr {
            SocketAddr::V6(v6) => {
                if let Some(v4) = v6.ip().to_ipv4_mapped() {
                    SocketAddr::V4(std::net::SocketAddrV4::new(v4, v6.port()))
                } else {
                    SocketAddr::V6(v6)
                }
            }
            v4 => v4,
        }
    }
}
