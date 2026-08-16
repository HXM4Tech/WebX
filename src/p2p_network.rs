use crate::tun::TunKanal;
use crate::wallet;
use crate::STATS;
use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
use std::collections::HashMap;
use std::net::{Ipv6Addr, SocketAddr};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::RwLock;
use blake3::Hasher;

const MAX_CONNECTED_PEERS: usize = 8;

pub fn socketaddr_formatter(socketaddr: SocketAddr) -> String {
    match socketaddr {
        SocketAddr::V4(socketaddr) => {
            format!("{}:{}", socketaddr.ip(), socketaddr.port())
        }
        SocketAddr::V6(socketaddr) => {
            if let Some(ipv4) = socketaddr.ip().to_ipv4_mapped() {
                return format!("{}:{}", ipv4, socketaddr.port());
            }

            format!("[{}]:{}", socketaddr.ip(), socketaddr.port())
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Neighbor {
    pub webx_ipv6: Ipv6Addr,
    pub socketaddr: SocketAddr,
}

impl Neighbor {
    pub fn new(webx_ipv6: Ipv6Addr, socketaddr: SocketAddr) -> Self {
        Self {
            webx_ipv6,
            socketaddr,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NeighborsDb {
    pub our_webx_ipv6: Ipv6Addr,
    pub neighbors: Vec<Neighbor>
}

impl NeighborsDb {
    pub fn new(our_webx_ipv6: Ipv6Addr) -> Self {
        Self {
            our_webx_ipv6,
            neighbors: Vec::new(),
        }
    }

    pub fn register_neighbor(&mut self, neighbor: Neighbor) -> Result<(), &str> {
        if self.neighbors.len() >= MAX_CONNECTED_PEERS {
            return Err("Max connected peers reached");
        }

        if self.neighbors.contains(&neighbor) {
            return Err("Neighbor already registered");
        }

        self.neighbors.push(neighbor);
        Ok(())
    }

    pub fn unregister_neighbor(&mut self, sockaddr: SocketAddr) -> Result<(), &str> {
        let index = self.neighbors.iter().position(|x| x.socketaddr == sockaddr);

        if index.is_none() {
            return Err("Neighbor not registered");
        }

        self.neighbors.remove(index.unwrap());
        Ok(())
    }

    pub fn get_sockaddr_to_route_to(&self, webx_ipv6: Ipv6Addr) -> SocketAddr {
        let mut closest_neighbor: Option<&Neighbor> = None;
        let mut closest_distance: u128 = u128::MAX;

        for neighbor in self.neighbors.iter() {
            let distance = Self::xor_distance(neighbor.webx_ipv6, webx_ipv6);

            if closest_distance > distance {
                closest_distance = distance;
                closest_neighbor = Some(neighbor);
            }
        }

        if Self::xor_distance(self.our_webx_ipv6, webx_ipv6) < closest_distance {
            return SocketAddr::from(([0, 0, 0, 0], 0));
        }

        closest_neighbor.map(|n| n.socketaddr).unwrap()
    }

    pub fn get_neighbors_hashmap(&self) -> HashMap<Ipv6Addr, SocketAddr> {
        let mut known_peers = HashMap::new();

        for peer in self.neighbors.iter() {
            known_peers.insert(peer.webx_ipv6, peer.socketaddr);
        }

        known_peers
    }

    fn xor_distance(a1: Ipv6Addr, a2: Ipv6Addr) -> u128 {
        let a1_bytes = a1.octets();
        let a2_bytes = a2.octets();

        let mut distance = 0u128;

        for i in 0..16 {
            distance <<= 8;
            distance |= (a1_bytes[i] ^ a2_bytes[i]) as u128;
        }

        distance
    }
}

#[derive(Debug)]
pub struct PacketForP2P {
    pub ipv6_packet: Vec<u8>,
    pub signature: Vec<u8>,
    pub recid: u8,

    pub hop_limit: u8,
}

impl PacketForP2P {
    pub fn new(mut ipv6_packet: Vec<u8>, wlt: &wallet::Wallet) -> Self {
        let hop_limit = std::cmp::min(ipv6_packet[7], 16u8); // max hop limit is 16
        ipv6_packet[7] = 0; // clear hop limit as it should be able to change without breaking the signature

        let (signature, recid) = wlt.sign_recoverable(&ipv6_packet);
        let public_key = wlt.public_key.to_sec1_bytes();

        // calculate 6 bit checksum of public key
        let mut checksum = 0;
        for i in 0..32 {
            checksum ^= public_key[i];
            checksum %= 0b01000000;
        }

        Self {
            ipv6_packet,
            signature: signature.to_bytes().to_vec(),
            recid: ((recid.to_byte() << 6) | checksum),
            hop_limit,
        }
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, &str> {
        if bytes.len() < 105 {
            return Err("Packet is too small");
        }

        let length = 40 + (u16::from_be_bytes([bytes[4], bytes[5]]) as usize);

        if bytes.len() != (length + 65) {
            return Err("Invalid packet length");
        }

        let mut ipv6_packet = bytes[0..length].to_vec();

        let hop_limit = std::cmp::min(ipv6_packet[7], 16u8); // max hop limit is 16
        ipv6_packet[7] = 0; // clear hop limit as it should be able to change without breaking the signature

        let signature = bytes[length..(length + 64)].to_vec();
        let recid = bytes[length + 64];

        Ok(Self {
            ipv6_packet,
            signature,
            recid,
            hop_limit,
        })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        let mut ipv6_packet_bytes = self.ipv6_packet.clone();
        ipv6_packet_bytes[7] = self.hop_limit;

        bytes.extend(ipv6_packet_bytes);
        bytes.extend(self.signature.clone());
        bytes.push(self.recid);

        bytes
    }

    pub fn verify(&self) -> bool {
        let Ok(signature) = Signature::from_slice(&self.signature) else { return false; };
        let Some(recovery_id) = RecoveryId::from_byte(self.recid >> 6) else { return false; };

        let mut hasher = Hasher::new();
        hasher.update(&self.ipv6_packet);
        let prehash = hasher.finalize().as_slice().to_owned();

        // recover the public key from the signature and recid
        let Ok(public_key) = VerifyingKey::recover_from_prehash(
            &prehash,
            &signature,
            recovery_id,
        ) else { return false; };

        // check public key checksum (last 6 bits of recid)
        let public_key_bytes = public_key.to_sec1_bytes();

        let mut valid_checksum = 0;
        for i in 0..32 {
            valid_checksum ^= public_key_bytes[i];
            valid_checksum %= 0b01000000;
        }

        if valid_checksum != (self.recid & 0b00111111) {
            return false;
        }

        self.ipv6_packet[9..24] == wallet::Wallet::generate_ipv6_hash_part(&public_key_bytes)
    }

    pub fn into_ipv6_packet(mut self) -> Vec<u8> {
        self.ipv6_packet[7] = self.hop_limit;

        self.ipv6_packet
    }
}

#[repr(u8)]
enum MsgType {
    // just this one byte
    KeepAlive = 0,
    // PacketForP2P (variable length; no need to send lenght as it could be determinded from IPv6 header)
    Packet = 1,

    // just this one byte
    Disconnect = 254,
    Unknown = 255,
}

impl MsgType {
    fn from_byte(byte: u8) -> Self {
        match byte {
            0 => Self::KeepAlive,
            1 => Self::Packet,
            254 => Self::Disconnect,
            _ => Self::Unknown,
        }
    }
}

async fn server(
    our_wallet: wallet::Wallet,
    port: u16,
    neighbors_db: Arc<RwLock<NeighborsDb>>,
    queue: Arc<RwLock<HashMap<SocketAddr, kanal::AsyncSender<PacketForP2P>>>>,
    tun_channel: TunKanal,
) -> Result<(), Box<dyn std::error::Error>> {
    let listener = tokio::net::TcpListener::bind((Ipv6Addr::UNSPECIFIED, port)).await?;
    log_ok!("(P2P) Server has started and is listening on port {}", port);

    loop {
        let (mut stream, source) = listener.accept().await.unwrap();
        let handler_neighbors_db = neighbors_db.clone();
        let handler_queue = queue.clone();
        let handler_wallet = our_wallet.clone();
        let mut handler_tun_channel = tun_channel.clone();

        // SERVER
        tokio::task::spawn(async move {
            let mut their_hello_msg = [0u8; 16 + 64 + 1];

            if stream.read_exact(&mut their_hello_msg).await.is_err() {
                let _ = stream.write_u8(MsgType::Disconnect as u8).await;
                log_error!(
                    "(P2P) Connection with {} failed, cannot read message",
                    socketaddr_formatter(source)
                );
                return;
            }

            let their_webx_ipv6: [u8; 16] = their_hello_msg[0..16].try_into().unwrap();
            let their_webx_ipv6 = Ipv6Addr::from(their_webx_ipv6);

            // verify their hello message signature
            {
                let hello_recid = their_hello_msg[80];

                let Ok(hello_signature) = Signature::from_slice(&their_hello_msg[16..80]) else {
                    let _ = stream.write_u8(MsgType::Disconnect as u8).await;
                    log_error!("(P2P) Connection from {} rejected, authorization failed", socketaddr_formatter(source));
                    return;
                };
                let Some(hello_recovery_id) = RecoveryId::from_byte(hello_recid >> 6) else {
                    let _ = stream.write_u8(MsgType::Disconnect as u8).await;
                    log_error!("(P2P) Connection from {} rejected, authorization failed", socketaddr_formatter(source));
                    return;
                };

                let mut hasher = Hasher::new();
                hasher.update(b"hello");
                let prehash = hasher.finalize().as_slice().to_owned();

                let Ok(their_public_key) = VerifyingKey::recover_from_prehash(
                    &prehash,
                    &hello_signature,
                    hello_recovery_id,
                ) else {
                    let _ = stream.write_u8(MsgType::Disconnect as u8).await;
                    log_error!("(P2P) Connection from {} rejected, authorization failed", socketaddr_formatter(source));
                    return;
                };

                let their_public_key_bytes = their_public_key.to_sec1_bytes();

                // check public key checksum (last 6 bits of recid)
                let mut valid_checksum = 0;
                for i in 0..32 {
                    valid_checksum ^= their_public_key_bytes[i];
                    valid_checksum %= 0b01000000;
                }

                if valid_checksum != (hello_recid & 0b00111111) {
                    let _ = stream.write_u8(MsgType::Disconnect as u8).await;
                    log_error!(
                        "(P2P) Connection from {} rejected, authorization failed",
                        socketaddr_formatter(source)
                    );
                    return;
                }

                // check if their public key matches their WebX IPv6 address
                if their_webx_ipv6.octets()[1..16]
                    != wallet::Wallet::generate_ipv6(&their_public_key).octets()[1..16]
                {
                    let _ = stream.write_u8(MsgType::Disconnect as u8).await;
                    log_error!(
                        "(P2P) Connection from {} rejected, authorization failed",
                        socketaddr_formatter(source)
                    );
                    return;
                }
            }

            // send our hello message
            {
                let (hello_signature, hello_recid) = &handler_wallet.sign_recoverable(b"hello");
                let hello_signature = hello_signature.to_bytes();
                let hello_recid = hello_recid.to_byte();

                let our_pubkey_bytes = handler_wallet.public_key.to_sec1_bytes();

                // algorithm to embed checksum in recid
                let mut checksum = 0;
                for i in 0..32 {
                    checksum ^= our_pubkey_bytes[i];
                    checksum %= 0b01000000;
                }

                let mut our_hello_msg = Vec::new();
                our_hello_msg.extend_from_slice(&handler_wallet.ipv6.octets());
                our_hello_msg.extend_from_slice(&hello_signature);
                our_hello_msg.push((hello_recid << 6) | checksum);

                if stream.write_all(&our_hello_msg).await.is_err() {
                    log_error!(
                        "(P2P) Connection with {} failed",
                        socketaddr_formatter(source)
                    );
                    return; // do not send disconnect message as we can't write to stream
                }
            }

            // add them to our neighbor db
            if (*handler_neighbors_db.write().await)
                .register_neighbor(Neighbor::new(their_webx_ipv6, source))
                .is_err()
            {
                let _ = stream.write_u8(MsgType::Disconnect as u8).await;
                log_error!(
                    "(P2P) Connection with {} failed, cannot register neighbor",
                    socketaddr_formatter(source)
                );
                return;
            };

            // add them to our queue
            let (tx, rx) = kanal::unbounded_async();

            handler_queue.write().await.insert(source, tx);

            log_ok!(
                "(P2P) Connected to {} with WebX IPv6 address {}",
                socketaddr_formatter(source),
                their_webx_ipv6
            );

            handle_peer(
                source,
                their_webx_ipv6,
                &handler_wallet,
                handler_neighbors_db,
                handler_queue,
                rx,
                &mut handler_tun_channel,
                stream,
            )
            .await;
        });
    }
}

async fn client(
    our_wallet: &wallet::Wallet,
    server_addr_vec: &[SocketAddr],
    neighbors_db: Arc<RwLock<NeighborsDb>>,
    queue: Arc<RwLock<HashMap<SocketAddr, kanal::AsyncSender<PacketForP2P>>>>,
    tun_channel: &mut TunKanal,
    reconnecting: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut server_addr = SocketAddr::new(Ipv6Addr::UNSPECIFIED.into(), 0);
    let mut stream = None;

    for a in server_addr_vec {
        tokio::select!(
            s = tokio::net::TcpStream::connect(a) => {
                match s {
                    Ok(s) => {
                        server_addr = *a;
                        stream = Some(s);
                        break;
                    },
                    Err(_) => continue,
                }
            },
            _ = tokio::time::sleep(std::time::Duration::from_secs(3)) => {
                continue;
            }
        )
    }

    let mut stream = stream.ok_or("Could not connect to the peer")?;

    {
        let (hello_signature, hello_recid) = &our_wallet.sign_recoverable(b"hello");
        let hello_signature = hello_signature.to_bytes();
        let hello_recid = hello_recid.to_byte();

        let our_pubkey_bytes = our_wallet.public_key.to_sec1_bytes();

        // algorithm to embed checksum in recid
        let mut checksum = 0;
        for i in 0..32 {
            checksum ^= our_pubkey_bytes[i];
            checksum %= 0b01000000;
        }

        let mut our_hello_msg = Vec::new();
        our_hello_msg.extend_from_slice(&our_wallet.ipv6.octets());
        our_hello_msg.extend_from_slice(&hello_signature);
        our_hello_msg.push((hello_recid << 6) | checksum);

        if stream.write_all(&our_hello_msg).await.is_err() {
            if !reconnecting {
                log_error!(
                    "(P2P) Connection to {} failed",
                    socketaddr_formatter(server_addr)
                );
            }
            return Err("Unable to communicate".into()); // do not send disconnect message as we can't write to stream
        }
    }

    let mut their_hello_msg = [0u8; 16 + 64 + 1];

    if stream.read_exact(&mut their_hello_msg).await.is_err() {
        let _ = stream.write_u8(MsgType::Disconnect as u8).await;
        if !reconnecting {
            log_error!(
                "(P2P) Connection with {} failed, cannot read message",
                socketaddr_formatter(server_addr)
            );
        }
        return Err("Unable to communicate".into());
    }

    let their_webx_ipv6: [u8; 16] = their_hello_msg[0..16].try_into().unwrap();
    let their_webx_ipv6 = Ipv6Addr::from(their_webx_ipv6);

    // verify their hello message signature
    {
        let hello_recid = their_hello_msg[80];

        let Ok(hello_signature) = Signature::from_slice(&their_hello_msg[16..80]) else {
            let _ = stream.write_u8(MsgType::Disconnect as u8).await;
            if !reconnecting {
                log_error!("(P2P) Connection with {} cannot be enstabilished, authorization failed", socketaddr_formatter(server_addr));
            }
            return Err("Auth failed".into());
        };
        let Some(hello_recovery_id) = RecoveryId::from_byte(hello_recid >> 6) else {
            let _ = stream.write_u8(MsgType::Disconnect as u8).await;
            if !reconnecting {
                log_error!("(P2P) Connection with {} cannot be enstabilished, authorization failed", socketaddr_formatter(server_addr));
            }
            return Err("Auth failed".into());
        };

        let mut hasher = Hasher::new();
        hasher.update(b"hello");
        let prehash = hasher.finalize().as_slice().to_owned();

        let Ok(their_public_key) = VerifyingKey::recover_from_prehash(
            &prehash,
            &hello_signature,
            hello_recovery_id,
        ) else {
            let _ = stream.write_u8(MsgType::Disconnect as u8).await;
            if !reconnecting {
                log_error!("(P2P) Connection with {} cannot be enstabilished, authorization failed", socketaddr_formatter(server_addr));
            }
            return Err("Auth failed".into());
        };

        let their_public_key_bytes = their_public_key.to_sec1_bytes();

        // check public key checksum (last 6 bits of recid)
        let mut valid_checksum = 0;
        for i in 0..32 {
            valid_checksum ^= their_public_key_bytes[i];
            valid_checksum %= 0b01000000;
        }

        if valid_checksum != (hello_recid & 0b00111111) {
            let _ = stream.write_u8(MsgType::Disconnect as u8).await;
            if !reconnecting {
                log_error!(
                    "(P2P) Connection with {} cannot be enstabilished, authorization failed",
                    socketaddr_formatter(server_addr)
                );
            }
            return Err("Auth failed".into());
        }

        // check if their public key matches their WebX IPv6 address
        if their_webx_ipv6.octets()[1..16]
            != wallet::Wallet::generate_ipv6(&their_public_key).octets()[1..16]
        {
            let _ = stream.write_u8(MsgType::Disconnect as u8).await;
            if !reconnecting {
                log_error!(
                    "(P2P) Connection with {} cannot be enstabilished, authorization failed",
                    socketaddr_formatter(server_addr)
                );
            }
            return Err("Auth failed".into());
        }
    }

    // add them to our peer tree
    if (*neighbors_db.write().await)
        .register_neighbor(Neighbor::new(their_webx_ipv6, server_addr))
        .is_err()
    {
        let _ = stream.write_u8(MsgType::Disconnect as u8).await;
        if !reconnecting {
            log_error!(
                "(P2P) Connection with {} failed, cannot register in peer tree",
                socketaddr_formatter(server_addr)
            );
        }
        return Err("Unable to register in peer tree".into());
    };

    // add them to our queue
    let (tx, rx) = kanal::unbounded_async();
    queue.write().await.insert(server_addr, tx);

    log_ok!(
        "(P2P) Connected to {} with WebX IPv6 address {}",
        socketaddr_formatter(server_addr),
        their_webx_ipv6
    );

    handle_peer(
        server_addr,
        their_webx_ipv6,
        our_wallet,
        neighbors_db,
        queue,
        rx,
        tun_channel,
        stream,
    )
    .await;

    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn handle_peer(
    source: SocketAddr,
    their_webx_ipv6: Ipv6Addr,
    our_wallet: &wallet::Wallet,
    neighbors_db: Arc<RwLock<NeighborsDb>>,
    queue: Arc<RwLock<HashMap<SocketAddr, kanal::AsyncSender<PacketForP2P>>>>,
    queue_rx: kanal::AsyncReceiver<PacketForP2P>,
    tun_channel: &mut TunKanal,
    mut stream: tokio::net::TcpStream,
) {
    loop {
        tokio::select! {
            packet = queue_rx.recv() => {
                if let Ok(packet) = packet {
                    let mut msg = vec![MsgType::Packet as u8];
                    msg.extend_from_slice(&packet.to_bytes());

                    if stream.write_all(&msg).await.is_err() {
                        break;
                    }
                }
            },
            msg_type = stream.read_u8() => {
                if let Ok(msg_type) = msg_type {
                    match MsgType::from_byte(msg_type) {
                        MsgType::KeepAlive => {
                            // do nothing
                        },
                        MsgType::Disconnect => {
                            break;
                        },
                        MsgType::Packet => {
                            // read 40 bytes (ipv6 header)
                            let mut ipv6_header = [0u8; 40];
                            if stream.read_exact(&mut ipv6_header).await.is_err() {
                                break;
                            }

                            // get payload length from ipv6 header
                            let payload_length = u16::from_be_bytes([ipv6_header[4], ipv6_header[5]]) as usize;

                            // read payload
                            let mut payload = vec![0u8; payload_length];
                            if stream.read_exact(&mut payload).await.is_err() {
                                break;
                            }

                            // read signature + recid
                            let mut signature_and_recid = [0u8; 65];
                            if stream.read_exact(&mut signature_and_recid).await.is_err() {
                                break;
                            }

                            let mut packet = Vec::new();
                            packet.extend_from_slice(&ipv6_header);
                            packet.extend_from_slice(&payload);
                            packet.extend_from_slice(&signature_and_recid);

                            if let Ok(mut packet) = PacketForP2P::from_bytes(&packet) {
                                if packet.ipv6_packet[24..40] == our_wallet.ipv6.octets() {
                                    if packet.verify() {
                                        // send to TUN interface
                                        if tun_channel.send(packet.into_ipv6_packet()).await.is_err() {
                                            log_error!("Failed to send packet to TUN interface");
                                        }
                                        *STATS.total_packets_received.lock().await += 1;

                                    } else {
                                        let addr: [u8; 16] = packet.ipv6_packet[24..40].try_into().unwrap();
                                        log_error!("Packet from {} is not valid", Ipv6Addr::from(addr));
                                    }
                                } else {
                                    let t_neighbors_db = neighbors_db.clone();
                                    let t_queue = queue.clone();

                                    tokio::task::spawn(async move {
                                        if packet.hop_limit == 0 {
                                            return;
                                        }

                                        packet.hop_limit -= 1;

                                        let addr: [u8; 16] = packet.ipv6_packet[24..40].try_into().unwrap();
                                        let addr = Ipv6Addr::from(addr);
                                        let route_to = t_neighbors_db.read().await.get_sockaddr_to_route_to(addr);

                                        if route_to == SocketAddr::from(([0, 0, 0, 0], 0)) || route_to == source {
                                            return;
                                        }

                                        let queue = t_queue.read().await;
                                        if let Some(queue_inner) = queue.get(&route_to) {
                                            let _ = queue_inner.send(packet).await;
                                        }

                                        *STATS.total_packets_forwarded.lock().await += 1;
                                    });
                                }
                            } else {
                                log_error!("Failed to parse packet from {}", their_webx_ipv6);
                            }
                        },
                        _ => {
                            continue;
                        }
                    }
                } else {
                    break;
                }
            },
            // if nothing happens over 10 seconds, send keepalive
            _ = tokio::time::sleep(std::time::Duration::from_secs(10)) => {
                if stream.write_u8(MsgType::KeepAlive as u8).await.is_err() {
                    break;
                }
            }
        }
    }

    let _ = neighbors_db.write().await.unregister_neighbor(source);

    queue.write().await.remove(&source);
    let _ = stream.write_u8(MsgType::Disconnect as u8).await;

    log_warn!(
        "(P2P) Connection with {} closed",
        socketaddr_formatter(source)
    );
}

pub async fn p2p_job(
    our_wallet: wallet::Wallet,
    server_enabled: bool,
    server_port: u16,
    neighbors_db: Arc<RwLock<NeighborsDb>>,
    queue: Arc<RwLock<HashMap<SocketAddr, kanal::AsyncSender<PacketForP2P>>>>,
    tun_channel: TunKanal,
    initial_peers: Vec<Vec<SocketAddr>>,
) {
    for peer in initial_peers {
        let client_wallet = our_wallet.clone();
        let client_tree = neighbors_db.clone();
        let client_queue = queue.clone();
        let mut client_tun_channel = tun_channel.clone();

        tokio::task::spawn(async move {
            let mut reconnecting = false;

            loop {
                if client(
                    &client_wallet,
                    &peer,
                    client_tree.clone(),
                    client_queue.clone(),
                    &mut client_tun_channel,
                    reconnecting,
                )
                .await
                .is_err()
                    && !reconnecting
                {
                    log_warn!(
                        "(P2P) Failed to connect to {}",
                        socketaddr_formatter(peer[0])
                    );
                };
                reconnecting = true;
                tokio::time::sleep(std::time::Duration::from_secs(10)).await;
            }
        });
    }

    if server_enabled {
        let res = server(
            our_wallet,
            server_port,
            neighbors_db,
            queue,
            tun_channel,
        )
        .await;

        if res.is_err() {
            panic!("P2P: server failed: {:?}", res.err().unwrap());
        }
    } else {
        log_warn!("(P2P) Server disabled in config file");
        std::future::pending::<()>().await;
    }
}
