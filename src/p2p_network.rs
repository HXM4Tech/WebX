use crate::wallet;
use generic_array::GenericArray;
use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
use xxhash_rust::xxh3::xxh3_128;
use std::collections::HashMap;
use std::net::Ipv6Addr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::RwLock;
use crate::tun::TunKanal;
use crate::STATS;

const MAX_PEER_TREE_DEPTH: u8 = 3;
const MAX_CONNECTED_PEERS: usize = 8;

fn socketaddr_formatter(socketaddr: std::net::SocketAddr) -> String {
    match socketaddr {
        std::net::SocketAddr::V4(socketaddr) => return format!("{}:{}", socketaddr.ip(), socketaddr.port()),
        std::net::SocketAddr::V6(socketaddr) => {
            if let Some(ipv4) = socketaddr.ip().to_ipv4_mapped() {
                return format!("{}:{}", ipv4, socketaddr.port());
            }
        
            format!("[{}]:{}", socketaddr.ip(), socketaddr.port())
        },
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum PeerTreeRouteDest {
    Exact,
    SameCountry,
    SameTimezone,
    NoRoute,
}

#[derive(Clone, Debug)] // PartialEq and Eq are manually implemented (only ipv6 is compared)
pub struct PeerTree {
    pub ipv6: Ipv6Addr,
    pub connected_peers: Vec<PeerTree>,
    pub level: u8,
}

impl PeerTree {
    pub fn new(ipv6: Ipv6Addr) -> Self {
        Self {
            ipv6,
            connected_peers: Vec::new(),
            level: 0,
        }
    }

    fn align_level(&mut self, our_level: u8) {
        self.level = our_level;

        if our_level >= MAX_PEER_TREE_DEPTH {
            self.connected_peers.clear();
            return;
        }

        for peer in self.connected_peers.iter_mut() {
            peer.align_level(our_level + 1);
        }
    }

    pub fn register_peer(&mut self, mut peer: PeerTree) -> Result<(), &str> {
        if self.connected_peers.len() >= MAX_CONNECTED_PEERS {
            return Err("Max connected peers reached");
        }

        if self.connected_peers.contains(&peer) {
            return Err("Peer already connected");
        }

        peer.align_level(self.level + 1);
        peer.unregister_peer_from_all_levels(self.ipv6);

        self.connected_peers.push(peer);
        Ok(())
    }

    pub fn unregister_peer(&mut self, ipv6: Ipv6Addr) -> Result<(), &str> {
        let index = self.connected_peers.iter().position(|x| x.ipv6 == ipv6);

        if index.is_none() {
            return Err("Peer not connected");
        }

        self.connected_peers.remove(index.unwrap());
        Ok(())
    }

    fn unregister_peer_from_all_levels(&mut self, ipv6: Ipv6Addr) {
        self.unregister_peer(ipv6).ok().unwrap_or(());

        for peer in self.connected_peers.iter_mut() {
            peer.unregister_peer_from_all_levels(ipv6);
        }
    }

    fn get_shortest_route_to_target(&self, ipv6: Ipv6Addr) -> (Vec<Ipv6Addr>, PeerTreeRouteDest) {
        if let Some(peer) = self.connected_peers.iter().find(|x| x.ipv6 == ipv6) {
            return (vec![peer.ipv6], PeerTreeRouteDest::Exact);
        }

        let mut shortest_route = Vec::new();
        let mut shortest_route_same_country = Vec::new();
        let mut shortest_route_same_time_zone = Vec::new();

        for peer in self.connected_peers.iter() {
            let (mut route, route_type) = peer.get_shortest_route_to_target(ipv6);

            if route.is_empty() {
                continue;
            }

            route.insert(0, peer.ipv6);

            if route_type == PeerTreeRouteDest::Exact
                && (shortest_route.is_empty() || route.len() < shortest_route.len())
            {
                shortest_route = route;
            } else if route_type == PeerTreeRouteDest::SameCountry
                && (shortest_route_same_country.is_empty()
                    || route.len() < shortest_route_same_country.len())
            {
                shortest_route_same_country = route;
            } else if route_type == PeerTreeRouteDest::SameTimezone
                && (shortest_route_same_time_zone.is_empty()
                    || route.len() < shortest_route_same_time_zone.len())
            {
                shortest_route_same_time_zone = route;
            }
        }

        if !shortest_route.is_empty() {
            return (shortest_route, PeerTreeRouteDest::Exact);
        }

        if let Some(peer) = self
            .connected_peers
            .iter()
            .find(|x| x.ipv6.octets()[1..4] == ipv6.octets()[1..4])
        {
            return (vec![peer.ipv6], PeerTreeRouteDest::SameCountry);
        }

        if !shortest_route_same_country.is_empty() {
            return (shortest_route_same_country, PeerTreeRouteDest::SameCountry);
        }

        if let Some(peer) = self
            .connected_peers
            .iter()
            .find(|x| x.ipv6.octets()[1] == ipv6.octets()[1])
        {
            return (vec![peer.ipv6], PeerTreeRouteDest::SameTimezone);
        }

        if !shortest_route_same_time_zone.is_empty() {
            return (
                shortest_route_same_time_zone,
                PeerTreeRouteDest::SameTimezone,
            );
        }

        (Vec::new(), PeerTreeRouteDest::NoRoute)
    }

    pub fn get_ipv6_to_route_to(&self, ipv6: Ipv6Addr) -> Ipv6Addr {
        let (route, dest) = self.get_shortest_route_to_target(ipv6);

        if dest == PeerTreeRouteDest::NoRoute {
            if self.connected_peers.is_empty() {
                return Ipv6Addr::UNSPECIFIED;
            }

            return self.connected_peers[0].ipv6;
        }

        route[0]
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        bytes.extend_from_slice(&self.ipv6.octets());
        bytes.push(self.connected_peers.len() as u8);

        for peer in self.connected_peers.iter() {
            bytes.extend_from_slice(&peer.to_bytes());
        }

        bytes
    }

    pub fn get_size_as_bytes(&self) -> usize {
        let mut size = 17;

        for peer in self.connected_peers.iter() {
            size += peer.get_size_as_bytes();
        }

        size
    }

    pub fn from_bytes(bytes: &[u8]) -> Self {
        let mut ipv6_bytes = [0u8; 16];
        ipv6_bytes.copy_from_slice(&bytes[0..16]);
        let ipv6 = Ipv6Addr::from(ipv6_bytes);

        let mut connected_peers = Vec::new();
        let num_connected_peers = bytes[16];

        let mut offset = 17;

        for _ in 0..num_connected_peers {
            let peer = PeerTree::from_bytes(&bytes[offset..]);
            offset += peer.get_size_as_bytes();
            connected_peers.push(peer);
        }

        let mut res = Self {
            ipv6,
            connected_peers,
            level: 0,
        };
        res.align_level(0);

        res
    }

    pub fn get_subtree<'a>(&'a self, ipv6: Ipv6Addr) -> Option<&'a Self> {
        if self.ipv6 == ipv6 {
            return Some(self);
        }

        for peer in self.connected_peers.iter() {
            let subtree = peer.get_subtree(ipv6);

            if subtree.is_some() {
                return subtree;
            }
        }

        None
    }

    pub fn get_subtree_mut<'a>(&'a mut self, ipv6: Ipv6Addr) -> Option<&'a mut Self> {
        if self.ipv6 == ipv6 {
            return Some(self);
        }

        for peer in self.connected_peers.iter_mut() {
            let subtree = peer.get_subtree_mut(ipv6);

            if subtree.is_some() {
                return subtree;
            }
        }

        None
    }

    pub fn get_known_peers(&self) -> HashMap<Ipv6Addr, u8> {
        let mut known_peers = HashMap::new();

        for peer in self.connected_peers.iter() {
            let mut peer_known_peers = peer.get_known_peers();
            for (ipv6, level) in peer_known_peers.drain() {
                if !known_peers.contains_key(&ipv6) || known_peers[&ipv6] > level { 
                    known_peers.insert(ipv6, level);
                }
            }

            known_peers.insert(peer.ipv6, peer.level);
        }

        known_peers
    }
}

impl PartialEq for PeerTree {
    fn eq(&self, other: &Self) -> bool {
        self.ipv6 == other.ipv6
    }
}

impl Eq for PeerTree {}

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
        let signature_generic_array = GenericArray::from_slice(&self.signature);
        let Ok(signature) = Signature::from_bytes(signature_generic_array) else { return false; };
        let Some(recovery_id) = RecoveryId::from_byte(self.recid >> 6) else { return false; };

        let prehash = xxh3_128(&self.ipv6_packet).to_be_bytes();

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

        self.ipv6_packet[12..24] == wallet::Wallet::generate_ipv6_hash_part(&public_key_bytes)
    }

    pub fn to_ipv6_packet(mut self) -> Vec<u8> {
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
    // this one byte + lenght (4 bytes) + PeerTree (variable length)
    FullPeerTree = 2,
    // level (1 byte) + address (16 bytes)
    NewPeerInTree = 3,
    // level (1 byte) + address (16 bytes)
    RemovePeerFromTree = 4,

    // just this one byte
    Disconnect = 254,
    Unknown = 255,
}

impl MsgType {
    fn from_byte(byte: u8) -> Self {
        match byte {
            0 => Self::KeepAlive,
            1 => Self::Packet,
            2 => Self::FullPeerTree,
            3 => Self::NewPeerInTree,
            4 => Self::RemovePeerFromTree,
            254 => Self::Disconnect,
            _ => Self::Unknown,
        }
    }
}

async fn server(
    our_wallet: wallet::Wallet,
    port: u16,
    tree: Arc<RwLock<PeerTree>>,
    queue: Arc<RwLock<HashMap<Ipv6Addr, kanal::AsyncSender<PacketForP2P>>>>,
    tun_channel: TunKanal,
    routing_broadcast_tx: tokio::sync::broadcast::Sender<Vec<u8>>,
) -> Result<(), Box<dyn std::error::Error>> {
    let listener = tokio::net::TcpListener::bind((Ipv6Addr::UNSPECIFIED, port)).await?;
    log_ok!("(P2P) Server has started and is listening on port {}", port);

    loop {
        let (mut stream, source) = listener.accept().await.unwrap();
        let handler_tree = tree.clone();
        let handler_queue = queue.clone();
        let handler_wallet = our_wallet.clone();
        let handler_tun_channel = tun_channel.clone();
        let handler_routing_broadcast_tx = routing_broadcast_tx.clone();

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
                let hello_signature = GenericArray::from_slice(&their_hello_msg[16..80]);
                let hello_recid = their_hello_msg[80];

                let Ok(hello_signature) = Signature::from_bytes(hello_signature) else {
                    let _ = stream.write_u8(MsgType::Disconnect as u8).await;
                    log_error!("(P2P) Connection from {} rejected, authorization failed", socketaddr_formatter(source));
                    return;
                };
                let Some(hello_recovery_id) = RecoveryId::from_byte(hello_recid >> 6) else {
                    let _ = stream.write_u8(MsgType::Disconnect as u8).await;
                    log_error!("(P2P) Connection from {} rejected, authorization failed", socketaddr_formatter(source));
                    return;
                };

                let prehash = xxh3_128(b"hello").to_be_bytes();

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
                if their_webx_ipv6.octets()[4..16] != wallet::Wallet::generate_ipv6(&their_public_key).octets()[4..16] {
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

                // algorith to embed checksum in recid
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
                    log_error!("(P2P) Connection with {} failed", socketaddr_formatter(source));
                    return; // do not send disconnect message as we can't write to stream
                }
            }

            // add them to our peer tree
            if (*handler_tree.write().await)
                .register_peer(PeerTree::new(their_webx_ipv6))
                .is_err()
            {
                let _ = stream.write_u8(MsgType::Disconnect as u8).await;
                log_error!(
                    "(P2P) Connection with {} failed, cannot register in peer tree",
                    socketaddr_formatter(source)
                );
                return;
            };

            // add them to our queue
            let (tx, rx) = kanal::unbounded_async();

            handler_queue.write().await.insert(their_webx_ipv6, tx);

            log_ok!(
                "(P2P) Connected to {} with WebX IPv6 address {}",
                socketaddr_formatter(source),
                their_webx_ipv6
            );

            handle_peer(
                source,
                their_webx_ipv6,
                handler_wallet,
                handler_tree,
                handler_queue,
                rx,
                handler_tun_channel,
                stream,
                handler_routing_broadcast_tx,
            ).await;
        });
    }
}

async fn client(
    our_wallet: wallet::Wallet,
    server_addr: std::net::SocketAddr,
    peers_tree: Arc<RwLock<PeerTree>>,
    queue: Arc<RwLock<HashMap<Ipv6Addr, kanal::AsyncSender<PacketForP2P>>>>,
    tun_channel: TunKanal,
    routing_broadcast_tx: tokio::sync::broadcast::Sender<Vec<u8>>,
) -> Result<(), Box<dyn std::error::Error>> {
    tokio::select! {
        _ = tokio::time::sleep(std::time::Duration::from_secs(3)) => {
            log_error!("(P2P) Connection to {} failed, timeout exceeded", socketaddr_formatter(server_addr));
            return Err("timeout exceeded".into());
        },
        stream = tokio::net::TcpStream::connect(server_addr) => {
            let mut stream = stream?;

            {
                let (hello_signature, hello_recid) = &our_wallet.sign_recoverable(b"hello");
                let hello_signature = hello_signature.to_bytes();
                let hello_recid = hello_recid.to_byte();
        
                let our_pubkey_bytes = our_wallet.public_key.to_sec1_bytes();
        
                // algorith to embed checksum in recid
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
                    log_error!("(P2P) Connection with {} failed", socketaddr_formatter(server_addr));
                    return Err("Unable to communicate".into()); // do not send disconnect message as we can't write to stream
                }
            }
        
            let mut their_hello_msg = [0u8; 16 + 64 + 1];
        
            if stream.read_exact(&mut their_hello_msg).await.is_err() {
                let _ = stream.write_u8(MsgType::Disconnect as u8).await;
                log_error!(
                    "(P2P) Connection with {} failed, cannot read message",
                    socketaddr_formatter(server_addr)
                );
                return Err("Unable to communicate".into());
            }
        
            let their_webx_ipv6: [u8; 16] = their_hello_msg[0..16].try_into().unwrap();
            let their_webx_ipv6 = Ipv6Addr::from(their_webx_ipv6);
        
            // verify their hello message signature
            {
                let hello_signature = GenericArray::from_slice(&their_hello_msg[16..80]);
                let hello_recid = their_hello_msg[80];
        
                let Ok(hello_signature) = Signature::from_bytes(hello_signature) else {
                    let _ = stream.write_u8(MsgType::Disconnect as u8).await;
                    log_error!("(P2P) Connection with {} cannot be enstabilished, authorization failed", socketaddr_formatter(server_addr));
                    return Err("Auth failed".into());
                };
                let Some(hello_recovery_id) = RecoveryId::from_byte(hello_recid >> 6) else {
                    let _ = stream.write_u8(MsgType::Disconnect as u8).await;
                    log_error!("(P2P) Connection with {} cannot be enstabilished, authorization failed", socketaddr_formatter(server_addr));
                    return Err("Auth failed".into());
                };

                let prehash = xxh3_128(b"hello").to_be_bytes();
        
                let Ok(their_public_key) = VerifyingKey::recover_from_prehash(
                    &prehash,
                    &hello_signature,
                    hello_recovery_id,
                ) else {
                    let _ = stream.write_u8(MsgType::Disconnect as u8).await;
                    log_error!("(P2P) Connection with {} cannot be enstabilished, authorization failed", socketaddr_formatter(server_addr));
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
                    log_error!(
                        "(P2P) Connection with {} cannot be enstabilished, authorization failed",
                        socketaddr_formatter(server_addr)
                    );
                    return Err("Auth failed".into());
                }

                // check if their public key matches their WebX IPv6 address
                if their_webx_ipv6.octets()[4..16] != wallet::Wallet::generate_ipv6(&their_public_key).octets()[4..16] {
                    let _ = stream.write_u8(MsgType::Disconnect as u8).await;
                    log_error!(
                        "(P2P) Connection with {} cannot be enstabilished, authorization failed",
                        socketaddr_formatter(server_addr)
                    );
                    return Err("Auth failed".into());
                }
            }
        
            // add them to our peer tree
            if (*peers_tree.write().await)
                .register_peer(PeerTree::new(their_webx_ipv6))
                .is_err()
            {
                let _ = stream.write_u8(MsgType::Disconnect as u8).await;
                log_error!(
                    "(P2P) Connection with {} failed, cannot register in peer tree",
                    socketaddr_formatter(server_addr)
                );
                return Err("Unable to register in peer tree".into());
            };
        
            // add them to our queue
            let (tx, rx) = kanal::unbounded_async();
            queue.write().await.insert(their_webx_ipv6, tx);

            log_ok!(
                "(P2P) Connected to {} with WebX IPv6 address {}",
                socketaddr_formatter(server_addr),
                their_webx_ipv6
            );
        
            handle_peer(
                server_addr,
                their_webx_ipv6,
                our_wallet,
                peers_tree,
                queue,
                rx,
                tun_channel,
                stream,
                routing_broadcast_tx,
            )
            .await;
        
            Ok(())
        }
    }
}

async fn handle_peer(
    source: std::net::SocketAddr,
    their_webx_ipv6: Ipv6Addr,
    our_wallet: wallet::Wallet,
    peers_tree: Arc<RwLock<PeerTree>>,
    queue: Arc<RwLock<HashMap<Ipv6Addr, kanal::AsyncSender<PacketForP2P>>>>,
    queue_rx: kanal::AsyncReceiver<PacketForP2P>,
    mut tun_channel: TunKanal,
    mut stream: tokio::net::TcpStream,
    routing_broadcast_tx: tokio::sync::broadcast::Sender<Vec<u8>>,
) {
    // send our peer tree
    {
        let mut our_tree_msg = vec![MsgType::FullPeerTree as u8];
        let tree_as_bytes = (*peers_tree.read().await).to_bytes();
        our_tree_msg.extend_from_slice(&(tree_as_bytes.len() as u32).to_be_bytes());
        our_tree_msg.extend_from_slice(&tree_as_bytes);

        if stream.write_all(&our_tree_msg).await.is_err() {
            log_error!("(P2P) Connection with {} failed", socketaddr_formatter(source));
            return; // do not send disconnect message as we can't write to stream
        }
    }

    let mut routing_broadcast_rx = routing_broadcast_tx.subscribe();

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
            routing_info = routing_broadcast_rx.recv() => {
                if let Ok(routing_info) = routing_info {
                    let sender_addr: [u8; 16] = routing_info[1..17].try_into().unwrap();
                    let peer_changed_addr: [u8; 16] = match MsgType::from_byte(routing_info[0]) {
                        MsgType::NewPeerInTree => routing_info[21..37].try_into().unwrap(),
                        MsgType::RemovePeerFromTree => routing_info[17..33].try_into().unwrap(),
                        _ => {
                            continue;
                        }
                    };

                    if peer_changed_addr == their_webx_ipv6.octets() || sender_addr == their_webx_ipv6.octets() {
                        continue;
                    }

                    if stream.write_all(&routing_info).await.is_err() {
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
                                        if tun_channel.send(packet.to_ipv6_packet()).await.is_err() {
                                            log_error!("Failed to send packet to TUN interface");
                                        }
                                        *STATS.total_packets_received.lock().await += 1;

                                    } else {
                                        let addr: [u8; 16] = packet.ipv6_packet[24..40].try_into().unwrap();
                                        log_error!("Packet from {} is not valid", Ipv6Addr::from(addr));
                                    }
                                } else {
                                    let t_peers_tree = peers_tree.clone();
                                    let t_queue = queue.clone();

                                    tokio::task::spawn(async move {
                                        if packet.hop_limit == 0 {
                                            return;
                                        }

                                        packet.hop_limit -= 1;

                                        let addr: [u8; 16] = packet.ipv6_packet[24..40].try_into().unwrap();
                                        let addr = Ipv6Addr::from(addr);
                                        let route_to = t_peers_tree.read().await.get_ipv6_to_route_to(addr);

                                        if route_to == Ipv6Addr::UNSPECIFIED || route_to == their_webx_ipv6 {
                                            return;
                                        } else {
                                            let queue = t_queue.read().await;
                                            if let Some(queue_inner) = queue.get(&route_to) {
                                                let _ = queue_inner.send(packet).await;
                                            }

                                            *STATS.total_packets_forwarded.lock().await += 1;
                                        }
                                    });
                                }
                            } else {
                                log_error!("Failed to parse packet from {}", their_webx_ipv6);
                            }
                        },
                        MsgType::FullPeerTree => {
                            // read tree length
                            let mut tree_length = [0u8; 4];
                            if stream.read_exact(&mut tree_length).await.is_err() {
                                break;
                            }
                            let tree_length = u32::from_be_bytes(tree_length) as usize;

                            // read tree
                            let mut tree_bytes = vec![0u8; tree_length];
                            if stream.read_exact(&mut tree_bytes).await.is_err() {
                                break;
                            }

                            {
                                // parse tree
                                let tree = PeerTree::from_bytes(&tree_bytes);

                                // re-register peer
                                let mut peers_tree = peers_tree.write().await;
                                let _ = peers_tree.unregister_peer(their_webx_ipv6);
                                let _ = peers_tree.register_peer(tree);

                                // send routing to add peer to all peers
                                let mut msg = vec![MsgType::NewPeerInTree as u8];
                                msg.extend_from_slice(&our_wallet.ipv6.octets());
                                msg.extend_from_slice(&(tree_bytes.len() as u32).to_be_bytes());
                                msg.extend_from_slice(&tree_bytes);

                                let _ = routing_broadcast_tx.send(msg);
                            }
                            
                        },
                        MsgType::NewPeerInTree => {
                            let mut sender_addr = [0u8; 16];
                            if stream.read_exact(&mut sender_addr).await.is_err() {
                                break;
                            }

                            let mut tree_length = [0u8; 4];
                            if stream.read_exact(&mut tree_length).await.is_err() {
                                break;
                            }
                            let tree_length = u32::from_be_bytes(tree_length) as usize;

                            // read tree
                            let mut tree_bytes = vec![0u8; tree_length];
                            if stream.read_exact(&mut tree_bytes).await.is_err() {
                                break;
                            }

                            if peers_tree.read().await.get_subtree(Ipv6Addr::from(sender_addr)).is_none() {
                                continue;
                            }

                            // parse tree
                            let tree = PeerTree::from_bytes(&tree_bytes);

                            if tree.ipv6 == our_wallet.ipv6 {
                                continue;
                            }

                            // register in tree
                            {
                                let mut peers_tree = peers_tree.write().await;
                                let subtree = peers_tree.get_subtree_mut(Ipv6Addr::from(sender_addr)).unwrap();
                                if subtree.register_peer(tree).is_ok() {
                                    // propagate message to other peers via routing_broadcast_tx
                                    let mut msg = vec![MsgType::NewPeerInTree as u8];
                                    msg.extend_from_slice(&sender_addr);
                                    msg.extend_from_slice(&(tree_length as u32).to_be_bytes());
                                    msg.extend_from_slice(&tree_bytes);

                                    let _ = routing_broadcast_tx.send(msg);
                                }
                            }
                            
                        },
                        MsgType::RemovePeerFromTree => {
                            let mut sender_addr = [0u8; 16];
                            if stream.read_exact(&mut sender_addr).await.is_err() {
                                break;
                            }

                            let mut peer_to_remove = [0u8; 16];
                            if stream.read_exact(&mut peer_to_remove).await.is_err() {
                                break;
                            }

                            if peers_tree.read().await.get_subtree(Ipv6Addr::from(sender_addr)).is_none() {
                                continue;
                            }

                            // unregister peer_to_remove from sender's tree
                            {
                                let mut peers_tree = peers_tree.write().await;
                                let subtree = peers_tree.get_subtree_mut(Ipv6Addr::from(sender_addr)).unwrap();
                                if subtree.unregister_peer(Ipv6Addr::from(peer_to_remove)).is_ok() {
                                    // propagate message to other peers via routing_broadcast_tx
                                    let mut msg = vec![MsgType::RemovePeerFromTree as u8];
                                    msg.extend_from_slice(&sender_addr);
                                    msg.extend_from_slice(&peer_to_remove);

                                    let _ = routing_broadcast_tx.send(msg);
                                }
                            }
                        },
                        MsgType::Unknown => {
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

    let _ = peers_tree.write().await.unregister_peer(their_webx_ipv6);

    {
        let mut msg = vec![MsgType::RemovePeerFromTree as u8];
        msg.extend_from_slice(&our_wallet.ipv6.octets());
        msg.extend_from_slice(&their_webx_ipv6.octets());
        let _ = routing_broadcast_tx.send(msg);
    }

    queue.write().await.remove(&their_webx_ipv6);
    let _ = stream.write_u8(MsgType::Disconnect as u8).await;
    log_warn!("(P2P) Connection with {} closed", socketaddr_formatter(source));
}

pub async fn p2p_job(
    our_wallet: wallet::Wallet,
    server_enabled: bool,
    server_port: u16,
    tree: Arc<RwLock<PeerTree>>,
    queue: Arc<RwLock<HashMap<Ipv6Addr, kanal::AsyncSender<PacketForP2P>>>>,
    tun_channel: TunKanal,
    initial_peers: Vec<std::net::SocketAddr>,
) {
    let (routing_broadcast_tx, _) = tokio::sync::broadcast::channel(1024);

    for peer in initial_peers {
        let client_wallet = our_wallet.clone();
        let client_tree = tree.clone();
        let client_queue = queue.clone();
        let client_tun_channel = tun_channel.clone();
        let client_routing_broadcast_tx = routing_broadcast_tx.clone();

        tokio::task::spawn(async move {
            if client(
                client_wallet,
                peer,
                client_tree,
                client_queue,
                client_tun_channel,
                client_routing_broadcast_tx,
            ).await.is_err() {
                log_warn!("(P2P) Failed to connect to {}", socketaddr_formatter(peer));
            };
        });
    }

    if server_enabled {
        let res = server(
            our_wallet,
            server_port,
            tree,
            queue,
            tun_channel,
            routing_broadcast_tx,
        ).await;

        if res.is_err() {
            panic!("P2P: server failed: {:?}", res.err().unwrap());
        }
    } else {
        log_warn!("(P2P) Server disabled in config file");
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(1000)).await;
        }
    }
}
