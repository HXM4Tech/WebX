use k256::ecdsa::{
    signature::hazmat::RandomizedPrehashSigner,
    RecoveryId,
    Signature,
    SigningKey,
    VerifyingKey
};

use k256::elliptic_curve::Generate;
use getrandom::{SysRng, rand_core::UnwrapErr};

use std::net::Ipv6Addr;
use blake3::Hasher;

pub const IPV6_PREFIX: u8 = 0xd4;

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Wallet {
    private_key: SigningKey,
    pub public_key: VerifyingKey,
    pub public_key_checksum: u8,
    pub ipv6: Ipv6Addr,
}

impl Wallet {
    pub fn new() -> Self {
        let private_key = SigningKey::generate_from_rng(&mut UnwrapErr(SysRng));
        let public_key = *private_key.clone().verifying_key();

        let ipv6 = Self::generate_ipv6(&public_key);

        let pubkey_sec1_bytes = public_key.to_sec1_bytes();
        let public_key_checksum = pubkey_sec1_bytes.iter().fold(0u8, |acc, &b| acc ^ b) & 0b00111111;

        Self {
            private_key,
            public_key,
            public_key_checksum,
            ipv6,
        }
    }

    pub fn from_file(path: &str) -> Result<Self, ()> {
        // if file does not exist, return Err
        if !std::path::Path::new(path).exists() {
            return Err(());
        }

        let mut new_priv_key = false;

        let private_key = match std::fs::read(path) {
            Ok(private_key_file) => {
                if let Ok(sk) = SigningKey::from_slice(&private_key_file) {
                    sk
                } else {
                    log_error!("Cannot parse private key from file");
                    log_warn!("New wallet has been generated!");
                    new_priv_key = true;
                    SigningKey::generate_from_rng(&mut UnwrapErr(SysRng))
                }
            }
            Err(e) => {
                log_error!("Cannot read private key file: {}", e);
                log_warn!("New wallet has been generated!");
                new_priv_key = true;
                SigningKey::generate_from_rng(&mut UnwrapErr(SysRng))
            }
        };

        let private_key_clone = private_key.clone();
        let public_key = private_key_clone.verifying_key();

        let ipv6 = Self::generate_ipv6(public_key);

        let pubkey_sec1_bytes = public_key.to_sec1_bytes();
        let public_key_checksum = pubkey_sec1_bytes.iter().fold(0u8, |acc, &b| acc ^ b) & 0b00111111;

        let res = Self {
            private_key,
            public_key: *public_key,
            public_key_checksum,
            ipv6,
        };

        if new_priv_key {
            res.save_to_file(path).unwrap_or_else(|e| {
                log_error!("Cannot save private key to file: {}", e);
            });
        }

        Ok(res)
    }

    pub fn save_to_file(&self, path: &str) -> std::io::Result<()> {
        let mut to_save = Vec::new();
        to_save.extend_from_slice(&self.private_key.to_bytes());

        std::fs::write(path, to_save)
    }

    fn fill_ipv6_hash_part(public_key: &[u8], out: &mut [u8]) {
        let mut hasher = Hasher::new();
        hasher.update(public_key);
        hasher.finalize_xof().fill(out);
    }

    pub fn generate_ipv6_hash_part(public_key: &[u8]) -> [u8; 15] {
        let mut res = [0u8; 15];
        Self::fill_ipv6_hash_part(public_key, &mut res);
        res
    }

    pub fn generate_ipv6(public_key: &VerifyingKey) -> Ipv6Addr {
        let mut ipv6 = [0u8; 16];

        ipv6[0] = IPV6_PREFIX;
        Self::fill_ipv6_hash_part(&public_key.to_sec1_bytes(), &mut ipv6[1..16]);

        Ipv6Addr::from(ipv6)
    }

    pub fn sign_recoverable(&self, message: &[u8]) -> (Signature, RecoveryId) {
        let mut hasher = Hasher::new();
        hasher.update(message);
        let prehash = hasher.finalize();
        
        let sig = self
            .private_key
            .sign_prehash_with_rng(&mut UnwrapErr(SysRng), prehash.as_slice())
            .unwrap();

        let recid =
            RecoveryId::trial_recovery_from_prehash(&self.public_key, prehash.as_slice(), &sig).unwrap();

        (sig, recid)
    }

    pub fn string_public_key(&self) -> String {
        hex::encode(self.public_key.to_sec1_bytes())
    }
}
