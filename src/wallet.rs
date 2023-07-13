use k256::ecdsa::{
    signature::hazmat::RandomizedPrehashSigner, RecoveryId, Signature, SigningKey,
    VerifyingKey,
};
use rand_core::OsRng;
use xxhash_rust::xxh3::xxh3_128;
use std::net::Ipv6Addr;
use generic_array::GenericArray;

pub const IPV6_PREFIX: u8 = 0x4c;

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Wallet {
    private_key: SigningKey,
    pub public_key: VerifyingKey,
    pub ipv6: Ipv6Addr,
}

impl Wallet {
    pub fn new() -> Self {
        let private_key = SigningKey::random(&mut OsRng);

        let private_key_clone = private_key.clone();
        let public_key = private_key_clone.verifying_key();

        let ipv6 = Self::generate_ipv6(public_key);

        Self {
            private_key,
            public_key: *public_key,
            ipv6,
        }
    }

    pub fn from_file(path: &str) -> Result<Self, ()> {
        // if file does not exist, return Err
        if !std::path::Path::new(path).exists() {
            return Err(());
        }

        let mut new_priv_key = false;
        let mut tz_cc = [0u8; 3];

        let private_key = match std::fs::read(path) {
            Ok(private_key_file) => {
                // pick the 3 first bytes of the file - the timezone and country code, where the wallet was generated
                tz_cc.copy_from_slice(&private_key_file[0..3]);

                let bytes_generic_array = GenericArray::from_slice(&private_key_file[3..]);

                if let Ok(sk) = SigningKey::from_bytes(&bytes_generic_array) {
                    sk
                } else {
                    log_error!("Cannot parse private key from file");
                    log_warn!("New wallet has been generated!");
                    new_priv_key = true;
                    SigningKey::random(&mut OsRng)
                }
            },
            Err(e) => {
                log_error!("Cannot read private key file: {}", e);
                log_warn!("New wallet has been generated!");
                new_priv_key = true;
                SigningKey::random(&mut OsRng)
            }
        };

        let private_key_clone = private_key.clone();
        let public_key = private_key_clone.verifying_key();

        let ipv6 = {
            if new_priv_key {
                Self::generate_ipv6(public_key)
            } else {
                let mut addr: [u8; 16] = Self::generate_ipv6(public_key).octets();
                addr[1..4].copy_from_slice(&tz_cc);
                Ipv6Addr::from(addr)
            }
        };

        let res = Self {
            private_key,
            public_key: *public_key,
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
        to_save.extend_from_slice(&self.ipv6.octets()[1..4]);
        to_save.extend_from_slice(&self.private_key.to_bytes());
        
        std::fs::write(path, to_save)
    }

    pub fn generate_ipv6_hash_part(public_key: &Box<[u8]>) -> [u8; 12] {
        let hash = xxh3_128(&public_key).to_be_bytes();
        let mut res = [0u8; 12];
        res.copy_from_slice(&hash[0..12]);
        res
    }

    pub fn generate_ipv6(public_key: &VerifyingKey) -> Ipv6Addr {
        let mut ipv6 = [0u8; 16];
        ipv6[0] = IPV6_PREFIX;

        use crate::loc;
        
        let tz = loc::get_tz();
        ipv6[1] = loc::get_time_offset(tz);
        ipv6[2..4].copy_from_slice(&loc::get_country_code(tz));

        ipv6[4..16].copy_from_slice(&Self::generate_ipv6_hash_part(&public_key.to_sec1_bytes()));

        Ipv6Addr::from(ipv6)
    }

    pub fn sign_recoverable(&self, message: &[u8]) -> (Signature, RecoveryId) {
        let prehash = xxh3_128(message).to_be_bytes();
        let sig = self.private_key.sign_prehash_with_rng(&mut OsRng, &prehash).unwrap();
        let recid = RecoveryId::trial_recovery_from_prehash(&self.public_key, &prehash, &sig).unwrap();

        (sig, recid)
    }

    pub fn string_public_key(&self) -> String {
        hex::encode(self.public_key.to_sec1_bytes())
    }
}
