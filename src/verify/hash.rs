use base64::Engine;
use libsecp256k1::RecoveryId;
use sha3::{
    digest::{generic_array::GenericArray, typenum::U64},
    Digest,
};

use crate::file_format::format_naive_date_time;
use crate::file_format::{RevisionContent, RevisionMetadata, RevisionSignature, RevisionWitness};

pub type Hasher = sha3::Sha3_512;
pub type Hash = GenericArray<u8, U64>;

pub fn hash_eq(hash: &Hash, expected: &str) -> bool {
    hex::encode(hash) == expected.to_lowercase()
}
pub trait VerifyHash {
    fn expected_hash(&self) -> &str;
    fn verify(&self, hash: &Hash) -> bool {
        hash_eq(hash, self.expected_hash())
    }
}
pub trait Hashable {
    fn hash(&self) -> Hash;
}

impl Hashable for RevisionMetadata {
    fn hash(&self) -> Hash {
        let mut hasher = Hasher::new();
        hasher.update(&self.domain_id);
        hasher.update(format_naive_date_time(&self.time_stamp).to_string());
        hasher.update(&self.previous_verification_hash);
        hasher.finalize()
    }
}
pub struct FileHashMissing;
pub struct Base64Invalid;
impl RevisionContent {
    pub fn file_hash(&self) -> Result<Option<Hash>, Base64Invalid> {
        let Some(file) = &self.file else {
            return Ok(None)
        };
        let input = file.data.as_bytes();
        let mut output = Vec::with_capacity(base64::decoded_len_estimate(input.len()));
        base64::prelude::BASE64_STANDARD_NO_PAD
            .decode_vec(input, &mut output)
            .map_err(|_| Base64Invalid)?;
        let mut hasher = Hasher::new();
        hasher.update(output);
        Ok(Some(hasher.finalize()))
    }
    pub fn expected_file_hash(&self) -> Result<&str, FileHashMissing> {
        Ok(self.content.get("file_hash").ok_or(FileHashMissing)?)
    }
}
impl Hashable for RevisionContent {
    fn hash(&self) -> Hash {
        let mut hasher = Hasher::new();
        // btreemaps are sorted
        for value in self.content.values() {
            hasher.update(value);
        }
        hasher.finalize()
    }
}

#[test]
fn test_revision_signature() {
    let verification_hash = "ea456cb8244bccf0e1602faa2ad982063ec76e566ba7c1c69e9449ac069190dfd8ddfed5a1472b50ce86f98315620529875b0bc450275bf7e1f7d2e860cf3ff8";
    let revision_signature = RevisionSignature {
        signature: "0xcd5c7a3bb3e1896cde7d6e556998ce1a116e41fd3809481c9a4ceb2c61cff8ab2e39dfadddd5913c391990f13b3b44703967129dabf96f5919e3c6964b8c61121b".to_string(),
        public_key: "0x04f00d6e178562a62ec9e595da4294f640dca429fc98e7128b8e7ee83039912d64a924bea34e629b9b45990c65e92efc3d74533f870479d10ff895834fff4fa1e8".to_string(),
        wallet_address: "0x1ad5da43de60aa7d311f9b4e9c3342c155e6d2e0".to_string(),
        signature_hash: "0529f4806097e4a7570b25361bc08854c83e057caeb7f35dadc91ad64c282b581fd6108fd44f3fb1bda8157281831b869d5cab021129f215eb2dff2a8b4557d1".to_string(),
    };
    assert!(revision_signature.verify_current(verification_hash));
}

impl RevisionSignature {
    pub fn verify_current(&self, verification_hash: &str) -> bool {
        let Some(public_key) = self.public_key.strip_prefix("0x") else {return false};
        let Some(stripped_sig) = self
            .signature
            .strip_prefix("0x") else {return false};
        #[repr(C)]
        #[allow(dead_code)]
        struct Data {
            data: [u8; 64],
            recovery: u8,
        }
        let Data { data, recovery } = {
            let mut data = [0u8; 65];
            if hex::decode_to_slice(stripped_sig, &mut data).is_err() {
                return false;
            };
            unsafe { std::mem::transmute(data) }
        };
        let mut hasher = sha3::Keccak256::default();
        hasher.update("\x19Ethereum Signed Message:\n");
        hasher.update((49 + verification_hash.len()).to_string());
        hasher.update("I sign the following page verification_hash: [0x");
        hasher.update(verification_hash);
        hasher.update("]");
        let hash = libsecp256k1::Message::parse(&<[u8; 32]>::from(hasher.finalize()));
        let Ok(sig) = libsecp256k1::Signature::parse_standard(&data) else {return false};
        let Ok(recov) = RecoveryId::parse_rpc(recovery) else {return false};
        let Ok(pubkey) = libsecp256k1::recover(&hash, &sig, &recov) else {return false};
        hex::encode(pubkey.serialize())[..] == public_key.to_lowercase()
    }
}
impl Hashable for RevisionSignature {
    fn hash(&self) -> Hash {
        let mut hasher = Hasher::new();
        hasher.update(&self.signature);
        hasher.update(&self.public_key);
        hasher.finalize()
    }
}

impl RevisionWitness {
    pub fn check_verification_hash(&self) -> bool {
        hash_eq(
            &self.event_verification_hash(),
            self.expected_event_verification_hash(),
        )
    }
    pub fn event_verification_hash(&self) -> Hash {
        let mut hasher = Hasher::new();
        hasher.update(&self.domain_snapshot_genesis_hash);
        hasher.update(&self.merkle_root);
        hasher.finalize()
    }
    pub fn expected_event_verification_hash(&self) -> &str {
        &self.witness_event_verification_hash
    }
}

impl Hashable for RevisionWitness {
    fn hash(&self) -> Hash {
        let mut hasher = Hasher::new();
        hasher.update(&self.domain_snapshot_genesis_hash);
        hasher.update(&self.merkle_root);
        hasher.update(&self.witness_network);
        hasher.update(&self.witness_event_transaction_hash);
        hasher.finalize()
    }
}

macro_rules! verify_hash {
    ($id:ident$(<$($lt:lifetime),*>)?$(.$p:ident)*) => {
        impl$(<$($lt),*>)? VerifyHash for $id $(<$($lt),*>)? {
            fn expected_hash(&self) -> &str {
                &self$(.$p)*
            }
        }
    };
}
verify_hash!(RevisionContent.content_hash);
verify_hash!(RevisionMetadata.metadata_hash);
verify_hash!(RevisionSignature.signature_hash);
verify_hash!(RevisionWitness.witness_hash);
