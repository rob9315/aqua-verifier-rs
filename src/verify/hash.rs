use sha3::digest::Output;
use sha3::Digest;

use crate::file_format::{
    format_time_stamp, from_hex, hash_to_hex, pubkey_to_hex, signature_to_hex,
};
use crate::file_format::{
    FileContent, Revision, RevisionContent, RevisionMetadata, RevisionSignature, RevisionWitness,
};

use super::SignatureResult;

pub type Hasher = sha3::Sha3_512;
pub type Hash = Output<Hasher>;

pub struct FileHashError;
impl ::std::fmt::Debug for FileHashError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("File hash missing").finish()
    }
}
impl RevisionContent {
    pub fn expected_file_hash(&self) -> Result<Hash, FileHashError> {
        let s = self.content.get("file_hash").ok_or(FileHashError)?;
        from_hex(s).map(Into::into).ok_or(FileHashError)
    }
}

impl RevisionSignature {
    pub fn verify_current(&self, verification_hash: &Hash) -> SignatureResult {
        let hash = sha3::Keccak256::default()
            .chain_update(
                "\x19Ethereum Signed Message:\n177I sign the following page verification_hash: [0x",
            )
            .chain_update(hash_to_hex(verification_hash))
            .chain_update("]")
            .finalize();
        let message = libsecp256k1::Message::parse(&<[u8; 32]>::from(hash));
        let computed = libsecp256k1::recover(&message, &self.signature.0, &self.signature.1);
        SignatureResult {
            listed_wallet_address: self.wallet_address,
            computed_public_key: computed,
            expected_public_key: self.public_key,
        }
    }
}

macro_rules! hash_fn {
    ($vis:vis fn $name:ident($rev:ident: &$T:ty $(,$arg:ident: $Arg:ty)*) {
        $($t:tt)*
    }) => {
        $vis fn $name($rev: &$T, $($arg: $Arg)*) -> Hash {
            #[allow(unused_mut)]
            let mut hasher = Hasher::new();
            hash_fn!(@impl{hasher $rev $T $({$arg $Arg})*} + $($t)*);
            hasher.finalize()
        }
    };
    (@impl{$hasher:ident $rev:ident $T:ty $({$arg:ident $Arg:ty})*} + {$($x:tt)*} $($t:tt)*) => {
        #[allow(clippy::redundant_closure_call)]
        $hasher.update((||{$($x)*})());
        hash_fn!(@impl{$hasher $rev $T $({$arg $Arg})*} $($t)*);
    };
    (@impl{$hasher:ident $rev:ident $T:ty $({$arg:ident $Arg:ty})*} + |$h:ident|{$($x:tt)*} $($t:tt)*) => {
        #[allow(clippy::redundant_closure_call)]
        (|$h: &mut Hasher|{$($x)*})(&mut $hasher);
        hash_fn!(@impl{$hasher $rev $T $({$arg $Arg})*} $($t)*);
    };
    (@impl{$hasher:ident $rev:ident $T:ty $({$arg:ident $Arg:ty})*} + $(.$path:ident)+ $($t:tt)*) => {
        $hasher.update(&$rev $(.$path)+);
        hash_fn!(@impl{$hasher $rev $T $({$arg $Arg})*} $($t)*);
    };
    (@impl{$hasher:ident $rev:ident $T:ty $({$arg:ident $Arg:ty})*}) => {}
}

hash_fn!(
    pub fn metadata_hash(metadata: &RevisionMetadata) {
        .domain_id
        + {format_time_stamp(&metadata.time_stamp).to_string()}
        + |hasher| {
            if let Some(previous_verification_hash) = metadata.previous_verification_hash {
                hasher.update(hash_to_hex(&previous_verification_hash));
            }
        }
    }
);
hash_fn!(
    pub fn content_hash(content: &RevisionContent) {
        |hasher| {
            // btreemaps are sorted
            for value in content.content.values() {
                hasher.update(value);
            }
        }
    }
);
hash_fn!(
    pub fn file_hash(content: &FileContent) {
        .data
    }
);
hash_fn!(
    pub fn verification_hash(revision: &Revision, previous: Option<&Revision>) {
        {hash_to_hex(&revision.content.content_hash)}
        + {hash_to_hex(&revision.metadata.metadata_hash)}
        + |hasher| {
            if let Some(previous) = previous {
                if let Some(signature) = &previous.signature {
                    hasher.update(hash_to_hex(&signature.signature_hash));
                }
                if let Some(witness) = &previous.witness {
                    hasher.update(hash_to_hex(&witness.witness_hash));
                }
            }
        }
    }
);

hash_fn!(
    pub fn signature_hash(signature: &RevisionSignature) {
        { signature_to_hex(&signature.signature) }
        + { pubkey_to_hex(&signature.public_key) }
    }
);
hash_fn!(
    pub fn event_verification_hash(witness: &RevisionWitness) {
        {hash_to_hex(&witness.domain_snapshot_genesis_hash)}
        + {hash_to_hex(&witness.merkle_root)}
    }
);
hash_fn!(
    pub fn witness_hash(witness: &RevisionWitness) {
        {hash_to_hex(&witness.domain_snapshot_genesis_hash)}
        + {hash_to_hex(&witness.merkle_root)}
        + .witness_network
        + .witness_event_transaction_hash
    }
);
