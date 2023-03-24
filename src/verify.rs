use std::time::{Duration, Instant};

use crate::file_format::{hash_to_hex, pubkey_to_hex, wallet_to_hex, HashChain, Revision};

pub mod hash;
use hash::{content_hash, event_verification_hash, file_hash, metadata_hash, verification_hash};

use self::hash::{FileHashError, Hash};

mod witness;

pub const CHECKMARK: &str = "✅";
pub const WARNING_SIGN: &str = "⚠️";
pub const CROSS: &str = "❌";
pub const LOCK: &str = "🔏";
pub const WATCH: &str = "⌚";
pub const INDENT: &str = "\n    ";
pub const DIM: &str = "\x1b[2m";
pub const RED: &str = "\x1b[31m";
pub const RESET: &str = "\x1b[0m";

pub fn get_verification_set(
    data: &HashChain,
    depth: Option<usize>,
) -> Result<Vec<&Revision>, String> {
    let revs = data.revisions.len();
    let height = depth.map(|d| d.min(revs)).unwrap_or(revs);
    let mut cur = Some(data.hash_chain_info.latest_verification_hash);
    let mut revs = vec![std::mem::MaybeUninit::uninit(); height];
    for i in 0..height {
        let Some(current) = &cur else {
            return Err("Not all revisions included".to_string());
        };
        let Some(rev) = data.revisions.get(current) else {
            return Err(format!("Failure getting revision {}", hash_to_hex(current)));
        };
        cur = rev.metadata.previous_verification_hash;
        revs[height - i - 1] = std::mem::MaybeUninit::new(rev);
    }
    Ok(unsafe { std::mem::transmute(revs) })
}

pub fn verify_revision(
    rev: &Revision,
    prev: Option<&Revision>,
    verify_merkle_proof: bool,
) -> (VerifyResult, Duration) {
    let now = Instant::now();
    let correct = verify_revision_without_elapsed(rev, prev, verify_merkle_proof);
    (correct, now.elapsed())
}

pub struct ChainConsistency {
    prev: Option<Hash>,
    this: Option<Hash>,
}
impl From<&ChainConsistency> for bool {
    fn from(value: &ChainConsistency) -> Self {
        value.prev == value.this
    }
}
impl ::std::fmt::Debug for ChainConsistency {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChainConsistency")
            .field("prev", &self.prev.as_ref().map(hash_to_hex))
            .field("this", &self.this.as_ref().map(hash_to_hex))
            .finish()
    }
}
impl ::std::fmt::Display for ChainConsistency {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let err = match (&self.this, &self.prev) {
            (None, Some(_)) => {
                " Chain INCONSISTENT (current revision doesn't point to previous one)"
            }
            (Some(_), None) => {
                " Chain INCONSISTENT (current revision points at missing previous revision)"
            }
            (Some(a), Some(b)) if a != b => {
                " Chain INCONSISTENT (current revision points to different previous one)"
            }
            _ => return Ok(()),
        };
        f.write_str(INDENT)?;
        f.write_str(RED)?;
        f.write_str(CROSS)?;
        f.write_str(err)?;
        f.write_str(RESET)
    }
}

pub struct HashResult {
    computed: Hash,
    expected: Hash,
}
impl HashResult {
    fn matches(&self) -> bool {
        self.computed == self.expected
    }
    fn to_str(
        &self,
        show_if_correct: bool,
        name: &str,
        f: &mut ::std::fmt::Formatter,
    ) -> ::std::fmt::Result {
        let indent = if show_if_correct { "  " } else { INDENT };
        if self.matches() {
            if show_if_correct {
                f.write_str(indent)?;
                f.write_str(CHECKMARK)?;
                f.write_str(name)?;
                f.write_str(" hash matches")?;
            }
        } else {
            f.write_str(indent)?;
            f.write_str(RED)?;
            f.write_str(CROSS)?;
            f.write_str(name)?;
            f.write_str(" hash does not match")?;
            f.write_str(RESET)?;
        }
        Ok(())
    }
}
impl ::std::fmt::Debug for HashResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HashResult")
            .field("computed", &hash_to_hex(&self.computed))
            .field("expected", &hash_to_hex(&self.expected))
            .finish()
    }
}

impl From<HashResult> for bool {
    fn from(value: HashResult) -> Self {
        value.computed == value.expected
    }
}

pub struct SignatureResult {
    listed_wallet_address: [u8; 20],
    computed_public_key: Result<libsecp256k1::PublicKey, libsecp256k1::Error>,
    expected_public_key: libsecp256k1::PublicKey,
}
impl SignatureResult {
    pub fn verify_wallet_address(&self) -> bool {
        use sha3::Digest;
        let pubkey = self.expected_public_key.serialize();
        pubkey[0] == 0x04
            && sha3::Keccak256::digest(&pubkey[1..])[12..] == self.listed_wallet_address
    }
}
impl From<SignatureResult> for bool {
    fn from(value: SignatureResult) -> Self {
        value
            .computed_public_key
            .map(|computed| computed == value.expected_public_key && value.verify_wallet_address())
            .unwrap_or(false)
    }
}
impl ::std::fmt::Display for SignatureResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(INDENT)?;
        match self.computed_public_key {
            Ok(computed) => {
                if computed == self.expected_public_key {
                    if !self.verify_wallet_address() {
                        f.write_str(RED)?;
                        f.write_str(CROSS)?;
                        f.write_str(LOCK)?;
                        f.write_str(" Wallet Address manipulated")?;
                        f.write_str(RESET)?;
                        return Ok(());
                    }
                    f.write_str(CHECKMARK)?;
                    f.write_str(LOCK)?;
                    f.write_str(" Signed by ")?;
                    wallet_to_hex(self.listed_wallet_address).fmt(f)?;
                } else {
                    f.write_str(RED)?;
                    f.write_str(CROSS)?;
                    f.write_str(LOCK)?;
                    f.write_str(" Signature INVALID")?;
                    f.write_str(RESET)?;
                }
            }
            Err(err) => {
                f.write_str(RED)?;
                f.write_str(CROSS)?;
                f.write_str(LOCK)?;
                f.write_str(" Error when trying to check Signature: ")?;
                err.fmt(f)?;
                f.write_str(RESET)?;
            }
        };
        Ok(())
    }
}
impl ::std::fmt::Debug for SignatureResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SignatureResult")
            .field(
                "listed_wallet_address",
                &wallet_to_hex(self.listed_wallet_address),
            )
            .field(
                "computed_public_key",
                &self.computed_public_key.as_ref().map(pubkey_to_hex),
            )
            .field(
                "expected_public_key",
                &pubkey_to_hex(&self.expected_public_key),
            )
            .finish()
    }
}

#[derive(Debug)]
pub struct VerifyResult {
    pub chain_consistency: ChainConsistency,
    pub metadata: HashResult,
    pub file_hash: Option<Result<HashResult, FileHashError>>,
    pub content: HashResult,
    pub verification: HashResult,
    pub signature: Option<SignatureResult>,
    pub witness: Option<WitnessResult>,
}

impl ::std::fmt::Display for VerifyResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.verification.to_str(true, " Verification", f)?;
        self.chain_consistency.fmt(f)?;
        match &self.file_hash {
            Some(Ok(file_hash)) => {
                f.write_str("\n  ")?;
                file_hash.to_str(true, "📄 File", f)?;
            }
            Some(Err(_e)) => {
                f.write_str(INDENT)?;
                f.write_str(RED)?;
                f.write_str(CROSS)?;
                f.write_str(" File exists but Hash MISSING")?;
                f.write_str(RESET)?;
            }
            None => {}
        }
        self.content.to_str(false, " Content", f)?;
        self.metadata.to_str(false, " Metadata", f)?;
        match &self.signature {
            Some(signature) => signature.fmt(f)?,
            None => {
                f.write_str(INDENT)?;
                f.write_str(DIM)?;
                f.write_str(WARNING_SIGN)?;
                f.write_str(" Not signed")?;
                f.write_str(RESET)?;
            }
        }
        match &self.witness {
            Some(witness) => {
                witness.fmt(f)?;
            }
            None => {
                f.write_str(INDENT)?;
                f.write_str(DIM)?;
                f.write_str(WARNING_SIGN)?;
                f.write_str(" Not witnessed")?;
                f.write_str(RESET)?;
            }
        }
        // todo! the rest
        Ok(())
    }
}

impl From<VerifyResult> for bool {
    fn from(value: VerifyResult) -> Self {
        let mut correct =
            value.metadata.into() && value.content.into() && value.verification.into();
        if let Some(file_hash) = value.file_hash {
            correct &= match file_hash {
                Ok(file_hash) => file_hash.into(),
                Err(_) => false,
            };
        }
        if let Some(witness) = value.witness {
            correct &= witness.verification.into() && matches!(witness.lookup, Ok(true));
            if let Some(merkle) = witness.merkle {
                correct &= merkle
            }
        }
        if let Some(signature) = value.signature {
            correct &= bool::from(signature)
        }
        correct
    }
}

#[derive(Debug)]
pub struct WitnessResult {
    pub verification: HashResult,
    pub lookup: Result<bool, std::io::Error>,
    pub merkle: Option<bool>,
}

impl ::std::fmt::Display for WitnessResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let verification = self.verification.matches();
        if verification
            && self.lookup.as_ref().map_err(drop).copied().unwrap_or(false)
            && self.merkle.unwrap_or(true)
        {
            f.write_str(INDENT)?;
            f.write_str(CHECKMARK)?;
            f.write_str(WATCH)?;
            f.write_str(" Witness event verification hash has been verified via etherscan.io")?;
            if self.merkle.is_none() {
                f.write_str(" (")?;
                f.write_str(WARNING_SIGN)?;
                f.write_str(" Merkle Check has been omitted)")?;
            }
            return Ok(());
        }

        // todo! the rest
        Ok(())
    }
}

fn verify_revision_without_elapsed(
    rev: &Revision,
    prev: Option<&Revision>,
    verify_merkle_proof: bool,
) -> VerifyResult {
    let prev_verification = ChainConsistency {
        prev: prev.map(|prev| prev.metadata.verification_hash),
        this: rev.metadata.previous_verification_hash,
    };

    let metadata = HashResult {
        computed: metadata_hash(&rev.metadata),
        expected: rev.metadata.metadata_hash,
    };

    let file_hash = rev.content.file.as_ref().map(|file| {
        rev.content.expected_file_hash().map(|expected| HashResult {
            computed: file_hash(file),
            expected,
        })
    });

    let content = HashResult {
        computed: content_hash(&rev.content),
        expected: rev.content.content_hash,
    };

    let verification = HashResult {
        computed: verification_hash(rev, prev),
        expected: rev.metadata.verification_hash,
    };

    let signature = rev
        .signature
        .as_ref()
        .map(|signature| signature.verify_current(&rev.metadata.verification_hash));

    let witness = rev.witness.as_ref().map(|witness| WitnessResult {
        verification: HashResult {
            computed: event_verification_hash(witness),
            expected: witness.witness_event_verification_hash,
        },
        lookup: witness.lookup(),
        merkle: verify_merkle_proof.then(|| witness.merkle_proof(&rev.metadata.verification_hash)),
    });

    VerifyResult {
        chain_consistency: prev_verification,
        metadata,
        file_hash,
        content,
        verification,
        signature,
        witness,
    }
}
