use std::time::{Duration, Instant};

use crate::{
    file_format::{HashChain, Revision},
    verify::hash::Hasher,
};

use hash::{hash_eq, Hashable, VerifyHash};

mod hash;

mod witness;

pub fn get_verification_set(
    data: &HashChain,
    depth: Option<usize>,
) -> Result<Vec<&Revision>, String> {
    let revs = data.revisions.len();
    let height = depth.map(|d| d.min(revs)).unwrap_or(revs);
    let mut cur = &data.hash_chain_info.latest_verification_hash;
    let mut revs = vec![std::mem::MaybeUninit::uninit(); height];
    for i in 0..height {
        let Some(rev) = data.revisions.get(cur) else {
            return Err(format!("Failure getting revision {cur}"));
        };
        revs[height - i - 1] = std::mem::MaybeUninit::new(rev);
        cur = &rev.metadata.previous_verification_hash;
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

#[derive(Debug)]
pub struct VerifyResult {
    pub metadata: bool,
    pub file_hash: Option<bool>,
    pub content: bool,
    pub prev_signature: Option<bool>,
    pub prev_witness: Option<bool>,
    pub witness: Option<WitnessResult>,
    pub signature: Option<bool>,
    pub verification: bool,
}

impl From<VerifyResult> for bool {
    fn from(value: VerifyResult) -> Self {
        let mut correct = value.metadata && value.content && value.verification;
        if let Some(file_hash) = value.file_hash {
            correct &= file_hash;
        }
        if let Some(prev_signature) = value.prev_signature {
            correct &= prev_signature;
        }
        if let Some(prev_witness) = value.prev_witness {
            correct &= prev_witness
        }
        if let Some(witness) = value.witness {
            correct &= witness.verification && matches!(witness.lookup, Ok(true));
            if let Some(merkle) = witness.merkle {
                correct &= merkle
            }
        }
        if let Some(signature) = value.signature {
            correct &= signature
        }
        correct
    }
}

#[derive(Debug)]
pub struct WitnessResult {
    pub verification: bool,
    pub lookup: Result<bool, std::io::Error>,
    pub merkle: Option<bool>,
}

fn verify_revision_without_elapsed(
    rev: &Revision,
    prev: Option<&Revision>,
    verify_merkle_proof: bool,
) -> VerifyResult {
    // verify metadata hash
    let metadata = rev.metadata.verify(&rev.metadata.hash());

    // verify file hash if there is a file
    let file_hash = match (&rev.content.file_hash(), rev.content.expected_file_hash()) {
        (Ok(Some(hash)), Ok(expected)) => Some(hash_eq(hash, expected)),
        (Ok(None), _) => None,
        _ => Some(false),
    };
    // verify content hash
    let content = rev.content.verify(&rev.content.hash());
    let prev_witness;
    let prev_signature;
    if let Some(prev) = prev {
        // verify previous signature if there is one
        prev_signature = if let Some(signature) = &prev.signature {
            Some(signature.verify(&signature.hash()))
        } else {
            // Previous signature data not found
            rev.verification_context
                .has_previous_signature
                .then_some(false)
        };
        // verify previous witness
        prev_witness = if let Some(witness) = &prev.witness {
            Some(witness.verify(&witness.hash()))
        } else {
            // Previous witness data not found
            rev.verification_context
                .has_previous_witness
                .then_some(false)
        };
    } else {
        // Revision has previous signature but no previous revision provided to validate
        prev_signature = rev
            .verification_context
            .has_previous_signature
            .then_some(false);
        // Revision has previous witness but no previous revision provided to validate
        prev_witness = rev
            .verification_context
            .has_previous_witness
            .then_some(false);
    }

    let witness = rev.witness.as_ref().map(|witness| WitnessResult {
        verification: witness.check_verification_hash(),
        lookup: witness.lookup(),
        merkle: verify_merkle_proof.then(|| {
            if rev.metadata.verification_hash == witness.domain_snapshot_genesis_hash {
                // DomainSnapshot
                true
            } else {
                witness.merkle_proof(&rev.metadata.verification_hash)
            }
        }),
    });

    let signature = rev
        .signature
        .as_ref()
        .map(|signature| signature.verify_current(&rev.metadata.verification_hash));

    let verification_hash = {
        use sha3::Digest;
        let mut hasher = Hasher::new();
        hasher.update(&rev.content.content_hash);
        hasher.update(&rev.metadata.metadata_hash);
        if let Some(prev) = prev {
            if let Some(signature) = &prev.signature {
                hasher.update(&signature.signature_hash);
            }
            if let Some(witness) = &prev.witness {
                hasher.update(&witness.witness_hash);
            }
        }
        hasher.finalize()
    };

    let verification = hash_eq(&verification_hash, &rev.metadata.verification_hash);

    VerifyResult {
        metadata,
        file_hash,
        content,
        prev_signature,
        prev_witness,
        witness,
        signature,
        verification,
    }
}
