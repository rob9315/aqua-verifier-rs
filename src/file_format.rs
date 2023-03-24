use std::collections::{BTreeMap, HashMap};

use chrono::NaiveDateTime;
use serde::{Deserialize, Serialize};

mod helpers;
use helpers::*;
pub use helpers::{format_time_stamp, from_hex, hash_to_hex, pubkey_to_hex, signature_to_hex};

use crate::verify::hash::Hash;

#[derive(Serialize, Deserialize)]
pub struct Namespace {
    pub case: bool,
    pub title: String,
}

#[derive(Serialize, Deserialize)]
pub struct SiteInfo {
    pub sitename: String,
    pub dbname: String,
    pub base: String,
    pub generator: String,
    pub case: String,
    pub namespaces: BTreeMap<i32, Namespace>,
}

#[derive(Serialize, Deserialize)]
pub struct HashChainInfo {
    pub genesis_hash: String,
    pub domain_id: String,
    pub content: Option<String>,
    pub latest_verification_hash: String,
    pub site_info: Option<SiteInfo>,
    pub title: String,
    pub namespace: i32,
    pub chain_height: i32,
}

#[derive(Serialize, Deserialize)]
pub struct HashChain {
    #[serde(flatten)]
    pub hash_chain_info: HashChainInfo,
    pub revisions: HashMap<String, Revision>,
}

#[derive(Serialize, Deserialize)]
pub struct VerificationContext {
    pub has_previous_signature: bool,
    pub has_previous_witness: bool,
}

#[derive(Serialize, Deserialize)]
pub struct FileContent {
    #[serde(deserialize_with = "base64de", serialize_with = "base64ser")]
    pub data: Vec<u8>,
    pub filename: String,
    pub size: i32,
    pub comment: String,
}

#[derive(Serialize, Deserialize)]
pub struct RevisionContent {
    pub rev_id: i32,
    // BTreeMap so that the keys are sorted alphabetically
    pub content: BTreeMap<String, String>,
    #[serde(deserialize_with = "hash_de", serialize_with = "hash_ser")]
    pub content_hash: Hash,
    pub file: Option<FileContent>,
}

#[derive(Serialize, Deserialize)]
pub struct RevisionMetadata {
    pub domain_id: String,
    #[serde(deserialize_with = "time_stamp_from_str")]
    #[serde(serialize_with = "time_stamp_to_str")]
    pub time_stamp: NaiveDateTime,
    pub previous_verification_hash: String,
    #[serde(deserialize_with = "hash_de", serialize_with = "hash_ser")]
    pub metadata_hash: Hash,
    #[serde(deserialize_with = "hash_de", serialize_with = "hash_ser")]
    pub verification_hash: Hash,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RevisionSignature {
    #[serde(
        deserialize_with = "eth_signature_de",
        serialize_with = "eth_signature_ser"
    )]
    pub signature: (libsecp256k1::Signature, libsecp256k1::RecoveryId),
    #[serde(deserialize_with = "eth_pubkey_de", serialize_with = "eth_pubkey_ser")]
    pub public_key: libsecp256k1::PublicKey,
    pub wallet_address: String,
    #[serde(deserialize_with = "hash_de", serialize_with = "hash_ser")]
    pub signature_hash: Hash,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MerkleNode {
    pub witness_event_id: i32,
    pub depth: usize,
    #[serde(deserialize_with = "opt_hash_de", serialize_with = "opt_hash_ser")]
    pub left_leaf: Option<Hash>,
    #[serde(deserialize_with = "opt_hash_de", serialize_with = "opt_hash_ser")]
    pub right_leaf: Option<Hash>,
    #[serde(deserialize_with = "hash_de", serialize_with = "hash_ser")]
    pub successor: Hash,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RevisionWitness {
    pub witness_event_id: i32,
    pub domain_id: String,
    pub domain_snapshot_title: String,
    #[serde(deserialize_with = "hash_de", serialize_with = "hash_ser")]
    pub witness_hash: Hash,
    #[serde(deserialize_with = "hash_de", serialize_with = "hash_ser")]
    pub domain_snapshot_genesis_hash: Hash,
    #[serde(deserialize_with = "hash_de", serialize_with = "hash_ser")]
    pub merkle_root: Hash,
    #[serde(deserialize_with = "hash_de", serialize_with = "hash_ser")]
    pub witness_event_verification_hash: Hash,
    pub witness_network: String,
    pub smart_contract_address: String,
    #[serde(deserialize_with = "hash_de", serialize_with = "hash_ser")]
    pub witness_event_transaction_hash: Hash,
    pub sender_account_address: String,
    pub source: String,
    pub structured_merkle_proof: Vec<MerkleNode>,
}

#[derive(Serialize, Deserialize)]
pub struct Revision {
    pub verification_context: VerificationContext,
    pub content: RevisionContent,
    pub metadata: RevisionMetadata,
    #[serde(default, deserialize_with = "none_on_failed_parse")]
    pub signature: Option<RevisionSignature>,
    #[serde(default, deserialize_with = "none_on_failed_parse")]
    pub witness: Option<RevisionWitness>,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OfflineData {
    pub pages: Vec<HashChain>,
    pub site_info: SiteInfo,
}
