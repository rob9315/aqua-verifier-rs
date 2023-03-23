use std::collections::{BTreeMap, HashMap};

use chrono::NaiveDateTime;
use serde::{Deserialize, Serialize};

mod helpers;
pub use helpers::format_naive_date_time;
use helpers::{ignore_when_empty_sig, naive_date_time_from_str, naive_date_time_to_str};

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
    pub data: String,
    pub filename: String,
    pub size: i32,
    pub comment: String,
}

#[derive(Serialize, Deserialize)]
pub struct RevisionContent {
    pub rev_id: i32,
    // BTreeMap so that the keys are sorted alphabetically
    pub content: BTreeMap<String, String>,
    pub content_hash: String,
    pub file: Option<FileContent>,
}

#[derive(Serialize, Deserialize)]
pub struct RevisionMetadata {
    pub domain_id: String,
    #[serde(deserialize_with = "naive_date_time_from_str")]
    #[serde(serialize_with = "naive_date_time_to_str")]
    pub time_stamp: NaiveDateTime,
    pub previous_verification_hash: String,
    pub metadata_hash: String,
    pub verification_hash: String,
}

#[derive(Serialize, Deserialize)]
pub struct RevisionSignature {
    pub signature: String,
    pub public_key: String,
    pub wallet_address: String,
    pub signature_hash: String,
}

#[derive(Serialize, Deserialize)]
pub struct MerkleNode {
    pub witness_event_id: i32,
    pub depth: usize,
    pub left_leaf: Option<String>,
    pub right_leaf: Option<String>,
    pub successor: String,
}

#[derive(Serialize, Deserialize)]
pub struct RevisionWitness {
    pub witness_event_id: i32,
    pub domain_id: String,
    pub domain_snapshot_title: String,
    pub witness_hash: String,
    pub domain_snapshot_genesis_hash: String,
    pub merkle_root: String,
    pub witness_event_verification_hash: String,
    pub witness_network: String,
    pub smart_contract_address: String,
    pub witness_event_transaction_hash: String,
    pub sender_account_address: String,
    pub source: String,
    pub structured_merkle_proof: Vec<MerkleNode>,
}

#[derive(Serialize, Deserialize)]
pub struct Revision {
    pub verification_context: VerificationContext,
    pub content: RevisionContent,
    pub metadata: RevisionMetadata,
    #[serde(deserialize_with = "ignore_when_empty_sig")]
    pub signature: Option<RevisionSignature>,
    pub witness: Option<RevisionWitness>,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OfflineData {
    pub pages: Vec<HashChain>,
    pub site_info: SiteInfo,
}
