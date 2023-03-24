use std::{
    collections::HashSet,
    time::{Duration, Instant},
};

use parking_lot::Mutex;

use crate::file_format::{from_hex, hash_to_hex, MerkleNode, RevisionWitness};

use super::hash::{Hash, Hasher};

fn reqwest_io(err: reqwest::Error) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::Other, err)
}

fn get_merkle_proof_hashes(
    merkle_nodes: &[MerkleNode],
    merkle_root: &Hash,
) -> Option<HashSet<Hash>> {
    if merkle_nodes.is_empty() {
        // no nodes
        return None;
    }

    let mut hashes = HashSet::with_capacity(merkle_nodes.len() + 1);
    let mut open_successors = HashSet::with_capacity(merkle_nodes.len());
    for node in merkle_nodes {
        if let Some(left_node) = &node.left_leaf {
            if !open_successors.remove(left_node) && !hashes.insert(*left_node) {
                // duplicate leaf
                return None;
            }
        }
        if let Some(right_node) = &node.right_leaf {
            if !open_successors.remove(right_node) && !hashes.insert(*right_node) {
                // duplicate leaf
                return None;
            }
        }
        let successor = match (&node.left_leaf, &node.right_leaf) {
            (Some(left), None) => *left,
            (None, Some(right)) => *right,
            (Some(left), Some(right)) => {
                use sha3::Digest;
                Hasher::new()
                    .chain_update(hash_to_hex(left))
                    .chain_update(hash_to_hex(right))
                    .finalize()
            }
            // this is unreachable because previously at least one of the hashes was the "successor" as such at least
            // one of them exists
            _ => unreachable!(),
        };
        if successor != node.successor {
            // successor incorrectly computed
            return None;
        }
        if !hashes.remove(&successor) && !open_successors.insert(successor) {
            // hash collision?
            return None;
        }
    }
    if !open_successors.remove(merkle_root) {
        // merkle_root not present
        return None;
    }
    for open_successor in open_successors {
        if !hashes.remove(&open_successor) {
            // chain not intact
            return None;
        }
    }

    Some(hashes)
}

impl RevisionWitness {
    pub fn lookup(&self) -> Result<bool, std::io::Error> {
        let network = WitnessNetwork::try_from(&self.witness_network[..]).map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "could not parse witness network",
            )
        })?;
        check_etherscan(
            &network,
            &self.witness_event_transaction_hash,
            &self.witness_event_verification_hash,
        )
    }
    pub fn merkle_proof(&self, verification_hash: &Hash) -> bool {
        get_merkle_proof_hashes(&self.structured_merkle_proof, &self.merkle_root)
            .map(|set| set.contains(verification_hash))
            .unwrap_or(false)
    }
}

macro_rules! networks {
    ($($network:ident = $url:literal),* $(,)?) => {
        #[allow(non_camel_case_types)]
        pub enum WitnessNetwork {
            $($network),*
        }
        impl WitnessNetwork {
            pub fn address(&self) -> &'static str {
                match self {
                    $(WitnessNetwork::$network => $url),*
                }
            }
        }
        impl<'a> TryFrom<&'a str> for WitnessNetwork {
            type Error = ();
            fn try_from(s: &'a str) -> Result<WitnessNetwork, ()> {
                Ok(match s {
                    $(stringify!($network) => WitnessNetwork::$network,)*
                    _ => return Err(()),
                })
            }
        }
    };
}
networks! {
    mainnet = "https://etherscan.io/tx",
    ropsten = "https://ropsten.etherscan.io/tx",
    kovan = "https://kovan.etherscan.io/tx",
    rinkeby = "https://rinkeby.etherscan.io/tx",
    goerli = "https://goerli.etherscan.io/tx",
}

static REGEX: once_cell::sync::OnceCell<regex::Regex> = once_cell::sync::OnceCell::new();
static GLOBAL_REQ_TIMER: Mutex<Option<Instant>> = Mutex::new(None);
const ETHERSCAN_TIMEOUT: Duration = Duration::from_millis(300);

fn check_etherscan(
    network: &WitnessNetwork,
    event_transaction_hash: &str,
    event_verification_hash: &Hash,
) -> Result<bool, std::io::Error> {
    let resp = reqwest::blocking::Client::new()
        .get(format!("{}/{}", network.address(), event_transaction_hash))
        .send()
        .map_err(reqwest_io)?;
    let data = resp.bytes().map_err(reqwest_io)?;
    let text = std::str::from_utf8(&data)
        .map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err))?;

    loop {
        let mut timer = GLOBAL_REQ_TIMER.lock();
        if let Some(time) = *timer {
            if time.elapsed() < ETHERSCAN_TIMEOUT {
                continue;
            }
        }
        *timer = Some(Instant::now());
        break;
    }

    let regex =
        REGEX.get_or_init(|| regex::Regex::new("<span id='rawinput'.+?>(.+?)</span>").unwrap());

    let Some(m) = regex.captures(text) else {
        return Ok(false);
    };
    let Some(capture) = m.get(1) else {
        return Ok(false);
    };
    let Some(hash) = capture.as_str().strip_prefix("0x9cef4ea1") else {
        return Ok(false);
    };

    let Some(hash) = from_hex(hash) else {
        return Ok(false);
    };

    Ok(&Hash::from(hash) == event_verification_hash)
}
