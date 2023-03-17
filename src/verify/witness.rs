use std::time::{Duration, Instant};

use parking_lot::Mutex;

use crate::{
    file_format::{MerkleNode, RevisionWitness},
    verify::hash::hash_eq,
};

use super::hash::Hasher;

fn reqwest_io(err: reqwest::Error) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::Other, err)
}

fn verify_merkle_proof(merkle_nodes: &[MerkleNode], verification_hash: &str) -> bool {
    if merkle_nodes.is_empty() {
        return false;
    }

    let mut successor: Option<&str> = None;
    for node in merkle_nodes {
        if let Some(successor) = successor {
            if node.left_leaf.as_ref().map(|a| &a[..]) != Some(successor)
                && node.right_leaf.as_ref().map(|a| &a[..]) != Some(successor)
            {
                return false;
            }
        } else if node.left_leaf.as_ref().map(|a| &a[..]) != Some(verification_hash)
            && node.right_leaf.as_ref().map(|a| &a[..]) != Some(verification_hash)
        {
            return false;
        }
        let successor_matches = match (&node.left_leaf, &node.right_leaf) {
            (Some(left), None) => left == &node.successor,
            (None, Some(right)) => right == &node.successor,
            (Some(left), Some(right)) => {
                use sha3::Digest;
                let mut hasher = Hasher::new();
                hasher.update(left);
                hasher.update(right);
                hash_eq(&hasher.finalize(), &node.successor)
            }
            _ => unreachable!(),
        };
        if !successor_matches {
            return false;
        }
        successor = Some(&node.successor[..]);
    }

    true
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
    pub fn merkle_proof(&self, verification_hash: &str) -> bool {
        verify_merkle_proof(&self.structured_merkle_proof, verification_hash)
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
    event_verification_hash: &str,
) -> Result<bool, std::io::Error> {
    let resp = reqwest::blocking::Client::new()
        .get(format!("{}/{event_transaction_hash}", network.address()))
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

    Ok(hash.to_lowercase() == event_verification_hash.to_lowercase())
}
