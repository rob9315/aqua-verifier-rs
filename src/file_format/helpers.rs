use chrono::{
    format::{DelayedFormat, StrftimeItems},
    NaiveDateTime,
};
use libsecp256k1::{PublicKey, RecoveryId, Signature};
use serde::{de::DeserializeOwned, Deserialize, Deserializer, Serializer};

use crate::verify::hash::Hash;

// https://stackoverflow.com/a/57623355

// YYYYMMDDHHMMSS
// year month day hour minute second
const TIMESTAMP_FORMAT: &str = "%Y%m%d%H%M%S";

pub(crate) fn time_stamp_from_str<'de, D>(deserializer: D) -> Result<NaiveDateTime, D::Error>
where
    D: Deserializer<'de>,
{
    let s: String = Deserialize::deserialize(deserializer)?;
    NaiveDateTime::parse_from_str(&s, TIMESTAMP_FORMAT).map_err(serde::de::Error::custom)
}

pub fn format_time_stamp(timestamp: &NaiveDateTime) -> DelayedFormat<StrftimeItems<'static>> {
    timestamp.format(TIMESTAMP_FORMAT)
}

pub(crate) fn time_stamp_to_str<S>(
    timestamp: &NaiveDateTime,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(&format_time_stamp(timestamp).to_string())
}

pub(crate) fn none_on_failed_parse<'de, D, E>(deserializer: D) -> Result<Option<E>, D::Error>
where
    D: Deserializer<'de>,
    E: DeserializeOwned,
{
    let value = serde_json::Value::deserialize(deserializer)?;
    Ok(serde_json::from_value::<E>(value).ok())
}

pub(crate) fn base64de<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
    use base64::prelude::{Engine, BASE64_STANDARD_NO_PAD};
    let s: String = Deserialize::deserialize(deserializer)?;
    BASE64_STANDARD_NO_PAD
        .decode(s)
        .map_err(serde::de::Error::custom)
}

pub(crate) fn base64ser<S: Serializer>(
    bytes: &[u8],
    ser: S,
) -> std::result::Result<S::Ok, S::Error> {
    use base64::prelude::{Engine, BASE64_STANDARD_NO_PAD};
    ser.serialize_str(&BASE64_STANDARD_NO_PAD.encode(bytes))
}

#[repr(C)]
#[allow(dead_code)]
struct RecoverySignature {
    signature: [u8; 64],
    recovery_id: u8,
}

pub(crate) fn eth_signature_de<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<(Signature, RecoveryId), D::Error> {
    use libsecp256k1::util::SIGNATURE_SIZE;
    const INVALID_ETH_RECOVSIG: &str = "Invalid ethereum recovery signature";
    let s = String::deserialize(deserializer)?;
    let data: [u8; SIGNATURE_SIZE + 1] =
        from_prefixed_hex(&s).ok_or_else(|| serde::de::Error::custom(INVALID_ETH_RECOVSIG))?;
    let RecoverySignature {
        signature,
        recovery_id,
    } = unsafe { std::mem::transmute(data) };
    let signature = Signature::parse_standard(&signature).map_err(serde::de::Error::custom)?;
    let recovery_id = RecoveryId::parse_rpc(recovery_id).map_err(serde::de::Error::custom)?;
    Ok((signature, recovery_id))
}

pub(crate) fn eth_signature_ser<S: Serializer>(
    recovery_signature: &(Signature, RecoveryId),
    serializer: S,
) -> Result<S::Ok, S::Error> {
    let s = signature_to_hex(recovery_signature);
    serializer.serialize_str(s.as_ref())
}

pub(crate) fn eth_pubkey_de<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<PublicKey, D::Error> {
    const INVALID_PUBKEY: &str = "Invalid public key";
    let s = String::deserialize(deserializer)?;
    let data = from_prefixed_hex(&s).ok_or_else(|| serde::de::Error::custom(INVALID_PUBKEY))?;
    let pubkey = PublicKey::parse(&data).map_err(serde::de::Error::custom)?;
    Ok(pubkey)
}

pub(crate) fn eth_pubkey_ser<S: Serializer>(
    pubkey: &PublicKey,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    let s = pubkey_to_hex(pubkey);
    serializer.serialize_str(s.as_ref())
}

pub(crate) fn hash_de<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Hash, D::Error> {
    const INVALID_HASH: &str = "Invalid sha3_512 hash";
    let s = String::deserialize(deserializer)?;
    let data = from_hex(&s).ok_or_else(|| serde::de::Error::custom(INVALID_HASH))?;
    Ok(Hash::from(data))
}

pub(crate) fn hash_ser<S: Serializer>(hash: &Hash, serializer: S) -> Result<S::Ok, S::Error> {
    let s = hash_to_hex(hash);
    serializer.serialize_str(s.as_ref())
}

pub(crate) fn opt_hash_de<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<Hash>, D::Error> {
    Ok(hash_de(deserializer).ok())
}

pub(crate) fn opt_hash_ser<S: Serializer>(
    opt_hash: &Option<Hash>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    match &opt_hash {
        Some(hash) => hash_ser(hash, serializer),
        None => serializer.serialize_none(),
    }
}

pub fn from_prefixed_hex<const SIZE: usize>(s: &str) -> Option<[u8; SIZE]> {
    // strip away 0x prefix
    let stripped = s.strip_prefix("0x")?;
    from_hex(stripped)
}
pub fn from_hex<const SIZE: usize>(s: &str) -> Option<[u8; SIZE]> {
    // make sure it has the correct length (2 characters per byte) and that it is only valic characters
    if !s.as_bytes().len() == SIZE * 2 || !s.is_ascii() {
        return None;
    }
    let mut data = [0u8; SIZE];
    hex::decode_to_slice(s, &mut data).ok()?;
    Some(data)
}

// Safety: The hex crate always writes valid ascii which is valid utf-8
struct StackStr<const X: usize>([u8; X]);
impl<const X: usize> AsRef<[u8]> for StackStr<X> {
    fn as_ref(&self) -> &[u8] {
        &self.0[..]
    }
}
impl<const X: usize> AsRef<str> for StackStr<X> {
    fn as_ref(&self) -> &str {
        unsafe { ::core::str::from_utf8_unchecked(self.as_ref()) }
    }
}
impl<const X: usize> AsRef<[u8; X]> for StackStr<X> {
    fn as_ref(&self) -> &[u8; X] {
        &self.0
    }
}
impl<const X: usize> ::std::fmt::Display for StackStr<X> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_ref())
    }
}
macro_rules! into_prefixed_hex {
    ($vis:vis $ident:ident $($s:tt)*) => {
        $vis fn $ident(arr: [u8; $($s)*]) -> impl AsRef<str> + AsRef<[u8]> + AsRef<[u8; 2 + 2 * ($($s)*)]> + ::std::fmt::Display {
            let mut s = [0u8; 2 + 2 * ($($s)*)];
            s[0] = b'0';
            s[1] = b'x';
            // Safety: This will never error as it has exactly enough space in the buffer
            unsafe {
                hex::encode_to_slice(arr, &mut s[2..]).unwrap_unchecked();
            }
            StackStr(s)
        }
    };
}
pub fn signature_to_hex(
    (signature, recovery_id): &(Signature, RecoveryId),
) -> impl AsRef<str> + AsRef<[u8]> {
    into_prefixed_hex!(raw_to_hex libsecp256k1::util::SIGNATURE_SIZE + 1);
    let recovery_signature = RecoverySignature {
        signature: signature.serialize(),
        recovery_id: recovery_id.serialize(),
    };
    raw_to_hex(unsafe { ::core::mem::transmute(recovery_signature) })
}
pub fn pubkey_to_hex(pubkey: &PublicKey) -> impl AsRef<str> + AsRef<[u8]> {
    into_prefixed_hex!(raw_to_hex libsecp256k1::util::SIGNATURE_SIZE + 1);
    raw_to_hex(pubkey.serialize())
}
pub fn hash_to_hex(
    hash: &Hash,
) -> impl AsRef<str> + AsRef<[u8]> + AsRef<[u8; 64 * 2]> + ::std::fmt::Display {
    let mut data = [0u8; 64 * 2];
    // Safety: data is exactly the right size for the hex output
    unsafe {
        hex::encode_to_slice(<[u8; 64]>::from(*hash), &mut data).unwrap_unchecked();
    }
    StackStr(data)
}
