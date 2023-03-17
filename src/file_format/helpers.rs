use chrono::{
    format::{DelayedFormat, StrftimeItems},
    NaiveDateTime,
};
use serde::{Deserialize, Deserializer, Serializer};

use super::RevisionSignature;

// https://stackoverflow.com/a/57623355

// YYYYMMDDHHMMSS
// year month day hour minute second
const TIMESTAMP_FORMAT: &str = "%Y%m%d%H%M%S";

pub(crate) fn naive_date_time_from_str<'de, D>(deserializer: D) -> Result<NaiveDateTime, D::Error>
where
    D: Deserializer<'de>,
{
    let s: String = Deserialize::deserialize(deserializer)?;
    NaiveDateTime::parse_from_str(&s, TIMESTAMP_FORMAT).map_err(serde::de::Error::custom)
}

pub fn format_naive_date_time(timestamp: &NaiveDateTime) -> DelayedFormat<StrftimeItems<'static>> {
    timestamp.format(TIMESTAMP_FORMAT)
}

pub(crate) fn naive_date_time_to_str<S>(
    timestamp: &NaiveDateTime,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(&format_naive_date_time(timestamp).to_string())
}

pub(crate) trait EmptySigCheck {
    fn empty_sig(&self) -> bool;
}
pub(crate) fn ignore_when_empty_sig<'de, D, E>(deserializer: D) -> Result<Option<E>, D::Error>
where
    D: Deserializer<'de>,
    E: Deserialize<'de> + EmptySigCheck,
{
    let Ok(e) = E::deserialize(deserializer) else {return Ok(None)};
    if e.empty_sig() {
        return Ok(None);
    }
    Ok(Some(e))
}
impl EmptySigCheck for RevisionSignature {
    fn empty_sig(&self) -> bool {
        self.signature.is_empty()
    }
}
