use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::file_format::{HashChainInfo, Revision};

fn mut_endpoint(endpoint: &mut reqwest::Url) {
    if let Ok(mut segments) = endpoint.path_segments_mut() {
        segments.push("rest.php");
        segments.push("data_accounting");
    }
}

fn do_req(url: reqwest::Url, token: Option<&str>) -> reqwest::Result<reqwest::blocking::Response> {
    let mut builder = reqwest::blocking::Client::new()
        .get(url)
        .header(reqwest::header::CONTENT_TYPE, "application/json");
    if let Some(token) = token {
        builder = builder.header(reqwest::header::AUTHORIZATION, format!("Bearer {token}"));
    }
    builder.send()
}

macro_rules! parse {
    ($($t:tt)*) => {
        {
            let resp = $($t)*?;
            match resp.error_for_status_ref() {
                Ok(_) => Ok(serde_json::from_str(&resp.text()?).map(JsonResult::Ok)),
                Err(e) => serde_json::from_str(&resp.text()?)
                    .map_err(|_| e)
                    .map(JsonResult::Err)
                    .map(Ok),
            }
        }
    };
}

#[derive(Serialize, Deserialize)]
pub struct ServerInfo {
    pub api_version: String,
}

pub fn get_server_info(
    mut endpoint: reqwest::Url,
    token: Option<&str>,
) -> reqwest::Result<serde_json::Result<JsonResult<ServerInfo>>> {
    mut_endpoint(&mut endpoint);
    if let Ok(mut segments) = endpoint.path_segments_mut() {
        segments.push("get_server_info");
    }
    parse!(do_req(endpoint, token))
}

pub fn get_revision(
    mut endpoint: reqwest::Url,
    token: Option<&str>,
    verification_hash: &str,
) -> reqwest::Result<serde_json::Result<JsonResult<Revision>>> {
    mut_endpoint(&mut endpoint);
    if let Ok(mut segments) = endpoint.path_segments_mut() {
        segments.push("get_revision");
        segments.push(verification_hash);
    }
    parse!(do_req(endpoint, token))
}

pub fn get_revision_hashes(
    mut endpoint: reqwest::Url,
    token: Option<&str>,
    verification_hash: &str,
) -> reqwest::Result<serde_json::Result<JsonResult<Vec<String>>>> {
    mut_endpoint(&mut endpoint);
    if let Ok(mut segments) = endpoint.path_segments_mut() {
        segments.push("get_revision_hashes");
        segments.push(verification_hash);
    }
    parse!(do_req(endpoint, token))
}

#[repr(transparent)]
pub struct GenesisHash(str);
impl<T: AsRef<str>> From<T> for &GenesisHash {
    fn from(value: T) -> Self {
        // Safety: GenesisHash is repr(transparent)
        unsafe { std::mem::transmute(value.as_ref()) }
    }
}
impl HashChainInfoUrl for &GenesisHash {
    fn to_url(self, mut endpoint: reqwest::Url) -> reqwest::Url {
        mut_endpoint(&mut endpoint);
        if let Ok(mut segments) = endpoint.path_segments_mut() {
            segments.push("get_hash_chain_info");
            segments.push("genesis_hash");
        }
        endpoint
            .query_pairs_mut()
            .append_pair("identifier", &self.0);
        endpoint
    }
}

pub struct Title(String);
impl Title {
    pub fn log_info(s: &str) -> Title {
        if s.contains('_') {
            eprintln!("Warning: Underscores in title are converted to spaces.")
        }
        if s.contains(": ") {
            eprintln!("Warning: Space after ':' detected. You might need to remove it to match MediaWiki title.")
        }
        Title::validate(s)
    }
    pub fn validate(s: &str) -> Title {
        Title(s.replace('_', " "))
    }
}

impl HashChainInfoUrl for Title {
    fn to_url(self, mut endpoint: reqwest::Url) -> reqwest::Url {
        mut_endpoint(&mut endpoint);
        if let Ok(mut segments) = endpoint.path_segments_mut() {
            segments.push("get_hash_chain_info");
            segments.push("title");
        }
        endpoint
            .query_pairs_mut()
            .append_pair("identifier", &self.0);
        endpoint
    }
}

pub trait HashChainInfoUrl {
    fn to_url(self, endpoint: reqwest::Url) -> reqwest::Url;
}

pub fn get_hash_chain_info(
    endpoint: reqwest::Url,
    token: Option<&str>,
    target: impl HashChainInfoUrl,
) -> reqwest::Result<serde_json::Result<JsonResult<HashChainInfo>>> {
    let url = target.to_url(endpoint);
    parse!(do_req(url, token))
}

// todo! deal with json errors here

pub enum JsonResult<T> {
    Ok(T),
    Err(HttpError),
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HttpError {
    #[serde(default)]
    message_translations: HashMap<String, String>,
    http_code: u32,
    http_reason: String,
}

impl std::fmt::Display for HttpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&format!(
            "HttpError {} {}",
            self.http_code, self.http_reason
        ))
    }
}
