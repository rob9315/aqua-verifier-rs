use std::fmt::Display;
use std::{fs::File, path::PathBuf};

use aqua_verifier::api::{get_hash_chain_info, get_revision, get_revision_hashes, get_server_info};
use aqua_verifier::api::{JsonResult, Title};
use aqua_verifier::file_format::{HashChainInfo, OfflineData, Revision};
use aqua_verifier::verify::{get_verification_set, verify_revision};
use clap::{CommandFactory, Parser};

const API_VERSION: &str = "0.3.0";

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Whether to have verbose output or not
    #[arg(short)]
    verbose: bool,
    /// <The url of the server, e.g. https://pkc.inblock.io>
    #[arg(short, long, default_value = "http://localhost:9352")]
    server: reqwest::Url,
    /// Ignore verifying the witness merkle proof of each revision
    #[arg(short, long)]
    ignore_merkle_proof: bool,
    /// OAuth2 access token to access the API
    #[arg(short, long)]
    token: Option<String>,
    /// The file to read from for the data
    #[arg(short, long)]
    file: Option<PathBuf>,
    /// Limits depth to follow down the verification chain. By default, verifies all revisions
    #[arg(short, long)]
    depth: Option<usize>,
    #[arg()]
    titles: Vec<String>,
}

fn main() {
    let args = Args::parse();

    if let Some(filepath) = &args.file {
        let file = File::open(filepath).expect("Specified file not found");
        let data: OfflineData = serde_json::from_reader(&file).expect("Misformatted JSON");
        if args.verbose {
            println!(
                "Decoded input as:\n{}",
                serde_json::to_string_pretty(&data).expect("Failed to format JSON")
            )
        }
        let mut verified = true;
        for page in data.pages.into_iter() {
            match get_verification_set(&page, args.depth) {
                Ok(verification_set) => {
                    verified &=
                        verify_page(&page.hash_chain_info, verification_set.into_iter(), &args);
                }
                Err(e) => {
                    eprintln!("{e:?}");
                    verified = false;
                }
            };
        }
        print_verified(verified, filepath.display());
    } else {
        if args.titles.is_empty() {
            println!("{}", clap::Command::render_help(&mut Args::command()));
            return;
        }

        macro_rules! handle_network_req {
            ($e:expr $(; $($u:tt)*)?) => {
                match $e
                    .expect("Failed to contact PKC.")
                    .expect("Failed to parse response from PKC.") {
                    JsonResult::Ok(k) => k,
                    JsonResult::Err(e) => {
                        eprintln!("{e}");
                        $($($u)*)?
                    }
                }
            };
        }

        let token = args.token.as_deref();

        let server_info =
            handle_network_req!(get_server_info(args.server.clone(), token); std::process::exit(1));
        if server_info.api_version != API_VERSION {
            println!("Incompatible API version:\nCurrent supported version: {API_VERSION}\nServer version: {}", &server_info.api_version);
        }
        let mut verified = true;
        for title in &args.titles {
            let hash_chain_info = handle_network_req!(get_hash_chain_info(
                args.server.clone(),
                token,
                Title::log_info(title)
            ); verified = false; continue;);
            let verification_set = handle_network_req!(get_verification_set_api(
                args.server.clone(),
                token,
                args.depth,
                &hash_chain_info
            ); verified = false; continue;);
            let page_verified = verify_page(&hash_chain_info, verification_set.iter(), &args);
            let mut url = args.server.clone();
            if let Ok(mut segments) = url.path_segments_mut() {
                segments.push("index.php");
                segments.push(title);
            }
            print_verified(page_verified, url);
            verified &= page_verified;
        }
        print_verified(verified, format!("{:?} on {}", &args.titles, &args.server));
    };
}

fn print_verified(verified: bool, src: impl Display) {
    println!(
        "{}: {src}",
        if verified {
            "Verified"
        } else {
            "Failed to verify"
        },
    );
}

fn verify_page<'i, I>(hash_chain_info: &HashChainInfo, verification_set: I, args: &Args) -> bool
where
    I: Iterator<Item = &'i Revision>,
{
    let verification_set: Vec<_> = verification_set.collect();

    if verification_set.is_empty() {
        eprintln!("No Revisions found for {}", hash_chain_info.title);
        return false;
    }

    println!(
        "Verifying {} Revisions for {}",
        verification_set.len(),
        hash_chain_info.title
    );

    let mut verified = true;
    for (i, rev) in verification_set.iter().enumerate() {
        println!(
            "{}. Verification of {}",
            i + 1,
            rev.metadata.verification_hash
        );
        let prev = i
            .checked_sub(1)
            .and_then(|j| verification_set.get(j))
            .copied();
        let (result, time) = verify_revision(rev, prev, !args.ignore_merkle_proof);
        println!("{result:#?} {time:?}");
        verified &= bool::from(result);
    }
    verified
}

fn get_verification_set_api(
    endpoint: reqwest::Url,
    token: Option<&str>,
    depth: Option<usize>,
    hash_chain_info: &HashChainInfo,
) -> reqwest::Result<serde_json::Result<JsonResult<Vec<Revision>>>> {
    macro_rules! forward_errs {
        ($($t:tt)*) => {
            match $($t)*? {
                Ok(JsonResult::Ok(k)) => k,
                Ok(JsonResult::Err(e)) => return Ok(Ok(JsonResult::Err(e))),
                Err(e) => return Ok(Err(e)),
            }
        };
    }

    let revision_hashes = forward_errs!(get_revision_hashes(
        endpoint.clone(),
        token,
        &hash_chain_info.genesis_hash
    ));
    let height = depth
        .map(|h| h.min(revision_hashes.len()))
        .unwrap_or(revision_hashes.len());
    let mut verification_set: Vec<std::mem::MaybeUninit<Revision>> = Vec::with_capacity(height);
    unsafe {
        // Safety: This is safe because the values are not used
        verification_set.set_len(height);
    };
    let mut cur = &hash_chain_info.latest_verification_hash;
    for i in 0..height {
        let rev = forward_errs!(get_revision(endpoint.clone(), token, cur));
        verification_set[height - i - 1] = std::mem::MaybeUninit::new(rev);
        // Safety: this was just inserted
        cur = unsafe {
            &verification_set[height - i - 1]
                .assume_init_ref()
                .metadata
                .previous_verification_hash
        };
    }
    let verification_set: Vec<Revision> = unsafe { std::mem::transmute(verification_set) };
    Ok(Ok(JsonResult::Ok(verification_set)))
}
