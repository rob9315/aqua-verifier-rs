use std::{fs::File, path::PathBuf};

use aqua_verifier::{
    file_format::OfflineData,
    verify::{get_verification_set, verify_revision},
};
use clap::{CommandFactory, Parser};

#[cfg(not(target_env = "msvc"))]
#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Whether to have verbose output or not
    #[arg(short)]
    verbose: bool,
    /// <The url of the server, e.g. https://pkc.inblock.io>
    #[arg(short, long, default_value = "http://localhost:9352")]
    server: String,
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

    if let Some(file) = args.file {
        let file = File::open(file).expect("Specified file not found");
        let data: OfflineData = serde_json::from_reader(&file).expect("Misformatted JSON");
        if args.verbose {
            println!(
                "Decoded input as:\n{}",
                serde_json::to_string_pretty(&data).expect("Failed to format JSON")
            )
        }
        for page in data.pages.into_iter() {
            let verification_set = match get_verification_set(&page, args.depth) {
                Ok(k) => k,
                Err(e) => {
                    eprintln!("{e:?}");
                    continue;
                }
            };

            println!(
                "Verifying {} Revisions for {}",
                verification_set.len(),
                page.hash_chain_info.title
            );

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
                println!("{result:#?} {time:?}")
            }
        }
    } else {
        if args.titles.is_empty() {
            println!("{}", clap::Command::render_help(&mut Args::command()));
            return;
        }
        for title in args.titles {}
    };
}