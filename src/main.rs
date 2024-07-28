use clap::{Arg, Command};
use colored::*;
use colored_json::ToColoredJson;
use indicatif::{ProgressBar, ProgressStyle};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::env;
use std::error::Error as StdError;
use std::fs::File;
use std::io::{self, BufRead, BufReader};
use thiserror::Error;
use tokio;

const API_URL: &str = "https://hashmob.net/api/v2/search/paid";

#[derive(Error, Debug)]
enum HashMobError {
    #[error("IO error: {0}")]
    Io(#[from] io::Error),
    #[error("Request error: {0}")]
    Request(#[from] reqwest::Error),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("Environment variable error: {0}")]
    EnvVar(#[from] std::env::VarError),
    #[error("No input provided")]
    NoInput,
    #[error("Colored JSON error: {0}")]
    ColoredJson(#[from] Box<dyn StdError>),
}

#[derive(Serialize)]
struct HashRequest {
    hashes: Vec<String>,
}

#[derive(Deserialize)]
struct ApiResponse {
    data: Data,
}

#[derive(Deserialize)]
struct Data {
    found: Vec<Found>,
}

#[derive(Deserialize)]
struct Found {
    hash: String,
    plain: String,
}

#[tokio::main]
async fn main() -> Result<(), HashMobError> {
    let matches = Command::new("HashMob Client")
        .version("1.0")
        .author("Volker Schwaberow <volker@schwaberow.de>")
        .about("Searches for hash cleartext counterparts in HashMob's database")
        .arg(
            Arg::new("quiet")
                .short('q')
                .long("quiet")
                .help("Output results as hash:plain pairs")
                .action(clap::ArgAction::SetTrue),
        )
        .arg(
            Arg::new("noformatting")
                .short('n')
                .long("no-formatting")
                .help("Disable JSON response formatting")
                .action(clap::ArgAction::SetTrue),
        )
        .arg(
            Arg::new("nocolor")
                .long("no-color")
                .help("Disable colored output")
                .action(clap::ArgAction::SetTrue),
        )
        .arg(
            Arg::new("INPUT")
                .help("Single hash, comma-separated hashes, or file path")
                .required(false)
                .index(1),
        )
        .get_matches();

    let quiet = matches.get_flag("quiet");
    let no_formatting = matches.get_flag("noformatting");
    let no_color = matches.get_flag("nocolor") || !atty::is(atty::Stream::Stdout);

    if no_color {
        colored::control::set_override(false);
    }

    let api_key = env::var("HASHMOB_KEY")?;

    if api_key.is_empty() {
        eprintln!("{}", "ERROR: API key not found".bright_red().bold());
        eprintln!(
            "{}",
            "A valid API key must be specified in the HASHMOB_KEY environment variable.".yellow()
        );
        eprintln!("\n{}", "To set the API key, use:".cyan());
        eprintln!("    {}", "export HASHMOB_KEY=your-api-key-here".green());
        return Err(HashMobError::EnvVar(std::env::VarError::NotPresent));
    }

    let hashes = if let Some(input) = matches.get_one::<String>("INPUT") {
        if let Ok(metadata) = std::fs::metadata(input) {
            if metadata.is_file() {
                if !quiet {
                    println!("{}", format!("Reading hashes from file: {}", input).cyan());
                }
                read_hashes_from_file(input)?
            } else {
                input.split(',').map(str::trim).map(String::from).collect()
            }
        } else {
            input.split(',').map(str::trim).map(String::from).collect()
        }
    } else if atty::isnt(atty::Stream::Stdin) {
        io::stdin().lock().lines().filter_map(Result::ok).collect()
    } else {
        eprintln!("{}", "Error: No input provided".bright_red().bold());
        eprintln!("{}", "Usage: hashmob [-q] [-n] <hash input>".yellow());
        eprintln!("{}", "Run with --help for full usage details.".cyan());
        return Err(HashMobError::NoInput);
    };

    let client = Client::new();
    let req_payload = HashRequest { hashes };

    let pb = ProgressBar::new_spinner();
    pb.set_style(
        ProgressStyle::default_spinner()
            .tick_chars("⠁⠂⠄⡀⢀⠠⠐⠈ ")
            .template("{spinner:.green} {msg}")
            .unwrap(),
    );
    pb.set_message("Querying HashMob database...");

    let resp = client
        .post(API_URL)
        .header("Content-Type", "application/json")
        .header("accept", "*/*")
        .header(
            "User-Agent",
            "rusthashmob v1.0 (github.com/vschwaberow/hashmob)",
        )
        .header("api-key", &api_key)
        .header("X-CSRF-TOKEN", "")
        .json(&req_payload)
        .send()
        .await?;

    let resp_body = resp.text().await?;
    pb.finish_with_message("Query completed");

    if quiet {
        let api_response: ApiResponse = serde_json::from_str(&resp_body)?;
        if api_response.data.found.is_empty() {
            println!("{}", "No matches found in the database.".yellow());
        } else {
            println!("{}", "Matches found:".green());
            api_response.data.found.iter().for_each(|found| {
                println!("{}:{}", found.hash.cyan(), found.plain.green());
            });
        }
    } else if no_formatting {
        println!("{}", resp_body);
    } else {
        let colored_json = resp_body.to_colored_json_auto()?;
        println!("{}", colored_json);
    }

    Ok(())
}

fn read_hashes_from_file(path: &str) -> io::Result<Vec<String>> {
    let file = File::open(path)?;
    let reader = BufReader::new(file);
    Ok(reader
        .lines()
        .filter_map(|line| line.ok())
        .filter(|line| !line.is_empty())
        .collect::<Vec<String>>())
}