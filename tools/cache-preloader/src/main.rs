use anyhow::{Context, Result};
use clap::Parser;
use flate2::write::GzEncoder;
use flate2::Compression;
use http_cache_reqwest::{CACacheManager, Cache, CacheMode, HttpCache, HttpCacheOptions};
use reqwest::Client;
use reqwest_middleware::{ClientBuilder, ClientWithMiddleware};
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::time::Instant;

#[derive(Parser, Debug)]
#[command(author, version, about = "Preload URLs into an HTTP cache directory", long_about = None)]
struct Args {
    /// File containing URLs to preload (one per line)
    #[arg(short, long)]
    urls_file: PathBuf,

    /// Cache directory where files will be stored
    #[arg(short, long, default_value = "./cache")]
    cache_dir: PathBuf,

    /// Create a tar.gz archive of the cache directory after preloading
    #[arg(short, long)]
    archive: Option<PathBuf>,
}

async fn fetch_url(client: &ClientWithMiddleware, url: &str) -> Result<()> {
    let start = Instant::now();
    let response = client
        .get(url)
        .send()
        .await
        .context(format!("Failed to fetch URL: {}", url))?;

    let status = response.status();
    let duration = start.elapsed();

    if status.is_success() {
        println!("✓ {} ({}ms)", url, duration.as_millis());
        Ok(())
    } else {
        anyhow::bail!("Failed with status {}: {}", status, url);
    }
}

fn create_archive(cache_dir: &Path, archive_path: &Path) -> Result<()> {
    println!("\nCreating archive at {:?}...", archive_path);

    let tar_file = File::create(archive_path).context("Failed to create archive file")?;
    let enc = GzEncoder::new(tar_file, Compression::default());
    let mut tar = tar::Builder::new(enc);

    // Add the entire cache directory to the tar archive
    tar.append_dir_all("cache", cache_dir)
        .context("Failed to add cache directory to archive")?;

    tar.finish().context("Failed to finalize archive")?;

    println!("✓ Archive created successfully");
    Ok(())
}

fn read_urls(urls_file: &Path) -> Result<Vec<String>> {
    let file =
        File::open(urls_file).context(format!("Failed to open URLs file: {:?}", urls_file))?;
    let reader = BufReader::new(file);

    let mut urls = Vec::new();
    for (line_num, line) in reader.lines().enumerate() {
        let line = line.context(format!(
            "Failed to read line {} from URLs file",
            line_num + 1
        ))?;
        let line = line.trim();

        // Skip empty lines and comments
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        urls.push(line.to_string());
    }

    Ok(urls)
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    println!("Cache Preloader");
    println!("===============");
    println!("URLs file: {:?}", args.urls_file);
    println!("Cache dir: {:?}", args.cache_dir);
    println!();

    // Read URLs from file
    let urls = read_urls(&args.urls_file)?;
    println!("Found {} URLs to preload\n", urls.len());

    if urls.is_empty() {
        println!("No URLs to preload. Exiting.");
        return Ok(());
    }

    // Create cache directory if it doesn't exist
    std::fs::create_dir_all(&args.cache_dir).context("Failed to create cache directory")?;

    // Create HTTP client with cache
    let client: ClientWithMiddleware = ClientBuilder::new(Client::new())
        .with(Cache(HttpCache {
            mode: CacheMode::Default,
            manager: CACacheManager::new(args.cache_dir.clone(), true),
            options: HttpCacheOptions::default(),
        }))
        .build();

    // Fetch URLs sequentially
    let total_start = Instant::now();
    let mut success_count = 0;
    let mut error_count = 0;

    for url in urls {
        match fetch_url(&client, &url).await {
            Ok(()) => success_count += 1,
            Err(e) => {
                eprintln!("✗ Error: {}", e);
                error_count += 1;
            }
        }
    }

    let total_duration = total_start.elapsed();

    println!("\n===============");
    println!("Summary:");
    println!("  Success: {}", success_count);
    println!("  Errors:  {}", error_count);
    println!("  Total time: {:.2}s", total_duration.as_secs_f64());
    println!();

    // Create archive if requested
    if let Some(archive_path) = args.archive {
        create_archive(&args.cache_dir, &archive_path)?;
    }

    if error_count > 0 {
        anyhow::bail!("{} URLs failed to load", error_count);
    }

    Ok(())
}
