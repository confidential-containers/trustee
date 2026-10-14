// Copyright (c) 2026 by The Confidential Container Authors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! `trustee cache`: tooling to prepare cache contents for deployments that
//! cannot fetch them themselves, e.g. air-gapped ones.
//!
//! Entries are collected in a directory with one subdirectory per namespace
//! (the `Directory` preload layout), packed into an OCI bundle, signed with a
//! cosign-compatible key and copied to a registry or carried over as an OCI
//! image layout.

use std::{
    path::{Path, PathBuf},
    sync::Arc,
};

use anyhow::{bail, Context, Result};
use clap::{Args, Subcommand};
use openssl::{
    ec::{EcGroup, EcKey},
    nid::Nid,
    pkey::PKey,
};
use pluggable_cache::{
    oci::{
        bundle::{self, BundleEntries},
        verify::{BundleVerifier, CosignKeyVerifier},
        Credentials, LayoutStore, OciStore, Reference, RegistryStore,
    },
    preload::read_tree,
    provider::validate_namespace,
};
use tracing::info;

/// Upper bound on the size of a single bundle entry.
const MAX_ENTRY_BYTES: usize = pluggable_cache::DEFAULT_MAX_VALUE_BYTES;

#[derive(Debug, Subcommand)]
pub(crate) enum CacheCommands {
    /// Fetch the VCEK for an AMD SEV-SNP attestation report into a preload
    /// directory, under the `snp_vcek` namespace
    FetchVcek {
        /// Raw attestation report (binary, as produced by the guest)
        #[arg(long)]
        report: PathBuf,
        /// Processor generation (Milan, Genoa, Turin), if the report does
        /// not record it
        #[arg(long)]
        processor: Option<String>,
        /// Base URL of the key distribution service, e.g. a mirror
        #[arg(long)]
        kds_url: Option<String>,
        /// Preload directory to write to
        #[arg(long)]
        dir: PathBuf,
    },
    /// Build, sign, copy and check cache bundles
    #[command(subcommand)]
    Bundle(BundleCommands),
}

#[derive(Debug, Args)]
pub(crate) struct Source {
    /// OCI image layout directory
    #[arg(long, conflicts_with = "from", required_unless_present = "from")]
    layout: Option<PathBuf>,
    /// Registry reference, e.g. registry.example.com/trustee/cache:v1
    #[arg(long)]
    from: Option<String>,
    /// Tag (or digest) of the bundle in the layout
    #[arg(long, default_value = "latest")]
    tag: String,
    #[command(flatten)]
    registry: RegistryArgs,
}

#[derive(Debug, Args)]
pub(crate) struct RegistryArgs {
    /// Registry user name
    #[arg(long, requires = "password_file")]
    username: Option<String>,
    /// File holding the registry password or token
    #[arg(long, requires = "username")]
    password_file: Option<PathBuf>,
    /// Talk to the registry over plain HTTP
    #[arg(long)]
    insecure_http: bool,
}

impl RegistryArgs {
    fn store(&self, reference: &Reference, push: bool) -> Result<RegistryStore> {
        let credentials = match (&self.username, &self.password_file) {
            (Some(username), Some(path)) => Some(Credentials {
                username: username.clone(),
                password: std::fs::read_to_string(path)
                    .with_context(|| format!("read {}", path.display()))?
                    .trim_end()
                    .to_string(),
            }),
            _ => None,
        };
        Ok(RegistryStore::new(
            reference,
            self.insecure_http,
            credentials,
            push,
        )?)
    }
}

impl Source {
    /// The store and the manifest reference within it.
    fn open(&self) -> Result<(Arc<dyn OciStore>, String)> {
        match (&self.layout, &self.from) {
            (Some(layout), None) => {
                Ok((Arc::new(LayoutStore::new(layout.clone())), self.tag.clone()))
            }
            (None, Some(from)) => {
                let reference: Reference = from.parse()?;
                Ok((
                    Arc::new(self.registry.store(&reference, false)?),
                    reference.manifest_reference(),
                ))
            }
            _ => bail!("exactly one of --layout and --from is required"),
        }
    }
}

#[derive(Debug, Subcommand)]
pub(crate) enum BundleCommands {
    /// Generate an ECDSA P-256 signing key pair, compatible with
    /// `cosign verify --key`
    Keygen {
        /// Private key output; the public key is written next to it with a
        /// `.pub` suffix
        #[arg(long)]
        output: PathBuf,
    },
    /// Pack a preload directory into a bundle in an OCI image layout
    Create {
        /// Directory with one subdirectory per namespace
        #[arg(long)]
        dir: PathBuf,
        /// OCI image layout directory to write (created if missing)
        #[arg(long)]
        layout: PathBuf,
        /// Tag of the bundle in the layout
        #[arg(long, default_value = "latest")]
        tag: String,
    },
    /// Sign a bundle in an OCI image layout
    Sign {
        #[arg(long)]
        layout: PathBuf,
        #[arg(long, default_value = "latest")]
        tag: String,
        /// PEM private key (ECDSA P-256/P-384/P-521, RSA or Ed25519)
        #[arg(long)]
        key: PathBuf,
        /// Repository the bundle will be published as, recorded in the
        /// signature, e.g. registry.example.com/trustee/cache
        #[arg(long)]
        identity: String,
    },
    /// Copy a bundle and its signature from an OCI image layout to a registry
    Push {
        #[arg(long)]
        layout: PathBuf,
        #[arg(long, default_value = "latest")]
        tag: String,
        /// Target reference, e.g. registry.example.com/trustee/cache:v1
        #[arg(long)]
        to: String,
        #[command(flatten)]
        registry: RegistryArgs,
    },
    /// Copy a bundle and its signature from a registry to an OCI image layout
    Pull {
        /// Source reference, e.g. registry.example.com/trustee/cache:v1
        #[arg(long)]
        from: String,
        #[arg(long)]
        layout: PathBuf,
        #[arg(long, default_value = "latest")]
        tag: String,
        #[command(flatten)]
        registry: RegistryArgs,
    },
    /// Check a bundle's signature against trusted public keys
    Verify {
        #[command(flatten)]
        source: Source,
        /// Trusted PEM public key; may be repeated
        #[arg(long = "public-key", required = true)]
        public_keys: Vec<PathBuf>,
    },
    /// List the namespaces and keys in a bundle
    Inspect {
        #[command(flatten)]
        source: Source,
    },
}

pub(crate) async fn run(command: CacheCommands) -> Result<()> {
    match command {
        CacheCommands::FetchVcek {
            report,
            processor,
            kds_url,
            dir,
        } => fetch_vcek(&report, processor.as_deref(), kds_url.as_deref(), &dir).await,
        CacheCommands::Bundle(command) => run_bundle(command).await,
    }
}

async fn fetch_vcek(
    report: &Path,
    processor: Option<&str>,
    kds_url: Option<&str>,
    dir: &Path,
) -> Result<()> {
    let report = std::fs::read(report).with_context(|| format!("read {}", report.display()))?;
    let location = verifier::snp::vcek_location(&report, processor, kds_url)?;
    info!("fetching VCEK from {}", location.url);

    // The URL carries the chip ID, so never send it over plain HTTP.
    let url = reqwest::Url::parse(&location.url).context("parse VCEK URL")?;
    if url.scheme() != "https" {
        bail!("the KDS URL must use https: {}", location.url);
    }
    let client = reqwest::Client::builder()
        .https_only(true)
        .build()
        .context("build HTTPS client")?;
    let response = client.get(url).send().await.context("request VCEK")?;
    if !response.status().is_success() {
        bail!(
            "fetching {} failed with {}",
            location.url,
            response.status()
        );
    }
    let vcek = response.bytes().await?;

    let path = dir
        .join(verifier::snp::VCEK_CACHE_NAMESPACE)
        .join(location.key.as_str());
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&path, &vcek)?;
    println!("{}", path.display());
    Ok(())
}

async fn read_entries(dir: &Path) -> Result<BundleEntries> {
    let mut entries = BundleEntries::new();
    for entry in std::fs::read_dir(dir).with_context(|| format!("read {}", dir.display()))? {
        let entry = entry?;
        if !entry.file_type()?.is_dir() {
            continue;
        }
        let Some(namespace) = entry.file_name().to_str().map(str::to_string) else {
            bail!("invalid namespace directory {}", entry.path().display());
        };
        validate_namespace(&namespace)?;
        let namespace_entries = read_tree(&entry.path(), MAX_ENTRY_BYTES).await?;
        if !namespace_entries.is_empty() {
            entries.insert(namespace, namespace_entries);
        }
    }
    if entries.is_empty() {
        bail!("no entries found under {}", dir.display());
    }
    Ok(entries)
}

async fn run_bundle(command: BundleCommands) -> Result<()> {
    match command {
        BundleCommands::Keygen { output } => {
            let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
            let key = PKey::from_ec_key(EcKey::generate(&group)?)?;
            let public = output.with_extension("pub");
            crate::write_pem(&output, &public, &key)?;
            println!(
                "private key: {}\npublic key: {}",
                output.display(),
                public.display()
            );
        }
        BundleCommands::Create { dir, layout, tag } => {
            let entries = read_entries(&dir).await?;
            let store = LayoutStore::init(layout).await?;
            let digest = bundle::write(&store, &entries, &tag).await?;
            println!("{digest}");
        }
        BundleCommands::Sign {
            layout,
            tag,
            key,
            identity,
        } => {
            let pem = std::fs::read(&key).with_context(|| format!("read {}", key.display()))?;
            let key = PKey::private_key_from_pem(&pem).context("parse private key")?;
            let store = LayoutStore::new(layout);
            let (_, digest) = store
                .manifest(&tag)
                .await?
                .with_context(|| format!("bundle {tag} not found"))?;
            bundle::sign(&store, &digest, &identity, &key).await?;
            println!("signed {digest}");
        }
        BundleCommands::Push {
            layout,
            tag,
            to,
            registry,
        } => {
            let reference: Reference = to.parse()?;
            let target = registry.store(&reference, true)?;
            let target_tag = reference.tag.clone().unwrap_or_else(|| "latest".into());
            let digest = bundle::copy(
                &LayoutStore::new(layout),
                &target,
                &tag,
                &target_tag,
                MAX_ENTRY_BYTES,
            )
            .await?;
            println!("{}@{digest}", reference.name());
        }
        BundleCommands::Pull {
            from,
            layout,
            tag,
            registry,
        } => {
            let reference: Reference = from.parse()?;
            let source = registry.store(&reference, false)?;
            let target = LayoutStore::init(layout).await?;
            let digest = bundle::copy(
                &source,
                &target,
                &reference.manifest_reference(),
                &tag,
                MAX_ENTRY_BYTES,
            )
            .await?;
            println!("{digest}");
        }
        BundleCommands::Verify {
            source,
            public_keys,
        } => {
            let (store, reference) = source.open()?;
            let (digest, _) =
                bundle::read_manifest(store.as_ref(), &reference, MAX_ENTRY_BYTES).await?;
            CosignKeyVerifier::from_pem_files(&public_keys)?
                .verify(store.as_ref(), &digest)
                .await?;
            println!("verified {digest}");
        }
        BundleCommands::Inspect { source } => {
            let (store, reference) = source.open()?;
            let (digest, entries) =
                bundle::read(store.as_ref(), &reference, MAX_ENTRY_BYTES).await?;
            let summary = serde_json::json!({
                "digest": digest.to_string(),
                "namespaces": bundle::summarize(&entries),
            });
            println!("{}", serde_json::to_string_pretty(&summary)?);
        }
    }
    Ok(())
}
