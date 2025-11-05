# Cache Preloader

This tool preloads URL responses into an HTTP cache directory. The initial 
use-case for this tool is for [offline fetching of VCEKs](../../attestation-service/docs/amd-offline-certificate-cache.md),
but can be used to pre-fetch any module that is using `http-cache-reqwuest`.

## Features

- Preloads URLs from a file into a local cache directory
- Option to create a tar.gz archive of the cache for distribution

## Usage

### Basic Usage

```bash
cargo run -- --urls-file urls.txt --cache-dir ./cache
```

### With Archive Creation

```bash
cargo run -- --urls-file urls.txt --cache-dir ./cache --archive cache.tar.gz
```

## Command Line Options

- `-u, --urls-file <FILE>` - File containing URLs to preload (one per line)
- `-c, --cache-dir <DIR>` - Cache directory where files will be stored (default: `./cache`)
- `-a, --archive <FILE>` - Create a tar.gz archive of the cache directory after preloading

## URL File Format

Create a text file with one URL per line:

```
# VCEK URLs for Milan processors
https://kdsintf.amd.com/vcek/v1/Milan/abc123?blSPL=03&teeSPL=00&snpSPL=08&ucodeSPL=115
https://kdsintf.amd.com/vcek/v1/Milan/def456?blSPL=03&teeSPL=00&snpSPL=08&ucodeSPL=115

# VCEK URLs for Genoa processors
https://kdsintf.amd.com/vcek/v1/Genoa/789abc?blSPL=02&teeSPL=00&snpSPL=03&ucodeSPL=209
```

If using this tool for VCEK preloading, see these instructions on how to obtain
VCEK URLs: [Create URL Target File](../../attestation-service/docs/amd-offline-certificate-cache.md#1-create-url-target-file)
