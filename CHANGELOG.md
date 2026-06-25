# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added

- Added detailed AMD SEV-SNP parsed claims under `snp.evidence` and a `snp.generation` claim for the processor generation.

### Changed

- Preserved the existing flat AMD SEV-SNP parsed claim fields while adding detailed claims, keeping existing Attestation Service policies compatible.
- Updated the default AMD SEV-SNP policy to use the detailed `snp.evidence` claim paths.
