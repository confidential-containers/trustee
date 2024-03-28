// Copyright (C) Copyright IBM Corp. 2024
//
// SPDX-License-Identifier: Apache-2.0
//

use anyhow::*;
use async_trait;

#[derive(Default)]
pub struct FakeSeAttest {}

#[async_trait::async_trait]
pub trait SeFakeVerifier {
    async fn create<'a, 'b, 'c>(
        &self,
        _hkd_files: Vec<String>,
        _cert_file: &'a str,
        _signing_file: &'b str,
        _arpk_file: &'c str,
    ) -> Result<Vec<u8>>;

    async fn verify<'a, 'b>(
        &self,
        _evidence: &[u8],
        _arpk_file: &'a str,
        _hdr_file: &'b str,
    ) -> Result<Vec<u8>>;
}

#[async_trait::async_trait]
impl SeFakeVerifier for FakeSeAttest {
    async fn create<'a, 'b, 'c>(
        &self,
        _hkd_files: Vec<String>,
        _cert_file: &'a str,
        _signing_file: &'b str,
        _arpk_file: &'c str,
    ) -> Result<Vec<u8>> {
        Result::Ok("test".as_bytes().to_vec())
    }

    async fn verify<'a, 'b>(
        &self,
        _evidence: &[u8],
        _arpk_file: &'a str,
        _hkd_files: &'b str,
    ) -> Result<Vec<u8>> {
        Result::Ok("test".as_bytes().to_vec())
    }
}