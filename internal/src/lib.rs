// Copyright (c) 2023 by Alibaba.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! Internal Dependencies

use semver::{BuildMetadata, Prerelease, Version, VersionReq};

/// Authentication
pub mod auth;
/// Config
pub mod config;

/// KBS URL prefix
pub static KBS_PREFIX: &str = "/kbs";
/// KBS major version
pub static KBS_MAJOR_VERSION: u64 = 0;
/// KBS minor version
pub static KBS_MINOR_VERSION: u64 = 1;
/// KBS patch version
pub static KBS_PATCH_VERSION: u64 = 0;

lazy_static::lazy_static! {
    #[allow(missing_docs)]
    pub static ref VERSION_REQ: VersionReq = {
        let kbs_version = Version {
            major: KBS_MAJOR_VERSION,
            minor: KBS_MINOR_VERSION,
            patch: KBS_PATCH_VERSION,
            pre: Prerelease::EMPTY,
            build: BuildMetadata::EMPTY,
        };

        VersionReq::parse(&format!("<={kbs_version}")).unwrap()
    };
}

#[allow(missing_docs)]
#[macro_export]
macro_rules! kbs_path {
    ($path:expr) => {
        format!("{}/v{}/{}", KBS_PREFIX, KBS_MAJOR_VERSION, $path)
    };
}
