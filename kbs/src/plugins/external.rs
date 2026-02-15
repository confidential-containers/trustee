// Copyright (c) 2026 by Trustee Contributors
//
// SPDX-License-Identifier: Apache-2.0
//

//! Generated gRPC types for the external plugin protocol (`kbs.plugin.v1`).
//!
//! This module re-exports the protobuf-generated client and server types
//! used to communicate with external KBS plugins over gRPC.

pub mod plugin_api {
    tonic::include_proto!("kbs.plugin.v1");
}
