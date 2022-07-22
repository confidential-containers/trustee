// Copyright (c) 2022 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

//! Cache is responsible for storing verified Reference Values

use crate::reference_value::ReferenceValue;

use anyhow::Result;

/// Interface of a `Cache`.
/// We only provide a simple instance here which implements
/// Cache. In more scenarios, RV should be stored in persistent
/// storage, like database, file and so on. All of the mentioned
/// forms will have the same interface as following.
pub trait Cache {
    /// Store a reference value
    fn set(&mut self, name: String, rv: ReferenceValue) -> Result<Option<ReferenceValue>>;

    // Retrieve a reference value
    fn get(&self, name: &str) -> Result<Option<ReferenceValue>>;
}
