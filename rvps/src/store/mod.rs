// Copyright (c) 2022 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

//! Store is responsible for storing verified Reference Values

use crate::reference_value::ReferenceValue;

use anyhow::Result;

pub mod local_fs;

/// Interface of a `Store`.
/// We only provide a simple instance here which implements
/// Store. In more scenarios, RV should be stored in persistent
/// storage, like database, file and so on. All of the mentioned
/// forms will have the same interface as following.
pub trait Store {
    /// Store a reference value. If the given `name` exists,
    /// return the previous `Some<ReferenceValue>`, otherwise return `None`
    fn set(&mut self, name: String, rv: ReferenceValue) -> Result<Option<ReferenceValue>>;

    // Retrieve a reference value
    fn get(&self, name: &str) -> Result<Option<ReferenceValue>>;
}
