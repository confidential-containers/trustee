// Copyright (c) 2022 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

//! Pre-Processor of RVPS

use std::collections::HashMap;

use crate::Message;

use anyhow::*;

/// A Ware loaded in Pre-Processor will process all the messages passing
/// through the Pre-Processor. A series of Wares organized in order can
/// process all the messages in need before they are consumed by the
/// Extractors.
pub trait Ware {
    fn handle(
        &self,
        message: &mut Message,
        context: &mut HashMap<String, String>,
        next: Next<'_>,
    ) -> Result<()>;
}

/// Next encapsulates the remaining ware chain to run in [`Ware::handle`]. You can
/// forward the task down the chain with [`run`].
///
/// [`Ware::handle`]: Ware::handle
/// [`run`]: Self::run
#[derive(Clone)]
pub struct Next<'a> {
    wares: &'a [Box<dyn Ware>],
}

impl<'a> Next<'a> {
    pub(crate) fn new(wares: &'a [Box<dyn Ware>]) -> Self {
        Next { wares }
    }

    pub fn run(
        mut self,
        message: &mut Message,
        context: &'a mut HashMap<String, String>,
    ) -> Result<()> {
        if let Some((current, rest)) = self.wares.split_first() {
            self.wares = rest;
            current.handle(message, context, self)
        } else {
            Ok(())
        }
    }
}

/// PreProcessor's interfaces
/// `process` processes the given [`Message`], which contains
/// the provenance information and its type. The process
/// can modify the given [`Message`].
pub trait PreProcessorAPI {
    fn process(&self, message: &mut Message) -> Result<()>;
    fn add_ware(&mut self, ware: Box<dyn Ware>) -> &Self;
}

#[derive(Default)]
pub struct PreProcessor {
    wares: Vec<Box<dyn Ware>>,
}

impl PreProcessorAPI for PreProcessor {
    fn process(&self, message: &mut Message) -> Result<()> {
        let mut context = HashMap::new();
        let next = Next::new(&self.wares);
        next.run(message, &mut context)
    }

    fn add_ware(&mut self, ware: Box<dyn Ware>) -> &Self {
        self.wares.push(ware);
        self
    }
}
