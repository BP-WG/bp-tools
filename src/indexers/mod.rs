// Modern, minimalistic & standard-compliant cold wallet library.
//
// SPDX-License-Identifier: Apache-2.0
//
// Written in 2020-2024 by
//     Dr Maxim Orlovsky <orlovsky@lnp-bp.org>
//
// Copyright (C) 2020-2024 LNP/BP Standards Association. All rights reserved.
// Copyright (C) 2020-2024 Dr Maxim Orlovsky. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#[cfg(feature = "electrum")]
pub mod electrum;
#[cfg(feature = "esplora")]
pub mod esplora;
#[cfg(feature = "mempool")]
pub mod mempool;
#[cfg(any(feature = "electrum", feature = "esplora", feature = "mempool"))]
mod any;

#[cfg(any(feature = "electrum", feature = "esplora", feature = "mempool"))]
pub use any::{AnyIndexer, AnyIndexerError};
use bpstd::Tx;
use descriptors::Descriptor;

use crate::{Layer2, MayError, WalletCache, WalletDescr};

#[cfg(any(feature = "electrum", feature = "esplora"))]
const BATCH_SIZE: usize = 10;

pub trait Indexer {
    type Error;

    fn create<K, D: Descriptor<K>, L2: Layer2>(
        &self,
        descr: &WalletDescr<K, D, L2::Descr>,
    ) -> MayError<WalletCache<L2::Cache>, Vec<Self::Error>>;

    fn update<K, D: Descriptor<K>, L2: Layer2>(
        &self,
        descr: &WalletDescr<K, D, L2::Descr>,
        cache: &mut WalletCache<L2::Cache>,
    ) -> MayError<usize, Vec<Self::Error>>;

    fn broadcast(&self, tx: &Tx) -> Result<(), Self::Error>;
}
