// Modern, minimalistic & standard-compliant cold wallet library.
//
// SPDX-License-Identifier: Apache-2.0
//
// Written in 2024 by
//     Nicola Busanello <nicola.busanello@gmail.com>
//
// Copyright (C) 2024 LNP/BP Standards Association. All rights reserved.
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

use bpstd::Tx;
use descriptors::Descriptor;

use crate::{Indexer, Layer2, MayError, WalletCache, WalletDescr};

/// Type that contains any of the client types implementing the Indexer trait
#[derive(From)]
#[non_exhaustive]
pub enum AnyIndexer {
    #[cfg(feature = "electrum")]
    #[from]
    /// Electrum indexer
    Electrum(Box<electrum::client::Client>),
    #[cfg(feature = "esplora")]
    #[from]
    /// Esplora indexer
    Esplora(Box<super::esplora::Client>),
    #[cfg(feature = "mempool")]
    /// Mempool indexer
    Mempool(Box<super::esplora::Client>),
}

impl AnyIndexer {
    pub fn name(&self) -> &'static str {
        match self {
            #[cfg(feature = "electrum")]
            AnyIndexer::Electrum(_) => "electrum",
            #[cfg(feature = "esplora")]
            AnyIndexer::Esplora(_) => "esplora",
            #[cfg(feature = "mempool")]
            AnyIndexer::Mempool(_) => "mempool",
        }
    }
}

#[allow(clippy::large_enum_variant)]
#[derive(Debug, Display, Error, From)]
#[display(doc_comments)]
pub enum AnyIndexerError {
    #[cfg(feature = "electrum")]
    #[display(inner)]
    #[from]
    #[from(electrum::Error)]
    Electrum(super::electrum::ElectrumError),
    #[cfg(feature = "esplora")]
    #[display(inner)]
    #[from]
    Esplora(esplora::Error),
}

impl Indexer for AnyIndexer {
    type Error = AnyIndexerError;

    fn update<K, D: Descriptor<K>, L2: Layer2>(
        &self,
        descr: &WalletDescr<K, D, L2::Descr>,
        cache: &mut WalletCache<L2::Cache>,
        prune: bool,
    ) -> MayError<usize, Vec<Self::Error>> {
        match self {
            #[cfg(feature = "electrum")]
            AnyIndexer::Electrum(inner) => {
                let result = inner.update::<K, D, L2>(descr, cache, prune);
                MayError {
                    ok: result.ok,
                    err: result.err.map(|v| v.into_iter().map(|e| e.into()).collect()),
                }
            }
            #[cfg(feature = "esplora")]
            AnyIndexer::Esplora(inner) => {
                let result = inner.update::<K, D, L2>(descr, cache, prune);
                MayError {
                    ok: result.ok,
                    err: result.err.map(|v| v.into_iter().map(|e| e.into()).collect()),
                }
            }
            #[cfg(feature = "mempool")]
            AnyIndexer::Mempool(inner) => {
                let result = inner.update::<K, D, L2>(descr, cache, prune);
                MayError {
                    ok: result.ok,
                    err: result.err.map(|v| v.into_iter().map(|e| e.into()).collect()),
                }
            }
        }
    }

    fn broadcast(&self, tx: &Tx) -> Result<(), Self::Error> {
        match self {
            #[cfg(feature = "electrum")]
            AnyIndexer::Electrum(inner) => inner.broadcast(tx).map_err(|e| e.into()),
            #[cfg(feature = "esplora")]
            AnyIndexer::Esplora(inner) => inner.broadcast(tx).map_err(|e| e.into()),
            #[cfg(feature = "mempool")]
            AnyIndexer::Mempool(inner) => inner.broadcast(tx).map_err(|e| e.into()),
        }
    }
}
