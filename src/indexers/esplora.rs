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

use std::collections::BTreeMap;
use std::num::NonZeroU32;
use std::ops::{Deref, DerefMut};

use bpstd::{Address, DerivedAddr, LockTime, Outpoint, SeqNo, Tx, TxVer, Witness};
use descriptors::Descriptor;
use esplora::BlockingClient;
pub use esplora::{Builder, Config, Error};

use super::BATCH_SIZE;
use crate::{
    Indexer, Layer2, MayError, MiningInfo, Party, TxCredit, TxDebit, TxStatus, WalletAddr,
    WalletCache, WalletDescr, WalletTx,
};

/// Represents a client for interacting with the Esplora indexer.
#[derive(Debug, Clone)]
pub struct Client {
    pub(crate) inner: BlockingClient,
    pub(crate) kind: ClientKind,
}

impl Deref for Client {
    type Target = BlockingClient;

    fn deref(&self) -> &Self::Target { &self.inner }
}

impl DerefMut for Client {
    fn deref_mut(&mut self) -> &mut Self::Target { &mut self.inner }
}

/// Represents the kind of client used for interacting with the Esplora indexer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub enum ClientKind {
    #[default]
    Esplora,
    #[cfg(feature = "mempool")]
    Mempool,
}

impl Client {
    /// Creates a new Esplora client with the specified URL.
    ///
    /// # Arguments
    ///
    /// * `url` - The URL of the Esplora server.
    ///
    /// # Errors
    ///
    /// Returns an error if the client fails to connect to the Esplora server.
    #[allow(clippy::result_large_err)]
    pub fn new_esplora(url: &str) -> Result<Self, Error> {
        let inner = esplora::Builder::new(url).build_blocking()?;
        let client = Self {
            inner,
            kind: ClientKind::Esplora,
        };
        Ok(client)
    }
}

impl From<esplora::TxStatus> for TxStatus {
    fn from(status: esplora::TxStatus) -> Self {
        if let esplora::TxStatus {
            confirmed: true,
            block_height: Some(height),
            block_hash: Some(hash),
            block_time: Some(ts),
        } = status
        {
            TxStatus::Mined(MiningInfo {
                height: NonZeroU32::try_from(height).unwrap_or(NonZeroU32::MIN),
                time: ts,
                block_hash: hash,
            })
        } else {
            TxStatus::Mempool
        }
    }
}

impl From<esplora::PrevOut> for Party {
    fn from(prevout: esplora::PrevOut) -> Self { Party::Unknown(prevout.scriptpubkey) }
}

impl From<esplora::Vin> for TxCredit {
    fn from(vin: esplora::Vin) -> Self {
        TxCredit {
            outpoint: Outpoint::new(vin.txid, vin.vout),
            sequence: SeqNo::from_consensus_u32(vin.sequence),
            coinbase: vin.is_coinbase,
            script_sig: vin.scriptsig,
            witness: Witness::from_consensus_stack(vin.witness),
            value: vin.prevout.as_ref().map(|prevout| prevout.value).unwrap_or_default().into(),
            payer: vin.prevout.map(Party::from).unwrap_or(Party::Subsidy),
        }
    }
}

impl From<esplora::Tx> for WalletTx {
    fn from(tx: esplora::Tx) -> Self {
        WalletTx {
            txid: tx.txid,
            status: tx.status.into(),
            inputs: tx.vin.into_iter().map(TxCredit::from).collect(),
            outputs: tx
                .vout
                .into_iter()
                .enumerate()
                .map(|(n, vout)| TxDebit {
                    outpoint: Outpoint::new(tx.txid, n as u32),
                    beneficiary: Party::from(vout.scriptpubkey),
                    value: vout.value.into(),
                    spent: None,
                })
                .collect(),
            fee: tx.fee.into(),
            size: tx.size,
            weight: tx.weight,
            version: TxVer::from_consensus_i32(tx.version),
            locktime: LockTime::from_consensus_u32(tx.locktime),
        }
    }
}

/// Retrieves all transactions associated with a given script hash.
///
/// # Arguments
///
/// * `client` - The Esplora client.
/// * `derive` - The derived address.
///
/// # Errors
///
/// Returns an error if there was a problem retrieving the transactions.
#[allow(clippy::result_large_err)]
fn get_scripthash_txs_all(
    client: &Client,
    derive: &DerivedAddr,
) -> Result<Vec<esplora::Tx>, Error> {
    const PAGE_SIZE: usize = 25;
    let mut res = Vec::new();
    let mut last_seen = None;
    let script = derive.addr.script_pubkey();

    loop {
        let r = match client.kind {
            ClientKind::Esplora => client.inner.scripthash_txs(&script, last_seen)?,
            #[cfg(feature = "mempool")]
            ClientKind::Mempool => client.inner.address_txs(&derive.addr, last_seen)?,
        };
        match &r[..] {
            [a @ .., esplora::Tx { txid, .. }] if a.len() >= PAGE_SIZE - 1 => {
                last_seen = Some(*txid);
                res.extend(r);
            }
            _ => {
                res.extend(r);
                break;
            }
        }
    }
    Ok(res)
}

impl Indexer for Client {
    type Error = Error;

    fn create<K, D: Descriptor<K>, L2: Layer2>(
        &self,
        descriptor: &WalletDescr<K, D, L2::Descr>,
    ) -> MayError<WalletCache<L2::Cache>, Vec<Self::Error>> {
        let mut cache = WalletCache::new_nonsync();
        self.update::<K, D, L2>(descriptor, &mut cache).map(|_| cache)
    }

    fn update<K, D: Descriptor<K>, L2: Layer2>(
        &self,
        descriptor: &WalletDescr<K, D, L2::Descr>,
        cache: &mut WalletCache<L2::Cache>,
    ) -> MayError<usize, Vec<Self::Error>> {
        let mut errors = vec![];

        #[cfg(feature = "log")]
        log::debug!("Updating wallet from Esplora indexer");

        let mut address_index = BTreeMap::new();
        for keychain in descriptor.keychains() {
            let mut empty_count = 0usize;
            for derive in descriptor.addresses(keychain) {
                #[cfg(feature = "log")]
                log::trace!("Retrieving transaction for {derive}");

                let script = derive.addr.script_pubkey();

                let mut txids = Vec::new();
                match get_scripthash_txs_all(self, &derive) {
                    Err(err) => {
                        errors.push(err);
                        break;
                    }
                    Ok(txes) if txes.is_empty() => {
                        empty_count += 1;
                        if empty_count >= BATCH_SIZE {
                            break;
                        }
                    }
                    Ok(txes) => {
                        empty_count = 0;
                        txids = txes.iter().map(|tx| tx.txid).collect();
                        cache
                            .tx
                            .extend(txes.into_iter().map(WalletTx::from).map(|tx| (tx.txid, tx)));
                    }
                }

                let wallet_addr = WalletAddr::<i64>::from(derive);
                address_index.insert(script, (wallet_addr, txids));
            }
        }

        // TODO: Update headers & tip

        for (script, (wallet_addr, txids)) in &mut address_index {
            for txid in txids {
                let mut tx = cache.tx.remove(txid).expect("broken logic");
                for debit in &mut tx.outputs {
                    let Some(s) = debit.beneficiary.script_pubkey() else {
                        continue;
                    };
                    if &s == script {
                        cache.utxo.insert(debit.outpoint);
                        debit.beneficiary = Party::from_wallet_addr(wallet_addr);
                        wallet_addr.used = wallet_addr.used.saturating_add(1);
                        wallet_addr.volume.saturating_add_assign(debit.value);
                        wallet_addr.balance = wallet_addr
                            .balance
                            .saturating_add(debit.value.sats().try_into().expect("sats overflow"));
                    } else if debit.beneficiary.is_unknown() {
                        Address::with(&s, descriptor.network())
                            .map(|addr| {
                                debit.beneficiary = Party::Counterparty(addr);
                            })
                            .ok();
                    }
                }
                cache.tx.insert(tx.txid, tx);
            }
        }

        for (script, (wallet_addr, txids)) in &mut address_index {
            for txid in txids {
                let mut tx = cache.tx.remove(txid).expect("broken logic");
                for credit in &mut tx.inputs {
                    let Some(s) = credit.payer.script_pubkey() else {
                        continue;
                    };
                    if &s == script {
                        credit.payer = Party::from_wallet_addr(wallet_addr);
                        wallet_addr.balance = wallet_addr
                            .balance
                            .saturating_sub(credit.value.sats().try_into().expect("sats overflow"));
                    } else if credit.payer.is_unknown() {
                        Address::with(&s, descriptor.network())
                            .map(|addr| {
                                credit.payer = Party::Counterparty(addr);
                            })
                            .ok();
                    }
                    if let Some(prev_tx) = cache.tx.get_mut(&credit.outpoint.txid) {
                        if let Some(txout) =
                            prev_tx.outputs.get_mut(credit.outpoint.vout_u32() as usize)
                        {
                            let outpoint = txout.outpoint;
                            if tx.status.is_mined() {
                                cache.utxo.remove(&outpoint);
                            }
                            txout.spent = Some(credit.outpoint.into())
                        };
                    }
                }
                cache.tx.insert(tx.txid, tx);
            }
            cache
                .addr
                .entry(wallet_addr.terminal.keychain)
                .or_default()
                .insert(wallet_addr.expect_transmute());
        }

        if errors.is_empty() {
            #[cfg(feature = "log")]
            log::debug!("Wallet update from the indexer successfully complete with no errors");
            MayError::ok(0)
        } else {
            #[cfg(feature = "log")]
            {
                log::error!(
                    "The following errors has happened during wallet update from the indexer"
                );
                for err in &errors {
                    log::error!("- {err}");
                }
            }
            MayError::err(0, errors)
        }
    }

    fn broadcast(&self, tx: &Tx) -> Result<(), Self::Error> { self.inner.broadcast(tx) }
}
