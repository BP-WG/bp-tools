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

use bpstd::{
    Address, DerivedAddr, LockTime, Outpoint, ScriptPubkey, SeqNo, Tx, TxVer, Txid, Witness,
};
use descriptors::Descriptor;
use esplora::{BlockingClient, Error};

use super::cache::IndexerCache;
#[cfg(feature = "mempool")]
use super::mempool::Mempool;
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
    pub(crate) cache: IndexerCache,
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

#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(crate = "serde_crate")
)]
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct FullAddrStats {
    pub address: String,
    pub chain_stats: AddrTxStats,
    pub mempool_stats: AddrTxStats,
}

#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(crate = "serde_crate")
)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct AddrTxStats {
    pub tx_count: u64,
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
    pub fn new_esplora(url: &str, cache: IndexerCache) -> Result<Self, Error> {
        let inner = esplora::Builder::new(url).build_blocking()?;
        let client = Self {
            inner,
            kind: ClientKind::Esplora,
            cache,
        };
        Ok(client)
    }

    /// Retrieves all transactions associated with a given script hash.
    ///
    /// # Arguments
    ///
    /// * `client` - The Esplora client.
    /// * `derive` - The derived address.
    /// * `force_update` - A flag indicating whether to force an update of the transactions.
    ///
    /// # Errors
    ///
    /// Returns an error if there was a problem retrieving the transactions.
    #[allow(clippy::result_large_err)]
    fn get_scripthash_txs_all(
        &self,
        derive: &DerivedAddr,
        force_update: bool,
    ) -> Result<Vec<esplora::Tx>, Error> {
        // Check the cache first
        if !force_update {
            let mut addr_transactions_cache =
                self.cache.addr_transactions.lock().expect("poisoned lock");
            if let Some(cached_txs) = addr_transactions_cache.get(derive) {
                return Ok(cached_txs.clone());
            }
        }

        const PAGE_SIZE: usize = 25;
        let mut res = Vec::new();
        let mut last_seen = None;
        let script = derive.addr.script_pubkey();
        #[cfg(feature = "mempool")]
        let address = derive.addr.to_string();

        loop {
            let r = match self.kind {
                ClientKind::Esplora => self.inner.scripthash_txs(&script, last_seen)?,
                #[cfg(feature = "mempool")]
                ClientKind::Mempool => self.inner.address_txs(&address, last_seen)?,
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

        // Cache the results
        {
            let mut addr_transactions_cache =
                self.cache.addr_transactions.lock().expect("poisoned lock");
            addr_transactions_cache.put(derive.clone(), res.clone());
        }

        Ok(res)
    }

    fn get_addr_tx_stats_by_cache(&self, derive: &DerivedAddr) -> FullAddrStats {
        let mut addr_transactions_cache =
            self.cache.addr_transactions.lock().expect("poisoned lock");
        let address = derive.addr.to_string();

        if let Some(cached_txs) = addr_transactions_cache.get(derive) {
            let chain_stats_tx_count = cached_txs.iter().filter(|tx| tx.status.confirmed).count();
            let mempool_stats_tx_count =
                cached_txs.iter().filter(|tx| !tx.status.confirmed).count();
            return FullAddrStats {
                address,
                chain_stats: AddrTxStats {
                    tx_count: chain_stats_tx_count as u64,
                },
                mempool_stats: AddrTxStats {
                    tx_count: mempool_stats_tx_count as u64,
                },
            };
        }
        FullAddrStats::default()
    }

    fn get_addr_tx_stats_by_client(&self, derive: &DerivedAddr) -> Result<FullAddrStats, Error> {
        let address = derive.addr.to_string();
        let agent = self.agent();
        let url = self.url();

        let url = format!("{}/address/{}", url, address);

        let resp: FullAddrStats = agent.get(&url).call()?.into_json()?;
        Ok(resp)
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

impl Client {
    fn process_wallet_descriptor<K, D: Descriptor<K>, L2: Layer2>(
        &self,
        descriptor: &WalletDescr<K, D, L2::Descr>,
        cache: &mut WalletCache<L2::Cache>,
        errors: &mut Vec<Error>,
        update_mode: bool,
    ) -> BTreeMap<bpstd::ScriptPubkey, (WalletAddr<i64>, Vec<Txid>)> {
        let mut address_index = BTreeMap::new();

        for keychain in descriptor.keychains() {
            let mut empty_count = 0usize;
            eprint!(" keychain {keychain} ");
            for derive in descriptor.addresses(keychain) {
                eprint!(".");
                let empty = self.process_address::<K, D, L2>(
                    derive,
                    cache,
                    &mut address_index,
                    errors,
                    update_mode,
                );
                if empty {
                    empty_count += 1;
                    if empty_count >= BATCH_SIZE {
                        break;
                    }
                } else {
                    empty_count = 0;
                }
            }
        }

        address_index
    }

    fn process_address<K, D: Descriptor<K>, L2: Layer2>(
        &self,
        derive: DerivedAddr,
        cache: &mut WalletCache<L2::Cache>,
        address_index: &mut BTreeMap<ScriptPubkey, (WalletAddr<i64>, Vec<Txid>)>,
        errors: &mut Vec<Error>,
        update_mode: bool,
    ) -> bool {
        let script = derive.addr.script_pubkey();
        let mut txids = Vec::new();
        let mut empty = false;

        if update_mode {
            let tx_stats_by_cache = self.get_addr_tx_stats_by_cache(&derive);
            let tx_stats_by_client = self
                .get_addr_tx_stats_by_client(&derive)
                .map_err(|err| errors.push(err))
                .unwrap_or_default();
            if tx_stats_by_client.address.is_empty() || tx_stats_by_cache == tx_stats_by_client {
                let wallet_addr_key = WalletAddr::from(derive);
                let keychain = wallet_addr_key.terminal.keychain;

                if let Some(keychain_addr_set) = cache.addr.get(&keychain) {
                    // If `wallet_addr` has been cached before, it must be set in `address_index`
                    // to ensure the subsequent state updates correctly.
                    // Also, return (empty = false);
                    // This ensures that every cached `wallet_addr` is checked for updates.
                    if let Some(cached_wallet_addr) = keychain_addr_set.get(&wallet_addr_key) {
                        address_index
                            .insert(script, ((*cached_wallet_addr).expect_transmute(), txids));
                        return false;
                    }
                }
                return true;
            }
        }

        match self.get_scripthash_txs_all(&derive, update_mode) {
            Err(err) => {
                errors.push(err);
                empty = true;
            }
            Ok(txes) if txes.is_empty() => {
                empty = true;
            }
            Ok(txes) => {
                txids = txes.iter().map(|tx| tx.txid).collect();
                cache.tx.extend(txes.into_iter().map(WalletTx::from).map(|tx| (tx.txid, tx)));
            }
        }

        let wallet_addr = WalletAddr::<i64>::from(derive);
        address_index.insert(script, (wallet_addr, txids));

        empty
    }

    fn process_transactions<K, D: Descriptor<K>, L2: Layer2>(
        &self,
        descriptor: &WalletDescr<K, D, L2::Descr>,
        cache: &mut WalletCache<L2::Cache>,
        address_index: &mut BTreeMap<ScriptPubkey, (WalletAddr<i64>, Vec<Txid>)>,
    ) {
        // Keep the completed WalletAddr<i64> set
        // Ensure that the subsequent status is handled correctly
        let wallet_self_script_map: BTreeMap<ScriptPubkey, WalletAddr<i64>> =
            address_index.iter().map(|(s, (addr, _))| (s.clone(), addr.clone())).collect();
        // Remove items with empty `txids`
        address_index.retain(|_, (_, txids)| !txids.is_empty());

        for (script, (wallet_addr, txids)) in address_index.iter_mut() {
            // UTXOs and inputs must be processed separately due to the unordered nature and
            // dependencies of transaction IDs. Handling them in a single loop can cause
            // data inconsistencies. For example, if spending transactions are processed
            // first, new change UTXOs are added and spent UTXOs are removed. However,
            // in the subsequent loop, these already spent UTXOs are treated as new
            // transactions and reinserted into the UTXO set.
            for txid in txids.iter() {
                let mut tx = cache.tx.remove(txid).expect("broken logic");
                self.process_outputs::<_, _, L2>(
                    descriptor,
                    script,
                    wallet_addr,
                    &mut tx,
                    cache,
                    &wallet_self_script_map,
                );
                cache.tx.insert(tx.txid, tx);
            }

            for txid in txids.iter() {
                let mut tx = cache.tx.remove(txid).expect("broken logic");
                self.process_inputs::<_, _, L2>(
                    descriptor,
                    script,
                    wallet_addr,
                    &mut tx,
                    cache,
                    &wallet_self_script_map,
                );
                cache.tx.insert(tx.txid, tx);
            }
            cache
                .addr
                .entry(wallet_addr.terminal.keychain)
                .or_default()
                .insert(wallet_addr.expect_transmute());
        }
    }

    fn process_outputs<K, D: Descriptor<K>, L2: Layer2>(
        &self,
        descriptor: &WalletDescr<K, D, L2::Descr>,
        script: &ScriptPubkey,
        wallet_addr: &mut WalletAddr<i64>,
        tx: &mut WalletTx,
        cache: &mut WalletCache<L2::Cache>,
        wallet_self_script_map: &BTreeMap<ScriptPubkey, WalletAddr<i64>>,
    ) {
        for debit in &mut tx.outputs {
            let Some(s) = debit.beneficiary.script_pubkey() else {
                continue;
            };

            // Needs to be handled here. When iterating over keychain 0,
            // it is possible that a UTXO corresponds to the change `script-public-key` `s` and is
            // associated with keychain 1. However, the `script` corresponds to keychain 0.
            // This discrepancy can cause issues because the outer loop uses `address_index:
            // BTreeMap<ScriptPubkey, (WalletAddr<i64>, Vec<Txid>)>`, which is unordered
            // by keychain.
            //
            // If transactions related to keychain-1-ScriptPubkey are processed first, the change
            // UTXOs are correctly handled. However, when subsequently processing
            // transactions for keychain-0-ScriptPubkey, the previously set data for keychain-1
            // can be incorrectly modified (to `Counterparty`). This specific condition needs to be
            // handled.
            //
            // It should be handled using `wallet_self_script_map` to correctly process the
            // beneficiary of the transaction output.
            if &s == script {
                cache.utxo.insert(debit.outpoint);
                debit.beneficiary = Party::from_wallet_addr(wallet_addr);
                wallet_addr.used = wallet_addr.used.saturating_add(1);
                wallet_addr.volume.saturating_add_assign(debit.value);
                wallet_addr.balance = wallet_addr
                    .balance
                    .saturating_add(debit.value.sats().try_into().expect("sats overflow"));
            } else if debit.beneficiary.is_unknown() {
                if let Some(real_addr) = wallet_self_script_map.get(&s) {
                    debit.beneficiary = Party::from_wallet_addr(real_addr);
                    continue;
                }

                Address::with(&s, descriptor.network())
                    .map(|addr| {
                        debit.beneficiary = Party::Counterparty(addr);
                    })
                    .ok();
            }
        }
    }

    fn process_inputs<K, D: Descriptor<K>, L2: Layer2>(
        &self,
        descriptor: &WalletDescr<K, D, L2::Descr>,
        script: &ScriptPubkey,
        wallet_addr: &mut WalletAddr<i64>,
        tx: &mut WalletTx,
        cache: &mut WalletCache<L2::Cache>,
        wallet_self_script_map: &BTreeMap<ScriptPubkey, WalletAddr<i64>>,
    ) {
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
                if let Some(real_addr) = wallet_self_script_map.get(&s) {
                    credit.payer = Party::from_wallet_addr(real_addr);
                    continue;
                }

                Address::with(&s, descriptor.network())
                    .map(|addr| {
                        credit.payer = Party::Counterparty(addr);
                    })
                    .ok();
            }
            if let Some(prev_tx) = cache.tx.get_mut(&credit.outpoint.txid) {
                if let Some(txout) = prev_tx.outputs.get_mut(credit.outpoint.vout_u32() as usize) {
                    let outpoint = txout.outpoint;
                    if tx.status.is_mined() {
                        cache.utxo.remove(&outpoint);
                    }
                    txout.spent = Some(credit.outpoint.into())
                };
            }
        }
    }
}

impl Indexer for Client {
    type Error = Error;

    fn create<K, D: Descriptor<K>, L2: Layer2>(
        &self,
        descriptor: &WalletDescr<K, D, L2::Descr>,
    ) -> MayError<WalletCache<L2::Cache>, Vec<Self::Error>> {
        let mut cache = WalletCache::new();
        let mut errors = vec![];

        let mut address_index =
            self.process_wallet_descriptor::<K, D, L2>(descriptor, &mut cache, &mut errors, false);

        self.process_transactions::<K, D, L2>(descriptor, &mut cache, &mut address_index);

        if errors.is_empty() { MayError::ok(cache) } else { MayError::err(cache, errors) }
    }

    fn update<K, D: Descriptor<K>, L2: Layer2>(
        &self,
        descriptor: &WalletDescr<K, D, L2::Descr>,
        cache: &mut WalletCache<L2::Cache>,
    ) -> MayError<usize, Vec<Self::Error>> {
        let mut errors = vec![];

        let mut address_index =
            self.process_wallet_descriptor::<K, D, L2>(descriptor, cache, &mut errors, true);
        self.process_transactions::<K, D, L2>(descriptor, cache, &mut address_index);

        if errors.is_empty() {
            MayError::ok(address_index.len())
        } else {
            MayError::err(address_index.len(), errors)
        }
    }

    fn publish(&self, tx: &Tx) -> Result<(), Self::Error> { self.inner.broadcast(tx) }
}
