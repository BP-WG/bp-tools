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

use std::collections::BTreeMap;
use std::num::NonZeroU32;
use std::str::FromStr;

use bpstd::{Address, BlockHash, ConsensusEncode, Outpoint, Sats, Tx, TxIn, Txid, Weight};
use descriptors::Descriptor;
use electrum::{Client, ElectrumApi, GetHistoryRes, Param};
pub use electrum::{Config, ConfigBuilder, Error, Socks5Config};
use serde_json::Value;

use super::BATCH_SIZE;
use crate::{
    Indexer, Layer2, MayError, MiningInfo, Party, TxCredit, TxDebit, TxStatus, WalletAddr,
    WalletCache, WalletDescr, WalletTx,
};

#[derive(Clone, Eq, PartialEq, Hash, Debug, Display, Error)]
#[display(doc_comments)]
pub enum ElectrumApiError {
    /// Electrum indexer returned invalid hex value for the transaction {0}.
    InvalidTx(Txid),
    /// Electrum indexer returned invalid block hash hex value for the transaction {0}.
    InvalidBlockHash(Txid),
    /// Electrum indexer returned invalid block time value for the transaction {0}.
    InvalidBlockTime(Txid),
    /// electrum indexer returned zero block height for the transaction {0}.
    InvalidBlockHeight(Txid),
    /// electrum indexer returned invalid previous transaction, which doesn't have an output spent
    /// by transaction {0} input {1:?}.
    PrevOutTxMismatch(Txid, TxIn),
}

#[derive(Debug, Display, Error, From)]
#[display(inner)]
pub enum ElectrumError {
    #[from]
    Api(ElectrumApiError),
    #[from]
    Client(Error),
}

impl Indexer for Client {
    type Error = ElectrumError;

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
        let mut errors = Vec::<ElectrumError>::new();

        #[cfg(feature = "log")]
        log::debug!("Updating wallet from Electrum indexer");

        // First, we scan all addresses.
        // Addresses may be re-used, so known transactions doesn't help here.
        // We collect these transactions, which contain the most recent information, into a new
        // cache. We remove old transaction, since its data are now updated (for instance, if a
        // transaction was re-orged, it may have a different height).

        let mut address_index = BTreeMap::new();
        for keychain in descriptor.keychains() {
            let mut empty_count = 0usize;
            for derive in descriptor.addresses(keychain) {
                #[cfg(feature = "log")]
                log::trace!("Retrieving transaction for {derive}");

                let script = derive.addr.script_pubkey();

                let mut txids = Vec::new();
                let Ok(hres) =
                    self.script_get_history(&script).map_err(|err| errors.push(err.into()))
                else {
                    break;
                };
                if hres.is_empty() {
                    empty_count += 1;
                    if empty_count >= BATCH_SIZE {
                        break;
                    }
                    continue;
                }

                empty_count = 0;

                let mut process_history_entry =
                    |hr: GetHistoryRes| -> Result<WalletTx, ElectrumError> {
                        let txid = hr.tx_hash;
                        txids.push(txid);

                        #[cfg(feature = "log")]
                        log::trace!("- {txid}");

                        // get the tx details (requires electrum verbose support)
                        let tx_details = self.raw_call("blockchain.transaction.get", vec![
                            Param::String(hr.tx_hash.to_string()),
                            Param::Bool(true),
                        ])?;

                        let tx = tx_details
                            .get("hex")
                            .and_then(Value::as_str)
                            .and_then(|s| Tx::from_str(s).ok())
                            .ok_or(ElectrumApiError::InvalidTx(txid))?;

                        // build TxStatus
                        let status = if hr.height < 1 {
                            TxStatus::Mempool
                        } else {
                            let block_hash = tx_details
                                .get("blockhash")
                                .and_then(Value::as_str)
                                .and_then(|s| BlockHash::from_str(s).ok())
                                .ok_or(ElectrumApiError::InvalidBlockHash(txid))?;
                            let blocktime = tx_details
                                .get("blocktime")
                                .and_then(Value::as_u64)
                                .ok_or(ElectrumApiError::InvalidBlockTime(txid))?;
                            let height = NonZeroU32::try_from(hr.height as u32)
                                .map_err(|_| ElectrumApiError::InvalidBlockHeight(txid))?;
                            TxStatus::Mined(MiningInfo {
                                height,
                                time: blocktime,
                                block_hash,
                            })
                        };
                        let tx_size = tx.consensus_serialize().len();
                        let weight = tx.weight_units().to_u32();

                        // get inputs to build TxCredit's and total amount,
                        // collecting indexer errors
                        let mut input_total = Sats::ZERO;
                        let mut inputs = Vec::with_capacity(tx.inputs.len());
                        for input in tx.inputs {
                            // get value from previous output tx
                            let prev_tx = self.transaction_get(&input.prev_output.txid)?;
                            let prev_out = prev_tx
                                .outputs
                                .get(input.prev_output.vout.into_usize())
                                .ok_or_else(|| {
                                    ElectrumApiError::PrevOutTxMismatch(txid, input.clone())
                                })?;
                            let value = prev_out.value;
                            input_total += value;
                            inputs.push(TxCredit {
                                outpoint: input.prev_output,
                                payer: Party::Unknown(prev_out.script_pubkey.clone()),
                                sequence: input.sequence,
                                coinbase: false,
                                script_sig: input.sig_script,
                                witness: input.witness,
                                value,
                            })
                        }

                        // get outputs and total amount, build TxDebit's
                        let mut output_total = Sats::ZERO;
                        let mut outputs = Vec::with_capacity(tx.outputs.len());
                        for (no, txout) in tx.outputs.into_iter().enumerate() {
                            output_total += txout.value;
                            outputs.push(TxDebit {
                                outpoint: Outpoint::new(txid, no as u32),
                                beneficiary: Party::Unknown(txout.script_pubkey),
                                value: txout.value,
                                spent: None,
                            })
                        }

                        // build the WalletTx
                        Ok(WalletTx {
                            txid,
                            status,
                            inputs,
                            outputs,
                            fee: input_total - output_total,
                            size: tx_size as u32,
                            weight,
                            version: tx.version,
                            locktime: tx.lock_time,
                        })
                    };

                // build wallet transactions from script tx history, collecting indexer errors
                for hr in hres {
                    match process_history_entry(hr) {
                        Ok(tx) => {
                            cache.tx.insert(tx.txid, tx);
                        }
                        Err(e) => errors.push(e),
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

    fn broadcast(&self, tx: &Tx) -> Result<(), Self::Error> {
        self.transaction_broadcast(tx)?;
        Ok(())
    }
}
