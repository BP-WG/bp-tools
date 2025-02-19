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

use std::cmp;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::marker::PhantomData;
use std::ops::{AddAssign, Deref};

use bpstd::{
    Address, AddressNetwork, DerivedAddr, Descriptor, Idx, IdxBase, Keychain, Network, NormalIndex,
    Outpoint, Sats, Txid, Vout,
};
use nonasync::persistence::{
    CloneNoPersistence, Persistence, PersistenceError, PersistenceProvider, Persisting,
};
use psbt::{PsbtConstructor, Utxo};

use crate::{
    BlockInfo, CoinRow, Indexer, Layer2, Layer2Cache, Layer2Data, Layer2Descriptor, Layer2Empty,
    MayError, MiningInfo, NoLayer2, Party, TxRow, WalletAddr, WalletTx, WalletUtxo,
};

#[derive(Copy, Clone, Eq, PartialEq, Debug, Display, Error)]
#[display(doc_comments)]
pub enum NonWalletItem {
    /// transaction {0} is not known to the wallet.
    NonWalletTx(Txid),
    /// transaction {0} doesn't contains output number {1}.
    NoOutput(Txid, Vout),
    /// transaction output {0} doesn't belong to the wallet.
    NonWalletUtxo(Outpoint),
}

pub struct AddrIter<'descr, K, D: Descriptor<K>> {
    generator: &'descr D,
    network: AddressNetwork,
    keychain: Keychain,
    index: NormalIndex,
    _phantom: PhantomData<K>,
}

impl<K, D: Descriptor<K>> Iterator for AddrIter<'_, K, D> {
    type Item = DerivedAddr;

    fn next(&mut self) -> Option<Self::Item> {
        let addr = self.generator.derive_address(self.network, self.keychain, self.index).ok()?;
        let derived = DerivedAddr::new(addr, self.keychain, self.index);
        self.index.wrapping_inc_assign();
        Some(derived)
    }
}

#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(
        crate = "serde_crate",
        rename_all = "camelCase",
        bound(
            serialize = "D: serde::Serialize, L2: serde::Serialize",
            deserialize = "D: serde::Deserialize<'de>, L2: serde::Deserialize<'de>"
        )
    )
)]
#[derive(Getters, Debug)]
pub struct WalletDescr<K, D, L2 = Layer2Empty>
where
    D: Descriptor<K>,
    L2: Layer2Descriptor,
{
    #[getter(skip)]
    #[cfg_attr(feature = "serde", serde(skip))]
    persistence: Option<Persistence<Self>>,

    generator: D,
    #[getter(as_copy)]
    network: Network,
    layer2: L2,
    #[cfg_attr(feature = "serde", serde(skip))]
    _phantom: PhantomData<K>,
}

impl<K, D: Descriptor<K>> WalletDescr<K, D, Layer2Empty> {
    pub fn new_standard(descr: D, network: Network) -> Self {
        WalletDescr {
            persistence: None,
            generator: descr,
            network,
            layer2: none!(),
            _phantom: PhantomData,
        }
    }
}

impl<K, D: Descriptor<K>, L2: Layer2Descriptor> WalletDescr<K, D, L2> {
    pub fn new_layer2(descr: D, layer2: L2, network: Network) -> Self {
        WalletDescr {
            persistence: None,
            generator: descr,
            network,
            layer2,
            _phantom: PhantomData,
        }
    }

    pub fn addresses(&self, keychain: impl Into<Keychain>) -> AddrIter<K, D> {
        AddrIter {
            generator: &self.generator,
            network: self.network.into(),
            keychain: keychain.into(),
            index: NormalIndex::ZERO,
            _phantom: PhantomData,
        }
    }

    pub fn with_descriptor_mut<E>(
        &mut self,
        f: impl FnOnce(&mut D) -> Result<(), E>,
    ) -> Result<(), E> {
        f(&mut self.generator)?;
        self.mark_dirty();
        Ok(())
    }
}

impl<K, D: Descriptor<K>, L2: Layer2Descriptor> Deref for WalletDescr<K, D, L2> {
    type Target = D;

    fn deref(&self) -> &Self::Target { &self.generator }
}

impl<K, D: Descriptor<K>, L2: Layer2Descriptor> CloneNoPersistence for WalletDescr<K, D, L2> {
    fn clone_no_persistence(&self) -> Self {
        Self {
            persistence: None,
            generator: self.generator.clone(),
            network: self.network,
            layer2: self.layer2.clone(),
            _phantom: PhantomData,
        }
    }
}

impl<K, D: Descriptor<K>, L2: Layer2Descriptor> Persisting for WalletDescr<K, D, L2> {
    #[inline]
    fn persistence(&self) -> Option<&Persistence<Self>> { self.persistence.as_ref() }
    #[inline]
    fn persistence_mut(&mut self) -> Option<&mut Persistence<Self>> { self.persistence.as_mut() }
    #[inline]
    fn as_mut_persistence(&mut self) -> &mut Option<Persistence<Self>> { &mut self.persistence }
}

impl<K, D: Descriptor<K>, L2: Layer2Descriptor> Drop for WalletDescr<K, D, L2> {
    fn drop(&mut self) {
        if self.is_autosave() && self.is_dirty() {
            if let Err(e) = self.store() {
                #[cfg(feature = "log")]
                log::error!("impossible to automatically-save wallet descriptor on Drop: {e}");
                #[cfg(not(feature = "log"))]
                eprintln!("impossible to automatically-save wallet descriptor on Drop: {e}")
            }
        }
    }
}

#[derive(Debug)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(
        crate = "serde_crate",
        rename_all = "camelCase",
        bound(serialize = "L2: serde::Serialize", deserialize = "L2: serde::Deserialize<'de>")
    )
)]
pub struct WalletData<L2: Layer2Data> {
    #[cfg_attr(feature = "serde", serde(skip))]
    persistence: Option<Persistence<Self>>,

    /// This field is used by applications to link data with other wallet components
    #[cfg_attr(feature = "serde", serde(skip))]
    pub id: Option<String>,
    pub name: String,
    pub tx_annotations: BTreeMap<Txid, String>,
    pub txout_annotations: BTreeMap<Outpoint, String>,
    pub txin_annotations: BTreeMap<Outpoint, String>,
    pub addr_annotations: BTreeMap<Address, String>,
    pub last_used: BTreeMap<Keychain, NormalIndex>,
    pub layer2: L2,
}

impl<L2: Layer2Data> CloneNoPersistence for WalletData<L2> {
    fn clone_no_persistence(&self) -> Self {
        Self {
            persistence: None,
            id: self.id.clone(),
            name: self.name.clone(),
            tx_annotations: self.tx_annotations.clone(),
            txout_annotations: self.txout_annotations.clone(),
            txin_annotations: self.txin_annotations.clone(),
            addr_annotations: self.addr_annotations.clone(),
            layer2: self.layer2.clone(),
            last_used: self.last_used.clone(),
        }
    }
}

impl<L2: Layer2Data> Persisting for WalletData<L2> {
    #[inline]
    fn persistence(&self) -> Option<&Persistence<Self>> { self.persistence.as_ref() }
    #[inline]
    fn persistence_mut(&mut self) -> Option<&mut Persistence<Self>> { self.persistence.as_mut() }
    #[inline]
    fn as_mut_persistence(&mut self) -> &mut Option<Persistence<Self>> { &mut self.persistence }
}

impl WalletData<Layer2Empty> {
    pub fn new_layer1() -> Self {
        WalletData {
            persistence: None,
            id: None,
            name: none!(),
            tx_annotations: empty!(),
            txout_annotations: empty!(),
            txin_annotations: empty!(),
            addr_annotations: empty!(),
            layer2: none!(),
            last_used: empty!(),
        }
    }
}

impl<L2: Layer2Data> WalletData<L2> {
    pub fn new_layer2() -> Self
    where L2: Default {
        WalletData {
            persistence: None,
            id: None,
            name: none!(),
            tx_annotations: empty!(),
            txout_annotations: empty!(),
            txin_annotations: empty!(),
            addr_annotations: empty!(),
            layer2: none!(),
            last_used: empty!(),
        }
    }
}

impl<L2: Layer2Data> Drop for WalletData<L2> {
    fn drop(&mut self) {
        if self.is_autosave() && self.is_dirty() {
            if let Err(e) = self.store() {
                #[cfg(feature = "log")]
                log::error!("impossible to automatically-save wallet data on Drop: {e}");
                #[cfg(not(feature = "log"))]
                eprintln!("impossible to automatically-save wallet data on Drop: {e}")
            }
        }
    }
}

#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(
        crate = "serde_crate",
        rename_all = "camelCase",
        bound(serialize = "L2: serde::Serialize", deserialize = "L2: serde::Deserialize<'de>")
    )
)]
#[derive(Debug)]
pub struct WalletCache<L2: Layer2Cache> {
    #[cfg_attr(feature = "serde", serde(skip))]
    persistence: Option<Persistence<Self>>,

    /// This field is used by applications to link data with other wallet components
    #[cfg_attr(feature = "serde", serde(skip))]
    pub id: Option<String>,
    pub last_block: MiningInfo,
    pub last_change: NormalIndex,
    pub headers: BTreeSet<BlockInfo>,
    pub tx: BTreeMap<Txid, WalletTx>,
    pub utxo: BTreeSet<Outpoint>,
    pub addr: BTreeMap<Keychain, BTreeSet<WalletAddr>>,
    pub layer2: L2,
}

impl<L2C: Layer2Cache> WalletCache<L2C> {
    pub(crate) fn new_nonsync() -> Self {
        WalletCache {
            persistence: None,
            id: None,
            last_block: MiningInfo::genesis(),
            last_change: NormalIndex::ZERO,
            headers: none!(),
            tx: none!(),
            utxo: none!(),
            addr: none!(),
            layer2: none!(),
        }
    }

    pub fn with<I: Indexer, K, D: Descriptor<K>, L2: Layer2<Cache = L2C>>(
        descriptor: &WalletDescr<K, D, L2::Descr>,
        indexer: &I,
    ) -> MayError<Self, Vec<I::Error>> {
        indexer.create::<K, D, L2>(descriptor)
    }

    pub fn update<I: Indexer, K, D: Descriptor<K>, L2: Layer2<Cache = L2C>>(
        &mut self,
        descriptor: &WalletDescr<K, D, L2::Descr>,
        indexer: &I,
    ) -> MayError<usize, Vec<I::Error>> {
        let res = indexer.update::<K, D, L2>(descriptor, self);
        self.mark_dirty();
        res
    }

    pub fn sync_from_scratch<I: Indexer, K, D: Descriptor<K>, L2: Layer2<Cache = L2C>>(
        &mut self,
        descriptor: &WalletDescr<K, D, L2::Descr>,
        indexer: &I,
    ) -> MayError<(), Vec<I::Error>> {
        let res = indexer.create::<K, D, L2>(descriptor);
        let (ok, err) = res.split();
        *self = ok;
        self.mark_dirty();
        MayError { ok: (), err }
    }

    pub fn addresses_on(&self, keychain: Keychain) -> &BTreeSet<WalletAddr> {
        self.addr.get(&keychain).unwrap_or_else(|| {
            panic!("keychain #{keychain} is not supported by the wallet descriptor")
        })
    }

    pub fn has_outpoint(&self, outpoint: Outpoint) -> bool {
        let Some(tx) = self.tx.get(&outpoint.txid) else {
            return false;
        };
        let Some(out) = tx.outputs.get(outpoint.vout.to_usize()) else {
            return false;
        };
        matches!(out.beneficiary, Party::Wallet(_))
    }

    #[inline]
    pub fn is_unspent(&self, outpoint: Outpoint) -> bool { self.utxo.contains(&outpoint) }

    pub fn outpoint_by(&self, outpoint: Outpoint) -> Result<WalletUtxo, NonWalletItem> {
        let tx = self.tx.get(&outpoint.txid).ok_or(NonWalletItem::NonWalletTx(outpoint.txid))?;
        let debit = tx
            .outputs
            .get(outpoint.vout.into_usize())
            .ok_or(NonWalletItem::NoOutput(outpoint.txid, outpoint.vout))?;
        let terminal = debit.derived_addr().ok_or(NonWalletItem::NonWalletUtxo(outpoint))?.terminal;
        // TODO: Check whether TXO is spend
        Ok(WalletUtxo {
            outpoint,
            value: debit.value,
            terminal,
            status: tx.status,
        })
    }

    pub fn txos(&self) -> impl Iterator<Item = WalletUtxo> + '_ {
        self.tx.iter().flat_map(|(txid, tx)| {
            tx.outputs.iter().enumerate().filter_map(|(vout, out)| {
                if let Party::Wallet(w) = out.beneficiary {
                    Some(WalletUtxo {
                        outpoint: Outpoint::new(*txid, vout as u32),
                        value: out.value,
                        terminal: w.terminal,
                        status: tx.status,
                    })
                } else {
                    None
                }
            })
        })
    }

    pub fn utxos(&self) -> impl Iterator<Item = WalletUtxo> + '_ {
        self.utxo.iter().map(|outpoint| {
            let tx = self.tx.get(&outpoint.txid).expect("cache data inconsistency");
            let debit = tx.outputs.get(outpoint.vout_usize()).expect("cache data inconsistency");
            let terminal =
                debit.derived_addr().expect("UTXO doesn't belong to the wallet").terminal;
            // TODO: Check whether TXO is spend
            WalletUtxo {
                outpoint: *outpoint,
                value: debit.value,
                terminal,
                status: tx.status,
            }
        })
    }
}

impl<L2: Layer2Cache> CloneNoPersistence for WalletCache<L2> {
    fn clone_no_persistence(&self) -> Self {
        Self {
            persistence: None,
            id: self.id.clone(),
            last_block: self.last_block,
            last_change: self.last_change,
            headers: self.headers.clone(),
            tx: self.tx.clone(),
            utxo: self.utxo.clone(),
            addr: self.addr.clone(),
            layer2: self.layer2.clone(),
        }
    }
}

impl<L2: Layer2Cache> Persisting for WalletCache<L2> {
    #[inline]
    fn persistence(&self) -> Option<&Persistence<Self>> { self.persistence.as_ref() }
    #[inline]
    fn persistence_mut(&mut self) -> Option<&mut Persistence<Self>> { self.persistence.as_mut() }
    #[inline]
    fn as_mut_persistence(&mut self) -> &mut Option<Persistence<Self>> { &mut self.persistence }
}

impl<L2: Layer2Cache> Drop for WalletCache<L2> {
    fn drop(&mut self) {
        if self.is_autosave() && self.is_dirty() {
            if let Err(e) = self.store() {
                #[cfg(feature = "log")]
                log::error!("impossible to automatically-save wallet cache on Drop: {e}");
                #[cfg(not(feature = "log"))]
                eprintln!("impossible to automatically-save wallet cache on Drop: {e}")
            }
        }
    }
}

#[derive(Debug)]
pub struct Wallet<K, D: Descriptor<K>, L2: Layer2 = NoLayer2> {
    descr: WalletDescr<K, D, L2::Descr>,
    data: WalletData<L2::Data>,
    cache: WalletCache<L2::Cache>,
    layer2: L2,
}

impl<K, D: Descriptor<K>, L2: Layer2> Deref for Wallet<K, D, L2> {
    type Target = WalletDescr<K, D, L2::Descr>;

    fn deref(&self) -> &Self::Target { &self.descr }
}

impl<K, D: Descriptor<K>, L2: Layer2> CloneNoPersistence for Wallet<K, D, L2> {
    fn clone_no_persistence(&self) -> Self {
        Self {
            descr: self.descr.clone_no_persistence(),
            data: self.data.clone_no_persistence(),
            cache: self.cache.clone_no_persistence(),
            layer2: self.layer2.clone_no_persistence(),
        }
    }
}

impl<K, D: Descriptor<K>, L2: Layer2> PsbtConstructor for Wallet<K, D, L2> {
    type Key = K;
    type Descr = D;

    fn descriptor(&self) -> &D { &self.descr.generator }

    fn utxo(&self, outpoint: Outpoint) -> Option<Utxo> {
        self.cache.outpoint_by(outpoint).ok().map(WalletUtxo::into_utxo)
    }

    fn network(&self) -> Network { self.descr.network }

    fn next_derivation_index(&mut self, keychain: impl Into<Keychain>, shift: bool) -> NormalIndex {
        let keychain = keychain.into();
        let mut idx = self.last_published_derivation_index(keychain);
        let last_index = self.data.last_used.entry(keychain).or_default();
        idx = cmp::max(*last_index, idx);
        if shift {
            *last_index = idx.saturating_add(1u32);
            self.data.mark_dirty();
        }
        idx
    }
}

impl<K, D: Descriptor<K>> Wallet<K, D> {
    pub fn new_layer1(descr: D, network: Network) -> Self {
        Wallet {
            cache: WalletCache::new_nonsync(),
            data: WalletData::new_layer1(),
            descr: WalletDescr::new_standard(descr, network),
            layer2: none!(),
        }
    }
    pub fn data_l1(&self) -> &WalletData<Layer2Empty> { &self.data }
    pub fn cache_l1(&self) -> &WalletCache<Layer2Empty> { &self.cache }
}

impl<K, D: Descriptor<K>, L2: Layer2> Wallet<K, D, L2> {
    pub fn new_layer2(descr: D, l2_descr: L2::Descr, layer2: L2, network: Network) -> Self {
        Wallet {
            cache: WalletCache::new_nonsync(),
            data: WalletData::new_layer2(),
            descr: WalletDescr::new_layer2(descr, l2_descr, network),
            layer2,
        }
    }

    pub fn set_name(&mut self, name: String) {
        self.data.name = name;
        self.data.mark_dirty();
    }

    pub fn descriptor_mut<R>(
        &mut self,
        f: impl FnOnce(&mut WalletDescr<K, D, L2::Descr>) -> R,
    ) -> R {
        let res = f(&mut self.descr);
        self.descr.mark_dirty();
        res
    }

    pub fn data_l2(&self) -> &L2::Data { &self.data.layer2 }
    pub fn cache_l2(&self) -> &L2::Cache { &self.cache.layer2 }

    pub fn with_data_l2<R>(&mut self, f: impl FnOnce(&mut L2::Data) -> R) -> R {
        let res = f(&mut self.data.layer2);
        self.data.mark_dirty();
        res
    }
    pub fn with_cache_l2<R>(&mut self, f: impl FnOnce(&mut L2::Cache) -> R) -> R {
        let res = f(&mut self.cache.layer2);
        self.cache.mark_dirty();
        res
    }

    pub fn update<I: Indexer>(&mut self, indexer: &I) -> MayError<(), Vec<I::Error>> {
        self.cache.update::<I, K, D, L2>(&self.descr, indexer).map(|_| ())
    }

    pub fn sync_from_scratch<I: Indexer>(&mut self, indexer: &I) -> MayError<(), Vec<I::Error>> {
        self.cache.sync_from_scratch::<I, K, D, L2>(&self.descr, indexer).map(|_| ())
    }

    pub fn to_deriver(&self) -> D
    where
        D: Clone,
        K: Clone,
    {
        self.descr.clone()
    }

    fn last_published_derivation_index(&self, keychain: impl Into<Keychain>) -> NormalIndex {
        let keychain = keychain.into();
        self.address_coins()
            .keys()
            .filter(|ad| ad.terminal.keychain == keychain)
            .map(|ad| ad.terminal.index)
            .max()
            .as_ref()
            .map(NormalIndex::saturating_inc)
            .unwrap_or_default()
    }

    pub fn last_derivation_index(&self, keychain: impl Into<Keychain>) -> NormalIndex {
        let keychain = keychain.into();
        let last_index = self.data.last_used.get(&keychain).copied().unwrap_or_default();
        cmp::max(last_index, self.last_published_derivation_index(keychain))
    }

    pub fn next_address(&mut self, keychain: impl Into<Keychain>, shift: bool) -> Address {
        let keychain = keychain.into();
        let index = self.next_derivation_index(keychain, shift);
        self.addresses(keychain)
            .nth(index.index() as usize)
            .expect("address iterator always can produce address")
            .addr
    }

    pub fn balance(&self) -> Sats { self.cache.coins().map(|utxo| utxo.amount).sum::<Sats>() }

    #[inline]
    pub fn transactions(&self) -> &BTreeMap<Txid, WalletTx> { &self.cache.tx }

    #[inline]
    pub fn coins(&self) -> impl Iterator<Item = CoinRow<<L2::Cache as Layer2Cache>::Coin>> + '_ {
        self.cache.coins()
    }

    pub fn address_coins(
        &self,
    ) -> HashMap<DerivedAddr, Vec<CoinRow<<L2::Cache as Layer2Cache>::Coin>>> {
        let map = HashMap::new();
        self.coins().fold(map, |mut acc, txo| {
            acc.entry(txo.address).or_default().push(txo);
            acc
        })
    }

    pub fn address_balance(&self) -> impl Iterator<Item = WalletAddr> + '_ {
        self.cache.addr.values().flat_map(|set| set.iter()).copied()
    }

    #[inline]
    pub fn history(&self) -> impl Iterator<Item = TxRow<<L2::Cache as Layer2Cache>::Tx>> + '_ {
        self.cache.history()
    }

    pub fn has_outpoint(&self, outpoint: Outpoint) -> bool { self.cache.has_outpoint(outpoint) }
    pub fn is_unspent(&self, outpoint: Outpoint) -> bool { self.cache.is_unspent(outpoint) }

    pub fn outpoint_by(&self, outpoint: Outpoint) -> Result<WalletUtxo, NonWalletItem> {
        self.cache.outpoint_by(outpoint)
    }

    pub fn txos(&self) -> impl Iterator<Item = WalletUtxo> + '_ { self.cache.txos() }
    pub fn utxos(&self) -> impl Iterator<Item = WalletUtxo> + '_ { self.cache.utxos() }

    pub fn coinselect<'a>(
        &'a self,
        up_to: Sats,
        selector: impl Fn(&WalletUtxo) -> bool + 'a,
    ) -> impl Iterator<Item = Outpoint> + 'a {
        let mut selected = Sats::ZERO;
        self.utxos()
            .filter(selector)
            .take_while(move |utxo| {
                if selected <= up_to {
                    selected.add_assign(utxo.value);
                    true
                } else {
                    false
                }
            })
            .map(|utxo| utxo.outpoint)
    }
}

impl<K, D: Descriptor<K>, L2: Layer2> Wallet<K, D, L2> {
    pub fn load<P>(provider: P, autosave: bool) -> Result<Wallet<K, D, L2>, PersistenceError>
    where P: Clone
            + PersistenceProvider<WalletDescr<K, D, L2::Descr>>
            + PersistenceProvider<WalletData<L2::Data>>
            + PersistenceProvider<WalletCache<L2::Cache>>
            + PersistenceProvider<L2>
            + 'static {
        let descr = WalletDescr::<K, D, L2::Descr>::load(provider.clone(), autosave)?;
        let data = WalletData::<L2::Data>::load(provider.clone(), autosave)?;
        let cache = WalletCache::<L2::Cache>::load(provider.clone(), autosave)?;
        let layer2 = L2::load(provider, autosave)?;

        Ok(Wallet {
            descr,
            data,
            cache,
            layer2,
        })
    }

    pub fn set_id(&mut self, id: &impl ToString) {
        self.data.id = Some(id.to_string());
        self.cache.id = Some(id.to_string());
    }

    pub fn make_persistent<P>(
        &mut self,
        provider: P,
        autosave: bool,
    ) -> Result<bool, PersistenceError>
    where
        P: Clone
            + PersistenceProvider<WalletDescr<K, D, L2::Descr>>
            + PersistenceProvider<WalletData<L2::Data>>
            + PersistenceProvider<WalletCache<L2::Cache>>
            + PersistenceProvider<L2>
            + 'static,
    {
        let a = self.descr.make_persistent(provider.clone(), autosave)?;
        let b = self.data.make_persistent(provider.clone(), autosave)?;
        let c = self.cache.make_persistent(provider.clone(), autosave)?;
        let d = self.layer2.make_persistent(provider, autosave)?;
        Ok(a && b && c && d)
    }

    pub fn store(&mut self) -> Result<(), PersistenceError> {
        // TODO: Revert on failure

        self.descr.store()?;
        self.data.store()?;
        self.cache.store()?;
        self.layer2.store()?;

        Ok(())
    }
}
