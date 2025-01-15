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

use std::fmt::Debug;
use std::path::PathBuf;
use std::process::exit;

use bpstd::XpubDerivable;
use clap::Subcommand;
use descriptors::Descriptor;
use strict_encoding::Ident;

use crate::cli::{
    Config, DescrStdOpts, DescriptorOpts, ExecError, GeneralOpts, ResolverOpt, WalletOpts,
};
use crate::fs::FsTextStore;
use crate::indexers::esplora;
use crate::{AnyIndexer, Wallet};

/// Command-line arguments
#[derive(Parser)]
#[derive(Clone, Eq, PartialEq, Debug)]
#[command(author, version, about)]
pub struct Args<C: Clone + Eq + Debug + Subcommand, O: DescriptorOpts = DescrStdOpts> {
    /// Set verbosity level
    ///
    /// Can be used multiple times to increase verbosity.
    #[clap(short, long, global = true, action = clap::ArgAction::Count)]
    pub verbose: u8,

    #[command(flatten)]
    pub wallet: WalletOpts<O>,

    #[command(flatten)]
    pub resolver: ResolverOpt,

    /// Force-sync wallet data with the indexer before performing the operation
    #[clap(long, global = true)]
    pub sync: bool,

    /// Prune old transactions from the cache during the sync operation
    #[clap(long, global = true)]
    pub prune: bool,

    #[command(flatten)]
    pub general: GeneralOpts,

    /// Command to execute.
    #[clap(subcommand)]
    pub command: C,
}

impl<C: Clone + Eq + Debug + Subcommand, O: DescriptorOpts> Args<C, O> {
    pub fn translate<C1: Clone + Eq + Debug + Subcommand>(&self, cmd: &C1) -> Args<C1, O> {
        Args {
            verbose: self.verbose,
            wallet: self.wallet.clone(),
            resolver: self.resolver.clone(),
            sync: self.sync,
            prune: self.prune,
            general: self.general.clone(),
            command: cmd.clone(),
        }
    }
}

pub trait Exec {
    type Error: std::error::Error;
    const CONF_FILE_NAME: &'static str;

    fn exec(self, config: Config, name: &'static str) -> Result<(), Self::Error>;
}

impl<C: Clone + Eq + Debug + Subcommand, O: DescriptorOpts> Args<C, O> {
    pub fn process(&mut self) { self.general.process(); }

    pub fn conf_path(&self, name: &'static str) -> PathBuf {
        let mut conf_path = self.general.base_dir();
        conf_path.push(name);
        conf_path.set_extension("toml");
        conf_path
    }

    pub fn indexer(&self) -> Result<AnyIndexer, ExecError> {
        let network = self.general.network.to_string();
        Ok(match (&self.resolver.esplora, &self.resolver.electrum, &self.resolver.mempool) {
            (None, Some(url), None) => AnyIndexer::Electrum(Box::new(electrum::Client::new(url)?)),
            (Some(url), None, None) => AnyIndexer::Esplora(Box::new(esplora::Client::new_esplora(
                &url.replace("{network}", &network),
            )?)),
            (None, None, Some(url)) => AnyIndexer::Mempool(Box::new(esplora::Client::new_mempool(
                &url.replace("{network}", &network),
            )?)),
            _ => {
                eprintln!(
                    "Error: no blockchain indexer specified; use either --esplora --mempool or \
                     --electrum argument"
                );
                exit(1);
            }
        })
    }

    #[allow(clippy::multiple_bound_locations)]
    pub fn bp_wallet<D: Descriptor>(
        &self,
        conf: &Config,
    ) -> Result<Wallet<XpubDerivable, D>, ExecError>
    where
        for<'de> D: From<O::Descr> + serde::Serialize + serde::Deserialize<'de>,
    {
        eprint!("Loading descriptor");
        let sync = self.sync || self.wallet.descriptor_opts.is_some();

        let mut wallet: Wallet<XpubDerivable, D> =
            if let Some(d) = self.wallet.descriptor_opts.descriptor() {
                eprintln!(" from command-line argument");
                eprint!("Syncing");
                Wallet::new_layer1(d.into(), self.general.network)
            } else {
                let path = if let Some(wallet_path) = self.wallet.wallet_path.clone() {
                    eprint!(" from specified wallet directory ... ");
                    wallet_path
                } else {
                    let wallet_name = self
                        .wallet
                        .name
                        .as_ref()
                        .map(Ident::to_string)
                        .unwrap_or(conf.default_wallet.clone());
                    eprint!(" from wallet {wallet_name} ... ");
                    self.general.wallet_dir(wallet_name)
                };
                let provider = FsTextStore::new(path)?;
                let wallet = Wallet::load(provider, true)?;
                eprintln!("success");
                wallet
            };

        if sync {
            let indexer = self.indexer()?;
            eprint!("Syncing");
            if let Some(errors) = wallet.update(&indexer, self.prune).into_err() {
                eprintln!(" partial, some requests has failed:");
                for err in errors {
                    eprintln!("- {err}");
                }
            } else {
                eprintln!(" success");
            }
        }

        Ok(wallet)
    }
}
