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

use std::fs::File;
use std::path::{Path, PathBuf};
use std::process::exit;
use std::{fs, io};

use amplify::IoError;
use bpstd::psbt::{Beneficiary, TxParams};
use bpstd::{ConsensusEncode, Derive, IdxBase, Keychain, NormalIndex, Sats, Tx, XpubDerivable};
use colored::Colorize;
use descriptors::Descriptor;
use nonasync::persistence::PersistenceError;
use psbt::{ConstructionError, Payment, Psbt, PsbtConstructor, PsbtVer, UnfinalizedInputs};
use strict_encoding::Ident;

use crate::cli::{Args, Config, DescriptorOpts, Exec};
use crate::fs::FsTextStore;
use crate::{coinselect, AnyIndexerError, Indexer, OpType, Wallet, WalletAddr, WalletUtxo};

#[derive(Subcommand, Clone, PartialEq, Eq, Debug, Display)]
pub enum Command {
    /// List known named wallets
    #[display("list")]
    List,

    /// Get or set default wallet
    #[display("default")]
    Default {
        /// Name of the wallet to make it default
        default: Option<Ident>,
    },

    /// Create a named wallet
    #[display("create")]
    Create {
        /// The name for the new wallet
        name: Ident,
    },

    /// Generate a new wallet address(es)
    #[display("address")]
    Address {
        /// Use change keychain
        #[clap(short = '1', long)]
        change: bool,

        /// Use custom keychain
        #[clap(short, long, conflicts_with = "change")]
        keychain: Option<Keychain>,

        /// Use custom address index
        #[clap(short, long)]
        index: Option<NormalIndex>,

        /// Do not shift the last used index
        #[clap(short = 'D', long, conflicts_with_all = ["change", "index"])]
        dry_run: bool,

        /// Number of addresses to generate
        #[clap(short = 'C', long, default_value = "1")]
        count: u8,
    },

    /// Finalize a PSBT, optionally extracting and publishing the signed transaction
    #[display("finalize")]
    Finalize {
        /// Extract and send the signed transaction to the network.
        #[clap(short, long)]
        publish: bool,

        /// Name of PSBT file to finalize.
        psbt: PathBuf,

        /// File to save the extracted signed transaction.
        tx: Option<PathBuf>,
    },

    /// Extract a signed transaction from PSBT. The PSBT file itself is not modified
    #[display("finalize")]
    Extract {
        /// Send the extracted transaction to the network.
        #[clap(short, long)]
        publish: bool,

        /// Name of PSBT file to take the transaction from
        psbt: PathBuf,

        /// File to save the extracted signed transaction. If not provided, the transaction is
        /// print to STDOUT.
        tx: Option<PathBuf>,
    },
}

#[derive(Subcommand, Clone, PartialEq, Eq, Debug, Display)]
pub enum BpCommand {
    #[clap(flatten)]
    #[display(inner)]
    General(Command),

    /// List wallet balance and UTXOs
    #[display("balance")]
    Balance {
        /// Print balance for each individual address
        #[clap(short, long)]
        addr: bool,

        /// Print information about individual UTXOs
        #[clap(short, long)]
        utxo: bool,
    },

    /// Display history of wallet operations
    #[display("history")]
    History {
        /// Print full transaction ids
        #[clap(long)]
        txid: bool,

        /// Print operation details
        #[clap(long)]
        details: bool,
    },

    /// Inspect transaction
    Tx { tx: Tx },

    /// Inspect PSBT file
    Inspect {
        /// Name of a PSBT file to inspect
        psbt: PathBuf,
    },

    /// Compose a new PSBT for bitcoin payment
    #[display("construct")]
    Construct {
        /// Encode PSBT as V2
        #[clap(short = '2')]
        v2: bool,

        /// Bitcoin invoice in form of `<sats>@<address>`. To spend full wallet balance use
        /// `MAX` for the amount.
        ///
        /// If multiple `MAX` addresses provided the wallet balance is split between them in equal
        /// proportions.
        #[clap(long)]
        to: Vec<Beneficiary>,

        /// Fee
        fee: Sats,

        /// Name of a PSBT file to save. If not given, prints PSBT to STDOUT
        psbt: Option<PathBuf>,
    },
}

#[derive(Debug, Display, Error, From)]
#[non_exhaustive]
#[display(inner)]
pub enum ExecError {
    #[from]
    #[from(io::Error)]
    Io(IoError),

    #[from]
    Store(PersistenceError),

    #[from]
    ConstructPsbt(ConstructionError),

    #[from]
    DecodePsbt(psbt::DecodeError),

    #[from]
    Unfinalized(UnfinalizedInputs),

    /// indexer failed with {0}
    #[from]
    #[cfg_attr(feature = "electrum", from(electrum::Error))]
    #[cfg_attr(feature = "electrum", from(crate::indexers::electrum::ElectrumError))]
    #[cfg_attr(feature = "esplora", from(esplora::Error))]
    #[display(doc_comments)]
    Indexer(AnyIndexerError),
}

impl<O: DescriptorOpts> Exec for Args<Command, O> {
    type Error = ExecError;
    const CONF_FILE_NAME: &'static str = "bp.toml";

    fn exec(self, mut config: Config, conf_filename: &'static str) -> Result<(), Self::Error> {
        match &self.command {
            Command::List => {
                let dir = self.general.base_dir();
                let Ok(dir) = fs::read_dir(dir).inspect_err(|err| {
                    error!("Error reading wallet directory: {err:?}");
                    eprintln!("System directory is not initialized");
                    println!("no wallets found");
                }) else {
                    return Ok(());
                };
                println!("Known wallets:");
                let mut count = 0usize;
                for wallet in dir {
                    let Ok(entry) = wallet else {
                        continue;
                    };
                    let Ok(meta) = entry.metadata() else {
                        continue;
                    };
                    if !meta.is_dir() {
                        continue;
                    }
                    count += 1;
                    let name = entry.file_name().into_string().expect("invalid directory name");
                    print!(
                        "{name}{}",
                        if config.default_wallet == name { "\t[default]\t" } else { "\t\t" }
                    );
                    let provider = FsTextStore::new(entry.path().clone())?;
                    let wallet = match Wallet::<XpubDerivable, O::Descr>::load(provider, true) {
                        Err(err) => {
                            error!("Error loading wallet descriptor: {err}");
                            println!("# broken wallet descriptor");
                            continue;
                        }
                        Ok(wallet) => wallet,
                    };
                    println!("\t{}", wallet.descriptor());
                }
                if count == 0 {
                    println!("no wallets found");
                }
            }
            Command::Default { default } => {
                if let Some(default) = default {
                    config.default_wallet = default.to_string();
                    config.store(&self.conf_path(conf_filename));
                } else {
                    println!("Default wallet is '{}'", config.default_wallet);
                }
            }
            Command::Create { name } => {
                if !self.wallet.descriptor_opts.is_some() {
                    eprintln!("Error: you must provide an argument specifying wallet descriptor");
                    exit(1);
                }
                print!("Saving the wallet as '{name}' ... ");
                let mut wallet = self.bp_wallet::<O::Descr>(&config)?;
                let name = name.to_string();
                let provider = FsTextStore::new(self.general.wallet_dir(&name))?;
                wallet.make_persistent(provider, true)?;
                wallet.set_name(name);
                if let Err(err) = wallet.store() {
                    println!("error: {err}");
                } else {
                    println!("success");
                }
            }
            Command::Address {
                change,
                keychain,
                index,
                dry_run: no_shift,
                count: no,
            } => {
                let mut wallet = self.bp_wallet::<O::Descr>(&config)?;
                let keychain = match (change, keychain) {
                    (false, None) => wallet.default_keychain(),
                    (true, None) => (*change as u8).into(),
                    (false, Some(keychain)) => *keychain,
                    _ => unreachable!(),
                };
                if !wallet.keychains().contains(&keychain) {
                    eprintln!(
                        "Error: the specified keychain {keychain} is not a part of the descriptor"
                    );
                    exit(1);
                }
                let index =
                    index.unwrap_or_else(|| wallet.next_derivation_index(keychain, !*no_shift));
                println!("\nTerm.\tAddress");
                for derived_addr in
                    wallet.addresses(keychain).skip(index.index() as usize).take(*no as usize)
                {
                    println!("{}\t{}", derived_addr.terminal, derived_addr.addr);
                }
            }
            Command::Finalize {
                publish,
                psbt: psbt_path,
                tx,
            } => {
                let mut psbt = psbt_read(psbt_path)?;
                if psbt.is_finalized() {
                    eprintln!("The PSBT is already finalized");
                } else {
                    let wallet = self.bp_wallet::<O::Descr>(&config)?;
                    psbt_finalize(&mut psbt, wallet.descriptor())?;
                }

                psbt_write(&psbt, psbt_path)?;
                if let Ok(tx) = psbt_extract(&psbt, *publish, tx.as_deref()) {
                    if *publish {
                        let indexer = self.indexer()?;
                        eprint!("Publishing transaction via {} ... ", indexer.name());
                        indexer.broadcast(&tx)?;
                        eprintln!("success");
                    }
                }
            }
            Command::Extract {
                publish,
                psbt: psbt_path,
                tx,
            } => {
                let mut psbt = psbt_read(psbt_path)?;
                if !psbt.is_finalized() {
                    let wallet = self.bp_wallet::<O::Descr>(&config)?;
                    psbt_finalize(&mut psbt, wallet.descriptor())?;
                }

                if let Ok(tx) = psbt_extract(&psbt, *publish, tx.as_deref()) {
                    if *publish {
                        let indexer = self.indexer()?;
                        eprint!("Publishing transaction via {} ... ", indexer.name());
                        indexer.broadcast(&tx)?;
                        eprintln!("success");
                    }
                }
            }
        }

        Ok(())
    }
}

impl<O: DescriptorOpts> Exec for Args<BpCommand, O> {
    type Error = ExecError;
    const CONF_FILE_NAME: &'static str = "bp.toml";

    fn exec(mut self, config: Config, conf_filename: &'static str) -> Result<(), Self::Error> {
        match &self.command {
            BpCommand::General(cmd) => self.translate(cmd).exec(config, conf_filename)?,
            BpCommand::Balance {
                addr: false,
                utxo: false,
            } => {
                let runtime = self.bp_wallet::<O::Descr>(&config)?;
                println!("\nWallet total balance: {} ṩ", runtime.balance());
            }
            BpCommand::Balance {
                addr: true,
                utxo: false,
            } => {
                let wallet = self.bp_wallet::<O::Descr>(&config)?;
                println!("\nTerm.\t{:62}\t# used\tVol., ṩ\tBalance, ṩ", "Address");
                for info in wallet.address_balance() {
                    let WalletAddr {
                        addr,
                        terminal,
                        used,
                        volume,
                        balance,
                    } = info;
                    println!("{terminal}\t{:62}\t{used}\t{volume}\t{balance}", addr.to_string());
                }
                self.command = BpCommand::Balance {
                    addr: false,
                    utxo: false,
                };
                self.sync = false;
                self.exec(config, conf_filename)?;
            }
            BpCommand::Balance {
                addr: false,
                utxo: true,
            } => {
                let wallet = self.bp_wallet::<O::Descr>(&config)?;
                println!("Balance of {}", wallet.descriptor());
                println!("\nHeight\t{:>12}\t{:68}\tAddress", "Amount, ṩ", "Outpoint");
                for row in wallet.coins() {
                    println!(
                        "{}\t{: >12}\t{:68}\t{}",
                        row.height, row.amount, row.outpoint, row.address
                    );
                }
                self.command = BpCommand::Balance {
                    addr: false,
                    utxo: false,
                };
                self.sync = false;
                self.exec(config, conf_filename)?;
            }
            BpCommand::Balance {
                addr: true,
                utxo: true,
            } => {
                let wallet = self.bp_wallet::<O::Descr>(&config)?;
                println!("Balance of {}", wallet.descriptor());
                println!("\nHeight\t{:>12}\t{:68}", "Amount, ṩ", "Outpoint");
                for (derived_addr, utxos) in wallet.address_coins() {
                    println!("{}\t{}", derived_addr.addr, derived_addr.terminal);
                    for row in utxos {
                        println!("{}\t{: >12}\t{:68}", row.height, row.amount, row.outpoint);
                    }
                    println!()
                }
                self.command = BpCommand::Balance {
                    addr: false,
                    utxo: false,
                };
                self.sync = false;
                self.exec(config, conf_filename)?;
            }
            BpCommand::History { txid, details } => {
                let wallet = self.bp_wallet::<O::Descr>(&config)?;
                println!("History of {}", wallet.descriptor());
                println!(
                    "\nHeight\t{:<1$}\t    Amount, ṩ\tFee rate, ṩ/vbyte",
                    "Txid",
                    if *txid { 64 } else { 18 }
                );
                let mut rows = wallet.history().collect::<Vec<_>>();
                rows.sort_by_key(|row| row.height);
                for row in rows {
                    println!(
                        "{}\t{}\t{}{: >12}\t{: >8.2}",
                        row.height,
                        if *txid { row.txid.to_string() } else { format!("{:#}", row.txid) },
                        row.operation,
                        row.amount,
                        row.fee.sats() as f64 * 4.0 / row.weight as f64
                    );
                    if *details {
                        for (cp, value) in &row.own {
                            println!(
                                "\t* {value: >-12}ṩ\t{}\t{cp}",
                                if *value < 0 {
                                    "taken from"
                                } else if row.operation == OpType::Credit {
                                    "moved to  "
                                } else {
                                    "change    "
                                }
                            );
                        }
                        for (cp, value) in &row.counterparties {
                            println!(
                                "\t* {value: >-12}ṩ\t{}\t{cp}",
                                if *value > 0 {
                                    "received  "
                                } else if row.operation == OpType::Credit {
                                    "change?   "
                                } else {
                                    "paid to   "
                                }
                            );
                        }
                        println!("\t* {: >-12}ṩ\tminer fee", -row.fee.sats_i64());
                        println!();
                    }
                }
            }
            BpCommand::Tx { tx } => {
                println!(
                    "{}",
                    serde_yaml::to_string(&tx).expect("unable to generate YAML representation")
                );
            }
            BpCommand::Inspect { psbt } => {
                let psbt = psbt_read(psbt)?;
                println!(
                    "{}",
                    serde_yaml::to_string(&psbt).expect("unable to generate YAML representation")
                );
            }
            BpCommand::Construct {
                v2,
                to: beneficiaries,
                fee,
                psbt: psbt_file,
            } => {
                let mut wallet = self.bp_wallet::<O::Descr>(&config)?;

                // Do coin selection
                let total_amount =
                    beneficiaries.iter().try_fold(Sats::ZERO, |sats, b| match b.amount {
                        Payment::Max => Err(()),
                        Payment::Fixed(s) => sats.checked_add(s).ok_or(()),
                    });
                let coins: Vec<_> = match total_amount {
                    Ok(sats) if sats > Sats::ZERO => {
                        wallet.coinselect(sats + *fee, coinselect::all).collect()
                    }
                    _ => {
                        eprintln!(
                            "Warning: you are not paying to anybody but just aggregating all your \
                             balances to a single UTXO",
                        );
                        wallet.utxos().map(WalletUtxo::into_outpoint).collect()
                    }
                };

                // TODO: Support lock time and RBFs
                let params = TxParams::with(*fee);
                let (mut psbt, _) =
                    wallet.construct_psbt(coins, beneficiaries.iter().copied(), params)?;
                psbt.version = if *v2 { PsbtVer::V2 } else { PsbtVer::V0 };
                psbt_write_or_print(&psbt, psbt_file.as_deref())?;
            }
        };

        println!();

        Ok(())
    }
}

fn psbt_read(psbt_path: &Path) -> Result<Psbt, ExecError> {
    eprint!("Reading PSBT from file {} ... ", psbt_path.display());
    let mut psbt_file = File::open(psbt_path)?;
    let psbt = Psbt::decode(&mut psbt_file)?;
    eprintln!("success");
    Ok(psbt)
}

fn psbt_write(psbt: &Psbt, psbt_path: &Path) -> Result<(), ExecError> {
    eprint!("Saving PSBT to file {} ... ", psbt_path.display());
    let mut psbt_file = File::create(psbt_path)?;
    psbt.encode(psbt.version, &mut psbt_file)?;
    eprintln!("success");
    Ok(())
}

fn psbt_write_or_print(psbt: &Psbt, psbt_path: Option<&Path>) -> Result<(), ExecError> {
    match psbt_path {
        Some(file_name) => {
            psbt_write(psbt, file_name)?;
        }
        None => match psbt.version {
            PsbtVer::V0 => println!("{psbt}"),
            PsbtVer::V2 => println!("{psbt:#}"),
        },
    }
    Ok(())
}

fn psbt_finalize<D: Descriptor<K, V>, K, V>(
    psbt: &mut Psbt,
    descriptor: &D,
) -> Result<(), ExecError> {
    eprint!("Finalizing PSBT ... ");
    let inputs = psbt.finalize(descriptor);
    eprint!(
        "{} of {} inputs were finalized",
        inputs.to_string().bright_green(),
        psbt.inputs().count()
    );
    if psbt.is_finalized() {
        eprintln!(", transaction is ready for the extraction");
    } else {
        eprintln!(" and some non-finalized inputs remains");
    }
    Ok(())
}

fn psbt_extract(psbt: &Psbt, publish: bool, tx: Option<&Path>) -> Result<Tx, ExecError> {
    eprint!("Extracting signed transaction ... ");
    match psbt.extract() {
        Ok(extracted) => {
            eprintln!("success");
            if !publish && tx.is_none() {
                println!("{extracted}");
            }
            if let Some(file) = tx {
                eprint!("Saving transaction to file {} ...", file.display());
                let mut file = File::create(file)?;
                extracted.consensus_encode(&mut file)?;
                eprintln!("success");
            }
            Ok(extracted)
        }
        Err(e) if publish || tx.is_some() => {
            eprintln!(
                "PSBT still contains {} non-finalized inputs, failing to extract transaction",
                e.0.to_string().bright_red()
            );
            Err(e.into())
        }
        Err(e) => {
            eprintln!("{} more inputs still have to be finalized", e.0);
            Err(e.into())
        }
    }
}
