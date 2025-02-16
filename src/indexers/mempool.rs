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

impl super::esplora::Client {
    /// Creates a new mempool client with the specified URL.
    ///
    /// # Arguments
    ///
    /// * `url` - The URL of the mempool server.
    ///
    /// # Returns
    ///
    /// A `Result` containing the new mempool client if successful, or an `esplora::Error` if an
    /// error occurred.
    #[allow(clippy::result_large_err)]
    pub fn new_mempool(url: &str) -> Result<Self, esplora::Error> {
        let inner = esplora::Builder::new(url).build_blocking()?;
        let client = Self {
            inner,
            kind: super::esplora::ClientKind::Mempool,
        };
        Ok(client)
    }
}
