/* Copyright 2025 Ubique Innovation AG

Licensed to the Apache Software Foundation (ASF) under one
or more contributor license agreements.  See the NOTICE file
distributed with this work for additional information
regarding copyright ownership.  The ASF licenses this file
to you under the Apache License, Version 2.0 (the
"License"); you may not use this file except in compliance
with the License.  You may obtain a copy of the License at

  http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing,
software distributed under the License is distributed on an
"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
KIND, either express or implied.  See the License for the
specific language governing permissions and limitations
under the License.
 */
mod credman;
mod dcql;

// #[cfg(target_arch = "wasm32")]
use credman::{get_credentials, get_dc_request, return_error, select_credential};
#[cfg(feature = "cmwallet")]
use dcql::parsers::CMWalletDatabaseFormat as WalletParser;
#[cfg(feature = "ubiquewallet")]
use dcql::parsers::UbiqueWalletDatabaseFormat as WalletParser;
use dcql::parsers::PARSER;

#[cfg(target_arch = "wasm32")]
#[global_allocator]
static ALLOC: mini_alloc::MiniAlloc = mini_alloc::MiniAlloc::INIT;

fn main() {
    let _ = PARSER.set(Box::new(WalletParser));
    // let credentials = get_credentials(&UbiqueWalletDatabaseFormat);
    let credentials = get_credentials(&WalletParser);

    let Some((provider_index, query)) = get_dc_request() else {
        return_error("could not parse dc request");
        return;
    };
    if credentials.is_empty() {
        return_error("parsing credentials failed");
        return;
    }
    // We should have only single credential presentation for now
    let options = query.select_credentials(credentials.clone());
    let Some(first) = options.first() else {
        return_error(&format!(
            "dcql 1 selection failed, {:?}/{:?}",
            query.credential_sets, query.credentials
        ));
        return;
    };
    let Some(first) = first.set_options.first() else {
        return_error("dcql 2 selection failed");
        return;
    };
    let Some(first_set) = first.first() else {
        return_error("dcql 3 selection failed");
        return;
    };
    if first_set.options.is_empty() {
        return_error(&format!(
            "dcql no set-options, {:?}/{:?}",
            query.credential_sets, query.credentials
        ));
        return;
    }
    // Add all options we found
    for option in &first_set.options {
        let c = option.credential.clone();
        let attributes = if option.claims_queries.is_empty() {
            let cred_id = first_set.id.clone();
            let Some(credentials) = &query.credentials else {
                return_error("Invalid query");
                return;
            };
            let credentials = credentials.clone();
            credentials
                .into_iter()
                .filter(|a| a.id == cred_id)
                .flat_map(|a| {
                    a.claims.unwrap_or(Vec::new()).into_iter().map(|a| {
                        (
                            a.path.clone(),
                            a.path
                                .clone()
                                .into_iter()
                                .map(|a| match a {
                                    dcql::models::PointerPart::String(a) => a,
                                    dcql::models::PointerPart::Index(i) => i.to_string(),
                                    dcql::models::PointerPart::Null(_) => String::from("[]"),
                                })
                                .collect::<Vec<_>>()
                                .join("/"),
                        )
                    })
                })
                .collect()
        } else {
            option
                .claims_queries
                .clone()
                .into_iter()
                .map(|first_query| {
                    (
                        first_query.path.clone(),
                        first_query
                            .path
                            .clone()
                            .into_iter()
                            .map(|a| match a {
                                dcql::models::PointerPart::String(a) => a,
                                dcql::models::PointerPart::Index(i) => i.to_string(),
                                dcql::models::PointerPart::Null(_) => String::from("[]"),
                            })
                            .collect::<Vec<_>>()
                            .join("/"),
                    )
                })
                .collect::<Vec<_>>()
        };
        select_credential(c.clone(), attributes.clone(), provider_index, &WalletParser);
    }
}
