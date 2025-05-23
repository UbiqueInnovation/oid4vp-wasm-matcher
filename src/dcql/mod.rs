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
pub mod claims_pointer;
pub mod models;
pub mod parsers;

use claims_pointer::Selector;
use models::{
    ClaimsQuery, Credential, CredentialOptions, CredentialQuery, CredentialSetOption, DcqlQuery,
    Disclosure, Pointer, PointerPart, SetOption,
};
use parsers::PARSER;
use serde_json::Value;
use std::collections::BTreeMap;

pub trait InformationScore {
    fn score(&self) -> usize;
}

const DANGEROUS_PROPERTIES: [&str; 4] = ["birth", "date", "address", "street"];
const HIDING_PROPERTIES: [&str; 1] = ["age_over"];

impl InformationScore for &str {
    fn score(&self) -> usize {
        if DANGEROUS_PROPERTIES.iter().any(|a| self.contains(a)) {
            return 4;
        }
        if HIDING_PROPERTIES.iter().any(|a| self.contains(a)) {
            return 1;
        }
        2
    }
}
impl InformationScore for String {
    fn score(&self) -> usize {
        self.as_str().score()
    }
}
impl InformationScore for Vec<String> {
    fn score(&self) -> usize {
        let mut score = 0;
        for attribute in self {
            for dp in &DANGEROUS_PROPERTIES {
                if attribute.contains(dp) {
                    score += 4;
                    continue;
                }
            }
            for hiding_property in &HIDING_PROPERTIES {
                if attribute.contains(hiding_property) {
                    score += 1;
                    continue;
                }
            }
            score += 2;
        }
        score
    }
}
impl InformationScore for Pointer {
    fn score(&self) -> usize {
        let mut score = 0;
        for p in self {
            match p {
                PointerPart::String(attribute) => {
                    for dp in &DANGEROUS_PROPERTIES {
                        if attribute.contains(dp) {
                            score += 4;
                            continue;
                        }
                    }
                    for hiding_property in &HIDING_PROPERTIES {
                        if attribute.contains(hiding_property) {
                            score += 1;
                            continue;
                        }
                    }
                    score += 2;
                }
                _ => continue,
            }
        }
        score
    }
}

pub trait CredentialStore {
    fn get(&self) -> Vec<Credential>;
}
impl CredentialStore for Vec<Credential> {
    fn get(&self) -> Vec<Credential> {
        self.clone()
    }
}

impl DcqlQuery {
    pub fn select_credentials(
        &self,
        credential_store: impl CredentialStore,
    ) -> Vec<CredentialSetOption> {
        let credentials = credential_store.get();
        if let (Some(credential_sets), Some(credential_queries)) =
            (&self.credential_sets, &self.credentials)
        {
            let credential_query_map = credential_queries
                .iter()
                .map(|a| (a.id.clone(), a))
                .collect::<BTreeMap<_, _>>();
            let mut matching_sets: Vec<CredentialSetOption> = vec![];
            for credential_set in credential_sets {
                let mut variations = vec![];
                'option_loop: for option in &credential_set.options {
                    let mut possible_candidates: BTreeMap<String, CredentialOptions> =
                        BTreeMap::new();
                    for id in option {
                        let Some(credential_query) = credential_query_map.get(id) else {
                            continue 'option_loop;
                        };
                        let creds = credentials
                            .iter()
                            .filter_map(|a| {
                                a.is_satisfied(credential_query).map(|claims| Disclosure {
                                    credential: a.clone(),
                                    claims_queries: claims,
                                })
                            })
                            .collect::<Vec<_>>();

                        possible_candidates.insert(
                            credential_query.id.clone(),
                            CredentialOptions { options: creds },
                        );
                    }
                    // if it is required and none of the options matched, return
                    if !possible_candidates.is_empty() {
                        variations.push(possible_candidates);
                    }
                }
                if variations.is_empty() && credential_set.required {
                    return vec![];
                }
                if !variations.is_empty() {
                    matching_sets.push(CredentialSetOption {
                        purpose: credential_set
                            .purpose
                            .as_ref()
                            .and_then(|a| a.as_str().map(|a| a.to_string())),
                        set_options: variations
                            .into_iter()
                            .filter_map(|bt| {
                                let r = bt
                                    .into_iter()
                                    .filter_map(|kv| {
                                        if kv.1.options.is_empty() {
                                            None
                                        } else {
                                            Some(SetOption {
                                                id: kv.0,
                                                options: kv.1.options,
                                            })
                                        }
                                    })
                                    .collect::<Vec<_>>();
                                if r.is_empty() {
                                    None
                                } else {
                                    Some(r)
                                }
                            })
                            .collect(),
                    })
                }
            }
            return matching_sets;
        }
        if let Some(credential_queries) = &self.credentials {
            let mut matching_sets: Vec<CredentialSetOption> = vec![];
            let mut map = vec![];
            for credential_query in credential_queries {
                let creds: Vec<_> = credentials
                    .iter()
                    .filter_map(|a| {
                        a.is_satisfied(credential_query).map(|claims| Disclosure {
                            credential: a.clone(),
                            claims_queries: claims,
                        })
                    })
                    .collect();
                if creds.is_empty() {
                    return vec![];
                }

                map.push(SetOption {
                    id: credential_query.id.clone(),
                    options: creds,
                });
            }
            matching_sets.push(CredentialSetOption {
                purpose: None,
                set_options: vec![map],
            });
            return matching_sets;
        }
        vec![]
    }
}

pub struct DisplayMetadata {
    pub id: String,
    pub title: String,
    pub subtitle: String,
    pub icon: Value,
}

impl Credential {
    pub fn get_display_metadata(&self) -> DisplayMetadata {
        match self {
            Credential::DummyCredential(value) => {
                let id = value["id"]
                    .as_str()
                    .map(|a| a.to_string())
                    .unwrap_or_default();
                let title = value["title"]
                    .as_str()
                    .map(|a| a.to_string())
                    .unwrap_or_default();
                let subtitle = value["subtitle"]
                    .as_str()
                    .map(|a| a.to_string())
                    .unwrap_or_default();
                let icon = value["icon"].clone();

                DisplayMetadata {
                    id,
                    title,
                    subtitle,
                    icon,
                }
            }
        }
    }
    fn get_credential_format(&self) -> Option<String> {
        match self {
            Credential::DummyCredential(value) => {
                value["credential_format"].as_str().map(|a| a.to_string())
            }
        }
    }
    fn get_document_type(&self) -> Option<String> {
        match self {
            Credential::DummyCredential(value) => {
                value["document_type"].as_str().map(|a| a.to_string())
            }
        }
    }
    pub fn is_satisfied(&self, credential_query: &CredentialQuery) -> Option<Vec<ClaimsQuery>> {
        let format = credential_query.format.clone();
        // check that the requested format matches
        if let Some(f) = self.get_credential_format() {
            if f != format {
                return None;
            }
        }
        let Some(document_type) = self.get_document_type() else {
            return None;
        };
        // test for document_type
        match &credential_query.meta {
            Some(models::Meta::SdjwtVc { vct_values }) => {
                if !vct_values.contains(&document_type) {
                    return None;
                }
            }
            Some(models::Meta::IsoMdoc { doctype_value }) => {
                if doctype_value != &document_type {
                    return None;
                }
            }
            _ => {}
        }
        // if we have claims_sets we need to check possible combinations
        if let (Some(claims_sets), Some(claims)) =
            (&credential_query.claim_sets, &credential_query.claims)
        {
            let mut order_least = claims_sets.clone();
            // if claims_set is set all claims need an id
            // https://openid.net/specs/openid-4-verifiable-presentations-1_0-23.html#section-6.1
            if !claims.iter().all(|a| a.id().is_some()) {
                return None;
            }
            let claims_map = claims
                .iter()
                .map(|a| (a.id().unwrap_or(String::from("<invalid>")), a.to_owned()))
                .collect::<BTreeMap<_, _>>();
            // we SHOULD use the "principle of least information".
            order_least.sort_by(|a, b| {
                let left: usize = a
                    .iter()
                    .filter_map(|e| claims_map.get(e))
                    .map(|a| a.path.score())
                    .sum();
                let right = b
                    .iter()
                    .filter_map(|e| claims_map.get(e))
                    .map(|a| a.path.score())
                    .sum();
                left.cmp(&right)
            });
            //find first matching claims set
            'claim_set: for claim_set in order_least {
                let mut queries = vec![];
                for claim_query_id in &claim_set {
                    let Some(claim_query) = claims_map.get(claim_query_id) else {
                        continue 'claim_set;
                    };
                    if !claim_query.matches(self) {
                        continue 'claim_set;
                    }
                    queries.push(claim_query.clone());
                }
                return Some(queries);
            }
        }
        //when we have no claims_sets we need to check all claim_querries
        if let Some(claims) = &credential_query.claims {
            for claim_query in claims {
                if !claim_query.matches(self) {
                    return None;
                }
            }
            Some(vec![])
        } else {
            Some(vec![])
        }
    }
    pub fn get_claims(&self) -> serde_json::Value {
        match self {
            Credential::DummyCredential(value) => value["paths"].clone(),
        }
    }
}

impl ClaimsQuery {
    pub fn matches(&self, credential: &Credential) -> bool {
        match (self, credential.get_claims()) {
            (
                ClaimsQuery {
                    id: _id,
                    path,
                    values,
                },
                data,
            ) => {
                let path = if let Some(parser) = PARSER.get() {
                    parser.path_transform(&path)
                } else {
                    path.to_vec()
                };

                let Ok(data) = path.select(data) else {
                    return false;
                };
                if let Some(vals) = values.as_ref() {
                    return data.iter().all(|dr| vals.iter().any(|v| v == dr));
                }
                true
            }
        }
    }
}

// pub fn select_credentials(query: DcqlQuery, credentials: Vec<String>) -> Vec<CredentialSetOption> {
//     query
//         .select_credentials(credentials.iter().map(String::as_str).collect::<Vec<_>>())
//         .into_iter()
//         .collect()
// }

#[cfg(test)]
mod tests {
    use crate::dcql::{models::DcqlQuery, parsers::PARSER};

    use super::parsers::{CMWalletDatabaseFormat, ParseCredential, UbiqueWalletDatabaseFormat};

    #[test]
    fn test_dcql() {
        let query = include_str!("./test_vectors/query.json");
        let creds = include_str!("./test_vectors/ubique_format_db.json");
        let result = serde_json::from_str::<DcqlQuery>(query).unwrap();
        let creds = UbiqueWalletDatabaseFormat.parse(creds).unwrap();
        let r = result.select_credentials(creds.clone());
        // panic!("{r:?}");
        assert!(r.len() > 0);
    }
    #[test]
    fn test_cm_format() {
        let _ = PARSER.set(Box::new(CMWalletDatabaseFormat));
        let creds = include_str!("./test_vectors/cm_format_db.json");
        let creds = CMWalletDatabaseFormat.parse(creds).unwrap();
        let query_str = include_str!("./test_vectors/query_with_values.json");
        let query = serde_json::from_str::<DcqlQuery>(query_str).unwrap();
        let r = query.select_credentials(creds.clone());
        let first_option = r.first().unwrap();
        let first_set = first_option.set_options.first().unwrap();
        assert!(!first_set.is_empty());
    }
}
