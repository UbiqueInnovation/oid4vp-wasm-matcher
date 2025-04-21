pub mod claims_pointer;
pub mod models;

use claims_pointer::Selector;
use models::{
    ClaimsQuery, Credential, CredentialOptions, CredentialQuery, CredentialSetOption, DcqlQuery,
    Disclosure, Pointer, PointerPart, SetOption,
};
use std::collections::{BTreeMap, HashMap};

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

// impl<'a, T: AsRef<[&'a str]>> CredentialStore for T {
//     fn get(&self) -> Vec<Credential> {
//         self.as_ref()
//             .iter()
//             .filter_map(|a| a.parse().ok())
//             .collect()
//     }
// }
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
                .collect::<HashMap<_, _>>();
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
                            .map(|bt| {
                                bt.into_iter()
                                    .map(|kv| SetOption {
                                        id: kv.0,
                                        options: kv.1.options,
                                    })
                                    .collect::<Vec<_>>()
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

impl Credential {
    pub fn is_satisfied(&self, credential_query: &CredentialQuery) -> Option<Vec<ClaimsQuery>> {
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
                .map(|a| (a.id().unwrap(), a.to_owned()))
                .collect::<HashMap<_, _>>();
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
}

impl ClaimsQuery {
    pub fn matches(&self, credential: &Credential) -> bool {
        match (self, credential) {
            (
                ClaimsQuery {
                    id: _id,
                    path,
                    values,
                },
                Credential::DummyCredential(sd_jwt),
            ) => {
                let Ok(data) = path.select(sd_jwt.clone()) else {
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
