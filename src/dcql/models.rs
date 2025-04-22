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
use serde::{Deserialize, Serialize};
use serde_json::{Number, Value};
use std::hash::Hash;
use std::str::FromStr;

#[derive(Deserialize, Debug, Clone)]
pub struct DcqlQuery {
    pub credentials: Option<Vec<CredentialQuery>>,
    pub credential_sets: Option<Vec<CredentialSetQuery>>,
}

#[derive(Deserialize, Debug, Clone)]
pub struct CredentialQuery {
    pub id: String,
    pub format: String,
    pub multiple: Option<bool>,
    pub meta: Option<Meta>,
    pub trusted_authorities: Option<Vec<TrustedAuthority>>,
    pub require_cryptographic_holder_binding: Option<bool>,
    pub claims: Option<Vec<ClaimsQuery>>,
    pub claim_sets: Option<Vec<Vec<String>>>,
}

#[derive(Deserialize, Debug, Clone)]
#[serde(untagged)]
pub enum Meta {
    IsoMdoc { doctype_value: String },
    SdjwtVc { vct_values: Vec<String> },
}

#[derive(Deserialize, Debug, Clone)]
pub struct TrustedAuthority {
    pub r#type: String,
    pub values: Vec<String>,
}

#[derive(Debug, Clone)]
pub enum Credential {
    DummyCredential(serde_json::Value),
}

#[derive(Clone, Debug)]
pub struct CredentialOptions {
    pub options: Vec<Disclosure>,
}

#[derive(Clone, Debug)]
pub struct Disclosure {
    pub credential: Credential,
    pub claims_queries: Vec<ClaimsQuery>,
}

#[derive(Clone, Debug)]
pub struct CredentialSetOption {
    pub purpose: Option<String>,
    pub set_options: Vec<Vec<SetOption>>,
}
#[derive(Clone, Debug)]
pub struct SetOption {
    pub id: String,
    pub options: Vec<Disclosure>,
}

#[derive(Debug)]
pub enum ParseError {
    Invalid,
}

impl FromStr for Credential {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Ok(s) = serde_json::from_str(s) {
            return Ok(Credential::DummyCredential(s));
        }
        Err(ParseError::Invalid)
    }
}

#[derive(Deserialize, Debug, Clone)]
pub struct ClaimsQuery {
    pub id: Option<String>,
    pub path: Pointer,
    pub values: Option<Vec<Value>>,
}

impl ClaimsQuery {
    pub fn id(&self) -> Option<String> {
        self.id.clone()
    }
}

#[derive(Deserialize, Debug, Clone)]
pub struct CredentialSetQuery {
    pub options: Vec<Vec<String>>,
    #[serde(default = "default_required")]
    pub required: bool,
    pub purpose: Option<Value>,
}

pub const fn default_required() -> bool {
    true
}

pub type Pointer = Vec<PointerPart>;

#[derive(Deserialize, Debug, Clone, PartialEq, Eq, Hash)]
#[serde(untagged)]
pub enum PointerPart {
    String(String),
    Index(u64),
    Null(Option<bool>),
}

impl From<PointerPart> for Value {
    fn from(value: PointerPart) -> Self {
        match value {
            PointerPart::String(s) => Value::String(s.to_string()),
            PointerPart::Index(i) => {
                let Some(n) = Number::from_u128(i as u128) else {
                    return Value::Null;
                };
                Value::Number(n)
            }
            PointerPart::Null(_) => Value::Null,
        }
    }
}

impl From<&str> for PointerPart {
    fn from(value: &str) -> Self {
        Self::String(value.to_string())
    }
}
impl From<usize> for PointerPart {
    fn from(value: usize) -> Self {
        Self::Index(value as u64)
    }
}
impl<T> From<Option<T>> for PointerPart {
    fn from(_value: Option<T>) -> Self {
        Self::Null(None)
    }
}
