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
use std::{collections::HashMap, ffi::CString};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::dcql::models::{Credential, DcqlQuery};

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct CallingAppInfo {
    pub package_name: [::std::os::raw::c_char; 256usize],
    pub origin: [::std::os::raw::c_char; 512usize],
}

#[link(wasm_import_module = "credman")]
unsafe extern "C" {
    #[link_name = "AddEntry"]
    fn AddEntry(
        cred_id: ::std::os::raw::c_longlong,
        icon: *mut ::std::os::raw::c_char,
        icon_len: usize,
        title: *mut ::std::os::raw::c_char,
        subtitle: *mut ::std::os::raw::c_char,
        disclaimer: *mut ::std::os::raw::c_char,
        warning: *mut ::std::os::raw::c_char,
    );
    fn AddField(
        cred_id: ::std::os::raw::c_longlong,
        field_display_name: *mut ::std::os::raw::c_char,
        field_display_value: *mut ::std::os::raw::c_char,
    );
    fn AddStringIdEntry(
        cred_id: *const ::std::os::raw::c_char,
        icon: *const ::std::os::raw::c_char,
        icon_len: usize,
        title: *const ::std::os::raw::c_char,
        subtitle: *const ::std::os::raw::c_char,
        disclaimer: *const ::std::os::raw::c_char,
        warning: *const ::std::os::raw::c_char,
    );
    fn AddFieldForStringIdEntry(
        cred_id: *const ::std::os::raw::c_char,
        field_display_name: *const ::std::os::raw::c_char,
        field_display_value: *const ::std::os::raw::c_char,
    );
    fn GetRequestBuffer(buffer: *mut u8);
    fn GetRequestSize(size: *mut u32);
    #[link_name = "GetCallingAppInfo"]
    fn GetCallingAppInfo(info: *mut CallingAppInfo);
    fn AddPaymentEntry(
        cred_id: *mut ::std::os::raw::c_char,
        merchant_name: *mut ::std::os::raw::c_char,
        payment_method_name: *mut ::std::os::raw::c_char,
        payment_method_subtitle: *mut ::std::os::raw::c_char,
        payment_method_icon: *mut ::std::os::raw::c_char,
        payment_method_icon_len: usize,
        transaction_amount: *mut ::std::os::raw::c_char,
        bank_icon: *mut ::std::os::raw::c_char,
        bank_icon_len: usize,
        payment_provider_icon: *mut ::std::os::raw::c_char,
        payment_provider_icon_len: usize,
    );
    #[link_name = "GetCredentialsSize"]
    fn GetCredentialsSize(size: *mut u32);
    #[link_name = "ReadCredentialsBuffer"]
    fn ReadCredentialsBuffer(buffer: *mut u8, offset: usize, len: usize) -> usize;
}

pub trait ParseCredential {
    fn parse(&self, input: &str) -> Option<Vec<Credential>>;
}
pub trait ResultFormat {
    fn id(&self, credential_id: &str, provider_index: usize) -> String;
}

pub struct CMWalletDatabaseFormat;

impl ResultFormat for CMWalletDatabaseFormat {
    fn id(&self, credential_id: &str, provider_index: usize) -> String {
        json!({
            "provider_idx": provider_index,
            "id": credential_id
        })
        .to_string()
    }
}
impl ParseCredential for CMWalletDatabaseFormat {
    fn parse(&self, input: &str) -> Option<Vec<Credential>> {
        let Ok(credentials) = serde_json::from_str::<serde_json::Value>(input) else {
            return_error("could not parse json");
            return None;
        };
        let Some(mdocs) = credentials["credentials"]["mso_mdoc"].as_object().cloned() else {
            return None;
        };

        let mut mdocs: Vec<Credential> = mdocs
            .iter()
            .filter_map(|(doc_type, credentials)| {
                let Some(array) = credentials.as_array() else {
                    return None;
                };
                Some(array.iter().map(|a| {
                    let mut a = a.clone();
                    a["document_type"] = Value::String(doc_type.clone());
                    a["credential_format"] = Value::String("mso_mdoc".to_string());
                    Credential::DummyCredential(a)
                }))
            })
            .flatten()
            .collect();
        let Some(sdjwts) = credentials["credentials"]["dc+sd-jwt"].as_object().cloned() else {
            return None;
        };
        let sdjwts: Vec<Credential> = sdjwts
            .iter()
            .filter_map(|(doc_type, credentials)| {
                let Some(array) = credentials.as_array() else {
                    return None;
                };
                Some(array.iter().map(|a| {
                    let mut a = a.clone();
                    a["document_type"] = Value::String(doc_type.clone());
                    a["credential_format"] = Value::String("dc+sd-jwt".to_string());
                    Credential::DummyCredential(a)
                }))
            })
            .flatten()
            .collect();
        mdocs.extend(sdjwts);
        Some(mdocs)
    }
}

pub fn get_credentials(parser: &dyn ParseCredential) -> Vec<Credential> {
    let mut credentials_size: u32 = 0;
    unsafe {
        GetCredentialsSize(&mut credentials_size as *mut u32);
    };

    let mut buffer = vec![0u8; credentials_size as usize];
    unsafe {
        ReadCredentialsBuffer(buffer.as_mut_ptr(), 0, buffer.len());
    };

    let mut json_offset: [u8; 4] = [0, 0, 0, 0];
    json_offset.copy_from_slice(&buffer[..4]);
    let json_offset = u32::from_le_bytes(json_offset) as usize;

    let Ok(json_str) = std::str::from_utf8(&buffer[json_offset..]) else {
        return_error("utf8 errors invalid");
        return vec![];
    };
    parser.parse(json_str).unwrap_or_default()
}

pub fn select_credential(
    c: Credential,
    attributes: Vec<String>,
    provider_index: usize,
    result_format: &dyn ResultFormat,
) {
    let display_data = c.get_display_metadata();

    let Ok(title) = CString::new(display_data.title) else {
        return;
    };
    let Ok(subtitle) = CString::new(display_data.subtitle) else {
        return;
    };
    let id = result_format.id(&display_data.id, provider_index);
    let Ok(id) = CString::new(id) else {
        return;
    };
    unsafe {
        AddStringIdEntry(
            id.as_ptr(),
            std::ptr::null_mut(),
            0,
            title.as_ptr(),
            subtitle.as_ptr(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        );
        if attributes.is_empty() {
            AddFieldForStringIdEntry(id.as_ptr(), c"<nothing>".as_ptr(), std::ptr::null());
        }
        for a in attributes {
            let Ok(name) = CString::new(a) else {
                continue;
            };
            AddFieldForStringIdEntry(id.as_ptr(), name.as_ptr(), std::ptr::null());
        }
    }
}

pub fn return_error(title: &str) {
    let Ok(title) = CString::new(title) else {
        return;
    };
    unsafe {
        AddStringIdEntry(
            c"some_id".as_ptr(),
            std::ptr::null_mut(),
            0,
            title.as_ptr(),
            c"error".as_ptr(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        );
        AddFieldForStringIdEntry(c"some_id".as_ptr(), c"error".as_ptr(), std::ptr::null());
    }
}

pub fn get_dc_request() -> Option<(usize, DcqlQuery)> {
    let mut request_size: u32 = 0;
    unsafe {
        GetRequestSize(&mut request_size as *mut u32);
    }
    let mut buffer = vec![0u8; request_size as usize];
    unsafe {
        GetRequestBuffer(buffer.as_mut_ptr());
    };
    let Ok(json_str) = std::str::from_utf8(&buffer) else {
        return_error("dc not utf8");
        return None;
    };
    let query = match serde_json::from_str::<DCRequests>(json_str) {
        Ok(q) => q,
        Err(e) => {
            return_error(&format!("1: {e}"));
            return None;
        }
    };
    if query.providers.is_empty() {
        return_error(&format!("2 providers empty"));
        return None;
    }
    let Some(first_provider) = query
        .providers
        .iter()
        .enumerate()
        .filter(|(_, a)| matches!(a, Providers::OpenID4VP(_)))
        .next()
    else {
        return_error(&format!("3 no openid4vp provider found"));
        return None;
    };
    let Providers::OpenID4VP(provider) = first_provider.1 else {
        return None;
    };
    let query = match serde_json::from_str::<OpenID4VPRequest>(&provider.request) {
        Ok(q) => q,
        Err(e) => {
            return_error(&format!("2: {e}"));
            return None;
        }
    };
    Some((first_provider.0, query.dcql_query.clone()))
}

#[derive(Deserialize)]
struct DCRequests {
    providers: Vec<Providers>,
}
#[derive(Deserialize)]
#[serde(tag = "protocol")]
pub enum Providers {
    #[serde(rename = "openid4vp")]
    OpenID4VP(DCRequest),
    #[serde(other)]
    Unknown,
}
#[derive(Deserialize)]
struct DCRequest {
    request: String,
}
#[derive(Deserialize)]
struct OpenID4VPRequest {
    dcql_query: DcqlQuery,
}
