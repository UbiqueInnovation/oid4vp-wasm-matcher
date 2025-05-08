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
use std::{any::Any, ffi::CString};

use base64::Engine;
use serde::Deserialize;
use serde_json::Value;

use crate::dcql::{
    models::{Credential, DcqlQuery, Pointer},
    parsers::{CMWalletDatabaseFormat, ParseCredential, ResultFormat, DEBUG},
};

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

#[inline]
pub fn get_credentials(parser: &dyn ParseCredential) -> Vec<Credential> {
    let mut credentials_size: u32 = 0;
    unsafe {
        GetCredentialsSize(&mut credentials_size as *mut u32);
    };

    let mut buffer = vec![0u8; credentials_size as usize];
    unsafe {
        ReadCredentialsBuffer(buffer.as_mut_ptr(), 0, buffer.len());
    };
    let mut jo = 0;
    if let Some(_) = (parser as &dyn Any).downcast_ref::<CMWalletDatabaseFormat>() {
        let mut json_offset: [u8; 4] = [0, 0, 0, 0];
        json_offset.copy_from_slice(&buffer[..4]);
        let json_offset = u32::from_le_bytes(json_offset) as usize;
        jo = json_offset;
        if jo > buffer.len() {
            jo = 0;
        }
    }

    let Ok(json_str) = std::str::from_utf8(&buffer[jo..]) else {
        return_error("utf8 errors invalid");
        return vec![];
    };
    parser.set_debug(json_str);
    let Some(result) = parser.parse(json_str) else {
        return_error("invalid credential format");
        return vec![];
    };
    result
}

#[inline]
pub fn select_credential(
    c: Credential,
    attributes: Vec<(Pointer, String)>,
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
    let mut credentials_size: u32 = 0;
    unsafe {
        GetCredentialsSize(&mut credentials_size as *mut u32);
    };

    let mut buffer = vec![0u8; credentials_size as usize];
    unsafe {
        ReadCredentialsBuffer(buffer.as_mut_ptr(), 0, buffer.len());
    };
    let mut icon = std::ptr::null();
    let mut icon_len = 0;
    if let Some(_) = (result_format as &dyn Any).downcast_ref::<CMWalletDatabaseFormat>() {
        let start = display_data.icon["start"].as_i64().unwrap_or(0) as usize;
        let length = display_data.icon["length"].as_i64().unwrap_or(0) as usize;
        let icon_slice = buffer[start..start + length].to_vec();
        icon = icon_slice.as_ptr() as *const i8;
        icon_len = icon_slice.len();
        std::mem::forget(icon_slice);
    }

    unsafe {
        AddStringIdEntry(
            id.as_ptr(),
            icon,
            icon_len,
            title.as_ptr(),
            subtitle.as_ptr(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        );
        if attributes.is_empty() {
            AddFieldForStringIdEntry(id.as_ptr(), c"<nothing>".as_ptr(), std::ptr::null());
        }
        for (ptr, a) in attributes {
            let claims = c.get_claims();
            let display_name = result_format.get_display_name(&ptr, &claims).unwrap_or(a);
            let display_value = result_format
                .get_value(&ptr, &claims)
                .map(|a| CString::new(a).ok())
                .flatten();

            let Ok(name) = CString::new(display_name) else {
                continue;
            };
            let mut val_ptr = std::ptr::null();
            if let Some(val) = display_value.as_ref() {
                val_ptr = val.as_ptr();
            }
            AddFieldForStringIdEntry(id.as_ptr(), name.as_ptr(), val_ptr);
        }
    }
}

#[inline]
pub fn return_error(title: &str) {
    if !DEBUG.get().unwrap_or(&false) {
        return;
    }
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

#[inline]
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
        Err(_) => {
            return_error(&format!("666: {json_str}"));
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
        return_error(&format!("4 no openid4vp provider found"));
        return None;
    };

    let query = match &provider.request {
        Value::Object(_) => {
            let Some(Value::String(wrapped_request)) = provider.request.get("request") else {
                return_error(&format!("4 request object not found"));
                return None;
            };
            let parts = wrapped_request.split(".").collect::<Vec<_>>();
            if parts.len() != 3 {
                return_error(&format!("!=3 1 base64 decode failed {:?}", parts));
                return None;
            }
            let claims = base64::prelude::BASE64_URL_SAFE_NO_PAD
                .decode(&parts[1])
                .unwrap_or(Vec::new());
            if claims.is_empty() {
                return_error(&format!("!=3 2 base64 decode failed {}", parts[1]));
                return None;
            }
            let Ok(q) = serde_json::from_slice::<OpenID4VPRequest>(&claims) else {
                return_error(&format!(
                    "!=3 3 base64 decode failed {:?}",
                    std::str::from_utf8(&claims)
                ));
                return None;
            };
            q
        }
        Value::String(s) => {
            let mut query = s.to_string();
            if let Ok(wrapped_request) = serde_json::from_str::<WrappedRequest>(s) {
                let parts = wrapped_request.request.split(".").collect::<Vec<_>>();
                if parts.len() != 3 {
                    return_error(&format!("!=3 1 base64 decode failed {:?}", parts));
                    return None;
                }
                let claims = base64::prelude::BASE64_URL_SAFE_NO_PAD
                    .decode(&parts[1])
                    .unwrap_or(Vec::new());
                if claims.is_empty() {
                    return_error(&format!("!=3 2 base64 decode failed {}", parts[1]));
                    return None;
                }
                let Ok(new_query) = std::str::from_utf8(&claims) else {
                    return_error(&format!("!=3 invalid utf8"));
                    return None;
                };
                query = new_query.to_string();
            }

            let Ok(q) = serde_json::from_str::<OpenID4VPRequest>(&query) else {
                return_error(&format!("!=3 3 failed to decode object {:?}", query));
                return None;
            };
            q
        }
        _ => {
            return_error(&format!("4 unsupported data_type {:?}", provider.request));
            return None;
        }
    };
    Some((first_provider.0, query.dcql_query.clone()))
}

#[derive(Deserialize)]
struct DCRequests {
    #[serde(alias = "requests")]
    providers: Vec<Providers>,
}
#[derive(Deserialize)]
#[serde(tag = "protocol")]
pub enum Providers {
    #[serde(rename = "openid4vp")]
    #[serde(alias = "openid4vp-v1-unsigned")]
    #[serde(alias = "openid4vp-v1-signed")]
    OpenID4VP(DCRequest),
    #[serde(other)]
    Unknown,
}
#[derive(Deserialize)]
pub struct DCRequest {
    #[serde(alias = "data")]
    request: serde_json::Value,
}
#[derive(Deserialize)]
struct OpenID4VPRequest {
    dcql_query: DcqlQuery,
}

#[derive(Deserialize)]
struct WrappedRequest {
    request: String,
}
