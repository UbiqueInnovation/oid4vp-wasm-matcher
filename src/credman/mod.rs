use std::ffi::CString;

use serde::{Deserialize, Serialize};

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

pub fn get_credentials() -> Vec<Credential> {
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
    let Ok(credentials) = serde_json::from_str::<serde_json::Value>(json_str) else {
        return_error("could not parse json");
        return vec![];
    };
    let cs = credentials["credentials"]["mso_mdoc"].as_object().unwrap();
    cs.values()
        .into_iter()
        .flat_map(|a| {
            a.as_array()
                .unwrap()
                .iter()
                .map(|a| Credential::DummyCredential(a["paths"].clone()))
        })
        .collect()
}

pub fn select_credential(c: Credential, attributes: Vec<String>) {
    let Credential::DummyCredential(json) = c;

    // let Some(id) = json.get("id").and_then(|a| a.as_str()) else {
    //     return;
    // };
    // let Some(title) = json.get("title").and_then(|a| a.as_str()) else {
    //     return;
    // };
    let Ok(subtitle) = serde_json::to_string(&json) else {
        return;
    };
    // let Ok(id) = CString::new(id) else { return };
    // let Ok(title) = CString::new(title) else {
    //     return;
    // };
    let Ok(subtitle) = CString::new(subtitle) else {
        return;
    };
    unsafe {
        AddStringIdEntry(
            c"{\"provider_idx\":0, \"id\": 1}".as_ptr(),
            std::ptr::null_mut(),
            0,
            c"selected".as_ptr(),
            subtitle.as_ptr(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        );
        if attributes.is_empty() {
            AddFieldForStringIdEntry(
                c"{\"provider_idx\":0, \"id\": 1}".as_ptr(),
                c"<nothing>".as_ptr(),
                std::ptr::null(),
            );
        }
        for a in attributes {
            let Ok(name) = CString::new(a) else {
                continue;
            };
            AddFieldForStringIdEntry(
                c"{\"provider_idx\":0, \"id\": 1}".as_ptr(),
                name.as_ptr(),
                std::ptr::null(),
            );
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

pub fn get_dc_request() -> Option<DcqlQuery> {
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
    let query =
        match serde_json::from_str::<OpenID4VPRequest>(&query.providers.first().unwrap().request) {
            Ok(q) => q,
            Err(e) => {
                return_error(&format!("2: {e}"));
                return None;
            }
        };
    Some(query.dcql_query.clone())
}

#[derive(Deserialize)]
struct DCRequests {
    providers: Vec<DCRequest>,
}
#[derive(Deserialize)]
struct DCRequest {
    request: String,
}
#[derive(Deserialize)]
struct OpenID4VPRequest {
    dcql_query: DcqlQuery,
}
