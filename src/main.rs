use std::{ffi::CString, mem::MaybeUninit};

mod credman;
mod dcql;
use credman::{get_credentials, get_dc_request, return_error, select_credential};
use dcql::models::Credential;

#[cfg(target_arch = "wasm32")]
#[global_allocator]
static ALLOC: mini_alloc::MiniAlloc = mini_alloc::MiniAlloc::INIT;

fn main() {
    let credentials = get_credentials();
    let Some(query) = get_dc_request() else {
        return_error("could not parse dc request");
        return;
    };
    if credentials.is_empty() {
        return_error("no credentials");
        return;
    }
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

    let Some(first) = first_set.options.first() else {
        return_error("dcql selection failed");
        return;
    };
    let c = first.credential.clone();
    let attributes = if first.claims_queries.is_empty() {
        let cred_id = first_set.id.clone();
        query
            .credentials
            .unwrap()
            .into_iter()
            .filter(|a| a.id == cred_id)
            .flat_map(|a| {
                a.claims.unwrap().into_iter().map(|a| {
                    a.path
                        .clone()
                        .into_iter()
                        .map(|a| match a {
                            dcql::models::PointerPart::String(a) => a,
                            dcql::models::PointerPart::Index(i) => i.to_string(),
                            dcql::models::PointerPart::Null(_) => String::from("[]"),
                        })
                        .collect::<Vec<_>>()
                        .join(".")
                })
            })
            .collect()
    } else {
        first
            .claims_queries
            .clone()
            .into_iter()
            .map(|first_query| {
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
                    .join(".")
            })
            .collect::<Vec<_>>()
    };
    select_credential(c, attributes);
}
