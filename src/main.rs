mod credman;
mod dcql;
use credman::{
    get_credentials, get_dc_request, return_error, select_credential, CMWalletDatabaseFormat,
};

#[cfg(target_arch = "wasm32")]
#[global_allocator]
static ALLOC: mini_alloc::MiniAlloc = mini_alloc::MiniAlloc::INIT;

fn main() {
    let credentials = get_credentials(&CMWalletDatabaseFormat);
    let Some((provider_index, query)) = get_dc_request() else {
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
            option
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
        select_credential(
            c.clone(),
            attributes.clone(),
            provider_index,
            &CMWalletDatabaseFormat,
        );
    }
}
