use std::any::Any;

use serde_json::{json, Value};

#[cfg(target_arch = "wasm32")]
use crate::credman::return_error;

use super::models::Credential;

pub trait ParseCredential: Any {
    fn parse(&self, input: &str) -> Option<Vec<Credential>>;
}
pub trait ResultFormat: Any {
    fn id(&self, credential_id: &str, provider_index: usize) -> String;
}

pub struct CMWalletDatabaseFormat;
pub struct UbiqueWalletDatabaseFormat;

impl ResultFormat for UbiqueWalletDatabaseFormat {
    fn id(&self, credential_id: &str, provider_index: usize) -> String {
        json!({
            "provider_idx": provider_index,
            "id": credential_id
        })
        .to_string()
    }
}
impl ParseCredential for UbiqueWalletDatabaseFormat {
    fn parse(&self, input: &str) -> Option<Vec<Credential>> {
        let Some(arr) = serde_json::from_str::<Vec<serde_json::Value>>(input).ok() else {
            #[cfg(target_arch = "wasm32")]
            return_error("could not parse json");
            return None;
        };
        Some(
            arr.into_iter()
                .map(|a| Credential::DummyCredential(a))
                .collect(),
        )
    }
}

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
            #[cfg(target_arch = "wasm32")]
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

#[cfg(test)]
mod tests {
    use super::{ParseCredential, UbiqueWalletDatabaseFormat};

    #[test]
    fn test_ubique_credential_format() {
        let u = r#"[ {
          "paths" : {
            "issuance_date" : "2025-04-16T08:09:16Z",
            "expiry_date" : "2025-04-30T08:09:16Z",
            "iss" : "https://heidi-issuer-ws-dev.ubique.ch/d-trust/c/1wkh0tTjA32MnSuC9wuIeM",
            "_sd" : [ "4jSpzVtFdNhRup0OsIxYAHeTC6hhCoyvAacO8LKZFnQ", "KsiY4h3O_2jFIJkJIvHgcFIy2pjmX9TaL1M2AlLvaFw", "Kty8Ii4pZAKXfjIH4rmRjmYHOZl9m69N0WVc3ZFbRk4", "M8vqBt743otgdH8oo89CDVca9Z6WRH8hcWDIgkp9-nw", "MVolgqwDwdYQR_8TSCjKO4wNMWA1pRaIDcj_t774UX0", "THXFW6VDKRLwjiRKLY-zsid-e2DR7PMhptEU9ItVUSA", "VPs0BT5ToRL5Ef5mX1oVdl6MNDZ8JqTxFkVDGogVMJs", "W81aQ99GZnBGEq216I2IQLThqlq0PCRwuYylO8z-1KY", "Wb-pfUFPEMuQHUbvlk-aDGe7eS4WI5GdZVKhyBpauxg", "_tQngOPuKgIbzJN1qLZkqL7tNTU6BDcIRQPaWVP0BtQ", "gb75TLcjOMJDXZBiD04rfEVQ8woTekjnIp2tcp8qN7Y", "oGNb0R5S0nYisij16Rov8O5jrZg-BVA5NUMESS2L27c", "xtj753XufxrmP1Gg1NQMryATAvoPPDXTBOFbPGV_zKw", "yDqPBsIl9H9RzENcbiPdszGFPjaf-VZ6DMUy-RW_pW4", "z96q7FVpBxaOLdLBPHiApv64dR-9sK7tQraMI042euY" ],
            "issuing_country" : "CH",
            "issuing_authority" : "CH",
            "_sd_alg" : "sha-256",
            "cnf" : {
              "jwk" : {
                "kty" : "EC",
                "crv" : "P-256",
                "x" : "RxniEGi3qCPXOTCF6GpstE386wyc4RQsM1rdDvC_-7E",
                "y" : "Q0cbCAKWUrmvD0_uW8QjeFrKwramRAO1ke38DpQp2Ig"
              }
            },
            "exp" : 1746000556,
            "schema_identifier" : {
              "credentialIdentifier" : "ec-pid-tvkyi",
              "version" : "2.0.0"
            },
            "iat" : 1744790956,
            "render" : {
              "type" : "OverlaysCaptureBundleV1",
              "oca" : "https://heidi-issuer-ws-dev.ubique.ch/oca/IHsD7UJ9PvIRaNK47PxtOgwRTp4dCZ7g9ibU-TIEeiTU.json"
            },
            "document_number" : "asdsd",
            "gender" : 1,
            "age_over_18" : true,
            "age_over_16" : true,
            "birth_date" : "Date of Birth",
            "birth_place" : "Place of Birth",
            "given_name" : "Given Name",
            "birth_country" : "Country of Birth",
            "nationality" : "Nationality",
            "age_birth_year" : 1,
            "resident_address" : "Address",
            "resident_country" : "Country of Residence",
            "age_over_21" : true,
            "age_over_65" : true,
            "family_name" : "Familiy Name"
          },
          "credential_format" : "dc+sd-jwt",
          "document_type" : "https://demo.pid-issuer.bundesdruckerei.de/credentials/pid/1.0",
          "id" : 5,
          "title" : "Given Name Familiy Name",
          "subtitle" : "EC ARF compatible PID"
        }, {
          "paths" : {
            "issuance_date" : "2025-04-16T08:09:16Z",
            "expiry_date" : "2025-04-30T08:09:16Z",
            "iss" : "https://heidi-issuer-ws-dev.ubique.ch/d-trust/c/1wkh0tTjA32MnSuC9wuIeM",
            "_sd" : [ "1LOr8NkUxHUB5q1LIcIWCROlGG2KnKj8w78sdw2eok0", "BEus31gYTTy4BzNOzdH91l9L0yPZ2-Edv4fGAbE052c", "GqplLumbSahdJpr9ImLnq-nT3yZDpYygCzYKnY7raqQ", "MQN1Kc9W0Mr6KTF6Nh6lHHgzIbW1B6WvHiWs-QHC69U", "PoL2OJVWFpqm_eMuTxxYt3rGGPuSpQ06C0vDxgTEjRA", "Pzr4DbOu-zQfScoHnBWwr3jGRD57kbKe3Ck-mHfktcw", "Xl6sAN9Oc2dDoKChpo0Z-bnfzqoK7trIPsJr7Gzzn7o", "YdyAsNqKBepRbf7AZZ1trLlv8SqAf5VwFvBx8eKd1QA", "Z6YNr59bW7_NTWp1bqPHk7yQ5oZ173l4na9SmqlKElM", "e1GMpPy8b4LHbWtg9Fg5cqx1zpAQQGiKednp89UaiJU", "kKibzRdS3YtgHiwEozd4Om0NVOAhX2oCDnrQDl-z9Qg", "kQYzUXzIbOALTC-gsFytwZinmxCzDOimYnaS3wIrefA", "rKrVNi1qvUP7lEs0fMaGZOWjEMcjRnwIGeB4DNYL4VM", "txyd0I2_E8Ej3zBSIoCfrxwekk8EacsMsE6_zAbqZ_A", "yTLX70oK4wmOC0aZoFGEc9r5RAKrvYpTNBhMpDH8BTo" ],
            "issuing_country" : "CH",
            "issuing_authority" : "CH",
            "_sd_alg" : "sha-256",
            "cnf" : {
              "jwk" : {
                "kty" : "EC",
                "crv" : "P-256",
                "x" : "xch2RYhuahncU_vsx-sYPIzeadZ_d8YrsLK2Cksx8wM",
                "y" : "eZlvudFq-MCobvesGSvD1lGr8YhhmvxSSiR3Nvd2JtU"
              }
            },
            "exp" : 1746000556,
            "schema_identifier" : {
              "credentialIdentifier" : "ec-pid-tvkyi",
              "version" : "2.0.0"
            },
            "iat" : 1744790956,
            "render" : {
              "type" : "OverlaysCaptureBundleV1",
              "oca" : "https://heidi-issuer-ws-dev.ubique.ch/oca/IHsD7UJ9PvIRaNK47PxtOgwRTp4dCZ7g9ibU-TIEeiTU.json"
            },
            "document_number" : "asdsd",
            "gender" : 1,
            "age_over_18" : true,
            "age_over_16" : true,
            "birth_date" : "Date of Birth",
            "birth_place" : "Place of Birth",
            "given_name" : "Given Name",
            "birth_country" : "Country of Birth",
            "nationality" : "Nationality",
            "age_birth_year" : 1,
            "resident_address" : "Address",
            "resident_country" : "Country of Residence",
            "age_over_21" : true,
            "age_over_65" : true,
            "family_name" : "Familiy Name"
          },
          "credential_format" : "dc+sd-jwt",
          "document_type" : "https://demo.pid-issuer.bundesdruckerei.de/credentials/pid/1.0",
          "id" : 6,
          "title" : "Given Name Familiy Name",
          "subtitle" : "EC ARF compatible PID"
        }, {
          "paths" : {
            "eu.europa.ec.eudi.cor.1" : {
              "expiry_date" : "2025-04-30T08:09:18.504Z",
              "birth_place" : "Place of Birth",
              "age_over_21" : "true",
              "nationality" : "Nationality",
              "given_name" : "Given Name",
              "age_over_16" : "true",
              "issuing_authority" : "CH",
              "age_birth_year" : "1",
              "issuance_date" : "2025-04-16T08:09:18.504Z",
              "age_over_18" : "true",
              "gender" : "1",
              "resident_address" : "Address",
              "issuing_country" : "CH",
              "family_name" : "Familiy Name",
              "document_number" : "asdsd",
              "birth_country" : "Country of Birth",
              "age_over_65" : "true",
              "resident_country" : "Country of Residence",
              "birth_date" : "Date of Birth"
            },
            "exp" : 1746000558
          },
          "credential_format" : "dc+sd-jwt",
          "document_type" : "https://demo.pid-issuer.bundesdruckerei.de/credentials/pid/1.0",
          "id" : 7,
          "title" : "Given Name Familiy Name",
          "subtitle" : "EC ARF compatible PID"
        }, {
          "paths" : {
            "eu.europa.ec.eudi.cor.1" : {
              "age_birth_year" : "1",
              "birth_country" : "Country of Birth",
              "expiry_date" : "2025-04-30T08:09:18.505Z",
              "family_name" : "Familiy Name",
              "age_over_65" : "true",
              "birth_place" : "Place of Birth",
              "age_over_16" : "true",
              "nationality" : "Nationality",
              "resident_address" : "Address",
              "issuance_date" : "2025-04-16T08:09:18.505Z",
              "document_number" : "asdsd",
              "gender" : "1",
              "birth_date" : "Date of Birth",
              "issuing_country" : "CH",
              "resident_country" : "Country of Residence",
              "issuing_authority" : "CH",
              "age_over_18" : "true",
              "given_name" : "Given Name",
              "age_over_21" : "true"
            },
            "exp" : 1746000558
          },
          "credential_format" : "dc+sd-jwt",
          "document_type" : "https://demo.pid-issuer.bundesdruckerei.de/credentials/pid/1.0",
          "id" : 8,
          "title" : "Given Name Familiy Name",
          "subtitle" : "EC ARF compatible PID"
        }, {
          "paths" : {
            "issuance_date" : "2025-04-17T07:27:35Z",
            "expiry_date" : "2025-05-01T07:27:35Z",
            "iss" : "https://heidi-issuer-ws-dev.ubique.ch/d-trust/c/1wkh0tTjA32MnSuC9wuIeM",
            "_sd" : [ "-hhDqRad4Q7x7TtoGYVYA_j5CI4iWLDA5tjSZ1SuDHM", "9WcFso5yJvvjYmndcCFJd6nTrnrp-fxerdkmK0Jw7AE", "9lZQFKCfmv0iPIySSjXOa7-4QUAIZN43-TYJBQX_BX8", "DQjs999sttC63qA0XobQIR7FoBMthpvDhthrzfBo6FA", "Dfq2HZtndCjqIcGm_CsIoEstaN_BSvRMOpmdgK1QVZI", "Fd7BSG0GDGc3dq4KQ2Or0nB8P1TBIlbCUQT1-mxHmoY", "PMTC7_Nh4Xq1WYthqqSABhVm5yLBCXQ0LjhDLeLQit0", "RjJ6upq6BCG0zfzG11DwJYWPcxZG5wNYKsB6xyKIBWU", "VjzbaK01yZUgHmnT-fsAePgGnnT2Pxf-JbwWL-U5zK4", "hsLbgkKE3GE9JjXz96FGzs9f5Y5q7f9EjafGzbBB-dU", "hstF5aIuUB3PC51zeNFpp-s9VaQkCqJw4aASfinuqKo", "jWQmQZgRv-nMwqPKa5wVvnWrsLtfEXCM59di3_bRflc", "mqQPv0Hy27yAlOGQdPGdkG02Kw55x-qagtOKm86--d4", "uHxnphXXAfeMgb1KN2yfrDmSLJeeLkZLnLGZOHbFDlQ", "wiBnyCE37mA5c5ZQoo07EMGRRhbw9oVuwUYPddbk8tQ" ],
            "issuing_country" : "CH",
            "issuing_authority" : "CH",
            "_sd_alg" : "sha-256",
            "cnf" : {
              "jwk" : {
                "kty" : "EC",
                "crv" : "P-256",
                "x" : "4n9ZUPgQIa6cWqzWnZJzSez7rOPObLcNVo5IFv5eqB0",
                "y" : "GPzwQsBKy3xYNwICaGifoFV0Bf-c9mWMCvjSFmVa0YU"
              }
            },
            "exp" : 1746084455,
            "schema_identifier" : {
              "credentialIdentifier" : "ec-pid-tvkyi",
              "version" : "2.0.0"
            },
            "iat" : 1744874855,
            "render" : {
              "type" : "OverlaysCaptureBundleV1",
              "oca" : "https://heidi-issuer-ws-dev.ubique.ch/oca/IHsD7UJ9PvIRaNK47PxtOgwRTp4dCZ7g9ibU-TIEeiTU.json"
            },
            "document_number" : "asdsd",
            "gender" : 1,
            "age_over_18" : true,
            "age_over_16" : true,
            "birth_date" : "Date of Birth",
            "birth_place" : "Place of Birth",
            "given_name" : "Given Name",
            "birth_country" : "Country of Birth",
            "nationality" : "Nationality",
            "age_birth_year" : 1,
            "resident_address" : "Address",
            "resident_country" : "Country of Residence",
            "age_over_21" : true,
            "age_over_65" : true,
            "family_name" : "Familiy Name"
          },
          "credential_format" : "dc+sd-jwt",
          "document_type" : "https://demo.pid-issuer.bundesdruckerei.de/credentials/pid/1.0",
          "id" : 13,
          "title" : "Given Name Familiy Name",
          "subtitle" : "EC ARF compatible PID"
        }, {
          "paths" : {
            "eu.europa.ec.eudi.cor.1" : {
              "age_birth_year" : "1",
              "resident_country" : "Country of Residence",
              "age_over_18" : "true",
              "issuing_country" : "CH",
              "gender" : "1",
              "birth_date" : "Date of Birth",
              "age_over_21" : "true",
              "document_number" : "asdsd",
              "age_over_16" : "true",
              "birth_country" : "Country of Birth",
              "expiry_date" : "2025-05-01T07:27:36.372Z",
              "issuance_date" : "2025-04-17T07:27:36.372Z",
              "birth_place" : "Place of Birth",
              "issuing_authority" : "CH",
              "family_name" : "Familiy Name",
              "resident_address" : "Address",
              "nationality" : "Nationality",
              "age_over_65" : "true",
              "given_name" : "Given Name"
            },
            "exp" : 1746084456
          },
          "credential_format" : "dc+sd-jwt",
          "document_type" : "https://demo.pid-issuer.bundesdruckerei.de/credentials/pid/1.0",
          "id" : 14,
          "title" : "Given Name Familiy Name",
          "subtitle" : "EC ARF compatible PID"
        }, {
          "paths" : {
            "issuance_date" : "2025-04-16T08:38:27Z",
            "expiry_date" : "2025-04-30T08:38:27Z",
            "iss" : "https://heidi-issuer-ws-dev.ubique.ch/zvv/c/6AzYnNRHjIJ55OBFQkh0Zq",
            "_sd" : [ "9lTVg4TskqXJmBlN7DfUCbnqn8LRZDw-d1bJHTtCRd4", "MmGHVuqGyLMzCwDzkaZ6z5r90JyecMjYu5doC2YVqtM" ],
            "issuing_country" : "CH",
            "issuing_authority" : "CH",
            "_sd_alg" : "sha-256",
            "cnf" : {
              "jwk" : {
                "kty" : "EC",
                "crv" : "P-256",
                "x" : "BE3e076FdVyeD9jXfvpeyMQL7d_MzioJJdvuz8b1lDc",
                "y" : "tntEXCsyCxSm8Z1kXWz9ZmhYCj9NasDeIUUhksvWSxU"
              }
            },
            "exp" : 1746002307,
            "schema_identifier" : {
              "credentialIdentifier" : "asdasd-rom0o",
              "version" : "2.1.0"
            },
            "iat" : 1744792707,
            "render" : {
              "type" : "OverlaysCaptureBundleV1",
              "oca" : "https://heidi-issuer-ws-dev.ubique.ch/oca/IApG6LBGzVPUXR1AH4GjwLN0CSGk6LthombPy_soDhol.json"
            },
            "isReal" : "asd",
            "blubber" : "asd"
          },
          "credential_format" : "dc+sd-jwt",
          "document_type" : "test-jwt",
          "id" : 9,
          "title" : "Yes!",
          "subtitle" : "asd"
        }, {
          "paths" : {
            "issuance_date" : "2025-04-16T08:38:27Z",
            "expiry_date" : "2025-04-30T08:38:27Z",
            "iss" : "https://heidi-issuer-ws-dev.ubique.ch/zvv/c/6AzYnNRHjIJ55OBFQkh0Zq",
            "_sd" : [ "lQnbipmTHPNntjHeHWW213ygohm3JV2YKbP195qyeVQ", "uxfBxYRwSHe10KeTh9J4Jd7R_MWD1i3Pwq-IrtW2ddA" ],
            "issuing_country" : "CH",
            "issuing_authority" : "CH",
            "_sd_alg" : "sha-256",
            "cnf" : {
              "jwk" : {
                "kty" : "EC",
                "crv" : "P-256",
                "x" : "m5jaTFurCxXbHDCTegrJiV2pBxN8GYYs7kW6dKuYmJ8",
                "y" : "GCeGfSDml3nhSx4MA15lNRzqPJWWaf5YlNJZoMJJLOI"
              }
            },
            "exp" : 1746002307,
            "schema_identifier" : {
              "credentialIdentifier" : "asdasd-rom0o",
              "version" : "2.1.0"
            },
            "iat" : 1744792707,
            "render" : {
              "type" : "OverlaysCaptureBundleV1",
              "oca" : "https://heidi-issuer-ws-dev.ubique.ch/oca/IApG6LBGzVPUXR1AH4GjwLN0CSGk6LthombPy_soDhol.json"
            },
            "isReal" : "asd",
            "blubber" : "asd"
          },
          "credential_format" : "dc+sd-jwt",
          "document_type" : "test-jwt",
          "id" : 10,
          "title" : "Yes!",
          "subtitle" : "asd"
        }, {
          "paths" : {
            "ch.mytest.1" : {
              "issuing_authority" : "CH",
              "isReal" : "asd",
              "issuing_country" : "CH",
              "issuance_date" : "2025-04-16T08:38:28.31Z",
              "expiry_date" : "2025-04-30T08:38:28.31Z",
              "blubber" : "asd"
            },
            "exp" : 1746002308
          },
          "credential_format" : "dc+sd-jwt",
          "document_type" : "test-jwt",
          "id" : 11,
          "title" : "Yes!",
          "subtitle" : "asd"
        }, {
          "paths" : {
            "ch.mytest.1" : {
              "isReal" : "asd",
              "issuing_authority" : "CH",
              "expiry_date" : "2025-04-30T08:38:28.311Z",
              "blubber" : "asd",
              "issuing_country" : "CH",
              "issuance_date" : "2025-04-16T08:38:28.311Z"
            },
            "exp" : 1746002308
          },
          "credential_format" : "dc+sd-jwt",
          "document_type" : "test-jwt",
          "id" : 12,
          "title" : "Yes!",
          "subtitle" : "asd"
        }, {
          "paths" : {
            "_sd" : [ "0iPZTaQ8UfI7yP7qJUUm1CHu8cf3P-FHVwwKgU818Pc", "1iCv7HKGxFg9a6KBgKvlxRKBz0I3dNnATa54ibolD9M", "45OwOyscvpzenly6XoMQZtKfINKM8mcaXYb41aqMb4E", "E5yMQGgz7P05p-AAn8zkA7YzhJbnO-b2-B9wREwyOyE", "EHzyWurxGUmvhgP9nbfx4jFjUMhLTGZHOTDuScie0KI", "IvOW4PM92oEMcP3hI6oiE3nX-rCEcsXYwlRXOQXqeng", "Jx4HGoSPKwaQ1sdO1bT4DpGBJFnkJV1YtUwNLXOFkEQ", "LLRjTaHF-2ni5qpwwE9BehmZ3K-JFo0Y8AvTAr5MHRM", "RN4_4AOmjJuxB4NhNJO7laq03014Yc5Hrb3CgqNukTs", "SuALf7gEMAZnR_eysgANtM0aSB95F_Ppjs5eekNqZkQ", "SwN-UvGx8B7pkQk1TDyarlzT1wENc8cs6kUltLnMgys", "Wx3oDJPfuwGYkYUjrpJEbKQk9WYDXDS5xPfRiul30Bw", "aE9Fdc-JEPyQLYaeeZddN1L1hIjV9FSfqd8R1CcZl9s", "aX2zGJ7UWWwsWaMbF1JipB3yJL4phbFE0fgjjvLcp20", "b6IAILqTXQu-mZmpSFUNMynv1mcXDnCMM-aUUZrB69M", "cEZPxo3OeGYZx1o_fqM1_az3P2ISubf_5FRGesH1Xnw", "cwhIlhcKIX4j5gwgka26FLPI3E0x1K7c22hlsu7DLV0", "fQT879WfCPONBosnO2bKTO2VIa5tCTHdHAqF4idsElQ", "kwPmfpuXe5NkTxH0bYO4GDCzs2sN6cUj8YaWhQ7DenY", "lDnPavmCtpTLCvBUHww9lBcFku52Mfh27AM5fadsHPA", "ub8OjkZpNUHf-P2RNhDsplLIp-unMNpxNeAMHG9mZ94", "w6gL9c5DVLn9TqwHu96qOqbr_XYtEna9Pfe38PH2nSY", "ycF2TIqQbgk707-Uq6w9QJI-yuZqNe3aYB7Wr0BlILo" ],
            "_sd_alg" : "sha-256",
            "iss" : "did:tdw:QmPEZPhDFR4nEYSFK5bMnvECqdpf1tPTPJuWs9QrMjCumw:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:9a5559f0-b81c-4368-a170-e7b4ae424527",
            "cnf" : {
              "kty" : "EC",
              "crv" : "P-256",
              "x" : "7UzFpICYTSg5ifD_HYgZOLX3hytnlR5stZzfBASqc2c",
              "y" : "glCw98SPS2Luc1_jCob6qeJTRAzWjgq8gRMHYHtn5EI"
            },
            "iat" : 1744876712,
            "status" : {
              "status_list" : {
                "type" : "SwissTokenStatusList-1.0",
                "uri" : "https://status-reg.trust-infra.swiyu-int.admin.ch/api/v1/statuslist/ee024ad7-8315-4591-89bd-bd9d230f8403.jwt",
                "idx" : 1525
              }
            },
            "issuance_date" : "2025-04-17",
            "document_number" : "BETA-ID-NQBSL3PX",
            "age_over_18" : "true",
            "reference_id_type" : "Self-Declared",
            "birth_date" : "1988-06-19",
            "sex" : "1",
            "age_over_16" : "true",
            "expiry_date" : "2025-07-17",
            "personal_administrative_number" : "756.6199.0539.28",
            "birth_place" : "Vallorbe",
            "verification_type" : "Self-Service",
            "given_name" : "Marco Elio",
            "portrait" : "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",
            "additional_person_info" : "Allianzname: Prumaz-Magnin",
            "place_of_origin" : "Echallens VD",
            "nationality" : "CH, FR",
            "age_birth_year" : "1988",
            "issuing_country" : "CH",
            "issuing_authority" : "Beta Credential Service BCS",
            "verification_organization" : "Beta Credential Service BCS",
            "family_name" : "Prumaz",
            "age_over_65" : "false",
            "reference_id_expiry_date" : "2030-04-17"
          },
          "credential_format" : "dc+sd-jwt",
          "document_type" : "betaid-sdjwt",
          "id" : 15,
          "title" : "Prumaz Marco Elio",
          "subtitle" : "Beta ID"
        }, {
          "paths" : {
            "address" : {
              "_sd" : [ "1GLR2Gsb4Pw9-WjpHBkg8u2Hgj0fFntGX4gHc3GDJOY", "6Y8kbGTe-4Y35nQEdtIQ4gvHGUjBM6NLBSslSj5TBtA", "D96M6l786Iml2mkMPClfFrWv3ItkUNbHBHFUVmEQnZM", "FKQW-P82RBpMux86cVJgBvy_mNfYlmqyA6Zk-RrFOMc" ],
              "locality" : "KÖLN",
              "country" : "DE",
              "postal_code" : "51147",
              "street_address" : "HEIDESTRAẞE 17"
            },
            "iss" : "https://demo.pid-issuer.bundesdruckerei.de/c1",
            "place_of_birth" : {
              "_sd" : [ "Ue0Vo-3cOgzMTGWbPiZBRzxQSkwFVoxwX5xEUEtBk7k" ],
              "locality" : "BERLIN"
            },
            "_sd" : [ "1H4S3TKvi14BO2ofz_Ye9VzYTwc1PFgbtjGAErdh1Lg", "5N9w_V2XkoHjTm4Wngalk8634F4h19VQjkk0IdtbhUY", "DRjTCdpQa_xcQDcm9WYOJ0GOAb82ytPKaNghqzmtl2w", "JHO9I4bSFiL99SXJyznGgdAZdzQpjBwQ4eO5rsUdyEU", "iYEH-g5-j55ie5itWQT6EopSn0JiGbz-LM-cmAMP4D4", "nvR_2mCTa_KQaPyzstyGdImRbNmOqsCO7a7uRFy2kFU", "seVHqAk_MLJNJhkNvsrjPnI_tjUBR9ZHSM3aNMHAL_0" ],
            "issuing_country" : "DE",
            "issuing_authority" : "DE",
            "_sd_alg" : "sha-256",
            "cnf" : {
              "jwk" : {
                "kty" : "EC",
                "crv" : "P-256",
                "x" : "ZlFFYGXQv7vRG4wq8s96bj205gDMTleHlL4eCdB4rfc",
                "y" : "pmeZxicehLzIjPFn40V-7yTj2zukKxjAGTxmlVS7aWk"
              }
            },
            "exp" : 1746090238,
            "iat" : 1744880638,
            "status" : {
              "status_list" : {
                "uri" : "https://demo.pid-issuer.bundesdruckerei.de/status/46bfc37a-3764-406e-8b4b-366e6f8c0b83",
                "idx" : 12
              }
            },
            "age_equal_or_over" : {
              "_sd" : [ "0GVxf1Q5B2mIyGwp3W6kNo9kWpezKJRh2DU4r-5FzkQ", "EjezwpTol4M63ogqITmcpuj1kVYHam_J-ho8Edpxw6w", "IpEocUXWO5FTeM00wKDACQ4fR8l6V-c2q_k_rENvjf0", "WQIivSiQII14Z4lDP_eiwTDL2M1wrg1QZdkhTYXrnYk", "XUd1IdrXYIaKn7BKMb6rhlaDDtmLdsevE1gJywY5tcw", "cqbabTKeHFbQZF2JkfbDl8wAlEi9-aL81cNHuv7ZeBg" ],
              "12" : true,
              "14" : true,
              "16" : true,
              "18" : true,
              "21" : true,
              "65" : false
            },
            "family_name" : "MUSTERMANN",
            "given_name" : "ERIKA",
            "birthdate" : "1964-08-12",
            "age_birth_year" : 1964,
            "age_in_years" : 60,
            "birth_family_name" : "GABLER",
            "nationalities" : [ "DE" ]
          },
          "credential_format" : "dc+sd-jwt",
          "document_type" : "https://demo.pid-issuer.bundesdruckerei.de/credentials/pid/1.0",
          "id" : 16,
          "title" : "MUSTERMANN ERIKA",
          "subtitle" : "ID Card"
        }, {
          "paths" : {
            "address" : {
              "_sd" : [ "G9OBI8MvWDN5u-UXiFafwOj-YysjNV_4YSzC2Gr8Cjk", "LwOohde0_bFMTKyGQGHyaClvb8Q_YxomFvyYwraVPXM", "quqjIrp_Nk9IvBmN6zh1r43Sm2UvIaltgFznsuKMQ9I", "r2Viofpi4kaGQrVF4Baop23W94MLCb6--Y-hvK68GjM" ],
              "locality" : "KÖLN",
              "country" : "DE",
              "postal_code" : "51147",
              "street_address" : "HEIDESTRAẞE 17"
            },
            "iss" : "https://demo.pid-issuer.bundesdruckerei.de/c1",
            "place_of_birth" : {
              "_sd" : [ "bL7VFlIPEH9M96770W_7i0HgJRg9YHr5vOIBgzI_zQc" ],
              "locality" : "BERLIN"
            },
            "_sd" : [ "Lw7IbMPn26bi-7_sHdU5EfFD-x0cN9iBTRfK-QNO3zU", "P_074rsCOF68ALoLvnrpNTt5UMtfnTUJcCqxRO-AE4c", "Po4_HiL-Ep2NMTu1V4_tsTQr8qp9uKBFBbaVyKNxVNU", "RRaV9GMZnQXBPmaInbPjMHyah-yyaptJ4dNZjtwNpYI", "YCNyAhBdiZEZU7QC_330pW1omDoFrNXBpFEaLNaGwos", "YDgCbkxAuYBf028lt0aeFxwEcdfk2UlcoQaECAWiF90", "ljK9-NbPVgcTY3Ruho-wKDuHzYuZ7eZnhsrHQLeAiJ0" ],
            "issuing_country" : "DE",
            "issuing_authority" : "DE",
            "_sd_alg" : "sha-256",
            "cnf" : {
              "jwk" : {
                "kty" : "EC",
                "crv" : "P-256",
                "x" : "RRsOZgjHOmxGapcUTe9kz4KCjcBDbCgW_arykY6dq0U",
                "y" : "eF2yp3nv6fV58TnEuMwlkMujyX0Ze1hkprGRUBGSyRI"
              }
            },
            "exp" : 1746090238,
            "iat" : 1744880638,
            "status" : {
              "status_list" : {
                "uri" : "https://demo.pid-issuer.bundesdruckerei.de/status/46bfc37a-3764-406e-8b4b-366e6f8c0b83",
                "idx" : 10
              }
            },
            "age_equal_or_over" : {
              "_sd" : [ "5tPtnA0rKwLmJd0qyqvRgnnRwI-1OdKpIZwHL7BmhRM", "E1Fv6SliUBYAvUVpwEaLG9Vc6iA87m3N_wyy-VihqdU", "Ljpq0dkq2qZd6kNX6E9Rh-hGbvvom_65YeaHXCLxHmI", "TW2UvsrliY6EM-XHt__RBD_3sb85FZSQeV3q9zJartg", "igxd9jPuBMTQHcGAZM0nTHP8SWUXRcdInT-c3SQC734", "k1GjzmjAA1L6lWRtd7rYvv-uCz5dDvBVfARehwveXKs" ],
              "12" : true,
              "14" : true,
              "16" : true,
              "18" : true,
              "21" : true,
              "65" : false
            },
            "family_name" : "MUSTERMANN",
            "given_name" : "ERIKA",
            "birthdate" : "1964-08-12",
            "age_birth_year" : 1964,
            "age_in_years" : 60,
            "birth_family_name" : "GABLER",
            "nationalities" : [ "DE" ]
          },
          "credential_format" : "dc+sd-jwt",
          "document_type" : "https://demo.pid-issuer.bundesdruckerei.de/credentials/pid/1.0",
          "id" : 17,
          "title" : "MUSTERMANN ERIKA",
          "subtitle" : "ID Card"
        }, {
          "paths" : {
            "address" : {
              "_sd" : [ "4QjqdB5lvtHHTfXCEI7xqaXdBAkZOL7X_phCyO5iMAQ", "PAjCOUlp_Hmkq4N2I3kyivDlea06MKD3owA49zHpjbk", "v5DsDJ3Jehd7nCfFnYMkDZHNPQzjIkUcrMpJv3iAD7w", "vIAF3Qm3bdWuxZICvpBiyHbD6J1_Ls3IldyRNM79ylM" ],
              "locality" : "KÖLN",
              "country" : "DE",
              "postal_code" : "51147",
              "street_address" : "HEIDESTRAẞE 17"
            },
            "iss" : "https://demo.pid-issuer.bundesdruckerei.de/c1",
            "place_of_birth" : {
              "_sd" : [ "GoVp8OkqJYNMuh66-vLABiBSgZStJDukbf8Lvll8-ec" ],
              "locality" : "BERLIN"
            },
            "_sd" : [ "-O3uSqVMsXfH4rcF2ICJyqJqyqtty9K6RDfn4w_41Ss", "4-pa7xPWUnn-jBOXsvw94r3IhW656KrypA_ozffm1Ec", "JQJkMNad7x61ZJhEH3VkOtR2E9DVikE8BG1W29_FdDM", "gmOWWG8KLfyctuT1KoAGzdFEerr8BIzokKmlUs_3mXg", "oxCKksJmdlIqWrG_NhionVP1lja7sydhsGXd2z7rfCo", "rfLjvxejB7fN3oRJadvg0-eGoLUcd03jEGZSdq0tx4s", "sqo3RqY5guzkylRTE6dIt0IAGts3c5pAVxmfyX802mo" ],
            "issuing_country" : "DE",
            "issuing_authority" : "DE",
            "_sd_alg" : "sha-256",
            "cnf" : {
              "jwk" : {
                "kty" : "EC",
                "crv" : "P-256",
                "x" : "oUSjrpgMbHurF27BdJOBaHySFil3vQaCZvL-w-455fA",
                "y" : "T9CCbwYVcwmtLwlvdi5T3wGLpQq-e7Uraq0f9oKXyN4"
              }
            },
            "exp" : 1746090238,
            "iat" : 1744880638,
            "status" : {
              "status_list" : {
                "uri" : "https://demo.pid-issuer.bundesdruckerei.de/status/46bfc37a-3764-406e-8b4b-366e6f8c0b83",
                "idx" : 44
              }
            },
            "age_equal_or_over" : {
              "_sd" : [ "-3rPXKQRC8q59SHuKeDRiMTl1cUkkbAXgG90VoZKhHI", "-_-jYzco6N2O7TZC994ic9OM72bX8b_8oRHNBtilPkU", "AEtHKJgO3DT4ArxAuV389H7aazZiuEebK6kmxS_Dpxw", "CpFiezSQgzdQ1hF3O7ATWkvfsS_fxqbEzuI6sNome4g", "qM9aD3aS6oEy5iFm6MsylZ1gvehJ0JWPv111T-XIfdc", "qrTV2C0U9lODUzcSw-MNUQPRdjG4oPY-R0GUzemW0gU" ],
              "12" : true,
              "14" : true,
              "16" : true,
              "18" : true,
              "21" : true,
              "65" : false
            },
            "family_name" : "MUSTERMANN",
            "given_name" : "ERIKA",
            "birthdate" : "1964-08-12",
            "age_birth_year" : 1964,
            "age_in_years" : 60,
            "birth_family_name" : "GABLER",
            "nationalities" : [ "DE" ]
          },
          "credential_format" : "dc+sd-jwt",
          "document_type" : "https://demo.pid-issuer.bundesdruckerei.de/credentials/pid/1.0",
          "id" : 18,
          "title" : "MUSTERMANN ERIKA",
          "subtitle" : "ID Card"
        }, {
          "paths" : {
            "address" : {
              "_sd" : [ "7anZegWzAUKgotl8CRF6qMg0nxWZiYLWLFI7D_rsZbE", "He5kxMtMYfFW5bDhWcupKcFqESqqxTihZ6VI-Ljq268", "WH_uFRoE15fLkPs0Mej3iT3pCmnmc49_CmCXTj04vTc", "dFdG6qMaA_dn8Inea8PwtUr3DsHFKC8Ees_9cEnQ0BI" ],
              "locality" : "KÖLN",
              "country" : "DE",
              "postal_code" : "51147",
              "street_address" : "HEIDESTRAẞE 17"
            },
            "iss" : "https://demo.pid-issuer.bundesdruckerei.de/c1",
            "place_of_birth" : {
              "_sd" : [ "qD4ehiPag7nItjxbW_UFfd-UWQSm_wbRumCxdMIlOK4" ],
              "locality" : "BERLIN"
            },
            "_sd" : [ "06E6mLmEqpcjJaQ0ZXIVhP7oHtUj7N3sTIDuvXC17DQ", "4wwa1ylVk9Vb2dedwwwspG5QwTJSGFGiZcFX1fAavFM", "8tVYl0dxmYQeVCmACdMRQ_HMRcKweKVKOqS1-1kO0do", "93xat5hcpOZTvAn2Kjf0uT4DLv4JYa0x2aa3d4B-_rg", "94RfrN2tlg5kxUuV-OINznG4c2dpwnXFRv_Qx4eUEJY", "ADVZucqKDt37qn65o9q29gogdxC-OwHx2bxDLioN3wc", "sx-oiToOvNORSdn3p5vydyNRTCQpuLQZ1iaMehygXYo" ],
            "issuing_country" : "DE",
            "issuing_authority" : "DE",
            "_sd_alg" : "sha-256",
            "cnf" : {
              "jwk" : {
                "kty" : "EC",
                "crv" : "P-256",
                "x" : "bi_55HxZxobyo_T6Mz8A_9OyptRaruS6O9EKjmfljjY",
                "y" : "nMjkkgZ_BPt8hVdjG13KAgR0VNAj5Q3Udsy7vzGfux4"
              }
            },
            "exp" : 1746090238,
            "iat" : 1744880638,
            "status" : {
              "status_list" : {
                "uri" : "https://demo.pid-issuer.bundesdruckerei.de/status/46bfc37a-3764-406e-8b4b-366e6f8c0b83",
                "idx" : 105
              }
            },
            "age_equal_or_over" : {
              "_sd" : [ "5gfpR55hcWkvtb4zXQvQCSbVtKYzt5LmRFeC-d04lnM", "Jv2TQMQ9vvsnM_0YZlIbjOhPvJCWHmF9nPlFu4sAjmc", "QBu5DAEXra_i5XlQWMcgfnRyJIJU8-6U5NlNqWXG8vI", "TGdoZ6csbD5aSSu02nsBx47lBm9j-H0ZSWXVZvccIL0", "VNvZGnRhqf8zw6x6zMM32yTlc5ssFx7hpTRG1H3Rux0", "cWoTOsuaxMtDN4LK4cZoZDWYhX1ukls6XicGae_Mx1Q" ],
              "12" : true,
              "14" : true,
              "16" : true,
              "18" : true,
              "21" : true,
              "65" : false
            },
            "family_name" : "MUSTERMANN",
            "given_name" : "ERIKA",
            "birthdate" : "1964-08-12",
            "age_birth_year" : 1964,
            "age_in_years" : 60,
            "birth_family_name" : "GABLER",
            "nationalities" : [ "DE" ]
          },
          "credential_format" : "dc+sd-jwt",
          "document_type" : "https://demo.pid-issuer.bundesdruckerei.de/credentials/pid/1.0",
          "id" : 19,
          "title" : "MUSTERMANN ERIKA",
          "subtitle" : "ID Card"
        }, {
          "paths" : {
            "address" : {
              "_sd" : [ "A6zO1HatagDiMeCLPXbcR0DLzUnEBVsTu_2SDuTOnGs", "HSpcGmDYstaKONsd7COovub5Z1PXCeuUlsuXYDy743Y", "fhHT8kSKZONKeJY72Yi5K-7UOld-FAt15RSDxBWjNEs", "rOqAaizu249Tyg8MjpmpQGgvQG6qGsUJlW5llTHrVJc" ],
              "locality" : "KÖLN",
              "country" : "DE",
              "postal_code" : "51147",
              "street_address" : "HEIDESTRAẞE 17"
            },
            "iss" : "https://demo.pid-issuer.bundesdruckerei.de/c1",
            "place_of_birth" : {
              "_sd" : [ "eoJra6wA1ewI-0qVdu83MseLTbH-3O9h28bxPmgMOFg" ],
              "locality" : "BERLIN"
            },
            "_sd" : [ "3xrvWmEo_KDIuHw6JFQyVG3icL7F5LrNN_oCuRtJ5Fw", "8pTscdKFwUvp3BwDUaGcVUPJaYzVfYZ6on-7MWndFow", "DXZufcJKZeZlpsWON3qSM27SRztVe-XY_nQ3Ld_VF_M", "aXyQNKknzKFIVaixX9I3IBeZJdROkUN4micpTW-DZnw", "wG9viXkkCaVGKYGqcQERKvE1XnnZVWAjS5Ds2mI-wDA", "z6BHQ9vNKl9CYK6Kyvt95hLe3EW-lnBsyLYbSO2hoFU", "zEgCyT1R-w-Bk5tIe4waa4PQ8sSFsICiE40_EjfXdTE" ],
            "issuing_country" : "DE",
            "issuing_authority" : "DE",
            "_sd_alg" : "sha-256",
            "cnf" : {
              "jwk" : {
                "kty" : "EC",
                "crv" : "P-256",
                "x" : "cP1jbN4If7DxGuOoRIzts2OQ0w2Xe5-FT4meRKBLg-E",
                "y" : "4Up2a0m11CWasb5xKlXTur15Z59p4fOE8oxOepg48u8"
              }
            },
            "exp" : 1746090238,
            "iat" : 1744880638,
            "status" : {
              "status_list" : {
                "uri" : "https://demo.pid-issuer.bundesdruckerei.de/status/46bfc37a-3764-406e-8b4b-366e6f8c0b83",
                "idx" : 8
              }
            },
            "age_equal_or_over" : {
              "_sd" : [ "1x5RTcI-U-H6r8HYI9KT-afuUP-wVld2v65xgu9V3SQ", "7EPuDf8mReJZJL08IUMRlBZxUpZYcF5je4fp-pyhxFI", "G9xr-CE5Wt3dYC_EPMjxRw-XmCdRISVRx9Ja2NKssiA", "TuQMuIQCOQhGkb38Ag8I_Vv9ZDoIo1xZWD1I_SceqA0", "iRIYU0iyCaQPtkrM3w12FGqn3X-uwJie6goDqVbz6GE", "jwAuyJV_7R12aTaQjAElb1oHUPJHM6yZ0ZBmXynEDFs" ],
              "12" : true,
              "14" : true,
              "16" : true,
              "18" : true,
              "21" : true,
              "65" : false
            },
            "family_name" : "MUSTERMANN",
            "given_name" : "ERIKA",
            "birthdate" : "1964-08-12",
            "age_birth_year" : 1964,
            "age_in_years" : 60,
            "birth_family_name" : "GABLER",
            "nationalities" : [ "DE" ]
          },
          "credential_format" : "dc+sd-jwt",
          "document_type" : "https://demo.pid-issuer.bundesdruckerei.de/credentials/pid/1.0",
          "id" : 20,
          "title" : "MUSTERMANN ERIKA",
          "subtitle" : "ID Card"
        }, {
          "paths" : {
            "address" : {
              "_sd" : [ "B1tobLWImKHpSzIs9UCboe_UEMqe-V14qAH1Vto7Gw0", "Wgv1iTBeU2HRwnT85zCGnW1reXiUYeoX-MeuOXR1xFk", "k4VBRqVeam1MpZ8Cmnwq_6B2QbnGUx4siXWAu0Tdagg", "vQ2b3UwNNzOlKTQHnUznu6yaEZngjc-lREKimGFVw0o" ],
              "locality" : "KÖLN",
              "country" : "DE",
              "postal_code" : "51147",
              "street_address" : "HEIDESTRAẞE 17"
            },
            "iss" : "https://demo.pid-issuer.bundesdruckerei.de/c1",
            "place_of_birth" : {
              "_sd" : [ "XzYt-cFCjWJ0-rrDgcnrQ_vVsRJNBAjR4Mr_FPeLntc" ],
              "locality" : "BERLIN"
            },
            "_sd" : [ "BKtE9UzobOTLfK1qgTpDZSr_8_ZYwzaDCtinleJRo4U", "_817TozaDuOyG8aEEH2oCRcVzYd9X0X_xAHrXW6e318", "msMMSTgXuOo57nNaXQYHPbFwWayKIwH9s5Lijrw67aI", "oN63iMxg2AXAbGhotZkgxz3avZKfV6rjR_EDwEtCs7c", "oOOvSEws3SRNi90QQ2zaHuQ2N5LI4JQFkuwPOa0IM50", "u2YSG0rvyv43hfneu83bfK1vyokfAwRxxvS-aUfM3Bs", "xVuYMO3bZBglVQ0vfzg0pSVEVjkdz5AaA6SbWuMDnT0" ],
            "issuing_country" : "DE",
            "issuing_authority" : "DE",
            "_sd_alg" : "sha-256",
            "cnf" : {
              "jwk" : {
                "kty" : "EC",
                "crv" : "P-256",
                "x" : "ZYWj6h-8XJEhIaCU2Z3CVOZf3QbV9lhODV3vRzENym4",
                "y" : "JTcV0VfdDxC7eoUnPq-RIbXpMZPWz6qmzLvzJSMfpyI"
              }
            },
            "exp" : 1746090238,
            "iat" : 1744880638,
            "status" : {
              "status_list" : {
                "uri" : "https://demo.pid-issuer.bundesdruckerei.de/status/46bfc37a-3764-406e-8b4b-366e6f8c0b83",
                "idx" : 126
              }
            },
            "age_equal_or_over" : {
              "_sd" : [ "6qdshjXBfZybA4Wh7yUc8oVBIKqL1HjY7sUXLNIIg0A", "B3dLw_0RqfEIObQWvSS4qK9ljFxuJ_BYpkaGKvGdak4", "JVoMgT64CkhWyvQ2gKOPpp-k9EepxIxdAogjZpvUJL4", "Q4H7hX5C9rJ-J4hdseMPi3wMWo_bPDaF8ExeHYagqoU", "bO36xGm6RFxiil2UOc6W5Y9ppoBU8Mwl7ycjRDmlEU4", "i13ioE3eUAkax7kD_Y738iL_2a4Hiol_msk1udbkY_g" ],
              "12" : true,
              "14" : true,
              "16" : true,
              "18" : true,
              "21" : true,
              "65" : false
            },
            "family_name" : "MUSTERMANN",
            "given_name" : "ERIKA",
            "birthdate" : "1964-08-12",
            "age_birth_year" : 1964,
            "age_in_years" : 60,
            "birth_family_name" : "GABLER",
            "nationalities" : [ "DE" ]
          },
          "credential_format" : "dc+sd-jwt",
          "document_type" : "https://demo.pid-issuer.bundesdruckerei.de/credentials/pid/1.0",
          "id" : 21,
          "title" : "MUSTERMANN ERIKA",
          "subtitle" : "ID Card"
        }, {
          "paths" : {
            "address" : {
              "_sd" : [ "0BtephH9Qo3iKJ55v1QDwmQxqv8Qe8bEwQ5mv_tSBwY", "31oZpbu5hvCWzb6aUj8osEPDjOOd7jvgbhj46mhZq9A", "569MwmN8HKoIWwyOKqPbqRv8_Rz-Kux0SqE3SPE86LE", "Y-qMguhG45p3O1wDSbGsaAcz8QHVdqbjyoIQwaiBj0s" ],
              "locality" : "KÖLN",
              "country" : "DE",
              "postal_code" : "51147",
              "street_address" : "HEIDESTRAẞE 17"
            },
            "iss" : "https://demo.pid-issuer.bundesdruckerei.de/c1",
            "place_of_birth" : {
              "_sd" : [ "7lH6sRyncBbpL7KN0_qvzAVhFJUkM9aM3O1bj9RSf28" ],
              "locality" : "BERLIN"
            },
            "_sd" : [ "Jl2utqLwc9UfxzOq2TL_Uv27eNV3koG2OR3O5REqpAM", "LPfDq_hbDmsTmV9UJup_wL9y7JD4J7VAWeFpq0_ALaU", "RMPjhqa7rsI7NoygHl_ogQ3AHklsyBcen4HRrO0dyXs", "Rvr-VqPDEHjqezj-LNGF7qo1465nR-6w8COTKUMBVv8", "Xcd0b08ws2r_7aQkOB3VB3hGJe77M1KeuLLe2WmAonY", "_NTj61O1S9Nr8PEtrs654n35yDJdLoMRv1hVxKQ0E2k", "nAvIODzGsI0svMXPfg7eTxg6k8CA9MhOa9AZ5yC_0uY" ],
            "issuing_country" : "DE",
            "issuing_authority" : "DE",
            "_sd_alg" : "sha-256",
            "cnf" : {
              "jwk" : {
                "kty" : "EC",
                "crv" : "P-256",
                "x" : "S9ZI_vEjqzvkxftuWbOVFpBZlIJo6mG9tlmUixVu9Ec",
                "y" : "SilxEnvsUb5ey1gF-x1nfKEU8UViR4OpJmsjRtIQZug"
              }
            },
            "exp" : 1746090238,
            "iat" : 1744880638,
            "status" : {
              "status_list" : {
                "uri" : "https://demo.pid-issuer.bundesdruckerei.de/status/46bfc37a-3764-406e-8b4b-366e6f8c0b83",
                "idx" : 84
              }
            },
            "age_equal_or_over" : {
              "_sd" : [ "77hlLVV2VRodApnyqylpPopADh7X5BUrJhgOfW3veT4", "DCgE0caB96IviOBQRr8mJ6K7aSqmF8Wqcdcac8_4HRQ", "Yai0JdCdvdnIsClmyZdNykwg3KoueXJkJ3tf1L2XPbU", "_gng4vo4TaklNQ_EtDi3mO4insXos-BVA8eNQptk2_0", "pxiCtP_B5BXdfyhvWwYKjTbXhxN05xBeAwJssZdy-OY", "rSE_SoGNhvQvqOmxFYhgYT7RXoL35IaQchbbXuUBIJM" ],
              "12" : true,
              "14" : true,
              "16" : true,
              "18" : true,
              "21" : true,
              "65" : false
            },
            "family_name" : "MUSTERMANN",
            "given_name" : "ERIKA",
            "birthdate" : "1964-08-12",
            "age_birth_year" : 1964,
            "age_in_years" : 60,
            "birth_family_name" : "GABLER",
            "nationalities" : [ "DE" ]
          },
          "credential_format" : "dc+sd-jwt",
          "document_type" : "https://demo.pid-issuer.bundesdruckerei.de/credentials/pid/1.0",
          "id" : 22,
          "title" : "MUSTERMANN ERIKA",
          "subtitle" : "ID Card"
        }, {
          "paths" : {
            "address" : {
              "_sd" : [ "-AU67BH_XqRtQWfIyZoP71JcNdd6VoMBRiWDwKPLyzQ", "BiXyuV1NsgUj93UO11oxvQGLwLkAp2LseHu7CSz0aCY", "aOfID_E53dBs4RzKXOs28HyPIQ0AvNEBoZKeLvw-zVs", "jH6_9zkWhRlVkRcFjs40_n7Ydds0a76G3FcgLIVGXc0" ],
              "locality" : "KÖLN",
              "country" : "DE",
              "postal_code" : "51147",
              "street_address" : "HEIDESTRAẞE 17"
            },
            "iss" : "https://demo.pid-issuer.bundesdruckerei.de/c1",
            "place_of_birth" : {
              "_sd" : [ "op3Y2fVeCiuASJXrA-9qRrUfBXwmVVitfUkCgmn9SVM" ],
              "locality" : "BERLIN"
            },
            "_sd" : [ "2LlkSltGB4cWt8GqjXNX4AANGWMXD1Hx2btvE4G5BEk", "HrBkkKaQuQq_tsF28P99__TJpRgLEcaB6VIEAlumlA4", "VzzyI5rs7VOff85PhMnX5HxnSSOQSMK2UXsE-yFSBGs", "WpSTCzBcLQvlZxx-arAm1ID3oCsFE8foMC6AzOVkeNY", "_T6HsyvBzs-jjtDbfHmpRkuFsdhTgYUZD56exZ4oQUI", "b7_w_I3B42QSiGEiNVIpT16Z8yS7GG9m-BAT6SSLG_k", "bL8OhAMQGIpj74VMSumNbVmt72FQz0frc1Q1J8kMv2I" ],
            "issuing_country" : "DE",
            "issuing_authority" : "DE",
            "_sd_alg" : "sha-256",
            "cnf" : {
              "jwk" : {
                "kty" : "EC",
                "crv" : "P-256",
                "x" : "3E4lxvPDdYHIRs-yF8nid6gJTjvFqfYUPU7JkfsoP1Q",
                "y" : "GbhReJgfCTVSNULtB7g1NDKJlIDMflMLp30Pu6TG3fU"
              }
            },
            "exp" : 1746090238,
            "iat" : 1744880638,
            "status" : {
              "status_list" : {
                "uri" : "https://demo.pid-issuer.bundesdruckerei.de/status/46bfc37a-3764-406e-8b4b-366e6f8c0b83",
                "idx" : 123
              }
            },
            "age_equal_or_over" : {
              "_sd" : [ "33_xd7OVIi-OuFxF4fyrKXgbs2FlVp62lF9QcP2Mtno", "4MRP_4iohhCaXWKybl_vr462lGBMYo7IkjVV7kDNVoI", "C-wzr4_tgS5Z-XNuaEQTKAptKs2ZdooMfstvegJmibQ", "Vm48f66u7oko2efzcmsFB_-VY7cR1UXts3ydJblPp3U", "W6GJv-zSkh-dC13pRe8xdFbL3ycWpCbnDG_BD2pi-vQ", "ZZpZlQwNwFCv3I6wTtIkrcWDd1a779aey5SyEfPkySI" ],
              "12" : true,
              "14" : true,
              "16" : true,
              "18" : true,
              "21" : true,
              "65" : false
            },
            "family_name" : "MUSTERMANN",
            "given_name" : "ERIKA",
            "birthdate" : "1964-08-12",
            "age_birth_year" : 1964,
            "age_in_years" : 60,
            "birth_family_name" : "GABLER",
            "nationalities" : [ "DE" ]
          },
          "credential_format" : "dc+sd-jwt",
          "document_type" : "https://demo.pid-issuer.bundesdruckerei.de/credentials/pid/1.0",
          "id" : 23,
          "title" : "MUSTERMANN ERIKA",
          "subtitle" : "ID Card"
        }, {
          "paths" : {
            "address" : {
              "_sd" : [ "f4HcZmTe3k6OR3JhHHBuidppphrnVapS4hgWHL-io2g", "olqt6Vnk4_Q7n5kBTkbiNIPVmhiPPpNwI9rM-kAFH3Q", "veG0RG2M7-u8cHTZ6wMy-BxjYdpPhfgh3kW2550kdec", "wWX3dr7zrbG77wNJL1SezFri11lbxMsCbdLpb9AY3zo" ],
              "locality" : "KÖLN",
              "country" : "DE",
              "postal_code" : "51147",
              "street_address" : "HEIDESTRAẞE 17"
            },
            "iss" : "https://demo.pid-issuer.bundesdruckerei.de/c1",
            "place_of_birth" : {
              "_sd" : [ "B5YcRZazVCe9Peri1dvBNEUcxFYDagjlQN_Bpok97eQ" ],
              "locality" : "BERLIN"
            },
            "_sd" : [ "9tCcd0e8Tw4XdXt-I2Jcwdb-pVQI4UEVz-7b_od0KSI", "EbdmOSk9_iv1RNXUY8vlcevYasT7YssYh85SwrkU8rM", "Mgsr-1wt6bdxJ1MU5vooUiOpcPoB8wmvoAwEJWk1uJk", "UIWL3I6uQtvCKiIFvGsCdx_A4vVR-s3RBCUJLBQQYIA", "f8X8PrArSg2Wz2J9xVCHKKxYvma0dmSa5NJlQYSiwL0", "qxf_W5wR-Hxyh-3zdyt0i723AcZKlgcTeDpgoy7xoJE", "wxEraY4Y0wf0p3e2_o9O4SWGnP44mLibEPuxe9uSxaw" ],
            "issuing_country" : "DE",
            "issuing_authority" : "DE",
            "_sd_alg" : "sha-256",
            "cnf" : {
              "jwk" : {
                "kty" : "EC",
                "crv" : "P-256",
                "x" : "gDr3433F0NDpkJNYZfWktCNH8nAh9Vx0NRWqgTP9hUE",
                "y" : "2IUlSMEPofXtcQgX-Zj04iQcXqIbP-ZJ9zqjXXn1AH4"
              }
            },
            "exp" : 1746090238,
            "iat" : 1744880638,
            "status" : {
              "status_list" : {
                "uri" : "https://demo.pid-issuer.bundesdruckerei.de/status/46bfc37a-3764-406e-8b4b-366e6f8c0b83",
                "idx" : 61
              }
            },
            "age_equal_or_over" : {
              "_sd" : [ "BGtc36Zz7wx1hJE4H-pWsqYoKY2kyReUcd-zL88ZyGU", "LX5WfUI19Iyux-ujGtHdy9pI0a_5mAY-suuqrB088go", "NS1-Lo8hqv3xEFIZd7uOpZEIArmMTrAH0FDw1W3AWIc", "UNYqEPkapvs02hLvjgkfwbWlhJq3KwkZO9KzoXYSqNg", "e6plNJ6IFeIyY3zt4JcB8dYs1AUuPT_2MvaSDooLKQI", "rlhvfNlSmlRtFkCj8nAzCRGZG_fIIQ3XuAHMAJXxVBo" ],
              "12" : true,
              "14" : true,
              "16" : true,
              "18" : true,
              "21" : true,
              "65" : false
            },
            "family_name" : "MUSTERMANN",
            "given_name" : "ERIKA",
            "birthdate" : "1964-08-12",
            "age_birth_year" : 1964,
            "age_in_years" : 60,
            "birth_family_name" : "GABLER",
            "nationalities" : [ "DE" ]
          },
          "credential_format" : "dc+sd-jwt",
          "document_type" : "https://demo.pid-issuer.bundesdruckerei.de/credentials/pid/1.0",
          "id" : 24,
          "title" : "MUSTERMANN ERIKA",
          "subtitle" : "ID Card"
        }, {
          "paths" : {
            "address" : {
              "_sd" : [ "6NlX7szy4z1zW05SSzoSwAqfBUOtvE2yFqoJy0_tKjc", "A2MGjxJLhivrop_Ccgdtq8oUTQwt2YaTFluAx4W3lmM", "LukP7QK3G8zMjDiWL8QDsFA4tPUqNW2cBj-8jNPSUWc", "Rb6krS4Ed3t9uNG_K0uowuS8jLxnHBllnVOu9xbzVVw" ],
              "locality" : "KÖLN",
              "country" : "DE",
              "postal_code" : "51147",
              "street_address" : "HEIDESTRAẞE 17"
            },
            "iss" : "https://demo.pid-issuer.bundesdruckerei.de/c1",
            "place_of_birth" : {
              "_sd" : [ "_Hy5ME82G1xcuy3D6Zqr_s7iirhOh4BZdlg-8jBh8Cw" ],
              "locality" : "BERLIN"
            },
            "_sd" : [ "4n7-rJjVuqSNlUP-H2-53lksyKYus_wrSpEX5zwl5Tg", "R5WhWtZ0i_OZmfKLcIKtImxrjmx1O4lN7RLgQ0KbGtc", "V2JxA8GiMFGYUOfZ-63futiUAnVtVd3CuQ524MRf-4g", "VaUpmfvZjEszoSSMNwup2NxcDVdxJ6AuJLqYk3AXO-Q", "WHJ2vkc2tpsIU3mKYGa3UkldeomoHmc7vmie6Cq9QCY", "hXCzyesN8wwcyec7tunfce_4RYvgXYcHPRq7yeZHUa4", "x9bFDSsClZVmc_wEygpqpMnDe-OE6pazIdYVI73qzCE" ],
            "issuing_country" : "DE",
            "issuing_authority" : "DE",
            "_sd_alg" : "sha-256",
            "cnf" : {
              "jwk" : {
                "kty" : "EC",
                "crv" : "P-256",
                "x" : "2iUfHiu82cXOCXGOfJZW8AH24pK7BPVZocWfk6fdMC0",
                "y" : "m8sR-zIowdaaP0ZCb2-cMsmOP-LDdq9B9PV-siyl86o"
              }
            },
            "exp" : 1746090238,
            "iat" : 1744880638,
            "status" : {
              "status_list" : {
                "uri" : "https://demo.pid-issuer.bundesdruckerei.de/status/46bfc37a-3764-406e-8b4b-366e6f8c0b83",
                "idx" : 68
              }
            },
            "age_equal_or_over" : {
              "_sd" : [ "3-VhBlbeKTsai-_WDiSjfNzLnjrRzirRL2tf1Lb_Uoc", "Q1NCpY3ksaLU1XPW5HJTCsqE-BIOqFu17QxEDyDZKWA", "YH_st2lPwhCsh_LHvGbk95mXYHDI-fCHqaZIIoXE0-A", "ZXAjj-ORc-GLlPAr0CnL2SniRwj0rZTRdt3U41X2sOs", "lTjFDucSd-2P6czWvIpGPzxbPnEE7wPhwypaq8tx6lk", "qOnaHJDlx2cDqhQ5LCKRMKihfuZ79nry5QdXMnI0fQY" ],
              "12" : true,
              "14" : true,
              "16" : true,
              "18" : true,
              "21" : true,
              "65" : false
            },
            "family_name" : "MUSTERMANN",
            "given_name" : "ERIKA",
            "birthdate" : "1964-08-12",
            "age_birth_year" : 1964,
            "age_in_years" : 60,
            "birth_family_name" : "GABLER",
            "nationalities" : [ "DE" ]
          },
          "credential_format" : "dc+sd-jwt",
          "document_type" : "https://demo.pid-issuer.bundesdruckerei.de/credentials/pid/1.0",
          "id" : 25,
          "title" : "MUSTERMANN ERIKA",
          "subtitle" : "ID Card"
        }, {
          "paths" : {
            "address" : {
              "_sd" : [ "EOUfynMCEI2Sm20S_zO9z353h06hH67PTfE6XFtZ-sg", "TUcj8nEAGvAq8k2WbZdYMV74wyTzH4ZJwVXq7KvEFRo", "u3SWLzYTB5YqmzuTl6LuLhNlvBk2i-NPALm1lPLZ5fs", "yYCaPjAel2-teL6_sg0a7leUZSVWpT9yv0HhagvNLsI" ],
              "locality" : "KÖLN",
              "country" : "DE",
              "postal_code" : "51147",
              "street_address" : "HEIDESTRAẞE 17"
            },
            "iss" : "https://demo.pid-issuer.bundesdruckerei.de/c1",
            "place_of_birth" : {
              "_sd" : [ "JenKg7tHvJrTL8gcVNiHXHUYFgyoWS7OkfJm41nQjdk" ],
              "locality" : "BERLIN"
            },
            "_sd" : [ "362nmfhMtsKg0NnaX-41XE5DhLbg995N_cwdWErNyEU", "7sP1kA5Z9xp8M05HTCHSX2mJbd_Mad1jiYMmQrA5a0c", "DXMlQtgWVFK9rOUxQAtCDGYHvH45QtgPYphqq9reyzo", "RiCnv3h5MQX2f3emJsrqkwMjGZJrnJ-TTXBLWGgpkTw", "TkWNCzPFnnJ2wVxXgxJYul_GbJY9_UiLMrbYWh1UITA", "e-B7EQZBXTyRu41394LDlYWq30mKaP7RS5wJa6iUFhM", "si2cNoQu8UEe-NM2eLxcH4BTjnioCoNQkEwsIO4k0Tw" ],
            "issuing_country" : "DE",
            "issuing_authority" : "DE",
            "_sd_alg" : "sha-256",
            "cnf" : {
              "jwk" : {
                "kty" : "EC",
                "crv" : "P-256",
                "x" : "3AWxnf492Pf5RqaD7J1SJPYBU10-buGXFzvds-X5HeU",
                "y" : "9O9l-NAs2IsINlTZYlhq_UCEoGLo3FoJsdybLSni8kA"
              }
            },
            "exp" : 1746090238,
            "iat" : 1744880638,
            "status" : {
              "status_list" : {
                "uri" : "https://demo.pid-issuer.bundesdruckerei.de/status/46bfc37a-3764-406e-8b4b-366e6f8c0b83",
                "idx" : 107
              }
            },
            "age_equal_or_over" : {
              "_sd" : [ "-EDBP8LWpGdzSFYtCmmpEtLD9xpM3-vBUgHpZGB-IrU", "CiakmQJy8reyQJIAfbKbrzDXiHLxErU1Mpwxypx8aKw", "F1vInSfAC2HXBYElQzh6n_A6NN44j8VTPwFB90WgTlM", "KWoh-m2hUuPCGX8RXwIGX3DjG3LpqXknY_GJ3JPzWlY", "ojzadA5OJL8V3xOKFj0OgFtolQm9c5KJbGf3MXzW37A", "vfhFTXe6aa-Sw8uasJaSjaMOFKV0wuak28DEmWFIzy4" ],
              "12" : true,
              "14" : true,
              "16" : true,
              "18" : true,
              "21" : true,
              "65" : false
            },
            "family_name" : "MUSTERMANN",
            "given_name" : "ERIKA",
            "birthdate" : "1964-08-12",
            "age_birth_year" : 1964,
            "age_in_years" : 60,
            "birth_family_name" : "GABLER",
            "nationalities" : [ "DE" ]
          },
          "credential_format" : "dc+sd-jwt",
          "document_type" : "https://demo.pid-issuer.bundesdruckerei.de/credentials/pid/1.0",
          "id" : 26,
          "title" : "MUSTERMANN ERIKA",
          "subtitle" : "ID Card"
        }, {
          "paths" : {
            "address" : {
              "_sd" : [ "--I1LfAo4Yut7U7Ec2O5cwqYAKoOWX4mmnh0-0C7jvo", "MZjdRObaKtdQM7QYhXKguTaQPIbXCja7QA-ZUuPlLvU", "ip7pDdgjxv4pv12IdPSXrtzY77Pqvc9z1DqIwzUoUOI", "xLH6op7DdAL8huYaA3P_AxxawVIYYXCc3WQ8ESc2p_k" ],
              "locality" : "KÖLN",
              "country" : "DE",
              "postal_code" : "51147",
              "street_address" : "HEIDESTRAẞE 17"
            },
            "iss" : "https://demo.pid-issuer.bundesdruckerei.de/c1",
            "place_of_birth" : {
              "_sd" : [ "VMR7iiLQCWMvMBbTpvVICHl6m1AiJQ1RNssVLSw4o4o" ],
              "locality" : "BERLIN"
            },
            "_sd" : [ "3cfT6wLbs9AYxFVvspfg-qPn3JiqkxxmQ-zdXEx4Hn8", "G29B727Q9hAyKQL7TT7xmcZZPzU6aRL8M-UpKOHBNg4", "JQQNxE0Eh19lR5KNKmO2wK_EuVRm8RLDIWjn6M5kvrM", "Yb07IqAEIiyLa4_istBSHdWFlpklWUgbiQ_CjbYNeXA", "_8b8c59S1y6Oah5ZQfmYu9rZVHQhPHqjpG3KTfLapb8", "bBuf6UdaRvFACExo022xMEdSxERH4vc9VuqNnC1MHIk", "lnpC-_KyzBCqdlsqpEzegkRp4B84F-dk9eSCtcwoYQU" ],
            "issuing_country" : "DE",
            "issuing_authority" : "DE",
            "_sd_alg" : "sha-256",
            "cnf" : {
              "jwk" : {
                "kty" : "EC",
                "crv" : "P-256",
                "x" : "lFxZ5gBl9_kP02RgJu-bMmi_5WOmNUOm9QDCHc8Fk2U",
                "y" : "-RjiwrbeWt7NKgVMe95QQg6WH67AYMYTMB1sia0QQZc"
              }
            },
            "exp" : 1746090238,
            "iat" : 1744880638,
            "status" : {
              "status_list" : {
                "uri" : "https://demo.pid-issuer.bundesdruckerei.de/status/46bfc37a-3764-406e-8b4b-366e6f8c0b83",
                "idx" : 99
              }
            },
            "age_equal_or_over" : {
              "_sd" : [ "4kYQ0jveTXInX67Y7VN0BUw5tga7wd5pt3ziYaJvjU8", "5hTufwCW4_BrIMmKMTq6Yr9-1EEi_Ac6qRcY22m4nqw", "92-LLblIDNKN6wJ2N--6SiFatri-opOAa6eQ7K_cdKU", "I4G6B5eKRDG3SD_GLXN8T8wFjAa6s5pv7-YCtZFRXGw", "a68PXwGAmQhpqUq8j_pqIQd0rTJuo8wSp_vA_E8Gsb4", "susAxIzfNnYwPPJPHC1kIkKHFlzQ-opx1TQ3Y92bcVM" ],
              "12" : true,
              "14" : true,
              "16" : true,
              "18" : true,
              "21" : true,
              "65" : false
            },
            "family_name" : "MUSTERMANN",
            "given_name" : "ERIKA",
            "birthdate" : "1964-08-12",
            "age_birth_year" : 1964,
            "age_in_years" : 60,
            "birth_family_name" : "GABLER",
            "nationalities" : [ "DE" ]
          },
          "credential_format" : "dc+sd-jwt",
          "document_type" : "https://demo.pid-issuer.bundesdruckerei.de/credentials/pid/1.0",
          "id" : 27,
          "title" : "MUSTERMANN ERIKA",
          "subtitle" : "ID Card"
        }, {
          "paths" : {
            "address" : {
              "_sd" : [ "4raPVeFPh3kx3lthQgbOzZVDmoKhmGyNykgDpD-BkFA", "DfMeuoJNyB0TefMlZVM3AlqNkRhWSHEjYFT2dzcV7Qc", "U1O_gRrYxMe9F9VZETyKGMnUG8UXw_fDptwhADBdgsU", "puntnEIxqAltHjSkxdno5zw9v7tzrudRIhrjqokh_MA" ],
              "locality" : "KÖLN",
              "country" : "DE",
              "postal_code" : "51147",
              "street_address" : "HEIDESTRAẞE 17"
            },
            "iss" : "https://demo.pid-issuer.bundesdruckerei.de/c1",
            "place_of_birth" : {
              "_sd" : [ "AiDnRLWT_00AjAZi7QY4OwNw3Bggud22-5uqb22nqt8" ],
              "locality" : "BERLIN"
            },
            "_sd" : [ "Fu0-TZNVz5n8QoQn_YsEXytw0dllqbVbBtL0yCcplT8", "I5Fd_U4ZlNOTJjJYM3JepjXRDYwWb9BtQz5NW_Z41oM", "XvwiDrSxZVaqAnzAyMVGTDBD2WjudgnRZOgpUquElKE", "_hYeGsbzRtuS_2hlYt7bBvikFkG66yNf4btadYbgEUY", "cLBB6-iBtjpgyWCeqo5X29M-sjhGNN2DgkYXCGNKXIE", "g0ASe1-vNTOZhVMUq26vbqq7-wGj6qpMH4nTieukrxQ", "jFdC56nxXdxBZiOCwOwbeYmRXUjpMIOfCsJtZ_G9A6w" ],
            "issuing_country" : "DE",
            "issuing_authority" : "DE",
            "_sd_alg" : "sha-256",
            "cnf" : {
              "jwk" : {
                "kty" : "EC",
                "crv" : "P-256",
                "x" : "gylfRVEIUsvwvozdy5RZDbwDLc1lJx2mXqWjt8aJy_o",
                "y" : "tdBgMVfC6-MDYxppfy9SGtn7dTfO1Y5xP4XU_-g4ygs"
              }
            },
            "exp" : 1746090238,
            "iat" : 1744880638,
            "status" : {
              "status_list" : {
                "uri" : "https://demo.pid-issuer.bundesdruckerei.de/status/46bfc37a-3764-406e-8b4b-366e6f8c0b83",
                "idx" : 71
              }
            },
            "age_equal_or_over" : {
              "_sd" : [ "2lf1smmpNlwduuiOOcnL2YxVhmy9H7nCSni6LOQABbI", "3l-rYo2Z_UCAweTgDVsyuiav3UgoOqzxx0EB2XMViXU", "KuvqJmxtyT8ikmvAQRl7zwrW8jaFpma-YSJtaDtWyUw", "_H0j61YNcpEIaG87uATqlY9kDawnB77Srq-l8DBuM1Y", "tXF7IV3lernTdwG0Ydn7p0b4HChPicx_fBTvYV7CK80", "vEXToT-MEKe6FImLHKI3U8LejAQIKdX2RMgJ4lxfSVM" ],
              "12" : true,
              "14" : true,
              "16" : true,
              "18" : true,
              "21" : true,
              "65" : false
            },
            "family_name" : "MUSTERMANN",
            "given_name" : "ERIKA",
            "birthdate" : "1964-08-12",
            "age_birth_year" : 1964,
            "age_in_years" : 60,
            "birth_family_name" : "GABLER",
            "nationalities" : [ "DE" ]
          },
          "credential_format" : "dc+sd-jwt",
          "document_type" : "https://demo.pid-issuer.bundesdruckerei.de/credentials/pid/1.0",
          "id" : 28,
          "title" : "MUSTERMANN ERIKA",
          "subtitle" : "ID Card"
        }, {
          "paths" : {
            "address" : {
              "_sd" : [ "NRLHdVlMdsJGecHWtBKsjUbMPtTLUForQUiGnIwdsRY", "iIcuIva6_q8mejJY4LclVW2ydUA0ZCB5CxCXjqHuXCk", "nymR36waJtf-riePy6lmuU4ddWYq6wEdr_TusWxljs8", "ooNTbNgiSM_tWAoEXLpFF-3K_lggX-RAcMSKxA3w1HA" ],
              "locality" : "KÖLN",
              "country" : "DE",
              "postal_code" : "51147",
              "street_address" : "HEIDESTRAẞE 17"
            },
            "iss" : "https://demo.pid-issuer.bundesdruckerei.de/c1",
            "place_of_birth" : {
              "_sd" : [ "lbV6jnMkCoTBCzZic97az69UMGqBJZKSKkpgU1O0ygE" ],
              "locality" : "BERLIN"
            },
            "_sd" : [ "0-T0GRoXIDwMfFnx2k3KGnR2Yae66LWxse7rmjjC_aU", "BRBz5lnjuquhUjIPmauI2Usdv3Rnw4UJQdW33xrgvSg", "EjxqemoOFFyOG-dLIbcfaJAKoXRksIySvh66l3ImAmI", "IMndqwWuveAohm5gpAGnRrtJTBT5d_Py86TEIjQbbNg", "TtzGhbbrHt_UahxVfOsM5FWBLZ6S4FLUtkD4FSkxCpA", "f2LZ-kczouUrj7PBcI5zlrtUwd2zalRTzDQ6lNDLH5w", "ttEQ3hI7n5Pms5Hx53zaS_9cfZwJs00yuNYBldnyGJE" ],
            "issuing_country" : "DE",
            "issuing_authority" : "DE",
            "_sd_alg" : "sha-256",
            "cnf" : {
              "jwk" : {
                "kty" : "EC",
                "crv" : "P-256",
                "x" : "4LF5jEGQjHx6be5NF4qY31_oz4gQki8mply30Mt0sbU",
                "y" : "kkhb92Q2QH5F6vxcXrIL3ICO15VQ_a6XoDFajLfp8VI"
              }
            },
            "exp" : 1746090238,
            "iat" : 1744880638,
            "status" : {
              "status_list" : {
                "uri" : "https://demo.pid-issuer.bundesdruckerei.de/status/46bfc37a-3764-406e-8b4b-366e6f8c0b83",
                "idx" : 38
              }
            },
            "age_equal_or_over" : {
              "_sd" : [ "ALV2ggS3mR-RiGaj_GN_9eLHFoqDKj35gxc9QsrZLdQ", "Js4joUZW-SMtX_-Ds-VbmCW-P5wUPVIlRGNWRW8cNe4", "R-ORbaWccqSieSTd8N_jLBmYJ_shcwnJAeZi1QT74Ns", "cjdBOW2x_5xC7S5U6v8hvJAYJBm6KT-3Kc6TjIiwjxg", "iDgKC3IvjWFMYMP3xjF9N2ajRMlgfmFSw9ogU6VYPmE", "rnQejF7_purLu7BMf0ZhMdAqIVzFc1M_lwGovcDfV-8" ],
              "12" : true,
              "14" : true,
              "16" : true,
              "18" : true,
              "21" : true,
              "65" : false
            },
            "family_name" : "MUSTERMANN",
            "given_name" : "ERIKA",
            "birthdate" : "1964-08-12",
            "age_birth_year" : 1964,
            "age_in_years" : 60,
            "birth_family_name" : "GABLER",
            "nationalities" : [ "DE" ]
          },
          "credential_format" : "dc+sd-jwt",
          "document_type" : "https://demo.pid-issuer.bundesdruckerei.de/credentials/pid/1.0",
          "id" : 29,
          "title" : "MUSTERMANN ERIKA",
          "subtitle" : "ID Card"
        }, {
          "paths" : {
            "address" : {
              "_sd" : [ "0Jrc23YnzLJTqTVhSHKrO6f98cnpeHoOXpeAZ-8najo", "ZVHUa0Ug4e-2_m8X6FWF9P4DRNNbbOkjQEfY87rUhw8", "d08himKK7x3-P9c5gJWaBYhxb84c8Sq3tjvQAI-SAno", "fPWP2U6FudnO9jC4nPsBeqyu7GyMwu2SgRUNfAJh5O8" ],
              "locality" : "KÖLN",
              "country" : "DE",
              "postal_code" : "51147",
              "street_address" : "HEIDESTRAẞE 17"
            },
            "iss" : "https://demo.pid-issuer.bundesdruckerei.de/c1",
            "place_of_birth" : {
              "_sd" : [ "Aj0MXxNoWjO110vcWuaSdmpo9V3O8dtHG_6ax7JKAbo" ],
              "locality" : "BERLIN"
            },
            "_sd" : [ "1Z94k_LjZUpA5MLIey8IaI-31LBUAgBN8UuWrvqhogY", "2ApZQlQ6G4W9OOmKVEwWnVjRxKrk7Qfdpj8OWvzTNSk", "OT0DT95Usf7JuPxleYUo1BZLvsju6wTeK9kxLWpYrrU", "QXdQfjbucrE4dCLuX8TVnsRNomWnPNhSLXUMlN0Ary8", "ReHg2sLqU8ytXpPz3MEESseZWSUwai9K4CBdYwUnHww", "lsL_1BwMnfyMFnL9g-jAoPafXtuGX8GJO0WRdgof7jI", "z7e42dOz_wBOukkdjNML2ShLMMnrBEqGBu_f6I7HEBE" ],
            "issuing_country" : "DE",
            "issuing_authority" : "DE",
            "_sd_alg" : "sha-256",
            "cnf" : {
              "jwk" : {
                "kty" : "EC",
                "crv" : "P-256",
                "x" : "nLnnPKCaSRDR3hTSzmkT7zb3PAen3gFZO1rlBIjAcUo",
                "y" : "P6tFyjJOGh4DnBlfPC8xOxmMWLiL7C625YYxb2LjUMY"
              }
            },
            "exp" : 1746090238,
            "iat" : 1744880638,
            "status" : {
              "status_list" : {
                "uri" : "https://demo.pid-issuer.bundesdruckerei.de/status/46bfc37a-3764-406e-8b4b-366e6f8c0b83",
                "idx" : 122
              }
            },
            "age_equal_or_over" : {
              "_sd" : [ "7IgFoKkAO7ojo6nlpZU5Qdw7fUb0QSmVZYY2Ig_ZaWI", "DkJBlI3U37YUt1VBmGL9Xhj9pRpZHJhjGF4G_25dYmk", "LqoAHOOanMAvL5PX7oDXBJdvOySCZ6ZYFLuCMzO5pt0", "RG5V1zxIYql0_9rxV9VGY2g45vHSneG5sKgZc2z2rwU", "WloNfFeN7NFiZNUgECSqC8v22B30oTho2Pvket9zsyI", "tX5eBjf_DHESrklxgbnZZLUNoEFytzM_SGh2kqm-5sk" ],
              "12" : true,
              "14" : true,
              "16" : true,
              "18" : true,
              "21" : true,
              "65" : false
            },
            "family_name" : "MUSTERMANN",
            "given_name" : "ERIKA",
            "birthdate" : "1964-08-12",
            "age_birth_year" : 1964,
            "age_in_years" : 60,
            "birth_family_name" : "GABLER",
            "nationalities" : [ "DE" ]
          },
          "credential_format" : "dc+sd-jwt",
          "document_type" : "https://demo.pid-issuer.bundesdruckerei.de/credentials/pid/1.0",
          "id" : 30,
          "title" : "MUSTERMANN ERIKA",
          "subtitle" : "ID Card"
        }, {
          "paths" : {
            "address" : {
              "_sd" : [ "E8E0ehsMFyAfaWIgAQiCKzjdTqokz4TimLlfBo77wLM", "NksmpXIogCyaIfMND9JWayktocq9lFU3nK10Aaug730", "SBy2SNfHuVWF2j6yiBBjM3cS7VmjLE8pjngtc7B2rXo", "ylsoVUfOyB2qE61ZtvZc70MxAx6Z2-nLri3MhYriAsQ" ],
              "locality" : "KÖLN",
              "country" : "DE",
              "postal_code" : "51147",
              "street_address" : "HEIDESTRAẞE 17"
            },
            "iss" : "https://demo.pid-issuer.bundesdruckerei.de/c1",
            "place_of_birth" : {
              "_sd" : [ "8KA3QpK5kpdM4Wz8Nw8ybf5Lq4Shj3QZF7RAwCJkJaI" ],
              "locality" : "BERLIN"
            },
            "_sd" : [ "2jR99x4BZUoUcRmH-6nUT3xZ8u4924VpMXx_c_vnpBo", "5Z_-AHOwGCKgjp8b1Da1ZPzUUBeK0tqk_hVJFCuT42c", "eQGghxOyZx9rgUdY5vY216kOx_kPg3vHuOtOyNexDTs", "frjuEohu_C_Ypx-F8bdC91xltR93suYhMYJSjLHNwTQ", "jxjrPV9saKeXypQuEY-zZfgbmSfaX8I1yiIQciw6qvQ", "o195N5zLq2z0aGp4rR4YGkMZb914-Nub3uiwrffXt0M", "rXkkxLJPI8QVQW2j3P95RTXNCtqpMuwFHAizSTGbFNU" ],
            "issuing_country" : "DE",
            "issuing_authority" : "DE",
            "_sd_alg" : "sha-256",
            "cnf" : {
              "jwk" : {
                "kty" : "EC",
                "crv" : "P-256",
                "x" : "7fLbk_9c_8Tsnwq7HxLMaDuUqo_OZM8TMEcS7ridexk",
                "y" : "Zc23TiZB82b0ANx4R8jfQ1HBGl9gxE82nUGj-KyDhqU"
              }
            },
            "exp" : 1746090238,
            "iat" : 1744880638,
            "status" : {
              "status_list" : {
                "uri" : "https://demo.pid-issuer.bundesdruckerei.de/status/46bfc37a-3764-406e-8b4b-366e6f8c0b83",
                "idx" : 74
              }
            },
            "age_equal_or_over" : {
              "_sd" : [ "7LOo0qVFXmCe3y2rVG-PIixpngsCISotFhiotR-IfKY", "_H1fSj1MK33uzqgiWmhsIGpEavkayMoAG_YAzfL9cRg", "akH24fEknIprJmzAeg3GcYpzbpsCqUFjB-KIv8jGars", "giJcnusaxAEQlkbfzt_VqgFJCHSoRJnA-HTDPi-tc-Q", "xoSpeDMYlk9werRG7bdmEFiyT3d5uJyzt70h6bNYCI0", "zqlaTo35LX4Kq5Zu1Hb5nqEzSna3aP_LeAUGC2NT79w" ],
              "12" : true,
              "14" : true,
              "16" : true,
              "18" : true,
              "21" : true,
              "65" : false
            },
            "family_name" : "MUSTERMANN",
            "given_name" : "ERIKA",
            "birthdate" : "1964-08-12",
            "age_birth_year" : 1964,
            "age_in_years" : 60,
            "birth_family_name" : "GABLER",
            "nationalities" : [ "DE" ]
          },
          "credential_format" : "dc+sd-jwt",
          "document_type" : "https://demo.pid-issuer.bundesdruckerei.de/credentials/pid/1.0",
          "id" : 31,
          "title" : "MUSTERMANN ERIKA",
          "subtitle" : "ID Card"
        }, {
          "paths" : {
            "address" : {
              "_sd" : [ "E0J3DHmiPywQc91a_0kDEh7PsEBR-x2T8do7dG-yAiM", "SqR5CLlvhSQ7BvNlasrEceSHwzH88-zwx_ky-PmgUnA", "hsPyNGrBx30IYodrvxT-X9WjO7N3eUyUJbGfdhOMGog", "nMIv8PvWSDFoPVRUQznIcrWgy_j17nmWJ49lFdIINGg" ],
              "locality" : "KÖLN",
              "country" : "DE",
              "postal_code" : "51147",
              "street_address" : "HEIDESTRAẞE 17"
            },
            "iss" : "https://demo.pid-issuer.bundesdruckerei.de/c1",
            "place_of_birth" : {
              "_sd" : [ "yq2cmO-LZWIDDnCDsEEcPD8lYSBbvAvNjQnFjhJUpAA" ],
              "locality" : "BERLIN"
            },
            "_sd" : [ "4n9Z35772Qn7nOTrzoeZctzXi5m9uRWmv_FBQvVN3ec", "6de8gLJxz5xZbKMn1gbvOM96h67tN0J2NB3JC66KLxM", "ABOIkj2OjT3MBShBqxe5ZBRitSR6U7mFrxCk5eseJts", "dibbAoHuFGHp7GIbnXcRS4-5HuB7h7VySgpZHeCrrU8", "jYjIZ4rSGQLS7JfKsnRx7kXe8DvdQU_u5neRDJv6ezE", "tenjeXzuvxHmDRek7efJ7-4MFzhyYJHgBH5qEST2RMc", "xFNofCJ5epCxpsVbT61FfYlGT44vRGlPO6gnYFsrdFQ" ],
            "issuing_country" : "DE",
            "issuing_authority" : "DE",
            "_sd_alg" : "sha-256",
            "cnf" : {
              "jwk" : {
                "kty" : "EC",
                "crv" : "P-256",
                "x" : "ZnI-nRtSAHG3Fm7oe1N78YWcmR_zHYQ7X0Z4BvjcqvI",
                "y" : "vApESQuTTgEh8ZLODrt7NIExHzJ3VBJVpm8Qs1jhdBQ"
              }
            },
            "exp" : 1746090238,
            "iat" : 1744880638,
            "status" : {
              "status_list" : {
                "uri" : "https://demo.pid-issuer.bundesdruckerei.de/status/46bfc37a-3764-406e-8b4b-366e6f8c0b83",
                "idx" : 89
              }
            },
            "age_equal_or_over" : {
              "_sd" : [ "B5uhcfcKz2Q4i8DeLp6FD1n6sXQ6Kx3xEsGCR9LeA7k", "MG9-GXt0DQsqNqnX7MeJir93PMbTZ2uIjATpkd4hRxI", "_fX7A2f1pvBhvGntP-b-ZMYJ9HrfHgu_gngkwMNfTg8", "fFLVMiAOyBXl-0EyHvSPWGmE-OUeVZ9FWnfEu-bZoKs", "qdxjvdHMcA4OkGt31xIhZDwWR8vtRJHCqZ5B6JiUUfs", "qf83-AaupV2_KT2O1__5gCPvv9bA8nKgB30tuPgwJM0" ],
              "12" : true,
              "14" : true,
              "16" : true,
              "18" : true,
              "21" : true,
              "65" : false
            },
            "family_name" : "MUSTERMANN",
            "given_name" : "ERIKA",
            "birthdate" : "1964-08-12",
            "age_birth_year" : 1964,
            "age_in_years" : 60,
            "birth_family_name" : "GABLER",
            "nationalities" : [ "DE" ]
          },
          "credential_format" : "dc+sd-jwt",
          "document_type" : "https://demo.pid-issuer.bundesdruckerei.de/credentials/pid/1.0",
          "id" : 32,
          "title" : "MUSTERMANN ERIKA",
          "subtitle" : "ID Card"
        }, {
          "paths" : {
            "address" : {
              "_sd" : [ "AvCPkNAlMEBALF_IbtXXaH46jSbscH0oQGkRxWnRQG0", "hqvP6U6QBNPBb4FWLYHdIUydKspbARS54K-ugxj2aTg", "ip50aLPrQg_EiEtoSS8BpxwonQp0mfYMLoWj6vOSiKg", "odK3hve1cy2CJ9S_ZI2TlM_xC3TguP7bhEddu0MJvRA" ],
              "locality" : "KÖLN",
              "country" : "DE",
              "postal_code" : "51147",
              "street_address" : "HEIDESTRAẞE 17"
            },
            "iss" : "https://demo.pid-issuer.bundesdruckerei.de/c1",
            "place_of_birth" : {
              "_sd" : [ "oT3RskjiLCav1Gvu9Um8XmL2otgS4azyu232zr7mq5U" ],
              "locality" : "BERLIN"
            },
            "_sd" : [ "-QeZCTC7ZRLv53UgRJud2GJyDFiYl74WE-V2A-SuZUk", "2iHMtMNijb1UrN4poYfhGye1cK31WCKcJKqWVTSr9tI", "3OQNqGgAFYQ1HuXTGwYLyqR7dNByZBaQwXfHzp3NURk", "JkszJRq0fM_RvIf6B37Jj4vrjWaWUZNPjiCr9x_I9B4", "n1pc9CkdMzFkpij3EjCEjiiDXL08uoJKGVaTuPTukxI", "r7xK8jhUi13F_0SdUyoqi59Dh2SjAKJxWvqLsh1qPxk", "yKrYeWDD9Acr5K3XsXjZzMgik8tl46pLhR6rq5cwf1w" ],
            "issuing_country" : "DE",
            "issuing_authority" : "DE",
            "_sd_alg" : "sha-256",
            "cnf" : {
              "jwk" : {
                "kty" : "EC",
                "crv" : "P-256",
                "x" : "RZinCLoK8JgrRgKYC4xizUTdWBsLXtyVMCw7ybQootw",
                "y" : "9NmRFyvJyFpTi-oo6pZpkUwLosSza8jQsWnrsYUitaU"
              }
            },
            "exp" : 1746090238,
            "iat" : 1744880638,
            "status" : {
              "status_list" : {
                "uri" : "https://demo.pid-issuer.bundesdruckerei.de/status/46bfc37a-3764-406e-8b4b-366e6f8c0b83",
                "idx" : 37
              }
            },
            "age_equal_or_over" : {
              "_sd" : [ "9o8Y9GaPHyC0R2HeRxWvzNIVpNqz1Qwk5nku4c10MKk", "GhPVLaUql8GEO1aYI5bUNIPsugJd_eUFfMc94M2cP_Y", "L7kReyT_GK52DhcqEczdNg90z48T05PW0gqqKbjMe04", "T0J0BV64ROjAshO4SZW9J_7J2xjMRM4WG2Xgf_Fsnv8", "T41dSo6kzJ05QXM37n9BVXF2ZskyS_174qPunNqHRTk", "c0soHuC3UvppMotyarLHBP6dkj8J4PdiuWi7xko2UZg" ],
              "12" : true,
              "14" : true,
              "16" : true,
              "18" : true,
              "21" : true,
              "65" : false
            },
            "family_name" : "MUSTERMANN",
            "given_name" : "ERIKA",
            "birthdate" : "1964-08-12",
            "age_birth_year" : 1964,
            "age_in_years" : 60,
            "birth_family_name" : "GABLER",
            "nationalities" : [ "DE" ]
          },
          "credential_format" : "dc+sd-jwt",
          "document_type" : "https://demo.pid-issuer.bundesdruckerei.de/credentials/pid/1.0",
          "id" : 33,
          "title" : "MUSTERMANN ERIKA",
          "subtitle" : "ID Card"
        }, {
          "paths" : {
            "address" : {
              "_sd" : [ "55P6QnL5f_yW-j7K2eruXRrvYeMWZRdk0HN1bHjQeE0", "EtUZ2H27Q4ybMfqlZ4NuZ95EqFIp51dJEHsGD_VLRK8", "PUbLmzm0RyiLSWUslAd1jzcrbPN6tU57UNg7Ft76JEE", "dH4PT7bhoCS1GnNDPhTdyvEf4LQ-02vFgoQYAUnuBXk" ],
              "locality" : "KÖLN",
              "country" : "DE",
              "postal_code" : "51147",
              "street_address" : "HEIDESTRAẞE 17"
            },
            "iss" : "https://demo.pid-issuer.bundesdruckerei.de/c1",
            "place_of_birth" : {
              "_sd" : [ "lb446t70Mecudk8XeT8qxeK_efIcmRfDLYIXYyZgAOs" ],
              "locality" : "BERLIN"
            },
            "_sd" : [ "-8fWg72puU2gDZzBDCfUEODNgnWgaI_GCOycXR_q30U", "3UQZzVt-nHD7hRnyf4jOkx9_jSx4junUoOlbvQoqSo4", "4VTEa2YOCgtesCBEpAQdC21eHSgtLxbV7CGyiXOyXzs", "BXEEwqp7_cVr-x95sV1NggjPlP0fwyLodkg3ogVuJEk", "bu5kZWyrcj3otjG8fw1_0M8Pn0dVqfrt4DWhRUaNk9A", "x-i7sdleThlgPykvGYZmmx51JCOpAVG7j53YRRKhmGU", "xZ314PCmALV6x7R8iqkU5NAG7FsSXMwkefGV4Sb0004" ],
            "issuing_country" : "DE",
            "issuing_authority" : "DE",
            "_sd_alg" : "sha-256",
            "cnf" : {
              "jwk" : {
                "kty" : "EC",
                "crv" : "P-256",
                "x" : "aVd1KD2t7ifGThA8TnjBkTI4AWARFdPEio0AUzbgZ6w",
                "y" : "Krx4ZYP7eNSk61p4JW-5MyHoikZHq9mZw_HJOXgY60Q"
              }
            },
            "exp" : 1746090238,
            "iat" : 1744880638,
            "status" : {
              "status_list" : {
                "uri" : "https://demo.pid-issuer.bundesdruckerei.de/status/46bfc37a-3764-406e-8b4b-366e6f8c0b83",
                "idx" : 116
              }
            },
            "age_equal_or_over" : {
              "_sd" : [ "MiB7JCLbzZ4d24cmO1riojeu10MbRr5eEZMG92qcPSM", "SANZXZ8rm65a1HnWjC4V-XbigyxECCQpnC0_n4oFv4s", "SzYtYjwSd-Kccz7c8KNIgqDiU_ug8Bd7yVl9mav6wKo", "Y4NSva32hjiJ5WzBhlxPs1HqcZP69VuaQGaf5FS6euA", "pvHNDk6U2TLMGIl4pDFaja2BUl2GnySp0vvur9lT_KM", "zsUFWFlk6qTjRd2ihp8XmoYWrJCADyZntmr7WyAO920" ],
              "12" : true,
              "14" : true,
              "16" : true,
              "18" : true,
              "21" : true,
              "65" : false
            },
            "family_name" : "MUSTERMANN",
            "given_name" : "ERIKA",
            "birthdate" : "1964-08-12",
            "age_birth_year" : 1964,
            "age_in_years" : 60,
            "birth_family_name" : "GABLER",
            "nationalities" : [ "DE" ]
          },
          "credential_format" : "dc+sd-jwt",
          "document_type" : "https://demo.pid-issuer.bundesdruckerei.de/credentials/pid/1.0",
          "id" : 34,
          "title" : "MUSTERMANN ERIKA",
          "subtitle" : "ID Card"
        }, {
          "paths" : {
            "address" : {
              "_sd" : [ "ArSxQy_hoQMHjuVX-dxVF3z58x-klc-6qp50V3t7Bbg", "JsJdNjK3_2FQIB7jrDnpkN6-yACbAU8MiyyYUr49ugw", "enunsQ84z--ygGGn_Xxm6i0b14jdyMZUOmTAQfCJZYk", "pYhR4epXn8jm0s2uR__xQXMpxQYQMhKwMC_otVlPaws" ],
              "locality" : "KÖLN",
              "country" : "DE",
              "postal_code" : "51147",
              "street_address" : "HEIDESTRAẞE 17"
            },
            "iss" : "https://demo.pid-issuer.bundesdruckerei.de/c1",
            "place_of_birth" : {
              "_sd" : [ "AkpLj4I5G0P6nvRxCxUGOu3kmH-15wZOeCdlpMFCdXo" ],
              "locality" : "BERLIN"
            },
            "_sd" : [ "6E0QP5WpieoYEBzKpsKWLDlXgtSdcvs13mKdrmFJ7K0", "B2hHunFbCgqD3oMaFjBEsO5wYBXOiJlrWV7gaQ9uXzw", "DIZ_EVTM7ADoutisxu18IdGBKkMbR2CuWYuWNLROfVk", "NoSGidOhQHJ6YLovLNRqa8xtjQH-IV-gkBqRaH0vYu4", "XU_v8LoawEcu8eRTwERcesQaOFEeLt3C_oAo8B0xTjM", "dkQR1XMR1oax8w_Xc5ekdP-51v3G7GDH5ojlk9eXMIk", "gjVvS_FjVoVFZUCZuABo1M0NL0LELhuXBjG54KqrQ8I" ],
            "issuing_country" : "DE",
            "issuing_authority" : "DE",
            "_sd_alg" : "sha-256",
            "cnf" : {
              "jwk" : {
                "kty" : "EC",
                "crv" : "P-256",
                "x" : "YsFzKX_DiAWwIYTk9PVPs9hk2JPBk8syTeL356GkHPQ",
                "y" : "X5nzXqQ8_wMkFkKRPZHWFCu0-VsZGKRvsIgG5fSE4C0"
              }
            },
            "exp" : 1746090238,
            "iat" : 1744880638,
            "status" : {
              "status_list" : {
                "uri" : "https://demo.pid-issuer.bundesdruckerei.de/status/46bfc37a-3764-406e-8b4b-366e6f8c0b83",
                "idx" : 106
              }
            },
            "age_equal_or_over" : {
              "_sd" : [ "Cd3TnkwWsSCfzhxPqXc_DWa_Jq8TWCrzAoFISyauxlk", "NVtdZPhnqSO19pM259FIj--e7jXY0Ncnj8bOExR5eLg", "m5E7VLCItqk7p4_UpduL-jfBPmHzM0nVInmb6W_Qjng", "pUj-6Hh_kkoeD2C_FPcDORfLL5U5nR80VpwKpxnZgkc", "uAKfSN4-4JLdpUYVwXymyajenhHMSENwjCIrFjxfbto", "zGpq-TnFXqXXVXLl-jdtCcToTEZQc87-Qnvth779kdQ" ],
              "12" : true,
              "14" : true,
              "16" : true,
              "18" : true,
              "21" : true,
              "65" : false
            },
            "family_name" : "MUSTERMANN",
            "given_name" : "ERIKA",
            "birthdate" : "1964-08-12",
            "age_birth_year" : 1964,
            "age_in_years" : 60,
            "birth_family_name" : "GABLER",
            "nationalities" : [ "DE" ]
          },
          "credential_format" : "dc+sd-jwt",
          "document_type" : "https://demo.pid-issuer.bundesdruckerei.de/credentials/pid/1.0",
          "id" : 35,
          "title" : "MUSTERMANN ERIKA",
          "subtitle" : "ID Card"
        }, {
          "paths" : {
            "address" : {
              "_sd" : [ "-7_abgzEZ3Okeu8HAx1o5OzxHTeNZ2C49vaJbFdJO88", "SD6gygvEs105sOh3rHaXpoXgqo2L1AbgZiLZHo_B67s", "pNJ2QJ_crl61t47rhjPHks7kFDNtBX_RGFIVzep_-nM", "xl9aRjdGS7Ld0js_OG-FvJaawLrKgTnyKtaEOMMmjOg" ],
              "locality" : "KÖLN",
              "country" : "DE",
              "postal_code" : "51147",
              "street_address" : "HEIDESTRAẞE 17"
            },
            "iss" : "https://demo.pid-issuer.bundesdruckerei.de/c1",
            "place_of_birth" : {
              "_sd" : [ "JDOLJ7rcAhiYiZAbcpur1_RAD2LMsT0d4IRJjndR4DM" ],
              "locality" : "BERLIN"
            },
            "_sd" : [ "3PglSGp794-aKOno2d_PxOYRonlns9bwL9shg7-c2gc", "9bj5p19ireATyFDl135797VVwAGDyQluTLSCFYKvvNQ", "Mw8PJbq75WqEOGN_vfTvnYu0aWfR6FD4UXHEcaovsLo", "Xy2vvqWZ0Q_zUv4RoHshCwfFu7EfW8Q618OVXgjTmno", "ft1hGOJOiEtic555JVCmtT5xdi8mISFL8_Fvp5u21s0", "ktS5Ez5A_3AeLxSKoWSRKuUnhaMKy5F8K5b-EOfvJS0", "o_--mF25tIpw7Xwr9A6pwS0XDtI3B_mVbNlX1vos3kU" ],
            "issuing_country" : "DE",
            "issuing_authority" : "DE",
            "_sd_alg" : "sha-256",
            "cnf" : {
              "jwk" : {
                "kty" : "EC",
                "crv" : "P-256",
                "x" : "j-AB5BIRG39fvjsrrEKH3kDi9woZ32bYm8sGu3U_uc4",
                "y" : "InZrhkI5vCZyNdLprv8DJnGPCghieTe0VIEcNWMlv18"
              }
            },
            "exp" : 1746090238,
            "iat" : 1744880638,
            "status" : {
              "status_list" : {
                "uri" : "https://demo.pid-issuer.bundesdruckerei.de/status/46bfc37a-3764-406e-8b4b-366e6f8c0b83",
                "idx" : 48
              }
            },
            "age_equal_or_over" : {
              "_sd" : [ "H9_ycSuCiURP1VKzsIqRuFRCyimAZHjd14fe_Zup820", "SCuVf32YNkORS3JxNBsysfQy0RO2JG0nky09DSDylHY", "UhW-fQ3ZtuskWGjwFqV6GyYpDoprNHxbwEuUqC8XTfI", "eNtMmnIrufVMNAKEPiudTaHxcyw6U3FVXc0BESQxU-M", "lYgCvwZ_LlLnb2RIm5kWtWQhMjpek4rxoq6P94l0d7Q", "tgVEfH1gPlfaLE09sJ6UsUYyTWThTBgaJjwI-2ScfZM" ],
              "12" : true,
              "14" : true,
              "16" : true,
              "18" : true,
              "21" : true,
              "65" : false
            },
            "family_name" : "MUSTERMANN",
            "given_name" : "ERIKA",
            "birthdate" : "1964-08-12",
            "age_birth_year" : 1964,
            "age_in_years" : 60,
            "birth_family_name" : "GABLER",
            "nationalities" : [ "DE" ]
          },
          "credential_format" : "dc+sd-jwt",
          "document_type" : "https://demo.pid-issuer.bundesdruckerei.de/credentials/pid/1.0",
          "id" : 36,
          "title" : "MUSTERMANN ERIKA",
          "subtitle" : "ID Card"
        }, {
          "paths" : {
            "eu.europa.ec.eudi.pid.1" : {
              "age_over_12" : true,
              "age_over_14" : true,
              "age_over_65" : false,
              "issuance_date" : "2025-04-17T09:04:01.552Z",
              "birth_place" : "BERLIN",
              "issuing_country" : "DE",
              "age_over_21" : true,
              "age_birth_year" : 1964.0,
              "age_over_16" : true,
              "expiry_date" : "2025-05-01T09:04:01.552Z",
              "issuing_authority" : "DE",
              "age_over_18" : true,
              "resident_city" : "KÖLN",
              "birth_date" : "1964-08-12T00:00:00Z",
              "resident_postal_code" : "51147",
              "family_name_birth" : "GABLER",
              "given_name" : "ERIKA",
              "resident_street" : "HEIDESTRAẞE 17",
              "nationality" : "DE",
              "family_name" : "MUSTERMANN",
              "age_in_years" : 60.0,
              "resident_country" : "DE"
            },
            "exp" : 1746090241
          },
          "credential_format" : "dc+sd-jwt",
          "document_type" : "https://demo.pid-issuer.bundesdruckerei.de/credentials/pid/1.0",
          "id" : 37,
          "title" : "MUSTERMANN ERIKA",
          "subtitle" : "ID Card"
        }, {
          "paths" : {
            "eu.europa.ec.eudi.pid.1" : {
              "resident_postal_code" : "51147",
              "family_name_birth" : "GABLER",
              "family_name" : "MUSTERMANN",
              "age_over_21" : true,
              "age_over_12" : true,
              "resident_street" : "HEIDESTRAẞE 17",
              "age_over_65" : false,
              "age_over_14" : true,
              "age_over_18" : true,
              "issuing_country" : "DE",
              "resident_city" : "KÖLN",
              "age_in_years" : 60.0,
              "birth_date" : "1964-08-12T00:00:00Z",
              "given_name" : "ERIKA",
              "expiry_date" : "2025-05-01T09:04:01.554Z",
              "age_birth_year" : 1964.0,
              "issuing_authority" : "DE",
              "resident_country" : "DE",
              "issuance_date" : "2025-04-17T09:04:01.554Z",
              "age_over_16" : true,
              "nationality" : "DE",
              "birth_place" : "BERLIN"
            },
            "exp" : 1746090241
          },
          "credential_format" : "dc+sd-jwt",
          "document_type" : "https://demo.pid-issuer.bundesdruckerei.de/credentials/pid/1.0",
          "id" : 38,
          "title" : "MUSTERMANN ERIKA",
          "subtitle" : "ID Card"
        }, {
          "paths" : {
            "eu.europa.ec.eudi.pid.1" : {
              "family_name" : "MUSTERMANN",
              "age_over_14" : true,
              "birth_place" : "BERLIN",
              "resident_city" : "KÖLN",
              "expiry_date" : "2025-05-01T09:04:01.556Z",
              "age_birth_year" : 1964.0,
              "given_name" : "ERIKA",
              "age_over_18" : true,
              "age_in_years" : 60.0,
              "age_over_16" : true,
              "nationality" : "DE",
              "resident_street" : "HEIDESTRAẞE 17",
              "issuance_date" : "2025-04-17T09:04:01.556Z",
              "issuing_authority" : "DE",
              "age_over_21" : true,
              "age_over_12" : true,
              "resident_postal_code" : "51147",
              "birth_date" : "1964-08-12T00:00:00Z",
              "issuing_country" : "DE",
              "family_name_birth" : "GABLER",
              "resident_country" : "DE",
              "age_over_65" : false
            },
            "exp" : 1746090241
          },
          "credential_format" : "dc+sd-jwt",
          "document_type" : "https://demo.pid-issuer.bundesdruckerei.de/credentials/pid/1.0",
          "id" : 39,
          "title" : "MUSTERMANN ERIKA",
          "subtitle" : "ID Card"
        }, {
          "paths" : {
            "eu.europa.ec.eudi.pid.1" : {
              "age_in_years" : 60.0,
              "family_name_birth" : "GABLER",
              "family_name" : "MUSTERMANN",
              "issuing_authority" : "DE",
              "age_over_16" : true,
              "birth_date" : "1964-08-12T00:00:00Z",
              "resident_street" : "HEIDESTRAẞE 17",
              "age_over_18" : true,
              "expiry_date" : "2025-05-01T09:04:01.558Z",
              "resident_postal_code" : "51147",
              "nationality" : "DE",
              "age_over_65" : false,
              "age_birth_year" : 1964.0,
              "age_over_12" : true,
              "age_over_14" : true,
              "given_name" : "ERIKA",
              "age_over_21" : true,
              "birth_place" : "BERLIN",
              "resident_country" : "DE",
              "issuing_country" : "DE",
              "resident_city" : "KÖLN",
              "issuance_date" : "2025-04-17T09:04:01.558Z"
            },
            "exp" : 1746090241
          },
          "credential_format" : "dc+sd-jwt",
          "document_type" : "https://demo.pid-issuer.bundesdruckerei.de/credentials/pid/1.0",
          "id" : 40,
          "title" : "MUSTERMANN ERIKA",
          "subtitle" : "ID Card"
        }, {
          "paths" : {
            "eu.europa.ec.eudi.pid.1" : {
              "resident_postal_code" : "51147",
              "issuing_authority" : "DE",
              "age_over_14" : true,
              "resident_street" : "HEIDESTRAẞE 17",
              "family_name" : "MUSTERMANN",
              "age_birth_year" : 1964.0,
              "age_over_18" : true,
              "family_name_birth" : "GABLER",
              "age_over_65" : false,
              "age_over_12" : true,
              "age_over_21" : true,
              "age_over_16" : true,
              "expiry_date" : "2025-05-01T09:04:01.56Z",
              "resident_country" : "DE",
              "nationality" : "DE",
              "issuing_country" : "DE",
              "age_in_years" : 60.0,
              "birth_date" : "1964-08-12T00:00:00Z",
              "resident_city" : "KÖLN",
              "birth_place" : "BERLIN",
              "given_name" : "ERIKA",
              "issuance_date" : "2025-04-17T09:04:01.56Z"
            },
            "exp" : 1746090241
          },
          "credential_format" : "dc+sd-jwt",
          "document_type" : "https://demo.pid-issuer.bundesdruckerei.de/credentials/pid/1.0",
          "id" : 41,
          "title" : "MUSTERMANN ERIKA",
          "subtitle" : "ID Card"
        }, {
          "paths" : {
            "eu.europa.ec.eudi.pid.1" : {
              "resident_country" : "DE",
              "age_birth_year" : 1964.0,
              "issuance_date" : "2025-04-17T09:04:01.562Z",
              "issuing_country" : "DE",
              "resident_city" : "KÖLN",
              "nationality" : "DE",
              "family_name_birth" : "GABLER",
              "issuing_authority" : "DE",
              "birth_place" : "BERLIN",
              "age_over_65" : false,
              "age_over_14" : true,
              "age_over_18" : true,
              "resident_street" : "HEIDESTRAẞE 17",
              "age_over_12" : true,
              "age_in_years" : 60.0,
              "family_name" : "MUSTERMANN",
              "expiry_date" : "2025-05-01T09:04:01.562Z",
              "resident_postal_code" : "51147",
              "given_name" : "ERIKA",
              "age_over_16" : true,
              "birth_date" : "1964-08-12T00:00:00Z",
              "age_over_21" : true
            },
            "exp" : 1746090241
          },
          "credential_format" : "dc+sd-jwt",
          "document_type" : "https://demo.pid-issuer.bundesdruckerei.de/credentials/pid/1.0",
          "id" : 42,
          "title" : "MUSTERMANN ERIKA",
          "subtitle" : "ID Card"
        }, {
          "paths" : {
            "eu.europa.ec.eudi.pid.1" : {
              "given_name" : "ERIKA",
              "age_birth_year" : 1964.0,
              "age_over_65" : false,
              "resident_city" : "KÖLN",
              "family_name" : "MUSTERMANN",
              "age_over_14" : true,
              "age_in_years" : 60.0,
              "birth_date" : "1964-08-12T00:00:00Z",
              "age_over_12" : true,
              "issuing_authority" : "DE",
              "expiry_date" : "2025-05-01T09:04:01.564Z",
              "resident_country" : "DE",
              "resident_postal_code" : "51147",
              "nationality" : "DE",
              "age_over_16" : true,
              "issuing_country" : "DE",
              "age_over_18" : true,
              "issuance_date" : "2025-04-17T09:04:01.564Z",
              "resident_street" : "HEIDESTRAẞE 17",
              "birth_place" : "BERLIN",
              "family_name_birth" : "GABLER",
              "age_over_21" : true
            },
            "exp" : 1746090241
          },
          "credential_format" : "dc+sd-jwt",
          "document_type" : "https://demo.pid-issuer.bundesdruckerei.de/credentials/pid/1.0",
          "id" : 43,
          "title" : "MUSTERMANN ERIKA",
          "subtitle" : "ID Card"
        }, {
          "paths" : {
            "eu.europa.ec.eudi.pid.1" : {
              "age_over_12" : true,
              "resident_postal_code" : "51147",
              "age_over_65" : false,
              "resident_city" : "KÖLN",
              "birth_date" : "1964-08-12T00:00:00Z",
              "age_over_14" : true,
              "age_over_18" : true,
              "issuing_authority" : "DE",
              "age_birth_year" : 1964.0,
              "expiry_date" : "2025-05-01T09:04:01.566Z",
              "family_name_birth" : "GABLER",
              "issuance_date" : "2025-04-17T09:04:01.566Z",
              "resident_street" : "HEIDESTRAẞE 17",
              "age_over_16" : true,
              "issuing_country" : "DE",
              "birth_place" : "BERLIN",
              "resident_country" : "DE",
              "nationality" : "DE",
              "age_over_21" : true,
              "age_in_years" : 60.0,
              "family_name" : "MUSTERMANN",
              "given_name" : "ERIKA"
            },
            "exp" : 1746090241
          },
          "credential_format" : "dc+sd-jwt",
          "document_type" : "https://demo.pid-issuer.bundesdruckerei.de/credentials/pid/1.0",
          "id" : 44,
          "title" : "MUSTERMANN ERIKA",
          "subtitle" : "ID Card"
        }, {
          "paths" : {
            "eu.europa.ec.eudi.pid.1" : {
              "birth_place" : "BERLIN",
              "given_name" : "ERIKA",
              "age_over_14" : true,
              "issuing_country" : "DE",
              "family_name_birth" : "GABLER",
              "age_over_65" : false,
              "resident_postal_code" : "51147",
              "age_in_years" : 60.0,
              "age_over_18" : true,
              "age_birth_year" : 1964.0,
              "age_over_21" : true,
              "resident_street" : "HEIDESTRAẞE 17",
              "issuing_authority" : "DE",
              "resident_country" : "DE",
              "expiry_date" : "2025-05-01T09:04:01.568Z",
              "family_name" : "MUSTERMANN",
              "age_over_16" : true,
              "issuance_date" : "2025-04-17T09:04:01.568Z",
              "resident_city" : "KÖLN",
              "birth_date" : "1964-08-12T00:00:00Z",
              "nationality" : "DE",
              "age_over_12" : true
            },
            "exp" : 1746090241
          },
          "credential_format" : "dc+sd-jwt",
          "document_type" : "https://demo.pid-issuer.bundesdruckerei.de/credentials/pid/1.0",
          "id" : 45,
          "title" : "MUSTERMANN ERIKA",
          "subtitle" : "ID Card"
        }, {
          "paths" : {
            "eu.europa.ec.eudi.pid.1" : {
              "issuance_date" : "2025-04-17T09:04:01.569Z",
              "issuing_country" : "DE",
              "age_over_16" : true,
              "issuing_authority" : "DE",
              "age_birth_year" : 1964.0,
              "family_name_birth" : "GABLER",
              "age_over_65" : false,
              "resident_city" : "KÖLN",
              "given_name" : "ERIKA",
              "resident_postal_code" : "51147",
              "birth_date" : "1964-08-12T00:00:00Z",
              "age_over_18" : true,
              "age_over_14" : true,
              "age_over_21" : true,
              "birth_place" : "BERLIN",
              "age_over_12" : true,
              "age_in_years" : 60.0,
              "nationality" : "DE",
              "resident_country" : "DE",
              "resident_street" : "HEIDESTRAẞE 17",
              "family_name" : "MUSTERMANN",
              "expiry_date" : "2025-05-01T09:04:01.569Z"
            },
            "exp" : 1746090241
          },
          "credential_format" : "dc+sd-jwt",
          "document_type" : "https://demo.pid-issuer.bundesdruckerei.de/credentials/pid/1.0",
          "id" : 46,
          "title" : "MUSTERMANN ERIKA",
          "subtitle" : "ID Card"
        }, {
          "paths" : {
            "eu.europa.ec.eudi.pid.1" : {
              "age_birth_year" : 1964.0,
              "issuance_date" : "2025-04-17T09:04:01.571Z",
              "resident_postal_code" : "51147",
              "issuing_country" : "DE",
              "family_name" : "MUSTERMANN",
              "given_name" : "ERIKA",
              "birth_date" : "1964-08-12T00:00:00Z",
              "resident_country" : "DE",
              "birth_place" : "BERLIN",
              "age_over_14" : true,
              "nationality" : "DE",
              "age_over_18" : true,
              "age_in_years" : 60.0,
              "age_over_16" : true,
              "family_name_birth" : "GABLER",
              "issuing_authority" : "DE",
              "age_over_65" : false,
              "resident_street" : "HEIDESTRAẞE 17",
              "age_over_21" : true,
              "age_over_12" : true,
              "resident_city" : "KÖLN",
              "expiry_date" : "2025-05-01T09:04:01.571Z"
            },
            "exp" : 1746090241
          },
          "credential_format" : "dc+sd-jwt",
          "document_type" : "https://demo.pid-issuer.bundesdruckerei.de/credentials/pid/1.0",
          "id" : 47,
          "title" : "MUSTERMANN ERIKA",
          "subtitle" : "ID Card"
        }, {
          "paths" : {
            "eu.europa.ec.eudi.pid.1" : {
              "expiry_date" : "2025-05-01T09:04:01.573Z",
              "issuing_country" : "DE",
              "resident_country" : "DE",
              "age_over_14" : true,
              "age_over_18" : true,
              "family_name_birth" : "GABLER",
              "age_birth_year" : 1964.0,
              "birth_place" : "BERLIN",
              "given_name" : "ERIKA",
              "nationality" : "DE",
              "family_name" : "MUSTERMANN",
              "age_in_years" : 60.0,
              "age_over_16" : true,
              "age_over_21" : true,
              "age_over_65" : false,
              "issuance_date" : "2025-04-17T09:04:01.573Z",
              "resident_street" : "HEIDESTRAẞE 17",
              "birth_date" : "1964-08-12T00:00:00Z",
              "resident_city" : "KÖLN",
              "resident_postal_code" : "51147",
              "issuing_authority" : "DE",
              "age_over_12" : true
            },
            "exp" : 1746090241
          },
          "credential_format" : "dc+sd-jwt",
          "document_type" : "https://demo.pid-issuer.bundesdruckerei.de/credentials/pid/1.0",
          "id" : 48,
          "title" : "MUSTERMANN ERIKA",
          "subtitle" : "ID Card"
        }, {
          "paths" : {
            "eu.europa.ec.eudi.pid.1" : {
              "resident_country" : "DE",
              "age_over_18" : true,
              "age_over_12" : true,
              "given_name" : "ERIKA",
              "age_over_14" : true,
              "resident_street" : "HEIDESTRAẞE 17",
              "age_birth_year" : 1964.0,
              "age_over_21" : true,
              "family_name_birth" : "GABLER",
              "family_name" : "MUSTERMANN",
              "issuing_authority" : "DE",
              "resident_postal_code" : "51147",
              "birth_place" : "BERLIN",
              "birth_date" : "1964-08-12T00:00:00Z",
              "age_over_65" : false,
              "resident_city" : "KÖLN",
              "issuance_date" : "2025-04-17T09:04:01.575Z",
              "expiry_date" : "2025-05-01T09:04:01.575Z",
              "age_in_years" : 60.0,
              "nationality" : "DE",
              "age_over_16" : true,
              "issuing_country" : "DE"
            },
            "exp" : 1746090241
          },
          "credential_format" : "dc+sd-jwt",
          "document_type" : "https://demo.pid-issuer.bundesdruckerei.de/credentials/pid/1.0",
          "id" : 49,
          "title" : "MUSTERMANN ERIKA",
          "subtitle" : "ID Card"
        }, {
          "paths" : {
            "eu.europa.ec.eudi.pid.1" : {
              "birth_date" : "1964-08-12T00:00:00Z",
              "age_over_21" : true,
              "resident_city" : "KÖLN",
              "age_over_14" : true,
              "family_name" : "MUSTERMANN",
              "nationality" : "DE",
              "issuance_date" : "2025-04-17T09:04:01.577Z",
              "age_in_years" : 60.0,
              "resident_postal_code" : "51147",
              "family_name_birth" : "GABLER",
              "resident_street" : "HEIDESTRAẞE 17",
              "age_over_16" : true,
              "given_name" : "ERIKA",
              "expiry_date" : "2025-05-01T09:04:01.577Z",
              "age_birth_year" : 1964.0,
              "age_over_65" : false,
              "age_over_18" : true,
              "issuing_authority" : "DE",
              "birth_place" : "BERLIN",
              "issuing_country" : "DE",
              "resident_country" : "DE",
              "age_over_12" : true
            },
            "exp" : 1746090241
          },
          "credential_format" : "dc+sd-jwt",
          "document_type" : "https://demo.pid-issuer.bundesdruckerei.de/credentials/pid/1.0",
          "id" : 50,
          "title" : "MUSTERMANN ERIKA",
          "subtitle" : "ID Card"
        }, {
          "paths" : {
            "eu.europa.ec.eudi.pid.1" : {
              "age_in_years" : 60.0,
              "issuing_authority" : "DE",
              "expiry_date" : "2025-05-01T09:04:01.579Z",
              "family_name" : "MUSTERMANN",
              "resident_street" : "HEIDESTRAẞE 17",
              "given_name" : "ERIKA",
              "issuance_date" : "2025-04-17T09:04:01.579Z",
              "age_over_18" : true,
              "age_over_12" : true,
              "resident_postal_code" : "51147",
              "resident_city" : "KÖLN",
              "age_over_14" : true,
              "birth_place" : "BERLIN",
              "birth_date" : "1964-08-12T00:00:00Z",
              "issuing_country" : "DE",
              "age_over_16" : true,
              "age_over_65" : false,
              "age_birth_year" : 1964.0,
              "resident_country" : "DE",
              "nationality" : "DE",
              "age_over_21" : true,
              "family_name_birth" : "GABLER"
            },
            "exp" : 1746090241
          },
          "credential_format" : "dc+sd-jwt",
          "document_type" : "https://demo.pid-issuer.bundesdruckerei.de/credentials/pid/1.0",
          "id" : 51,
          "title" : "MUSTERMANN ERIKA",
          "subtitle" : "ID Card"
        }, {
          "paths" : {
            "eu.europa.ec.eudi.pid.1" : {
              "age_over_21" : true,
              "birth_date" : "1964-08-12T00:00:00Z",
              "resident_street" : "HEIDESTRAẞE 17",
              "given_name" : "ERIKA",
              "resident_city" : "KÖLN",
              "birth_place" : "BERLIN",
              "age_over_16" : true,
              "resident_postal_code" : "51147",
              "age_over_12" : true,
              "age_over_18" : true,
              "age_birth_year" : 1964.0,
              "family_name_birth" : "GABLER",
              "nationality" : "DE",
              "age_over_65" : false,
              "family_name" : "MUSTERMANN",
              "issuing_authority" : "DE",
              "resident_country" : "DE",
              "issuance_date" : "2025-04-17T09:04:01.58Z",
              "age_in_years" : 60.0,
              "age_over_14" : true,
              "issuing_country" : "DE",
              "expiry_date" : "2025-05-01T09:04:01.58Z"
            },
            "exp" : 1746090241
          },
          "credential_format" : "dc+sd-jwt",
          "document_type" : "https://demo.pid-issuer.bundesdruckerei.de/credentials/pid/1.0",
          "id" : 52,
          "title" : "MUSTERMANN ERIKA",
          "subtitle" : "ID Card"
        }, {
          "paths" : {
            "eu.europa.ec.eudi.pid.1" : {
              "age_over_14" : true,
              "nationality" : "DE",
              "resident_street" : "HEIDESTRAẞE 17",
              "age_over_16" : true,
              "age_birth_year" : 1964.0,
              "resident_city" : "KÖLN",
              "family_name_birth" : "GABLER",
              "given_name" : "ERIKA",
              "age_over_18" : true,
              "issuance_date" : "2025-04-17T09:04:01.582Z",
              "family_name" : "MUSTERMANN",
              "expiry_date" : "2025-05-01T09:04:01.582Z",
              "age_over_12" : true,
              "age_over_21" : true,
              "birth_date" : "1964-08-12T00:00:00Z",
              "birth_place" : "BERLIN",
              "age_in_years" : 60.0,
              "issuing_authority" : "DE",
              "resident_country" : "DE",
              "issuing_country" : "DE",
              "age_over_65" : false,
              "resident_postal_code" : "51147"
            },
            "exp" : 1746090241
          },
          "credential_format" : "dc+sd-jwt",
          "document_type" : "https://demo.pid-issuer.bundesdruckerei.de/credentials/pid/1.0",
          "id" : 53,
          "title" : "MUSTERMANN ERIKA",
          "subtitle" : "ID Card"
        }, {
          "paths" : {
            "eu.europa.ec.eudi.pid.1" : {
              "issuing_authority" : "DE",
              "age_over_21" : true,
              "birth_place" : "BERLIN",
              "issuing_country" : "DE",
              "birth_date" : "1964-08-12T00:00:00Z",
              "family_name" : "MUSTERMANN",
              "age_over_12" : true,
              "age_in_years" : 60.0,
              "resident_country" : "DE",
              "age_over_18" : true,
              "resident_city" : "KÖLN",
              "nationality" : "DE",
              "issuance_date" : "2025-04-17T09:04:01.583Z",
              "resident_postal_code" : "51147",
              "family_name_birth" : "GABLER",
              "expiry_date" : "2025-05-01T09:04:01.583Z",
              "resident_street" : "HEIDESTRAẞE 17",
              "age_over_16" : true,
              "age_birth_year" : 1964.0,
              "given_name" : "ERIKA",
              "age_over_14" : true,
              "age_over_65" : false
            },
            "exp" : 1746090241
          },
          "credential_format" : "dc+sd-jwt",
          "document_type" : "https://demo.pid-issuer.bundesdruckerei.de/credentials/pid/1.0",
          "id" : 54,
          "title" : "MUSTERMANN ERIKA",
          "subtitle" : "ID Card"
        }, {
          "paths" : {
            "eu.europa.ec.eudi.pid.1" : {
              "age_over_21" : true,
              "nationality" : "DE",
              "issuing_authority" : "DE",
              "age_over_18" : true,
              "age_over_16" : true,
              "expiry_date" : "2025-05-01T09:04:01.585Z",
              "family_name_birth" : "GABLER",
              "issuance_date" : "2025-04-17T09:04:01.585Z",
              "resident_city" : "KÖLN",
              "age_birth_year" : 1964.0,
              "age_in_years" : 60.0,
              "given_name" : "ERIKA",
              "age_over_65" : false,
              "birth_date" : "1964-08-12T00:00:00Z",
              "family_name" : "MUSTERMANN",
              "issuing_country" : "DE",
              "resident_street" : "HEIDESTRAẞE 17",
              "birth_place" : "BERLIN",
              "age_over_14" : true,
              "resident_country" : "DE",
              "resident_postal_code" : "51147",
              "age_over_12" : true
            },
            "exp" : 1746090241
          },
          "credential_format" : "dc+sd-jwt",
          "document_type" : "https://demo.pid-issuer.bundesdruckerei.de/credentials/pid/1.0",
          "id" : 55,
          "title" : "MUSTERMANN ERIKA",
          "subtitle" : "ID Card"
        }, {
          "paths" : {
            "eu.europa.ec.eudi.pid.1" : {
              "resident_postal_code" : "51147",
              "birth_date" : "1964-08-12T00:00:00Z",
              "age_over_18" : true,
              "birth_place" : "BERLIN",
              "resident_country" : "DE",
              "family_name" : "MUSTERMANN",
              "resident_city" : "KÖLN",
              "given_name" : "ERIKA",
              "age_over_14" : true,
              "age_over_16" : true,
              "expiry_date" : "2025-05-01T09:04:01.586Z",
              "age_over_21" : true,
              "nationality" : "DE",
              "age_birth_year" : 1964.0,
              "issuance_date" : "2025-04-17T09:04:01.586Z",
              "age_in_years" : 60.0,
              "issuing_authority" : "DE",
              "age_over_65" : false,
              "family_name_birth" : "GABLER",
              "issuing_country" : "DE",
              "resident_street" : "HEIDESTRAẞE 17",
              "age_over_12" : true
            },
            "exp" : 1746090241
          },
          "credential_format" : "dc+sd-jwt",
          "document_type" : "https://demo.pid-issuer.bundesdruckerei.de/credentials/pid/1.0",
          "id" : 56,
          "title" : "MUSTERMANN ERIKA",
          "subtitle" : "ID Card"
        }, {
          "paths" : {
            "eu.europa.ec.eudi.pid.1" : {
              "age_over_21" : true,
              "given_name" : "ERIKA",
              "resident_country" : "DE",
              "age_over_65" : false,
              "issuing_country" : "DE",
              "age_over_16" : true,
              "family_name" : "MUSTERMANN",
              "resident_postal_code" : "51147",
              "issuance_date" : "2025-04-17T09:04:01.588Z",
              "age_over_18" : true,
              "birth_date" : "1964-08-12T00:00:00Z",
              "birth_place" : "BERLIN",
              "age_in_years" : 60.0,
              "family_name_birth" : "GABLER",
              "age_over_12" : true,
              "expiry_date" : "2025-05-01T09:04:01.588Z",
              "resident_city" : "KÖLN",
              "issuing_authority" : "DE",
              "resident_street" : "HEIDESTRAẞE 17",
              "age_over_14" : true,
              "age_birth_year" : 1964.0,
              "nationality" : "DE"
            },
            "exp" : 1746090241
          },
          "credential_format" : "dc+sd-jwt",
          "document_type" : "https://demo.pid-issuer.bundesdruckerei.de/credentials/pid/1.0",
          "id" : 57,
          "title" : "MUSTERMANN ERIKA",
          "subtitle" : "ID Card"
        }, {
          "paths" : {
            "eu.europa.ec.eudi.pid.1" : {
              "birth_date" : "1964-08-12T00:00:00Z",
              "age_over_18" : true,
              "age_over_14" : true,
              "family_name" : "MUSTERMANN",
              "resident_street" : "HEIDESTRAẞE 17",
              "age_birth_year" : 1964.0,
              "expiry_date" : "2025-05-01T09:04:07.34Z",
              "age_over_65" : false,
              "age_in_years" : 60.0,
              "family_name_birth" : "GABLER",
              "birth_place" : "BERLIN",
              "resident_postal_code" : "51147",
              "resident_city" : "KÖLN",
              "given_name" : "ERIKA",
              "age_over_12" : true,
              "age_over_16" : true,
              "issuing_authority" : "DE",
              "issuance_date" : "2025-04-17T09:04:07.34Z",
              "nationality" : "DE",
              "resident_country" : "DE",
              "issuing_country" : "DE",
              "age_over_21" : true
            },
            "exp" : 1746090247
          },
          "credential_format" : "dc+sd-jwt",
          "document_type" : "https://demo.pid-issuer.bundesdruckerei.de/credentials/pid/1.0",
          "id" : 58,
          "title" : "MUSTERMANN ERIKA",
          "subtitle" : "ID Card"
        }, {
          "paths" : {
            "eu.europa.ec.eudi.pid.1" : {
              "age_over_65" : false,
              "resident_city" : "KÖLN",
              "issuing_authority" : "DE",
              "expiry_date" : "2025-05-01T09:04:07.342Z",
              "resident_country" : "DE",
              "age_over_14" : true,
              "age_birth_year" : 1964.0,
              "age_over_21" : true,
              "issuing_country" : "DE",
              "age_over_12" : true,
              "birth_place" : "BERLIN",
              "age_over_16" : true,
              "birth_date" : "1964-08-12T00:00:00Z",
              "family_name" : "MUSTERMANN",
              "issuance_date" : "2025-04-17T09:04:07.342Z",
              "family_name_birth" : "GABLER",
              "given_name" : "ERIKA",
              "age_over_18" : true,
              "age_in_years" : 60.0,
              "resident_street" : "HEIDESTRAẞE 17",
              "resident_postal_code" : "51147",
              "nationality" : "DE"
            },
            "exp" : 1746090247
          },
          "credential_format" : "dc+sd-jwt",
          "document_type" : "https://demo.pid-issuer.bundesdruckerei.de/credentials/pid/1.0",
          "id" : 59,
          "title" : "MUSTERMANN ERIKA",
          "subtitle" : "ID Card"
        }, {
          "paths" : {
            "eu.europa.ec.eudi.pid.1" : {
              "age_over_21" : true,
              "family_name" : "MUSTERMANN",
              "age_birth_year" : 1964.0,
              "issuing_country" : "DE",
              "age_in_years" : 60.0,
              "resident_street" : "HEIDESTRAẞE 17",
              "issuing_authority" : "DE",
              "age_over_12" : true,
              "resident_city" : "KÖLN",
              "resident_country" : "DE",
              "family_name_birth" : "GABLER",
              "age_over_14" : true,
              "resident_postal_code" : "51147",
              "expiry_date" : "2025-05-01T09:04:07.345Z",
              "birth_date" : "1964-08-12T00:00:00Z",
              "given_name" : "ERIKA",
              "nationality" : "DE",
              "age_over_65" : false,
              "age_over_16" : true,
              "birth_place" : "BERLIN",
              "age_over_18" : true,
              "issuance_date" : "2025-04-17T09:04:07.345Z"
            },
            "exp" : 1746090247
          },
          "credential_format" : "dc+sd-jwt",
          "document_type" : "https://demo.pid-issuer.bundesdruckerei.de/credentials/pid/1.0",
          "id" : 60,
          "title" : "MUSTERMANN ERIKA",
          "subtitle" : "ID Card"
        }, {
          "paths" : {
            "eu.europa.ec.eudi.pid.1" : {
              "age_over_21" : true,
              "resident_country" : "DE",
              "resident_city" : "KÖLN",
              "age_in_years" : 60.0,
              "issuing_authority" : "DE",
              "resident_postal_code" : "51147",
              "age_over_65" : false,
              "family_name_birth" : "GABLER",
              "nationality" : "DE",
              "issuing_country" : "DE",
              "expiry_date" : "2025-05-01T09:04:07.346Z",
              "birth_place" : "BERLIN",
              "resident_street" : "HEIDESTRAẞE 17",
              "age_birth_year" : 1964.0,
              "age_over_18" : true,
              "family_name" : "MUSTERMANN",
              "age_over_12" : true,
              "issuance_date" : "2025-04-17T09:04:07.346Z",
              "birth_date" : "1964-08-12T00:00:00Z",
              "age_over_16" : true,
              "given_name" : "ERIKA",
              "age_over_14" : true
            },
            "exp" : 1746090247
          },
          "credential_format" : "dc+sd-jwt",
          "document_type" : "https://demo.pid-issuer.bundesdruckerei.de/credentials/pid/1.0",
          "id" : 61,
          "title" : "MUSTERMANN ERIKA",
          "subtitle" : "ID Card"
        }, {
          "paths" : {
            "eu.europa.ec.eudi.pid.1" : {
              "resident_city" : "KÖLN",
              "family_name" : "MUSTERMANN",
              "age_in_years" : 60.0,
              "given_name" : "ERIKA",
              "resident_postal_code" : "51147",
              "resident_country" : "DE",
              "age_over_14" : true,
              "age_over_18" : true,
              "age_over_16" : true,
              "birth_date" : "1964-08-12T00:00:00Z",
              "issuing_country" : "DE",
              "nationality" : "DE",
              "expiry_date" : "2025-05-01T09:04:07.348Z",
              "age_over_12" : true,
              "birth_place" : "BERLIN",
              "age_over_65" : false,
              "age_over_21" : true,
              "issuing_authority" : "DE",
              "family_name_birth" : "GABLER",
              "issuance_date" : "2025-04-17T09:04:07.348Z",
              "resident_street" : "HEIDESTRAẞE 17",
              "age_birth_year" : 1964.0
            },
            "exp" : 1746090247
          },
          "credential_format" : "dc+sd-jwt",
          "document_type" : "https://demo.pid-issuer.bundesdruckerei.de/credentials/pid/1.0",
          "id" : 62,
          "title" : "MUSTERMANN ERIKA",
          "subtitle" : "ID Card"
        }, {
          "paths" : {
            "eu.europa.ec.eudi.pid.1" : {
              "issuance_date" : "2025-04-17T09:04:07.35Z",
              "issuing_country" : "DE",
              "resident_postal_code" : "51147",
              "age_over_16" : true,
              "family_name_birth" : "GABLER",
              "birth_place" : "BERLIN",
              "given_name" : "ERIKA",
              "age_birth_year" : 1964.0,
              "age_in_years" : 60.0,
              "resident_city" : "KÖLN",
              "age_over_21" : true,
              "age_over_12" : true,
              "resident_country" : "DE",
              "resident_street" : "HEIDESTRAẞE 17",
              "age_over_18" : true,
              "birth_date" : "1964-08-12T00:00:00Z",
              "family_name" : "MUSTERMANN",
              "nationality" : "DE",
              "age_over_14" : true,
              "issuing_authority" : "DE",
              "age_over_65" : false,
              "expiry_date" : "2025-05-01T09:04:07.35Z"
            },
            "exp" : 1746090247
          },
          "credential_format" : "dc+sd-jwt",
          "document_type" : "https://demo.pid-issuer.bundesdruckerei.de/credentials/pid/1.0",
          "id" : 63,
          "title" : "MUSTERMANN ERIKA",
          "subtitle" : "ID Card"
        }, {
          "paths" : {
            "eu.europa.ec.eudi.pid.1" : {
              "issuing_country" : "DE",
              "age_over_65" : false,
              "birth_date" : "1964-08-12T00:00:00Z",
              "age_in_years" : 60.0,
              "expiry_date" : "2025-05-01T09:04:07.351Z",
              "age_over_16" : true,
              "family_name" : "MUSTERMANN",
              "age_over_18" : true,
              "age_over_12" : true,
              "family_name_birth" : "GABLER",
              "issuing_authority" : "DE",
              "issuance_date" : "2025-04-17T09:04:07.351Z",
              "given_name" : "ERIKA",
              "birth_place" : "BERLIN",
              "resident_postal_code" : "51147",
              "age_over_21" : true,
              "resident_city" : "KÖLN",
              "age_birth_year" : 1964.0,
              "resident_country" : "DE",
              "age_over_14" : true,
              "resident_street" : "HEIDESTRAẞE 17",
              "nationality" : "DE"
            },
            "exp" : 1746090247
          },
          "credential_format" : "dc+sd-jwt",
          "document_type" : "https://demo.pid-issuer.bundesdruckerei.de/credentials/pid/1.0",
          "id" : 64,
          "title" : "MUSTERMANN ERIKA",
          "subtitle" : "ID Card"
        }, {
          "paths" : {
            "eu.europa.ec.eudi.pid.1" : {
              "resident_country" : "DE",
              "issuing_authority" : "DE",
              "issuing_country" : "DE",
              "age_over_12" : true,
              "age_over_21" : true,
              "given_name" : "ERIKA",
              "resident_postal_code" : "51147",
              "resident_street" : "HEIDESTRAẞE 17",
              "expiry_date" : "2025-05-01T09:04:07.352Z",
              "age_over_18" : true,
              "birth_place" : "BERLIN",
              "family_name_birth" : "GABLER",
              "issuance_date" : "2025-04-17T09:04:07.352Z",
              "birth_date" : "1964-08-12T00:00:00Z",
              "resident_city" : "KÖLN",
              "nationality" : "DE",
              "age_in_years" : 60.0,
              "age_over_16" : true,
              "family_name" : "MUSTERMANN",
              "age_birth_year" : 1964.0,
              "age_over_14" : true,
              "age_over_65" : false
            },
            "exp" : 1746090247
          },
          "credential_format" : "dc+sd-jwt",
          "document_type" : "https://demo.pid-issuer.bundesdruckerei.de/credentials/pid/1.0",
          "id" : 65,
          "title" : "MUSTERMANN ERIKA",
          "subtitle" : "ID Card"
        }, {
          "paths" : {
            "eu.europa.ec.eudi.pid.1" : {
              "expiry_date" : "2025-05-01T09:04:07.354Z",
              "resident_street" : "HEIDESTRAẞE 17",
              "age_over_16" : true,
              "resident_city" : "KÖLN",
              "issuing_authority" : "DE",
              "given_name" : "ERIKA",
              "resident_country" : "DE",
              "nationality" : "DE",
              "age_over_14" : true,
              "family_name" : "MUSTERMANN",
              "birth_place" : "BERLIN",
              "age_over_18" : true,
              "age_in_years" : 60.0,
              "age_over_12" : true,
              "age_birth_year" : 1964.0,
              "age_over_21" : true,
              "issuance_date" : "2025-04-17T09:04:07.354Z",
              "issuing_country" : "DE",
              "resident_postal_code" : "51147",
              "age_over_65" : false,
              "family_name_birth" : "GABLER",
              "birth_date" : "1964-08-12T00:00:00Z"
            },
            "exp" : 1746090247
          },
          "credential_format" : "dc+sd-jwt",
          "document_type" : "https://demo.pid-issuer.bundesdruckerei.de/credentials/pid/1.0",
          "id" : 66,
          "title" : "MUSTERMANN ERIKA",
          "subtitle" : "ID Card"
        }, {
          "paths" : {
            "eu.europa.ec.eudi.pid.1" : {
              "resident_country" : "DE",
              "age_over_16" : true,
              "nationality" : "DE",
              "given_name" : "ERIKA",
              "issuance_date" : "2025-04-17T09:04:07.355Z",
              "age_over_14" : true,
              "birth_date" : "1964-08-12T00:00:00Z",
              "family_name" : "MUSTERMANN",
              "expiry_date" : "2025-05-01T09:04:07.355Z",
              "resident_city" : "KÖLN",
              "age_over_18" : true,
              "age_in_years" : 60.0,
              "birth_place" : "BERLIN",
              "resident_street" : "HEIDESTRAẞE 17",
              "age_over_12" : true,
              "issuing_authority" : "DE",
              "issuing_country" : "DE",
              "resident_postal_code" : "51147",
              "family_name_birth" : "GABLER",
              "age_over_21" : true,
              "age_birth_year" : 1964.0,
              "age_over_65" : false
            },
            "exp" : 1746090247
          },
          "credential_format" : "dc+sd-jwt",
          "document_type" : "https://demo.pid-issuer.bundesdruckerei.de/credentials/pid/1.0",
          "id" : 67,
          "title" : "MUSTERMANN ERIKA",
          "subtitle" : "ID Card"
        }, {
          "paths" : {
            "eu.europa.ec.eudi.pid.1" : {
              "family_name" : "MUSTERMANN",
              "given_name" : "ERIKA",
              "resident_street" : "HEIDESTRAẞE 17",
              "age_over_14" : true,
              "resident_country" : "DE",
              "nationality" : "DE",
              "expiry_date" : "2025-05-01T09:04:07.357Z",
              "issuance_date" : "2025-04-17T09:04:07.357Z",
              "age_over_18" : true,
              "birth_place" : "BERLIN",
              "birth_date" : "1964-08-12T00:00:00Z",
              "age_in_years" : 60.0,
              "age_over_21" : true,
              "family_name_birth" : "GABLER",
              "resident_city" : "KÖLN",
              "issuing_country" : "DE",
              "age_over_12" : true,
              "issuing_authority" : "DE",
              "age_over_65" : false,
              "age_birth_year" : 1964.0,
              "resident_postal_code" : "51147",
              "age_over_16" : true
            },
            "exp" : 1746090247
          },
          "credential_format" : "dc+sd-jwt",
          "document_type" : "https://demo.pid-issuer.bundesdruckerei.de/credentials/pid/1.0",
          "id" : 68,
          "title" : "MUSTERMANN ERIKA",
          "subtitle" : "ID Card"
        }, {
          "paths" : {
            "eu.europa.ec.eudi.pid.1" : {
              "age_over_12" : true,
              "age_in_years" : 60.0,
              "age_over_18" : true,
              "age_over_21" : true,
              "birth_place" : "BERLIN",
              "resident_street" : "HEIDESTRAẞE 17",
              "age_over_16" : true,
              "resident_country" : "DE",
              "issuing_authority" : "DE",
              "family_name" : "MUSTERMANN",
              "family_name_birth" : "GABLER",
              "age_over_14" : true,
              "age_birth_year" : 1964.0,
              "resident_city" : "KÖLN",
              "issuance_date" : "2025-04-17T09:04:07.358Z",
              "birth_date" : "1964-08-12T00:00:00Z",
              "issuing_country" : "DE",
              "age_over_65" : false,
              "nationality" : "DE",
              "given_name" : "ERIKA",
              "expiry_date" : "2025-05-01T09:04:07.358Z",
              "resident_postal_code" : "51147"
            },
            "exp" : 1746090247
          },
          "credential_format" : "dc+sd-jwt",
          "document_type" : "https://demo.pid-issuer.bundesdruckerei.de/credentials/pid/1.0",
          "id" : 69,
          "title" : "MUSTERMANN ERIKA",
          "subtitle" : "ID Card"
        }, {
          "paths" : {
            "eu.europa.ec.eudi.pid.1" : {
              "resident_country" : "DE",
              "resident_city" : "KÖLN",
              "age_over_65" : false,
              "birth_date" : "1964-08-12T00:00:00Z",
              "age_over_16" : true,
              "family_name_birth" : "GABLER",
              "age_over_18" : true,
              "age_over_21" : true,
              "issuance_date" : "2025-04-17T09:04:07.36Z",
              "family_name" : "MUSTERMANN",
              "age_birth_year" : 1964.0,
              "birth_place" : "BERLIN",
              "age_in_years" : 60.0,
              "given_name" : "ERIKA",
              "age_over_12" : true,
              "nationality" : "DE",
              "resident_postal_code" : "51147",
              "issuing_country" : "DE",
              "resident_street" : "HEIDESTRAẞE 17",
              "expiry_date" : "2025-05-01T09:04:07.36Z",
              "issuing_authority" : "DE",
              "age_over_14" : true
            },
            "exp" : 1746090247
          },
          "credential_format" : "dc+sd-jwt",
          "document_type" : "https://demo.pid-issuer.bundesdruckerei.de/credentials/pid/1.0",
          "id" : 70,
          "title" : "MUSTERMANN ERIKA",
          "subtitle" : "ID Card"
        }, {
          "paths" : {
            "eu.europa.ec.eudi.pid.1" : {
              "given_name" : "ERIKA",
              "issuing_authority" : "DE",
              "nationality" : "DE",
              "age_birth_year" : 1964.0,
              "issuance_date" : "2025-04-17T09:04:07.362Z",
              "family_name" : "MUSTERMANN",
              "expiry_date" : "2025-05-01T09:04:07.362Z",
              "age_over_12" : true,
              "issuing_country" : "DE",
              "age_over_14" : true,
              "age_over_21" : true,
              "resident_city" : "KÖLN",
              "age_over_16" : true,
              "resident_country" : "DE",
              "age_over_18" : true,
              "birth_place" : "BERLIN",
              "age_over_65" : false,
              "age_in_years" : 60.0,
              "resident_street" : "HEIDESTRAẞE 17",
              "birth_date" : "1964-08-12T00:00:00Z",
              "resident_postal_code" : "51147",
              "family_name_birth" : "GABLER"
            },
            "exp" : 1746090247
          },
          "credential_format" : "dc+sd-jwt",
          "document_type" : "https://demo.pid-issuer.bundesdruckerei.de/credentials/pid/1.0",
          "id" : 71,
          "title" : "MUSTERMANN ERIKA",
          "subtitle" : "ID Card"
        }, {
          "paths" : {
            "eu.europa.ec.eudi.pid.1" : {
              "expiry_date" : "2025-05-01T09:04:07.363Z",
              "age_in_years" : 60.0,
              "birth_place" : "BERLIN",
              "nationality" : "DE",
              "age_birth_year" : 1964.0,
              "resident_city" : "KÖLN",
              "age_over_21" : true,
              "issuing_authority" : "DE",
              "issuance_date" : "2025-04-17T09:04:07.363Z",
              "age_over_14" : true,
              "resident_country" : "DE",
              "given_name" : "ERIKA",
              "age_over_12" : true,
              "family_name" : "MUSTERMANN",
              "family_name_birth" : "GABLER",
              "resident_postal_code" : "51147",
              "age_over_16" : true,
              "issuing_country" : "DE",
              "birth_date" : "1964-08-12T00:00:00Z",
              "age_over_65" : false,
              "age_over_18" : true,
              "resident_street" : "HEIDESTRAẞE 17"
            },
            "exp" : 1746090247
          },
          "credential_format" : "dc+sd-jwt",
          "document_type" : "https://demo.pid-issuer.bundesdruckerei.de/credentials/pid/1.0",
          "id" : 72,
          "title" : "MUSTERMANN ERIKA",
          "subtitle" : "ID Card"
        }, {
          "paths" : {
            "eu.europa.ec.eudi.pid.1" : {
              "issuance_date" : "2025-04-17T09:04:07.365Z",
              "issuing_country" : "DE",
              "birth_place" : "BERLIN",
              "age_over_14" : true,
              "nationality" : "DE",
              "birth_date" : "1964-08-12T00:00:00Z",
              "age_over_16" : true,
              "age_over_21" : true,
              "resident_country" : "DE",
              "age_over_12" : true,
              "given_name" : "ERIKA",
              "issuing_authority" : "DE",
              "resident_postal_code" : "51147",
              "age_in_years" : 60.0,
              "expiry_date" : "2025-05-01T09:04:07.365Z",
              "age_birth_year" : 1964.0,
              "family_name_birth" : "GABLER",
              "resident_city" : "KÖLN",
              "resident_street" : "HEIDESTRAẞE 17",
              "age_over_18" : true,
              "family_name" : "MUSTERMANN",
              "age_over_65" : false
            },
            "exp" : 1746090247
          },
          "credential_format" : "dc+sd-jwt",
          "document_type" : "https://demo.pid-issuer.bundesdruckerei.de/credentials/pid/1.0",
          "id" : 73,
          "title" : "MUSTERMANN ERIKA",
          "subtitle" : "ID Card"
        }, {
          "paths" : {
            "eu.europa.ec.eudi.pid.1" : {
              "age_over_12" : true,
              "age_in_years" : 60.0,
              "given_name" : "ERIKA",
              "birth_place" : "BERLIN",
              "resident_country" : "DE",
              "issuance_date" : "2025-04-17T09:04:07.366Z",
              "nationality" : "DE",
              "age_over_65" : false,
              "resident_city" : "KÖLN",
              "age_over_16" : true,
              "age_over_14" : true,
              "family_name_birth" : "GABLER",
              "age_over_21" : true,
              "age_birth_year" : 1964.0,
              "expiry_date" : "2025-05-01T09:04:07.366Z",
              "issuing_authority" : "DE",
              "birth_date" : "1964-08-12T00:00:00Z",
              "resident_street" : "HEIDESTRAẞE 17",
              "resident_postal_code" : "51147",
              "family_name" : "MUSTERMANN",
              "issuing_country" : "DE",
              "age_over_18" : true
            },
            "exp" : 1746090247
          },
          "credential_format" : "dc+sd-jwt",
          "document_type" : "https://demo.pid-issuer.bundesdruckerei.de/credentials/pid/1.0",
          "id" : 74,
          "title" : "MUSTERMANN ERIKA",
          "subtitle" : "ID Card"
        }, {
          "paths" : {
            "eu.europa.ec.eudi.pid.1" : {
              "age_over_12" : true,
              "age_in_years" : 60.0,
              "resident_country" : "DE",
              "age_over_14" : true,
              "family_name" : "MUSTERMANN",
              "given_name" : "ERIKA",
              "age_birth_year" : 1964.0,
              "issuing_authority" : "DE",
              "age_over_16" : true,
              "resident_street" : "HEIDESTRAẞE 17",
              "age_over_21" : true,
              "age_over_18" : true,
              "birth_place" : "BERLIN",
              "age_over_65" : false,
              "issuance_date" : "2025-04-17T09:04:07.368Z",
              "issuing_country" : "DE",
              "resident_postal_code" : "51147",
              "birth_date" : "1964-08-12T00:00:00Z",
              "resident_city" : "KÖLN",
              "expiry_date" : "2025-05-01T09:04:07.368Z",
              "nationality" : "DE",
              "family_name_birth" : "GABLER"
            },
            "exp" : 1746090247
          },
          "credential_format" : "dc+sd-jwt",
          "document_type" : "https://demo.pid-issuer.bundesdruckerei.de/credentials/pid/1.0",
          "id" : 75,
          "title" : "MUSTERMANN ERIKA",
          "subtitle" : "ID Card"
        }, {
          "paths" : {
            "eu.europa.ec.eudi.pid.1" : {
              "resident_country" : "DE",
              "age_over_65" : false,
              "age_birth_year" : 1964.0,
              "given_name" : "ERIKA",
              "age_over_14" : true,
              "birth_place" : "BERLIN",
              "resident_city" : "KÖLN",
              "birth_date" : "1964-08-12T00:00:00Z",
              "age_over_12" : true,
              "family_name" : "MUSTERMANN",
              "age_over_16" : true,
              "resident_postal_code" : "51147",
              "issuing_country" : "DE",
              "age_over_21" : true,
              "family_name_birth" : "GABLER",
              "issuance_date" : "2025-04-17T09:04:07.369Z",
              "issuing_authority" : "DE",
              "age_in_years" : 60.0,
              "age_over_18" : true,
              "nationality" : "DE",
              "expiry_date" : "2025-05-01T09:04:07.369Z",
              "resident_street" : "HEIDESTRAẞE 17"
            },
            "exp" : 1746090247
          },
          "credential_format" : "dc+sd-jwt",
          "document_type" : "https://demo.pid-issuer.bundesdruckerei.de/credentials/pid/1.0",
          "id" : 76,
          "title" : "MUSTERMANN ERIKA",
          "subtitle" : "ID Card"
        }, {
          "paths" : {
            "eu.europa.ec.eudi.pid.1" : {
              "issuing_country" : "DE",
              "family_name_birth" : "GABLER",
              "birth_place" : "BERLIN",
              "age_birth_year" : 1964.0,
              "age_over_21" : true,
              "issuance_date" : "2025-04-17T09:04:07.371Z",
              "resident_country" : "DE",
              "age_over_14" : true,
              "age_over_18" : true,
              "age_over_65" : false,
              "family_name" : "MUSTERMANN",
              "expiry_date" : "2025-05-01T09:04:07.371Z",
              "birth_date" : "1964-08-12T00:00:00Z",
              "issuing_authority" : "DE",
              "resident_street" : "HEIDESTRAẞE 17",
              "age_in_years" : 60.0,
              "age_over_12" : true,
              "nationality" : "DE",
              "age_over_16" : true,
              "resident_city" : "KÖLN",
              "given_name" : "ERIKA",
              "resident_postal_code" : "51147"
            },
            "exp" : 1746090247
          },
          "credential_format" : "dc+sd-jwt",
          "document_type" : "https://demo.pid-issuer.bundesdruckerei.de/credentials/pid/1.0",
          "id" : 77,
          "title" : "MUSTERMANN ERIKA",
          "subtitle" : "ID Card"
        }, {
          "paths" : {
            "eu.europa.ec.eudi.pid.1" : {
              "age_in_years" : 60.0,
              "family_name_birth" : "GABLER",
              "issuance_date" : "2025-04-17T09:04:07.373Z",
              "resident_street" : "HEIDESTRAẞE 17",
              "birth_date" : "1964-08-12T00:00:00Z",
              "given_name" : "ERIKA",
              "birth_place" : "BERLIN",
              "resident_postal_code" : "51147",
              "resident_country" : "DE",
              "age_over_21" : true,
              "age_over_16" : true,
              "age_over_18" : true,
              "expiry_date" : "2025-05-01T09:04:07.373Z",
              "family_name" : "MUSTERMANN",
              "age_over_12" : true,
              "issuing_authority" : "DE",
              "age_over_65" : false,
              "nationality" : "DE",
              "issuing_country" : "DE",
              "age_over_14" : true,
              "resident_city" : "KÖLN",
              "age_birth_year" : 1964.0
            },
            "exp" : 1746090247
          },
          "credential_format" : "dc+sd-jwt",
          "document_type" : "https://demo.pid-issuer.bundesdruckerei.de/credentials/pid/1.0",
          "id" : 78,
          "title" : "MUSTERMANN ERIKA",
          "subtitle" : "ID Card"
        }, {
          "paths" : {
            "eu.europa.ec.eudi.pid.1" : {
              "resident_city" : "KÖLN",
              "expiry_date" : "2025-05-01T09:04:07.374Z",
              "age_over_14" : true,
              "resident_street" : "HEIDESTRAẞE 17",
              "family_name_birth" : "GABLER",
              "birth_place" : "BERLIN",
              "nationality" : "DE",
              "family_name" : "MUSTERMANN",
              "issuing_authority" : "DE",
              "age_over_65" : false,
              "issuing_country" : "DE",
              "resident_country" : "DE",
              "age_over_16" : true,
              "age_over_12" : true,
              "age_over_18" : true,
              "issuance_date" : "2025-04-17T09:04:07.374Z",
              "age_birth_year" : 1964.0,
              "age_over_21" : true,
              "resident_postal_code" : "51147",
              "given_name" : "ERIKA",
              "birth_date" : "1964-08-12T00:00:00Z",
              "age_in_years" : 60.0
            },
            "exp" : 1746090247
          },
          "credential_format" : "dc+sd-jwt",
          "document_type" : "https://demo.pid-issuer.bundesdruckerei.de/credentials/pid/1.0",
          "id" : 79,
          "title" : "MUSTERMANN ERIKA",
          "subtitle" : "ID Card"
        }, {
          "paths" : {
            "address" : {
              "_sd" : [ "C7bzmLOV6oL-TEiCCZcRq7r1dWVQsdpAmBxD4rfwLOE", "FBlfyGlPOmpGgx5Y0ilFmMVTE8Yw7ziWhFgFCcMQdvk", "SD2Ln8jMPIIUcjPl_xuGK_DmvVgjgop6zNzBOkTZYLk", "a2DQdgFHAiYGtzkdDsMEU1ZRKpCbqWwbLyyCJntUKUk" ],
              "locality" : "KÖLN",
              "country" : "DE",
              "postal_code" : "51147",
              "street_address" : "HEIDESTRAẞE 17"
            },
            "iss" : "https://demo.pid-issuer.bundesdruckerei.de/c1",
            "place_of_birth" : {
              "_sd" : [ "H00S3QBkz8hAo8tHUv0ttHA4PdjboxHC6WtzpPtfTxw" ],
              "locality" : "BERLIN"
            },
            "_sd" : [ "1edPwelmfkpt5KdFBlONTfVb94ZxR92Idm-2anaMMoE", "3Exo1jl8LIy6ehdbhjlDTEKs0iADnCABF4odpeqYGXM", "4sPkpxAHPiGY-XPRTeUWedB7_5Jn7-m6sv7ADTOImmE", "5TT26QtXxjEzu_o2qO1HWZpdieFnyg7e8Z-EvkZcUyk", "gGz4axSgUx2MU9TNApxURIHvTBWXoyDDeR5vyrEV-Xk", "prayXbGLf7__gYi7lSPFnVMAjyHoByB3kP50L1qFpxQ", "qArUKMpEE-gXK2mCMb36lCOt2gJxjpdm4PA-dWs65LY" ],
            "issuing_country" : "DE",
            "issuing_authority" : "DE",
            "_sd_alg" : "sha-256",
            "cnf" : {
              "jwk" : {
                "kty" : "EC",
                "crv" : "P-256",
                "x" : "eGGBTl1PcJpO67Fk7sx2d0YIw98XiKd4EtuVWeDPEs0",
                "y" : "2J_TpYuY-EUbRIcBmYBCDsjR2Jp5u-mVW_8UCJg1Q8I"
              }
            },
            "exp" : 1746090252,
            "iat" : 1744880652,
            "status" : {
              "status_list" : {
                "uri" : "https://demo.pid-issuer.bundesdruckerei.de/status/6642e557-6f47-4050-90a7-53d5f3418861",
                "idx" : 55
              }
            },
            "age_equal_or_over" : {
              "_sd" : [ "1_-ZG-EA43BpZNkdbMzOpMo52NpDF4uDb3gblQza828", "5nZH8wiXewJmF6rK37yYeEFDoTNEbogji6Hj7EkuUVk", "6gtPSNNs8XQ-YezTC9_29_pAY-StSD1NThjkfKHcAV4", "6j8d3ochh8bL8SdsGDRy6ZPqKVmxmoHIrnw7FC-fYDM", "Nk7uUI5fR4y4ZU2WjZO8WXo99T6dEzAZlXNUtOGvaws", "RYlJ6LlSyhPazz3A3qDaaS1NWbzrm1l0Zw3c4e6HjCM" ],
              "12" : true,
              "14" : true,
              "16" : true,
              "18" : true,
              "21" : true,
              "65" : false
            },
            "family_name" : "MUSTERMANN",
            "given_name" : "ERIKA",
            "birthdate" : "1964-08-12",
            "age_birth_year" : 1964,
            "age_in_years" : 60,
            "birth_family_name" : "GABLER",
            "nationalities" : [ "DE" ]
          },
          "credential_format" : "dc+sd-jwt",
          "document_type" : "https://demo.pid-issuer.bundesdruckerei.de/credentials/pid/1.0",
          "id" : 80,
          "title" : "MUSTERMANN ERIKA",
          "subtitle" : "ID Card"
        }, {
          "paths" : {
            "address" : {
              "_sd" : [ "-TUN_kcb_r0-Ajcj5MB5-zmKKJUg-1_gtb0Ue7g2w_Y", "A_iDKQY2DaElDHK2mhQoBkr_XYodei4WTEWCupN4WtU", "LdGi7Iay5hqoq8ciCT2YR5faGympvd2XxWdsj5Wi-Jo", "dkiVI9mqyLZ5YWGRk6dvB1BNckC9ytRIhc0SLrt-xAg" ],
              "locality" : "KÖLN",
              "country" : "DE",
              "postal_code" : "51147",
              "street_address" : "HEIDESTRAẞE 17"
            },
            "iss" : "https://demo.pid-issuer.bundesdruckerei.de/c1",
            "place_of_birth" : {
              "_sd" : [ "9nDh469PimJQi6TYtLvuUsyVVYt3u9raJ6_vL3JvdAU" ],
              "locality" : "BERLIN"
            },
            "_sd" : [ "JtzPyB00Vs-v12BvOZbhA5t6I-MoMzcPU7VlxZV3_fE", "NgfZHUgR1KMipaU90wvPSvPhE_7zRJA8tY6B_vh8UPE", "RToxMu1UjmWlzlfFnCIZA0yPjs1d3B9hwTsbYXMzp6M", "ZneyN3ljdK1WNj00YW2umjnaBMDwuxSrndS4hliQtM0", "eX1fUhr_asi0oJFCzotVsVuVISKReqFzU9ja6rGs2TY", "ioQ4vAF-NBCB_hn29GZUN7TVZ_v0Y1KS8WGhcT2-ouM", "mxp9dlQMo682YBs1U3EZTnS0d20ZzyF-rcd16p1xuAM" ],
            "issuing_country" : "DE",
            "issuing_authority" : "DE",
            "_sd_alg" : "sha-256",
            "cnf" : {
              "jwk" : {
                "kty" : "EC",
                "crv" : "P-256",
                "x" : "i9M-ipw68bN-W-mmnIKsHwFKp8uyH3BBAvnmqXkwQAc",
                "y" : "3gj9onjzKLMcCf_nrwGorFSHWD4a-oXQy_BQ-zIppzU"
              }
            },
            "exp" : 1746090252,
            "iat" : 1744880652,
            "status" : {
              "status_list" : {
                "uri" : "https://demo.pid-issuer.bundesdruckerei.de/status/6642e557-6f47-4050-90a7-53d5f3418861",
                "idx" : 3
              }
            },
            "age_equal_or_over" : {
              "_sd" : [ "CcgUpx4KBlrsQ4NLI3WxOIT_d9gMGWmuDQ8kV1NhhW0", "Hpbt4Gs5ymHtjRGYIqEwBMRCEDm89VPAGfw7xf_CpGs", "Le5nRw5xvhB_7qkMYW-jdJNn6zNrr05a9WkR4l3YNLs", "NKUtiFcWns0RBaqtR1axM0IPBtMV50ORYl89PcJV1FY", "hj6-oNxOa8YVIucdmK4rauMNvrWAi8fR0Xrn8Plr4-M", "lGHmzWDqrwmkBvZBpd62oHyp8ob24r3xYWdMw6gc3xU" ],
              "12" : true,
              "14" : true,
              "16" : true,
              "18" : true,
              "21" : true,
              "65" : false
            },
            "family_name" : "MUSTERMANN",
            "given_name" : "ERIKA",
            "birthdate" : "1964-08-12",
            "age_birth_year" : 1964,
            "age_in_years" : 60,
            "birth_family_name" : "GABLER",
            "nationalities" : [ "DE" ]
          },
          "credential_format" : "dc+sd-jwt",
          "document_type" : "https://demo.pid-issuer.bundesdruckerei.de/credentials/pid/1.0",
          "id" : 81,
          "title" : "MUSTERMANN ERIKA",
          "subtitle" : "ID Card"
        }, {
          "paths" : {
            "address" : {
              "_sd" : [ "YTzDxBYVRZSY3fMzhdvpehaLisZW1So146-79PUhQdk", "tyvWK5weC05nBwtI_mX8YCvBOmhchOvPsvHmUVGfPZ0", "uUIoy3XIqnDWiAgw7eARi8lIYH6nBPeWSBloOO0dGss", "vKzgEg92w5UW8J4iHfpOZIiWp-qJgqpYjomF8Mh8z9I" ],
              "locality" : "KÖLN",
              "country" : "DE",
              "postal_code" : "51147",
              "street_address" : "HEIDESTRAẞE 17"
            },
            "iss" : "https://demo.pid-issuer.bundesdruckerei.de/c1",
            "place_of_birth" : {
              "_sd" : [ "24-mfBBuhyu68q8kvKh84VnU0IPMHPxRtCT0Wfey8EI" ],
              "locality" : "BERLIN"
            },
            "_sd" : [ "NpOl63m5ypcRMs1w8VmsJWJYAZGvx6qCa_ADs5tNPwc", "SVNGvcBsM95a9s5OJlirlNIBD798fpPDUU5wGZ6nofI", "cKzeWWVHgZLsgJ0otv4yC5wuk0hztGkNvxlxQAUTTOE", "ccFvmAJE34LUpTiNXWWNgL_fNPpEwJN40l0ZPrta1i8", "hZjjmM540WB3eZUlkSYb0w1MdS_Dj53XqYeO2KO33ms", "nWB0LlZn2kj_lLYd1AQe6PAImaZ5TL5kFDnAoU-3vNU", "oGeM-iMyw10Ce5TjSC0jLIYAHLTMqIAKDcn9y4924dY" ],
            "issuing_country" : "DE",
            "issuing_authority" : "DE",
            "_sd_alg" : "sha-256",
            "cnf" : {
              "jwk" : {
                "kty" : "EC",
                "crv" : "P-256",
                "x" : "35n0gEPZrqeAlp2iGYVC2eEYvgtugKY_G0A3nV9HZXY",
                "y" : "4p4F1xq_DN2FRG4IqOb7UJfaAbuDggyUo96hJFdzATk"
              }
            },
            "exp" : 1746090252,
            "iat" : 1744880652,
            "status" : {
              "status_list" : {
                "uri" : "https://demo.pid-issuer.bundesdruckerei.de/status/6642e557-6f47-4050-90a7-53d5f3418861",
                "idx" : 82
              }
            },
            "age_equal_or_over" : {
              "_sd" : [ "-zP8Y4CgWK7y010jikuoEfQe4AzPPMesRxQv5s7GRHI", "B051T5RxJhvM_Bl9mOg04hdGGi-mJEBCK6XaFJpas9U", "B8VAkz6rKOqSYrYtXRjsuNfcNB46SPZLOewM8QgDRdc", "JwGM3johbLMPxvEKYD5voZp7RJWcyxMfFE79M655VNU", "suaZAig6s2esWjaaVvyKmgMF6bOjKKEOeHP8CDVZZY4", "zVuPIxHv9MOOvTWkUaV8PeErrys6mcX8Eb94l3GMgpE" ],
              "12" : true,
              "14" : true,
              "16" : true,
              "18" : true,
              "21" : true,
              "65" : false
            },
            "family_name" : "MUSTERMANN",
            "given_name" : "ERIKA",
            "birthdate" : "1964-08-12",
            "age_birth_year" : 1964,
            "age_in_years" : 60,
            "birth_family_name" : "GABLER",
            "nationalities" : [ "DE" ]
          },
          "credential_format" : "dc+sd-jwt",
          "document_type" : "https://demo.pid-issuer.bundesdruckerei.de/credentials/pid/1.0",
          "id" : 82,
          "title" : "MUSTERMANN ERIKA",
          "subtitle" : "ID Card"
        }, {
          "paths" : {
            "address" : {
              "_sd" : [ "I64IKl9nmkXRwwpeqg_nXbA19aTVpsWxwoRdgrq8EAY", "M3W3dnwcjzev2rHcq3XdtMPcZ2JIZcppUQYgqdL5s2E", "UwDztaPP00yx4RVrEGnCKSljZVW2hviRhuLy8NN7k48", "dO7ugIBICFGzjmPPFd5NI4ZjyMO5kO-Fu4t_p9w3rj8" ],
              "locality" : "KÖLN",
              "country" : "DE",
              "postal_code" : "51147",
              "street_address" : "HEIDESTRAẞE 17"
            },
            "iss" : "https://demo.pid-issuer.bundesdruckerei.de/c1",
            "place_of_birth" : {
              "_sd" : [ "loNH92RSxHc_euoPy7D7FRTK3H33wMZVgmLN8TQQnQk" ],
              "locality" : "BERLIN"
            },
            "_sd" : [ "7NKQk24gEPEpvgfoWD_53bDGQgT96if-0a0G0aVUGnk", "91k_YmE9r0iYRcNkjM-aWrq0BHw098T3-QbSc0Su3yQ", "FDsmLPPSew42hGMHD0MF5GhvIkM4jTLGLyrGceT2feE", "WJni6ZoeP_zQ0dCYG1iIUxy9cAXRUoyZssXnqd5FvB8", "fATq3aGfHaEjLo3yMwyLM8f7F6nowYE6jBe8V0-KLMs", "x7dP363pTo3CClMo2-C6Qd6ikeZQShNEMWXnTi5sib8", "zGB73KP7NwsPUFw7RVTrOy7st7B_FOr1r6aN3NfkY7A" ],
            "issuing_country" : "DE",
            "issuing_authority" : "DE",
            "_sd_alg" : "sha-256",
            "cnf" : {
              "jwk" : {
                "kty" : "EC",
                "crv" : "P-256",
                "x" : "bNFSPC-j7Hztixs2Kj_lLRiewDYQVKlw9p8PTl7w7q4",
                "y" : "bZH9kmIddlLDfzF52dP2Snzy-JmnEIwsZ8nGpI2jBCM"
              }
            },
            "exp" : 1746090252,
            "iat" : 1744880652,
            "status" : {
              "status_list" : {
                "uri" : "https://demo.pid-issuer.bundesdruckerei.de/status/6642e557-6f47-4050-90a7-53d5f3418861",
                "idx" : 115
              }
            },
            "age_equal_or_over" : {
              "_sd" : [ "528NNG_6w7kinDsR4m70ZJSZOyOxLr4CRXUUHbXrzR4", "DV7WnFUql_H5aa2JTZSxDvqI7stRtZuIKCW5m-h2m2A", "Vt4TYknoomKj77n1ThuTGjCAc1nkpeWepLLQqYsaoys", "iDPjLqS6Wz5_nw11t9FmSzk-o3NjVefOVyG7kVXc5Gw", "joHm2wRwb9BkkiXFdeoRPl86dZf7QCrcvWiNyEASwgE", "pjHMeflnYIjQk82kXwzRttUrXLwViDRMCf7Dqk-npxA" ],
              "12" : true,
              "14" : true,
              "16" : true,
              "18" : true,
              "21" : true,
              "65" : false
            },
            "family_name" : "MUSTERMANN",
            "given_name" : "ERIKA",
            "birthdate" : "1964-08-12",
            "age_birth_year" : 1964,
            "age_in_years" : 60,
            "birth_family_name" : "GABLER",
            "nationalities" : [ "DE" ]
          },
          "credential_format" : "dc+sd-jwt",
          "document_type" : "https://demo.pid-issuer.bundesdruckerei.de/credentials/pid/1.0",
          "id" : 83,
          "title" : "MUSTERMANN ERIKA",
          "subtitle" : "ID Card"
        }, {
          "paths" : {
            "address" : {
              "_sd" : [ "7d2ifC4KfO9FXYasB3WSg2M2Ocd7QxRRoiRsEVkS3eM", "9pwuTvyXW5Ct8I9CLfkSujH_YtnjsG0RAUriAlXyHGs", "atPoKXYQP77l_LJ4NvGBbYEKgxLpjofOPMe5FlnH5Ds", "u4UEoMG4d4k_m1uBTBgdOGTmNtu07sDR3ESil8VW86c" ],
              "locality" : "KÖLN",
              "country" : "DE",
              "postal_code" : "51147",
              "street_address" : "HEIDESTRAẞE 17"
            },
            "iss" : "https://demo.pid-issuer.bundesdruckerei.de/c1",
            "place_of_birth" : {
              "_sd" : [ "2LvTwzMsXzg6z9cA1a-PjQpad1yMDb1fa1p_SC-zGKM" ],
              "locality" : "BERLIN"
            },
            "_sd" : [ "3peRGcZISrafeuEV5slCok0x_d63zV6JjmCk7ONkM5k", "40-ci5iRkIrjIicgWD-t8OZII8rABoNttvSGkp5F7ko", "Da47K_l_OhWK-mu-VPNMYxsXXuhjA6Mzqf7QqZIQgS8", "L3pvRAaqZ-jFbw8u0zZltUaTolxcyfK0NNOYVPvJRYs", "LmiW9Atf9Wp7ceW5JefTLaLD5ArKTPe7lroUn_ttqrc", "cLuIAZIt0lJm27NIiN-W2zmYK9jqxMJFVXJ7FN_ZK6I", "lJMYWMKNMpoO1lHEN67pqVQBa5Sl7T1XNuAEPZ9Cy80" ],
            "issuing_country" : "DE",
            "issuing_authority" : "DE",
            "_sd_alg" : "sha-256",
            "cnf" : {
              "jwk" : {
                "kty" : "EC",
                "crv" : "P-256",
                "x" : "T88Pmlnw_3B72Yd71C-mFPbfpysbZ3Mi99isJCYKc2I",
                "y" : "1E5Qbg0c9IMBja0XSk3YfSXieDQW2hV2u3hHTZF2Pao"
              }
            },
            "exp" : 1746090252,
            "iat" : 1744880652,
            "status" : {
              "status_list" : {
                "uri" : "https://demo.pid-issuer.bundesdruckerei.de/status/6642e557-6f47-4050-90a7-53d5f3418861",
                "idx" : 118
              }
            },
            "age_equal_or_over" : {
              "_sd" : [ "LfA0SEs1Uo_vxAnaiOVy8Xb3TMZ3dunx17RtSTlCTmE", "MBF772J7mmgxjlCS9E016fDOKcMZEwvhVSe6S0BEAdo", "PUCz5UAFnjLj3KXenXIRgHVRr5xA23CcJIlioJaZM6M", "e9AXADnv6R24q1uJXF8gURtXE_XswczaiPH-dsDxWb0", "peShIXaPCZIzUsxKfMmJFae_vB2o9aanDFfUn1moh5k", "yb-eBj6uzUvv0H19bDP8Te4huxbJzwm1Yt85ptVLZPA" ],
              "12" : true,
              "14" : true,
              "16" : true,
              "18" : true,
              "21" : true,
              "65" : false
            },
            "family_name" : "MUSTERMANN",
            "given_name" : "ERIKA",
            "birthdate" : "1964-08-12",
            "age_birth_year" : 1964,
            "age_in_years" : 60,
            "birth_family_name" : "GABLER",
            "nationalities" : [ "DE" ]
          },
          "credential_format" : "dc+sd-jwt",
          "document_type" : "https://demo.pid-issuer.bundesdruckerei.de/credentials/pid/1.0",
          "id" : 84,
          "title" : "MUSTERMANN ERIKA",
          "subtitle" : "ID Card"
        }, {
          "paths" : {
            "address" : {
              "_sd" : [ "2N4QFDE9S_5FFbP16vfu57k4xciDmwGJk_nDDucDk7E", "4y7pvrxt9ewawWqG2ZuK3iHQZe4gb1ER8V3AbmfZR8U", "5uIyZMhcGLvj2CTNezXwgySRl3no3UsSUqZAibMp8qc", "jALMu_JC31IhUNzXtu6-_ElIJn1sEuVtCcZTBp8Ksy8" ],
              "locality" : "KÖLN",
              "country" : "DE",
              "postal_code" : "51147",
              "street_address" : "HEIDESTRAẞE 17"
            },
            "iss" : "https://demo.pid-issuer.bundesdruckerei.de/c1",
            "place_of_birth" : {
              "_sd" : [ "5Z6FdUr85dtABioU2o3GlaOAj-bZUu3RDuZ419wKQEg" ],
              "locality" : "BERLIN"
            },
            "_sd" : [ "-UcEZB-D2-MsMObjXFNfmf-VfARGLXeoktU223dD8Ac", "0DEVQtve3SKCgCUgh5EDd-CfU2xdcoREPNL44uYsv68", "9QOJFEMgoOeah0RrDA5YacnuQc9wLo8FLPaZ_Rw6kow", "CJCRAkgJKUaQSNuPAd-LQdUss5dukBU9rd1gY0Mz_fk", "DBp500CB1d20Kz1Df3Zw4HKMAPhfSVMP08jTGHs6coo", "m0YyasiAu42zPRJyihk42a8hOblEG1s4SdMyASCaoUE", "yliNLvsYv1TnLu7qtTetPLEy9J7iwQ5c8Rd6cSQbYVM" ],
            "issuing_country" : "DE",
            "issuing_authority" : "DE",
            "_sd_alg" : "sha-256",
            "cnf" : {
              "jwk" : {
                "kty" : "EC",
                "crv" : "P-256",
                "x" : "BSNXemBDnq4dZ4cEKirilM5GRnGKnfOveKEAtwTxCEI",
                "y" : "rXTxEVX2OK1qrC590T4mvYC81RhsfEWMKyntnlJp3Ew"
              }
            },
            "exp" : 1746090252,
            "iat" : 1744880652,
            "status" : {
              "status_list" : {
                "uri" : "https://demo.pid-issuer.bundesdruckerei.de/status/6642e557-6f47-4050-90a7-53d5f3418861",
                "idx" : 86
              }
            },
            "age_equal_or_over" : {
              "_sd" : [ "06lo2R07HG6nUbPOS48qLkyvCta1JuDi4O4ggtvbLU4", "3pWHyv74-0uMCVRtjtsOlxLECXXiz2q4-lRe5sBBIsE", "L_wXzYEMd9Yi0GEoem3q73brHJsnS5441C0fcDeReS8", "g5LZbX-JEXnGr9JI4aogRPp4WUty8qSV4b9Yt-SjkAU", "qPHmOrphlak0heUiQf9PRTAI5qJYnsso_50r3-BveSY", "xBCi6KDzPRyFz1_5g6VyUOZzD9OB5Lyru7sE8PY3ODY" ],
              "12" : true,
              "14" : true,
              "16" : true,
              "18" : true,
              "21" : true,
              "65" : false
            },
            "family_name" : "MUSTERMANN",
            "given_name" : "ERIKA",
            "birthdate" : "1964-08-12",
            "age_birth_year" : 1964,
            "age_in_years" : 60,
            "birth_family_name" : "GABLER",
            "nationalities" : [ "DE" ]
          },
          "credential_format" : "dc+sd-jwt",
          "document_type" : "https://demo.pid-issuer.bundesdruckerei.de/credentials/pid/1.0",
          "id" : 85,
          "title" : "MUSTERMANN ERIKA",
          "subtitle" : "ID Card"
        }, {
          "paths" : {
            "address" : {
              "_sd" : [ "1SuIqCFGIhGtOQ6wGR8zGLkePbtPCsugSfncK3tOW2I", "71OJTNgmHRJVs2JYjtR3VrjuZd13J4x2fYwmUJE3GGM", "MTp_MOEsW0EmhM4Mzb_Zcqc_4N2JOGdQK_dtGu8Zq2k", "YgC8hTIklxxxkfwM6JUlgEcwhuM780kCNpTBiG9XCWk" ],
              "locality" : "KÖLN",
              "country" : "DE",
              "postal_code" : "51147",
              "street_address" : "HEIDESTRAẞE 17"
            },
            "iss" : "https://demo.pid-issuer.bundesdruckerei.de/c1",
            "place_of_birth" : {
              "_sd" : [ "kLGM1sdqXW80-v889za_UkVaDU56sp1S87KB7AGeBFo" ],
              "locality" : "BERLIN"
            },
            "_sd" : [ "-t0YMeMW13dSyzPOOxuZaiT66uBkD3FkHQsI00buGTs", "NBhNJuQZ9RIJCBCdZs0funePD_ahTTskiK7bwmwNYvE", "OtXaR6z4ffwsfNK0aKNmusz6tMVf9dXifpy9XrA_p4U", "cDMCIBdLbEtXbrcG7RY9JM0r_JUfEZTm-kNEx68AOe0", "hBrct9xAkE-befiFJjKvZVQ4gpD_XnhVndQkMkmuwRQ", "rEGifpCV9DisHk_Dn8n9lATF3GbMjRGfWs8cTSXh8Lg", "xJmJOtuDyFo8IAvfCE62D_n-4PI6Yx_6WHqWX-Cib3A" ],
            "issuing_country" : "DE",
            "issuing_authority" : "DE",
            "_sd_alg" : "sha-256",
            "cnf" : {
              "jwk" : {
                "kty" : "EC",
                "crv" : "P-256",
                "x" : "0lONPbpMRcQoRK_yTbO3RuSF6twH3SWWCL5RzWf43fI",
                "y" : "vCsB1psHlYuLJJh0M0rDljOIGBcPA6jPX0a4mcmhdPQ"
              }
            },
            "exp" : 1746090252,
            "iat" : 1744880652,
            "status" : {
              "status_list" : {
                "uri" : "https://demo.pid-issuer.bundesdruckerei.de/status/6642e557-6f47-4050-90a7-53d5f3418861",
                "idx" : 45
              }
            },
            "age_equal_or_over" : {
              "_sd" : [ "0KwmK4BMXcaolHzCxrtkfj-nwIwzhI5jf84u9Y-txwg", "1ki-EuEw6uPYT4VsmbmWikSUgGLcncu9kAyZrkESJAI", "5PGEObEOb79f_XRke1Hxao3tImV9MX7ShsgjZLwsrOw", "SLEaO2wjnLVOa0-JB0AFkuwrk3JhTXqlG9tCdG21RO4", "W0E615pAdRyOlKJACtItq6T_SyecW6SMzxxOePNyzEg", "eoQu5dtyJloMddl9cyIKVFEVesz_Xke-r_deoyysKSY" ],
              "12" : true,
              "14" : true,
              "16" : true,
              "18" : true,
              "21" : true,
              "65" : false
            },
            "family_name" : "MUSTERMANN",
            "given_name" : "ERIKA",
            "birthdate" : "1964-08-12",
            "age_birth_year" : 1964,
            "age_in_years" : 60,
            "birth_family_name" : "GABLER",
            "nationalities" : [ "DE" ]
          },
          "credential_format" : "dc+sd-jwt",
          "document_type" : "https://demo.pid-issuer.bundesdruckerei.de/credentials/pid/1.0",
          "id" : 86,
          "title" : "MUSTERMANN ERIKA",
          "subtitle" : "ID Card"
        }, {
          "paths" : {
            "address" : {
              "_sd" : [ "5M405E0bErt6x1BKMTL8v2aa5tBSJ0o-iH-BpffyF8Q", "hbaT_T1aZQdMljDmv7fpO3g1uSqXt5c0-PnNRysAifA", "q73LcRHmfhCoNvG6u0HAuNQMQpM-pCeXgnaEMi2jfZI", "remuYgelUdx2Qg_MmyRoHDy3sX8wUpt_qy3uGMa5caY" ],
              "locality" : "KÖLN",
              "country" : "DE",
              "postal_code" : "51147",
              "street_address" : "HEIDESTRAẞE 17"
            },
            "iss" : "https://demo.pid-issuer.bundesdruckerei.de/c1",
            "place_of_birth" : {
              "_sd" : [ "rdL8OV05pwhQLGE9xQOf9C5cufg_1biUv_gZaWvfCZI" ],
              "locality" : "BERLIN"
            },
            "_sd" : [ "H6d4FdLAhJ0ZkDANFX1Qeq3OPqRprWhoJbfRwiFxXD0", "NmOykORd4P-IkDDPWu5hMTyvntqTP_XztFu-iVB0zPY", "XL797BupRbdphF4qE22stAKkx0VeI-HB1UGBoDm_-9Q", "c2-6i4K4kJYhTxeM5XCFICgpTozGUdAP3l4BP_jAHE4", "j5LLabcPhD0EpSsOsj3wbSC9QfdMXSZTfXpeQ97k5aE", "pDrHjffD2kri5IQq-0kkDNksCYJx2ggwwc42LmBwbZo", "tb2xpIqd1C6K0yQU9_LyqjiEiFiDG-Dq9byC4tZHKUc" ],
            "issuing_country" : "DE",
            "issuing_authority" : "DE",
            "_sd_alg" : "sha-256",
            "cnf" : {
              "jwk" : {
                "kty" : "EC",
                "crv" : "P-256",
                "x" : "N2_yecO9XWby85bzQ4uQKOuDvPRAUjfeOFhfebmpe9o",
                "y" : "A9-U5Mj-KQEO596LcPDAedpFaT-FpY5EwHRid61ZgK4"
              }
            },
            "exp" : 1746090252,
            "iat" : 1744880652,
            "status" : {
              "status_list" : {
                "uri" : "https://demo.pid-issuer.bundesdruckerei.de/status/6642e557-6f47-4050-90a7-53d5f3418861",
                "idx" : 1
              }
            },
            "age_equal_or_over" : {
              "_sd" : [ "1iSoE_ctnNv6V3PvbPZDMcItf5_JhPmiqz-xDYuWjbA", "1vHUXjCp0ntITw5DTGkkUIbQXNJ29SfqiFK5ZTZQU5g", "eRfTVwor0c-kzB8yHT0vxmeyLkpfCp5-BqfLqchZvu4", "hG_Yypiiz6D3Zahsppg4n-K2cT_AEEQyl9sDi13rOIM", "ozgrVbmA9x3JpW78VRSI5Ayzr-OCkn-aL21zSsGPJgk", "vwERG8yn_Qjgw_gH5__om7QQf75Sf4ZlGLrBxTZ1F0g" ],
              "12" : true,
              "14" : true,
              "16" : true,
              "18" : true,
              "21" : true,
              "65" : false
            },
            "family_name" : "MUSTERMANN",
            "given_name" : "ERIKA",
            "birthdate" : "1964-08-12",
            "age_birth_year" : 1964,
            "age_in_years" : 60,
            "birth_family_name" : "GABLER",
            "nationalities" : [ "DE" ]
          },
          "credential_format" : "dc+sd-jwt",
          "document_type" : "https://demo.pid-issuer.bundesdruckerei.de/credentials/pid/1.0",
          "id" : 87,
          "title" : "MUSTERMANN ERIKA",
          "subtitle" : "ID Card"
        }, {
          "paths" : {
            "address" : {
              "_sd" : [ "Bh8U71zck8arvRov3OtGFcp7Aa6RKxloqOVlFEaFNQI", "FID3h5-WTyHtDGP6yWkCJaPVFZcRBzredTI6nVdZ6ns", "ZAARrAzZN5WviHsXkRHGjZ9qVi5fDXX2E69IyLIUyhw", "aP9SRF8fuwIsAeFX67Z7oO3pgNNoWK9IGOr473B4stk" ],
              "locality" : "KÖLN",
              "country" : "DE",
              "postal_code" : "51147",
              "street_address" : "HEIDESTRAẞE 17"
            },
            "iss" : "https://demo.pid-issuer.bundesdruckerei.de/c1",
            "place_of_birth" : {
              "_sd" : [ "YaQbg_xUeMOmABSgUw_u1-DZUJcbP-GJVEom6aemUUI" ],
              "locality" : "BERLIN"
            },
            "_sd" : [ "ERRM9Zre3bPS8IRe8NnYa7WtLIwMoPZJ1K_HLRqVUSg", "H6rlfYGkYofwysaayYfcbNGpaef6TqgJ1Qbdpm0sI64", "L9Rjg1QpMREOLawmG9RLpt457KqE9PXGKZsyyYT_EPA", "OU0mYlqUOV1xHQfVaXqkWstsYvzcODib0aa8SbVnWaY", "SciHhasu5zWyGy4nlYBK_feEKMEltVq45780oLgBcfw", "Yd9QJvl8_CSpnyU4cFnxbuWqGPp-NWyImaUx7OIxWwE", "ZLhBvru29s-J9EQ0femb15Pjb8KPY2j0hWwPIvgAhac" ],
            "issuing_country" : "DE",
            "issuing_authority" : "DE",
            "_sd_alg" : "sha-256",
            "cnf" : {
              "jwk" : {
                "kty" : "EC",
                "crv" : "P-256",
                "x" : "rhf1vggGdFvuEZUqc9Gzu1apvWEEwi_08PIiN3fYa0U",
                "y" : "ggMgsVLLT0hsRwhGZje4GElt64mXqvJ1D4TKikvyn6w"
              }
            },
            "exp" : 1746090252,
            "iat" : 1744880652,
            "status" : {
              "status_list" : {
                "uri" : "https://demo.pid-issuer.bundesdruckerei.de/status/6642e557-6f47-4050-90a7-53d5f3418861",
                "idx" : 7
              }
            },
            "age_equal_or_over" : {
              "_sd" : [ "088AmUINVj_jia0sK9Gnw9aO9ypjSJfsOSn16YLA2d0", "1lmS7RQmlt-D4OmAKeGXQfhxRjv4uJRi6UiBWArdnZo", "2OdvAfBx9o1rQsoZwIAuS1NTcN65x9top1GWCDGwVI8", "CR4ouNNGWaMFPGwhaOSUegkWLkD-fJFCYaQmYGiyDIM", "SZB-FhfMotVNrfgepoFiBk_uUUKKguZeSkLUuQs1Nu8", "vqAhXFhe0k9KenjjNPCuUV0PcPLmpEYcsaw8X1segdk" ],
              "12" : true,
              "14" : true,
              "16" : true,
              "18" : true,
              "21" : true,
              "65" : false
            },
            "family_name" : "MUSTERMANN",
            "given_name" : "ERIKA",
            "birthdate" : "1964-08-12",
            "age_birth_year" : 1964,
            "age_in_years" : 60,
            "birth_family_name" : "GABLER",
            "nationalities" : [ "DE" ]
          },
          "credential_format" : "dc+sd-jwt",
          "document_type" : "https://demo.pid-issuer.bundesdruckerei.de/credentials/pid/1.0",
          "id" : 88,
          "title" : "MUSTERMANN ERIKA",
          "subtitle" : "ID Card"
        }, {
          "paths" : {
            "address" : {
              "_sd" : [ "1B8ufUKIsldEqHh0QIMtdDiI812skCTYjitQb2XgIZs", "RlHmraavcwB4GsSSjvbFEmAeIOPJbwevIrBRocHmj5A", "XqhVHj6xQQ5hefKphcnOxp5j9C3GYTdqvkKVPj6PZYc", "ki-c6bGBWpmqXDyWBdnvyJ8BbD1XcupiWHGLWqP7Axo" ],
              "locality" : "KÖLN",
              "country" : "DE",
              "postal_code" : "51147",
              "street_address" : "HEIDESTRAẞE 17"
            },
            "iss" : "https://demo.pid-issuer.bundesdruckerei.de/c1",
            "place_of_birth" : {
              "_sd" : [ "wRjCNv3bvnOghUDiYY71aoumaR-OYtch4rgKcutc95Q" ],
              "locality" : "BERLIN"
            },
            "_sd" : [ "5rgq6rcav3gwehR7vH-uJKCnXwRqjoGcX-Vs3U5cEVU", "EVkZ1Nobdfact4-tctOxDNJyMazVim0gtFVjwfynZG0", "L--7iDZb8u32s5FlADJC-tQ2wET3swywwYLk2jGFVVI", "cYvPqmJ4ll6I6sTG4dn1tIgQ46y3G6S1s9AXnySe4MI", "lSJ77T4SJt_pSuB4oWfC4BlBFCSXbjQcwa5-MMripyA", "nbdHAWNptH8Tvww_kYuMFQcNpGQyp7bSdRIX-hmpscw", "sh5EQqb8A49jMb-G6lEc6Ftt27fAViGy0bLMbMGasdE" ],
            "issuing_country" : "DE",
            "issuing_authority" : "DE",
            "_sd_alg" : "sha-256",
            "cnf" : {
              "jwk" : {
                "kty" : "EC",
                "crv" : "P-256",
                "x" : "vOOJ38r6SsAW4wB7ieXtZRW-sRl8R2Cey3t_Oxu5zCU",
                "y" : "QPrbTg-CF_L8R4oshBKtt1eRzl_HCHzfhbwX2N3PPvU"
              }
            },
            "exp" : 1746090252,
            "iat" : 1744880652,
            "status" : {
              "status_list" : {
                "uri" : "https://demo.pid-issuer.bundesdruckerei.de/status/6642e557-6f47-4050-90a7-53d5f3418861",
                "idx" : 90
              }
            },
            "age_equal_or_over" : {
              "_sd" : [ "54h-MbcxjACFO50MpkVzUhTDKdCIuf0yxWWrcYtoTqE", "7829BmCRbdtAUXE3rEbas5UHn8Q5aEIGiE7czlI7LmU", "DRutf72ZjEU8XXYcE1_8KHw5c4PNfxiD6wD-jN5Hqfw", "G61jZSEjxwalhBwaanAjN8c13gWx89gRWqk-6Wr4884", "GddZ74_DRYoTXRyN0wWLe9vX_uOvoYP7Xw9bTjTsliQ", "IMUtV1n3txFnmGBkFdoYPaw4OtD1f2Ikkt0KbMWMh9Q" ],
              "12" : true,
              "14" : true,
              "16" : true,
              "18" : true,
              "21" : true,
              "65" : false
            },
            "family_name" : "MUSTERMANN",
            "given_name" : "ERIKA",
            "birthdate" : "1964-08-12",
            "age_birth_year" : 1964,
            "age_in_years" : 60,
            "birth_family_name" : "GABLER",
            "nationalities" : [ "DE" ]
          },
          "credential_format" : "dc+sd-jwt",
          "document_type" : "https://demo.pid-issuer.bundesdruckerei.de/credentials/pid/1.0",
          "id" : 89,
          "title" : "MUSTERMANN ERIKA",
          "subtitle" : "ID Card"
        }, {
          "paths" : {
            "address" : {
              "_sd" : [ "2kB14GAVJLjxf7rXnqmqTW2rIvmbrnhaEo3hlwySsRg", "B3OHkyA4bM-50kQWHIKtksDzOWN7fUEjh7k1Y_iNYMM", "MsfzZFMHwv8hbtk1LXxdc9U6YLJs8U0OwR6pPXwZvdY", "R-LcAJiSwyvWui90BAUOt_XkcDA6x-ZMtftdO1P4azY" ],
              "locality" : "KÖLN",
              "country" : "DE",
              "postal_code" : "51147",
              "street_address" : "HEIDESTRAẞE 17"
            },
            "iss" : "https://demo.pid-issuer.bundesdruckerei.de/c1",
            "place_of_birth" : {
              "_sd" : [ "YAET4ZfwTy5Nk2vjS7VG7jIAYgWM_VmWuxtq3S_BwXw" ],
              "locality" : "BERLIN"
            },
            "_sd" : [ "Cap521efO2HImtfkbxEbSEyr-qmYnypEKysscxs8ZtA", "HL9dts7sRmuwR8TtMMzSnnSQjlR5ILYrAvAqwpUVqfY", "_Hz1LczO7CeIAJNaQDmopIOyYotDwe1J_wrkxYkuqxo", "ak0PIOfxEHOl_BEagPoUjb-L2dI9xxLG7EfUA52UR7c", "gE7F1H-IiCTvsjByAKtPccllLuPyEZ4iY7WQiJPRY7Q", "pZlapN5AMS6jpMugeFGWrS91FkH6OErhXrpxRAD2WB4", "tFpQBs7SI9qhYnKO2ZDmy-jJVAr2Qa1_IXx114TJUwE" ],
            "issuing_country" : "DE",
            "issuing_authority" : "DE",
            "_sd_alg" : "sha-256",
            "cnf" : {
              "jwk" : {
                "kty" : "EC",
                "crv" : "P-256",
                "x" : "tFlLKObb7EKs_py3rCgTWTj7d0fEpUYT4-ADti4ru9k",
                "y" : "AuSe1iZdNd2uTcXBx19dOwQ_dWChcZEc9KMYL7l5ltw"
              }
            },
            "exp" : 1746090252,
            "iat" : 1744880652,
            "status" : {
              "status_list" : {
                "uri" : "https://demo.pid-issuer.bundesdruckerei.de/status/6642e557-6f47-4050-90a7-53d5f3418861",
                "idx" : 122
              }
            },
            "age_equal_or_over" : {
              "_sd" : [ "0ZBq8NUXZRMRL0dUejyri8jK_V0fp6twW-eu6GSS-Q8", "M49P_0K_E1y0CI7XHfEVVA2Brp5nQdDJTT4WyIoCvUw", "SVL4NGGzrHiIdnGm33b5SPAqvSm1YjlAjiJQmfp2Suw", "aAvePygLoTpigI4rGFgxHjAyq9Xosq-kfH19dOdVIXk", "uZwYilqsDrrtcVA9UK0UpHc4xZk-My9MuLe8y6Sq4W0", "wLTdM1yRWnerl510Ggxb-YImQQZySoD29Bibo5Qxijw" ],
              "12" : true,
              "14" : true,
              "16" : true,
              "18" : true,
              "21" : true,
              "65" : false
            },
            "family_name" : "MUSTERMANN",
            "given_name" : "ERIKA",
            "birthdate" : "1964-08-12",
            "age_birth_year" : 1964,
            "age_in_years" : 60,
            "birth_family_name" : "GABLER",
            "nationalities" : [ "DE" ]
          },
          "credential_format" : "dc+sd-jwt",
          "document_type" : "https://demo.pid-issuer.bundesdruckerei.de/credentials/pid/1.0",
          "id" : 90,
          "title" : "MUSTERMANN ERIKA",
          "subtitle" : "ID Card"
        }, {
          "paths" : {
            "address" : {
              "_sd" : [ "1yioRHd1bai4eAuDUFX6ffEOO-eZYRK4q02fpTcm-QE", "Ke-494jYnP35Z7ZLXcH6QDVC3Jy24zEKz7hi444SHDQ", "jKeO_48fZDfti1k4XKV8euXiysKiBKDw65x7IJbdpTk", "qTlwwagdkE-7cSY8aPsQ1RIFJDUutcPTssdxdAxZRTc" ],
              "locality" : "KÖLN",
              "country" : "DE",
              "postal_code" : "51147",
              "street_address" : "HEIDESTRAẞE 17"
            },
            "iss" : "https://demo.pid-issuer.bundesdruckerei.de/c1",
            "place_of_birth" : {
              "_sd" : [ "XaCYD5qEAB-YUZ9wDelEl8JyQSOFvna9ds8HKnArS0M" ],
              "locality" : "BERLIN"
            },
            "_sd" : [ "4SQz9n8EPKZCWiC0Thn_sLYoAhQwpuPzNtoO_yVkD8s", "8LI775F8sPQA5fpnjjpyhgquv0Mf47jXSjUxjMglOcg", "9NKBlfbgjWOwUa2EtZCGPhwPZclBr0Jv2qskky_UlYw", "AoBZYWshLvWhdqGWIHh_pxvLYKL_W5DmUASpXRhl7KA", "UA_ccmEhmJiMB1dJNFO_ucvqZjYEq0UTci11W3EvdyA", "XlUUav_QJiyeBO872QK8pQqlelJHQo6Hk1UKbIRTajk", "diIf-tMHYPJAKkCdDFHzTZ-vDC_ZT-YsKJDHJLIHXyY" ],
            "issuing_country" : "DE",
            "issuing_authority" : "DE",
            "_sd_alg" : "sha-256",
            "cnf" : {
              "jwk" : {
                "kty" : "EC",
                "crv" : "P-256",
                "x" : "K_6y-9z6E0RIEtotSUrGISQ9XjjfdrCN_XXQoiaxi34",
                "y" : "CNrFx0uEY9jmYfyj2FlaHgaCZqJ5qet0om3gr5hZgUo"
              }
            },
            "exp" : 1746090252,
            "iat" : 1744880652,
            "status" : {
              "status_list" : {
                "uri" : "https://demo.pid-issuer.bundesdruckerei.de/status/6642e557-6f47-4050-90a7-53d5f3418861",
                "idx" : 92
              }
            },
            "age_equal_or_over" : {
              "_sd" : [ "IzlLMDMa1cxYesgNd_KVCkadCq0SF6a_6ERFFfBeS4w", "MZsSKhYhJkDQ4beQa6M_ZHPeQ0rHQvUHRalrky-GWWw", "RGyiqWlRjrZygIbNGv1olX5yCpPqEfgGbCKRf9q24MU", "ZVDqcWE3yA6jzTRn5ALVbq-AjJJFwbTdwK9oBGnMnlk", "akO05bkIVB56E7sPMY-cCaEdSCtj3woPoOkpzlASshA", "qhaLdN4K0U1nw1vof_aOj1SSi8xiFVbhE3p59EiA1IE" ],
              "12" : true,
              "14" : true,
              "16" : true,
              "18" : true,
              "21" : true,
              "65" : false
            },
            "family_name" : "MUSTERMANN",
            "given_name" : "ERIKA",
            "birthdate" : "1964-08-12",
            "age_birth_year" : 1964,
            "age_in_years" : 60,
            "birth_family_name" : "GABLER",
            "nationalities" : [ "DE" ]
          },
          "credential_format" : "dc+sd-jwt",
          "document_type" : "https://demo.pid-issuer.bundesdruckerei.de/credentials/pid/1.0",
          "id" : 91,
          "title" : "MUSTERMANN ERIKA",
          "subtitle" : "ID Card"
        }, {
          "paths" : {
            "address" : {
              "_sd" : [ "8lfojDRDRNRMcEHeL8sZuKaCSJyBueE3fYPDWdXkr2w", "FK3gx0IKB506Q1ekJNJIGciUKTp6PCEZfF9862ERjM4", "doDohxdbDYJ9mU6f_NKfcr4GSvdKJkckitbGICaNWnI", "xlFhdN27TorP4rqaX2VAh0mxAUzhrWKZPs0eJSfOnQ8" ],
              "locality" : "KÖLN",
              "country" : "DE",
              "postal_code" : "51147",
              "street_address" : "HEIDESTRAẞE 17"
            },
            "iss" : "https://demo.pid-issuer.bundesdruckerei.de/c1",
            "place_of_birth" : {
              "_sd" : [ "tll-2epw61hvYWVtWZyHUNT9U3pj_JXRJZ2ZIzVe-sg" ],
              "locality" : "BERLIN"
            },
            "_sd" : [ "0pitgGVQ91DEVlD6ikKpps32LspKO9VnEcsJaRbw0cw", "5KB7_DBvSBG2LOtTMccwtjqELvZzM7-S1EZd1SZUoIY", "Az5HOGMbuI0a789ta79s76Iq3f2YaH20hXoM0HcnxuQ", "JWuZP0ECOvp1-x7DVc5u0JogEHvja2kwCE0H2pXKAL4", "ggWBlbrK422IXLt8k3Z2d7W9vi6ZIcSCsLGLPgtjAok", "h-7ZNJj45U49HX_nmbaLTDDD_htRuib-V0CRPAoMvws", "llcOhOlKKUX6GkFtvSha5WqTWoybJ_kM1rFEIEnZaB0" ],
            "issuing_country" : "DE",
            "issuing_authority" : "DE",
            "_sd_alg" : "sha-256",
            "cnf" : {
              "jwk" : {
                "kty" : "EC",
                "crv" : "P-256",
                "x" : "VWovqLNB_6zLeczw41J67sLzgL_ZKGrfYRB1ecMNl9E",
                "y" : "hIjp9IjAMtU48Fam9NY3HU9w2KGCSXN1GYSxxfrpx7s"
              }
            },
            "exp" : 1746090252,
            "iat" : 1744880652,
            "status" : {
              "status_list" : {
                "uri" : "https://demo.pid-issuer.bundesdruckerei.de/status/6642e557-6f47-4050-90a7-53d5f3418861",
                "idx" : 125
              }
            },
            "age_equal_or_over" : {
              "_sd" : [ "9mT8i7KN53G4awT5br8hg4YDG1UlP5DP40Mo8ZiTnIM", "AvuJecDjT8VV6eBlHOEBvb5XdnyuhlIyskHRCRjIxfQ", "JYWJLNcXdRkyxeKFcZLkbAKgy8-YkG5HxjH7cUFyDdk", "JeF83WlA2rO6_SImTZ-2nAAet-krkgKfa4BNZUdUon0", "Pnx9BodXUVmHPj0sykUVTNJtsHM73QXsfvgI4VymAMU", "rJ4xB6xPCMFD9ICtr7HtqRVByhGGI5PCrS104dM7SbE" ],
              "12" : true,
              "14" : true,
              "16" : true,
              "18" : true,
              "21" : true,
              "65" : false
            },
            "family_name" : "MUSTERMANN",
            "given_name" : "ERIKA",
            "birthdate" : "1964-08-12",
            "age_birth_year" : 1964,
            "age_in_years" : 60,
            "birth_family_name" : "GABLER",
            "nationalities" : [ "DE" ]
          },
          "credential_format" : "dc+sd-jwt",
          "document_type" : "https://demo.pid-issuer.bundesdruckerei.de/credentials/pid/1.0",
          "id" : 92,
          "title" : "MUSTERMANN ERIKA",
          "subtitle" : "ID Card"
        }, {
          "paths" : {
            "address" : {
              "_sd" : [ "E5ie1g24PtxLpDmSNsShu7lFWjDTGbXHoi9trQKx4NQ", "J59KdQD0VT6hMLJgKMuE4sreYUPyfO0U24LNtHOlSPI", "e430kTVPEJS6zgdMlhjW2g5FfNAWi6WdKvDi6X7Mjuk", "ii-Mmr92oykSWNfQml4c4YPYfKlFshyAzia3rHNqYTY" ],
              "locality" : "KÖLN",
              "country" : "DE",
              "postal_code" : "51147",
              "street_address" : "HEIDESTRAẞE 17"
            },
            "iss" : "https://demo.pid-issuer.bundesdruckerei.de/c1",
            "place_of_birth" : {
              "_sd" : [ "DocW9kKj8qSXsAV6PmKwajV7nQpuzmtA0Vb1U6yssAg" ],
              "locality" : "BERLIN"
            },
            "_sd" : [ "-tlFWh8y8ORjuvy1s85Iwm00YxTNcswpIyuGerVfwQg", "3vZJtdk-RAa9cTTeDK24hNYQP2mwgecTdrXoIOP4gu8", "Fz2OFPLS4whRD1e7nWyVAII1K5rNqJlZ5jkP2-K0gSQ", "ZKrqJtTXYzzQ3bwXcvzP8gJ38rdP6DvpAQCzcJUFqD4", "ew2HwfSNFwA_kuX6VtYufVyJXmyHjZDhIoq604PL8D8", "nWindKoBsMPUdGnXVZqA-r9OIunZokF-Yv8XwrFuKOQ", "oMjdLzyChGLiqopMpi7w-e2V8Ncdyy4VHxnVIbKkXSY" ],
            "issuing_country" : "DE",
            "issuing_authority" : "DE",
            "_sd_alg" : "sha-256",
            "cnf" : {
              "jwk" : {
                "kty" : "EC",
                "crv" : "P-256",
                "x" : "Sxl13Gic82ffT6Vo3etG82DyenGbw7LIK2zgRzbwU3o",
                "y" : "SmdpcFVTwINPf32p8cYyG8uHZA_fJcaPBf7LGUfeFUw"
              }
            },
            "exp" : 1746090252,
            "iat" : 1744880652,
            "status" : {
              "status_list" : {
                "uri" : "https://demo.pid-issuer.bundesdruckerei.de/status/6642e557-6f47-4050-90a7-53d5f3418861",
                "idx" : 25
              }
            },
            "age_equal_or_over" : {
              "_sd" : [ "_T4iUihxB9X3TdPSfYhYY288PnRSI7dIZFYG8SAc-RY", "jgSWTVyPczcblEWNEt1vpiGBYfn2w8cIP_ZjK2Prmvs", "q3uS1MUK1UjN54NnmiNbeq1LY46Csioian86jbwGzns", "vVzdObxhNLlEWReaas-IM7lRqZYKMyhJiWVF8-d__hI", "z33fH_zc5q7RkmJ147OhQgrE5tZkgPKWMUs114so7Ro", "zRhA6Ylr35qAgk39q5Ih_Ec6S3lKgZYSh-6W8xgySzw" ],
              "12" : true,
              "14" : true,
              "16" : true,
              "18" : true,
              "21" : true,
              "65" : false
            },
            "family_name" : "MUSTERMANN",
            "given_name" : "ERIKA",
            "birthdate" : "1964-08-12",
            "age_birth_year" : 1964,
            "age_in_years" : 60,
            "birth_family_name" : "GABLER",
            "nationalities" : [ "DE" ]
          },
          "credential_format" : "dc+sd-jwt",
          "document_type" : "https://demo.pid-issuer.bundesdruckerei.de/credentials/pid/1.0",
          "id" : 93,
          "title" : "MUSTERMANN ERIKA",
          "subtitle" : "ID Card"
        }, {
          "paths" : {
            "address" : {
              "_sd" : [ "9JI3N23vR4omLSEAK09i4yWysepzdMDnXDzkqsuzVY8", "ONGWZWEXsgZ9pSq_sIGBYz_VmbzAvYCtuYAgOPuZNJ8", "g1nSyOgm1ygN-3hASgHXiYvKlHwVWvM9nH_-dxXwXkY", "pTuSB3jUtx1O65Uje0AfOy8ZN495WZOOlsTg5N8SnqU" ],
              "locality" : "KÖLN",
              "country" : "DE",
              "postal_code" : "51147",
              "street_address" : "HEIDESTRAẞE 17"
            },
            "iss" : "https://demo.pid-issuer.bundesdruckerei.de/c1",
            "place_of_birth" : {
              "_sd" : [ "0kKOrtRkszpawdnBX6A5CSoVmWPIy25x5rcRFE22XEA" ],
              "locality" : "BERLIN"
            },
            "_sd" : [ "0F82bH-xQc_1lwx3MUdBtEGNg_EG1P3doYDXab0SQOI", "3yM1bspt0qkBi2msm9OX-9MgxUexIROmRyFXEVOjMS4", "70gJQSPPCTzUnqiv4k6ueYkD6tLx0d7wZrFMQG76ocQ", "MeUyHHPoI9-CqhGXZbCiod_HhqKItTt5vqhJbFF40ZU", "YkxMr3It-g5BTXH8Gt2OmZf7lwlC5GP8JBGZMngthjk", "bKfI-6Y04uq2hGzKsFb_uBK8vB62wyR49iTJollN59U", "sfbyHkIBTcvW6F-SdPPtVTwnLvGTQKwxsfB2zq4buQo" ],
            "issuing_country" : "DE",
            "issuing_authority" : "DE",
            "_sd_alg" : "sha-256",
            "cnf" : {
              "jwk" : {
                "kty" : "EC",
                "crv" : "P-256",
                "x" : "mOau2XAITz-3w1OaqCLn-8OTePK8s2qlNuyMr4zm9YI",
                "y" : "9CLEqZhQ_HZ2-XddPgwdMkHX3k3Ur40i4qdaY_eFmEE"
              }
            },
            "exp" : 1746090253,
            "iat" : 1744880653,
            "status" : {
              "status_list" : {
                "uri" : "https://demo.pid-issuer.bundesdruckerei.de/status/6642e557-6f47-4050-90a7-53d5f3418861",
                "idx" : 93
              }
            },
            "age_equal_or_over" : {
              "_sd" : [ "2D5oPEQilUC8ozqdR1MFTQCqErpHPb3Z_kW_EQePJDE", "HhjeFKz2KLNjn12h_dNv917GVO8P7GBMRo7Qcwpr6uc", "Rlc6WpKeFMWJiS4Z9CXmM7WsnykmPdGZd_ZZbRUWFUM", "TfR0kb4ZmORvfxEQSyyb0ofX1jlS8QD-aYXgiDzUGZU", "g2v90G9eNKgseGsjO9oOOSHbhIcKHvVsietGDe-0RhM", "y1W77QI7gDqz_UNqmhX-Bu8ByM2n0X2mUeGmP7EZubU" ],
              "12" : true,
              "14" : true,
              "16" : true,
              "18" : true,
              "21" : true,
              "65" : false
            },
            "family_name" : "MUSTERMANN",
            "given_name" : "ERIKA",
            "birthdate" : "1964-08-12",
            "age_birth_year" : 1964,
            "age_in_years" : 60,
            "birth_family_name" : "GABLER",
            "nationalities" : [ "DE" ]
          },
          "credential_format" : "dc+sd-jwt",
          "document_type" : "https://demo.pid-issuer.bundesdruckerei.de/credentials/pid/1.0",
          "id" : 94,
          "title" : "MUSTERMANN ERIKA",
          "subtitle" : "ID Card"
        }, {
          "paths" : {
            "address" : {
              "_sd" : [ "11BBJ4zq9-SCKKUVBgWKyf0u6BjLKchzJvmyU2wSxLA", "1Yq9UBhf2hvPXe8s0LQT6Bd2HoWn8uc7XfFrhFF2ayc", "mF9plnY5DJxGL743feq4P_T-mX0xh2TM8KBimzZESqI", "rzzO0f9peTuLtj2c4r7y8BWKbndXjjitGB1PrVyYNSo" ],
              "locality" : "KÖLN",
              "country" : "DE",
              "postal_code" : "51147",
              "street_address" : "HEIDESTRAẞE 17"
            },
            "iss" : "https://demo.pid-issuer.bundesdruckerei.de/c1",
            "place_of_birth" : {
              "_sd" : [ "PvsKEKDQqGMUr9MqzNrfRMARRk9H-oafgSbXDphFcGw" ],
              "locality" : "BERLIN"
            },
            "_sd" : [ "6sIFBdp1lsCs4f1RjkRJM8zctYJ3E4Dqs_JHxOnJ63k", "DvPbO31gV6n4WMOnLxu9dtaiLrrOJY-s8uYOxB8H5IU", "ETmhbAxbBHZVAsZC7rpJAuL-FCtWNmXqgUk30rnTFn0", "J1gSgkzDB3vadWOI3M3nov78Ae9hbgBDBsc2kYosSUI", "dqhnKHjMdFywQXgfpSwkXPR2iImpmov6ruhU52EPBHQ", "vy_DNVFX9bMa0DjGYaFcFk4FlY7-TKCMNLYzb_QWoAg", "xth7EKlq0VciaUSvU1WTvnL1U6cJotjnbSggEc6HuN4" ],
            "issuing_country" : "DE",
            "issuing_authority" : "DE",
            "_sd_alg" : "sha-256",
            "cnf" : {
              "jwk" : {
                "kty" : "EC",
                "crv" : "P-256",
                "x" : "DXhPtIA5J5HrdPHkyDIG9IWiEonKJcCjVq4xLbRIYPk",
                "y" : "jsA7Bm48CGBWd8mJKRTeAnYMn5XJ-zSBVNnBubKjkwg"
              }
            },
            "exp" : 1746090253,
            "iat" : 1744880653,
            "status" : {
              "status_list" : {
                "uri" : "https://demo.pid-issuer.bundesdruckerei.de/status/6642e557-6f47-4050-90a7-53d5f3418861",
                "idx" : 40
              }
            },
            "age_equal_or_over" : {
              "_sd" : [ "HQIWmuIcuOnXGPJAZyFjq2UjK4RZ5gn-S66UW45aurc", "OanAYyWJMEjgb_adJ1RXIcEHqsUkUanzsEga5dpUZDE", "iLjQG641DAaPj50ZXSOQnJLw82prC_7CDxaZPBZmKuc", "o8W9-cjhACQ9bYiertA1O0yt4RWWtR8bFODU_xKO_xs", "pjPdBwJVJf_sacJNXjm_9JUx82S9NFUwvFWyQ_3ldeo", "xgSWSbMO9ZAaOVnccfcmkb5FKcWHwIMlksnABmQBVsU" ],
              "12" : true,
              "14" : true,
              "16" : true,
              "18" : true,
              "21" : true,
              "65" : false
            },
            "family_name" : "MUSTERMANN",
            "given_name" : "ERIKA",
            "birthdate" : "1964-08-12",
            "age_birth_year" : 1964,
            "age_in_years" : 60,
            "birth_family_name" : "GABLER",
            "nationalities" : [ "DE" ]
          },
          "credential_format" : "dc+sd-jwt",
          "document_type" : "https://demo.pid-issuer.bundesdruckerei.de/credentials/pid/1.0",
          "id" : 95,
          "title" : "MUSTERMANN ERIKA",
          "subtitle" : "ID Card"
        }, {
          "paths" : {
            "address" : {
              "_sd" : [ "9N-lD503_kGF5L01Ud-V23yjbjF9EErOoXSQ7RI0yq8", "IO9wJ0ZWwH5vxOR_X6CJJuIDGpVvxXbqZpzQidDy-HU", "lYgkCmxUBD6dSSoXKeBUQWveD33GoxYjpk4Hosf52Rg", "sUYJFX1TQuMSiBwF0QaEfosu4muQHMfiswSNsvNp3a8" ],
              "locality" : "KÖLN",
              "country" : "DE",
              "postal_code" : "51147",
              "street_address" : "HEIDESTRAẞE 17"
            },
            "iss" : "https://demo.pid-issuer.bundesdruckerei.de/c1",
            "place_of_birth" : {
              "_sd" : [ "TVo7pSMSfoFej_Gta4bIV73MrAYF-FGL1r4iNu8I1eg" ],
              "locality" : "BERLIN"
            },
            "_sd" : [ "G2MlMZX19EdkEjpRHFGy0bZtY3ZZZPsyHURiMfsTMQ8", "LcCZuaw94OhmtNuFMjlcLBsecE9_cI_tfKTHO4TV88U", "S9YOiM3zw_t1TPTZnjF26Stn6RgqrzOhhB0aLtslDeA", "bPeOJXMJeShdovaqWpqqxbhFc3qIaIWPpp_R6dEPyGo", "kzLTcRgzZsKwxVqoQdRXSGxf512PeVdjnO2_mhAcrcI", "vSfdQW8-UlaMe3wSMmbfDUr2Veku0cvLJtoht595hLs", "wVW_Du9DI7bx1f8mEPtBAhpUS9-GpVw9jbp_PNDCGl8" ],
            "issuing_country" : "DE",
            "issuing_authority" : "DE",
            "_sd_alg" : "sha-256",
            "cnf" : {
              "jwk" : {
                "kty" : "EC",
                "crv" : "P-256",
                "x" : "t_dM1mMJS3XQxcncJkBTFHJzuyEqXODb6Z2V1ckV1Eg",
                "y" : "sIXYUx_SpBv_Rv7jURqbXn8E56-lB0KfwCCtafrEvRE"
              }
            },
            "exp" : 1746090253,
            "iat" : 1744880653,
            "status" : {
              "status_list" : {
                "uri" : "https://demo.pid-issuer.bundesdruckerei.de/status/6642e557-6f47-4050-90a7-53d5f3418861",
                "idx" : 116
              }
            },
            "age_equal_or_over" : {
              "_sd" : [ "PTgFJrjI3UEhkndnDwRPrOQSRn8z39Gh_Rt1yes5XIc", "YZElswAhFS4mfgD_unnXQuW08RBxMDdlbbcmlLfjwDw", "b_XR0zsnmeWL10I_eX3GaxespbRgKNBBJEfa0_0l_5g", "hSfFfiIAcjqlifqH71nw-oJE1hR6cJUy2Ylgupe8sW4", "t-hJ5ZBKVpq5LHJTqHq4lhRNPlMagxu8pW9KGr_cBNs", "xVRDPZeSeSTdQr5BAHIHdit3uIakqUebnN60Exmcysw" ],
              "12" : true,
              "14" : true,
              "16" : true,
              "18" : true,
              "21" : true,
              "65" : false
            },
            "family_name" : "MUSTERMANN",
            "given_name" : "ERIKA",
            "birthdate" : "1964-08-12",
            "age_birth_year" : 1964,
            "age_in_years" : 60,
            "birth_family_name" : "GABLER",
            "nationalities" : [ "DE" ]
          },
          "credential_format" : "dc+sd-jwt",
          "document_type" : "https://demo.pid-issuer.bundesdruckerei.de/credentials/pid/1.0",
          "id" : 96,
          "title" : "MUSTERMANN ERIKA",
          "subtitle" : "ID Card"
        }, {
          "paths" : {
            "address" : {
              "_sd" : [ "EH7anXRp_6qV1H-Hq0ZzczBIXvABP99YRt-MmYWkhNE", "Sv7uyb79U2wpE34S1wgv1Im9iehpc66cE814uMtYTio", "qnIskTt64ooEtgkf0dDzHeU-rh68MjGLZ9zVurFdKjc", "sJL-xU_itMsdAnIcAfDjouWCNemxHla8CCd4EhEhM0s" ],
              "locality" : "KÖLN",
              "country" : "DE",
              "postal_code" : "51147",
              "street_address" : "HEIDESTRAẞE 17"
            },
            "iss" : "https://demo.pid-issuer.bundesdruckerei.de/c1",
            "place_of_birth" : {
              "_sd" : [ "MtRpLmh_TRH0wEf0UVaUR4GwiGqTNeCqlNX-FSIBhX0" ],
              "locality" : "BERLIN"
            },
            "_sd" : [ "QZ_r0SwWihmiGR56HlOveIo31Ag1JaDvQAWrMDI39bA", "V_re-xj85y5olswLv9d4WE-iwU4-ibly-Nt3-__npOQ", "X0wHiF9tYOmGX2nJMhQNVq8iJha9B7ILgPYCCjWq8XQ", "fu8yjhqER8XOmaft2Y9YrBuHY6FlaZlfvC3ME1ELgjg", "iFNRj5JV7_SzOiHS48Xz6LCk1yrLonSlnvAsXFqBHFM", "qWt6J2oqMEPRD-MZNtKndpgeujwrIa7zOGNDIFF7HoQ", "w31AgDp76ml-biwd4qKOuZvFNxDyLproDNAQQXuqWW0" ],
            "issuing_country" : "DE",
            "issuing_authority" : "DE",
            "_sd_alg" : "sha-256",
            "cnf" : {
              "jwk" : {
                "kty" : "EC",
                "crv" : "P-256",
                "x" : "ntXJuJ364Z8WGTczBpNIfXhuGa8yL1qCXvx_jPDJifI",
                "y" : "Bn3fJXBOwjLlk44H0wGFiLPCXrJw1-vK37aDCoB1wFc"
              }
            },
            "exp" : 1746090253,
            "iat" : 1744880653,
            "status" : {
              "status_list" : {
                "uri" : "https://demo.pid-issuer.bundesdruckerei.de/status/6642e557-6f47-4050-90a7-53d5f3418861",
                "idx" : 30
              }
            },
            "age_equal_or_over" : {
              "_sd" : [ "-LDHrfYeT06GebPJdQXEGdV0hQq-uTeRWtQoAD8Tmd4", "1G32CTpOI_qLhiY_5dB2-yooY26DMiZhNxLQFaFtqQc", "46WNb3dC7kj3lNvj3FdmF-BCRd_IMCbcvwJSvgdeLkg", "JG3nWhqimlmNk_QKfViVAqT8W5KcS6eejqM72bOTW7s", "Xh9lbjHFavOz2SjEH7Gwe4u6lj_bBclGgJdJtPdHKbQ", "jQX8MbrEsh6fjqorDgLaUmt7m_UO-zvxS-5L0zU0Ly8" ],
              "12" : true,
              "14" : true,
              "16" : true,
              "18" : true,
              "21" : true,
              "65" : false
            },
            "family_name" : "MUSTERMANN",
            "given_name" : "ERIKA",
            "birthdate" : "1964-08-12",
            "age_birth_year" : 1964,
            "age_in_years" : 60,
            "birth_family_name" : "GABLER",
            "nationalities" : [ "DE" ]
          },
          "credential_format" : "dc+sd-jwt",
          "document_type" : "https://demo.pid-issuer.bundesdruckerei.de/credentials/pid/1.0",
          "id" : 97,
          "title" : "MUSTERMANN ERIKA",
          "subtitle" : "ID Card"
        }, {
          "paths" : {
            "address" : {
              "_sd" : [ "ArCl3mGbLWe1l46Y71FaTiEQ6LpyfgX4kuZnFL0cGIY", "MKpxGYTfPGM2-rgLa0bF0uMHgCd-nbJLw8UwNLNthYc", "jq4kZQ-qrXJl87M7Ne276tZY5_arDc4abqd64dAJt7w", "rEswfTpPfTvTyrBPWyQoh3oP-K3Nbk1u713erTPueKw" ],
              "locality" : "KÖLN",
              "country" : "DE",
              "postal_code" : "51147",
              "street_address" : "HEIDESTRAẞE 17"
            },
            "iss" : "https://demo.pid-issuer.bundesdruckerei.de/c1",
            "place_of_birth" : {
              "_sd" : [ "o-v4qPxvTBLk3R6ZBAlOGpbkDEXOT0N63eYF1K28mM4" ],
              "locality" : "BERLIN"
            },
            "_sd" : [ "AKPqYK6X204c9Ew9fynYSxfMwJDerYZmL_kOR1NIt1M", "Bvleh54q5QYBXx0vO79sTlzAjc8QvK0ILeCms-zwl6Y", "DO88Sk_27Z8TSVUNJPEQWAYUE2Kzm3DrC6yJYJj2f5I", "Eh-eiKB0p3M4enHM9LPimZZ37o-QIMHeEVSSHVxnThI", "F6QF43GFMe8ySRZxWouRlJQ47tdgaVzZavjlaIFSVOA", "gHI_V-qJLWkL3mBbRIPOEiff_tWGdPbuy1YpT0X-tFE", "uQZ4gInIjhgVJw3FyidSZgmy0Yyy-z0_dI4GY2xE8xY" ],
            "issuing_country" : "DE",
            "issuing_authority" : "DE",
            "_sd_alg" : "sha-256",
            "cnf" : {
              "jwk" : {
                "kty" : "EC",
                "crv" : "P-256",
                "x" : "iPuwrn_fNGhRpRcDZUlfIVKoUNilg0UlxX2gTM68bjk",
                "y" : "tkZjN64bihJfnWHsQm3yOwsMp2Spk-_fqaILIL1qbIQ"
              }
            },
            "exp" : 1746090253,
            "iat" : 1744880653,
            "status" : {
              "status_list" : {
                "uri" : "https://demo.pid-issuer.bundesdruckerei.de/status/6642e557-6f47-4050-90a7-53d5f3418861",
                "idx" : 18
              }
            },
            "age_equal_or_over" : {
              "_sd" : [ "0I6f2ctbcK98hi__C8mNJ8QUGNlW3rXidqDNf03PpQA", "KBFw8M_5Zl5mK59h5T72PGxFamJwAqq8JMBrZCWEZNA", "N3VJNsfgyJr8QA5FY_6C0wer0qG-eVuVdR1P84TBDhQ", "YBj_xnGetatUmNBAOZS-wSpXGcGKpxp1JgVf0fHWtVY", "Yeqby9RI3YYc2wwCdO7KHegndTT_J6NSJy0y4_5LABw", "uXXn1gLo30U0BcqQkoxVkgPU5F5cEV6ideC0Lr3rkhE" ],
              "12" : true,
              "14" : true,
              "16" : true,
              "18" : true,
              "21" : true,
              "65" : false
            },
            "family_name" : "MUSTERMANN",
            "given_name" : "ERIKA",
            "birthdate" : "1964-08-12",
            "age_birth_year" : 1964,
            "age_in_years" : 60,
            "birth_family_name" : "GABLER",
            "nationalities" : [ "DE" ]
          },
          "credential_format" : "dc+sd-jwt",
          "document_type" : "https://demo.pid-issuer.bundesdruckerei.de/credentials/pid/1.0",
          "id" : 98,
          "title" : "MUSTERMANN ERIKA",
          "subtitle" : "ID Card"
        }, {
          "paths" : {
            "address" : {
              "_sd" : [ "GUyuoj5V63i48_MFCZgTKBvq_NH50FFTlcp5EFH0fw4", "RKLJkcpeDmSOQJ9dOXYLggTfpcdIR8LMmacj-H79YTE", "UWsU-myYHTBwppIwN8hGo-VlAzl39l-ZzQJryKkKB4M", "ZNoO7yMxakG1qmVy0LAIhbH56VFvzVGeqJz4soY1uzc" ],
              "locality" : "KÖLN",
              "country" : "DE",
              "postal_code" : "51147",
              "street_address" : "HEIDESTRAẞE 17"
            },
            "iss" : "https://demo.pid-issuer.bundesdruckerei.de/c1",
            "place_of_birth" : {
              "_sd" : [ "yEn3mxX252psH5uMx4f24HG5wVHW60l28TISRFDMsuI" ],
              "locality" : "BERLIN"
            },
            "_sd" : [ "NgPwRelUPfxF1_odMhSwHhBaFT2jv7Ap8rjwgQaqvok", "Ya-xwUn7Qlv81m4tGXEaEB1fEjFLugVw-EXDtIfX8ao", "ZE-kJP54RAaY3OtaHFzG6FcpCi2gXOaipiPeFpBooys", "bD6HRhGI5HaoSh0_7YOfkpbWneKyk9RNs9UR1tTu_hQ", "d1GLukGa2H9J8ljHHvgaHVRuAvLimiIs7V4expgO4F0", "d2Qa5Hq8m-6JDXR3JfPx8bO9A9Ow5US_sry_0xDRs7Y", "n5oHx1I08iyLtGAhbYNvBngASYFHP0u-5NmQfO8d5_w" ],
            "issuing_country" : "DE",
            "issuing_authority" : "DE",
            "_sd_alg" : "sha-256",
            "cnf" : {
              "jwk" : {
                "kty" : "EC",
                "crv" : "P-256",
                "x" : "4H3nRH-qrDgL0Ih2W2hFcWmJEPw4k7-EO7IcM-gcqR0",
                "y" : "07UQZLEXeZ2zscdwdo0rRRJC2yz7YhgTP7hJ5sQ4d8Y"
              }
            },
            "exp" : 1746090253,
            "iat" : 1744880653,
            "status" : {
              "status_list" : {
                "uri" : "https://demo.pid-issuer.bundesdruckerei.de/status/6642e557-6f47-4050-90a7-53d5f3418861",
                "idx" : 20
              }
            },
            "age_equal_or_over" : {
              "_sd" : [ "1FQ3qs72RXeaVQorVnsl8mlN4iXLIulunF2QQCStFgc", "57QvFskNS-KqMXz1VJoDqEjRjR_stdYn2MuHPNCs8wo", "P4QxL3-sLMP3bVFMl7UMOOwQGiFOiQHq_XhgBq12sKo", "bC_S_0S3nmRHdY7KuaAWvghXY-ZZxYphTwGL19ybjUY", "lLigTDWkeuY4nLzqH8y8aDbs0XY5uwRE3QqLYavr6j8", "ouKmvj07H3ePV1Qlz9fuj836RkYR7m5-m12iN8GforA" ],
              "12" : true,
              "14" : true,
              "16" : true,
              "18" : true,
              "21" : true,
              "65" : false
            },
            "family_name" : "MUSTERMANN",
            "given_name" : "ERIKA",
            "birthdate" : "1964-08-12",
            "age_birth_year" : 1964,
            "age_in_years" : 60,
            "birth_family_name" : "GABLER",
            "nationalities" : [ "DE" ]
          },
          "credential_format" : "dc+sd-jwt",
          "document_type" : "https://demo.pid-issuer.bundesdruckerei.de/credentials/pid/1.0",
          "id" : 99,
          "title" : "MUSTERMANN ERIKA",
          "subtitle" : "ID Card"
        }, {
          "paths" : {
            "address" : {
              "_sd" : [ "9bWhovC4o5k1PxBylFQPCE5WIBM9COt_Ntkm9aCIMOg", "KjbiTF74Ag4EWOdU9pTRyjHLp8qDK_riW4YfUP8uPBI", "eBueoQ3kqvBEcN9BTokETJpI5Ua1a7Ool18vSdy8M1M", "wg9mk-Cip8zxUTdtKR09MiLCG7JrG1wQLsoul-tUEUc" ],
              "locality" : "KÖLN",
              "country" : "DE",
              "postal_code" : "51147",
              "street_address" : "HEIDESTRAẞE 17"
            },
            "iss" : "https://demo.pid-issuer.bundesdruckerei.de/c1",
            "place_of_birth" : {
              "_sd" : [ "YBXA0pTtfwrZQk8o5O9o_n2aoH9LaJaeS95BqAxoVrI" ],
              "locality" : "BERLIN"
            },
            "_sd" : [ "Kaouq2Lrv579ba-ZtwmXMENV4j48PVQy0frArG3y05U", "L8MfO1IWPVGiezhrM8b346lbx9VowzQuR1qxljX_qqU", "PR25pYcAv3KXNoXrlPDO8LylxYQS7pxClNpadMpdwwE", "bmlzQwzbl6_xmqDAGSiuAgOwyCpBnSDs2xur3_0hfD8", "hpdg0RxxxqZfJuGwMMMc9bv2tqDPehduRkXZDaqZOwo", "n7e0-Oczu8xDGq2mTjKonctEWfNhtCp4sOlFy2TmJvU", "ojGPZUrT8UNU6TGbZFt6jfKyGNzUC8k_B-0KXafqMSo" ],
            "issuing_country" : "DE",
            "issuing_authority" : "DE",
            "_sd_alg" : "sha-256",
            "cnf" : {
              "jwk" : {
                "kty" : "EC",
                "crv" : "P-256",
                "x" : "pVSHy2F2QuB-Y-4ZvjN-L7tBQkS9m5w-kCBULV3-GGE",
                "y" : "d-b82G631MgRfosHkh3O7KRLzaSkjGPtLfMj0YQA3AE"
              }
            },
            "exp" : 1746090253,
            "iat" : 1744880653,
            "status" : {
              "status_list" : {
                "uri" : "https://demo.pid-issuer.bundesdruckerei.de/status/6642e557-6f47-4050-90a7-53d5f3418861",
                "idx" : 85
              }
            },
            "age_equal_or_over" : {
              "_sd" : [ "3bjKYZVGEhRRymZHzg5whF33k76Su-smugKtsGC4qbM", "QjBNEwZuxrTmCzijVKr8Li1aggFzSclVg89URwinFRI", "ZoD4qxEH2KY-GVLItpgdK9jCL9Plrczp91A4k7b0Iw4", "_Sa99o0wGUrAoV0MKmrauz-9ibvOmtwDRfLxTQQ8gd4", "gQr-sddI58rfYEGfnDqVdCfhp15q1MBzihpsTvUHqE4", "vrqVVBV7TCS1KfAIevxsitE1ln_vEJ269xf31mi5Y-0" ],
              "12" : true,
              "14" : true,
              "16" : true,
              "18" : true,
              "21" : true,
              "65" : false
            },
            "family_name" : "MUSTERMANN",
            "given_name" : "ERIKA",
            "birthdate" : "1964-08-12",
            "age_birth_year" : 1964,
            "age_in_years" : 60,
            "birth_family_name" : "GABLER",
            "nationalities" : [ "DE" ]
          },
          "credential_format" : "dc+sd-jwt",
          "document_type" : "https://demo.pid-issuer.bundesdruckerei.de/credentials/pid/1.0",
          "id" : 100,
          "title" : "MUSTERMANN ERIKA",
          "subtitle" : "ID Card"
        }, {
          "paths" : {
            "address" : {
              "_sd" : [ "7SAsvNYS9L-6xE9m9wcBR9EZKWF_-cSgHVBDHej2Pxk", "IhKxQyrKB219gkAmY75xoFlP7nrOg7l84SrsVY5xGWQ", "dO2qq9CkgZ4czmTVGutYWRW95FiMCQeaTGutPRXw_EU", "eLJ5O3QHw9Muqc-TqD8iaoADkW4Z7hYQ7cKgFf7lN4k" ],
              "locality" : "KÖLN",
              "country" : "DE",
              "postal_code" : "51147",
              "street_address" : "HEIDESTRAẞE 17"
            },
            "iss" : "https://demo.pid-issuer.bundesdruckerei.de/c1",
            "place_of_birth" : {
              "_sd" : [ "JngE4dpA6W9xkCA9b206rvm_OH0mCahGQ7Zm_3f_TOY" ],
              "locality" : "BERLIN"
            },
            "_sd" : [ "HsaH_5qEP_U0Q5Zp-_jual3CuNUVEA0q9foYKmXnZu0", "JWTA8llKrGyisvqpPtw1hF4MGZpMPXk7BSbJ6Pv8hjg", "JzQ49By1E-E_ULI2RxWVkkLqx76KmzrZ2WxkPBmNgbE", "LwH2jwvD-zh1K2W8n6JBN7VvsZoH-gzSxIzz_ap5ees", "N4r5AXyaBjDtrWB_GeVvdr-4ZiSjsgYAEBgSMELaAXE", "b3x-HlffUiV8t6jn96u1Rzc546aLiFiwE0Y6xSytVBM", "isvT6E26VViyFxxSk5USB6-KQWqwSWogv0T_0iedh20" ],
            "issuing_country" : "DE",
            "issuing_authority" : "DE",
            "_sd_alg" : "sha-256",
            "cnf" : {
              "jwk" : {
                "kty" : "EC",
                "crv" : "P-256",
                "x" : "Xh2xaKKeldwWQmXlmDW1y5AB18uek6F9o0XvtXNazL4",
                "y" : "_XMYTbNS5sUtIR9sJ9xWNmQILPg5C2P3Yvoy8qBWHo8"
              }
            },
            "exp" : 1746090253,
            "iat" : 1744880653,
            "status" : {
              "status_list" : {
                "uri" : "https://demo.pid-issuer.bundesdruckerei.de/status/6642e557-6f47-4050-90a7-53d5f3418861",
                "idx" : 74
              }
            },
            "age_equal_or_over" : {
              "_sd" : [ "9WxlzroKplTWDPFZlj85H-Iu0auoDXLGdPIaYwvWEJY", "XsGdtdwyQOnCnl06c2SsuP-LTlzPOCMSGmYO7nvMLd8", "df7LdlMMCI6Svcq25dXXV4-ytVckUJddSK0Xv-rbXnk", "dlSX5_dp5QGUNG-arQZbmfNjTqCrwfWOhYizr-L3QEc", "llIq8ZiIm2IlBoL_NAovLPe2RNErinC4bRjnv_vBaBw", "oi1MLmEYHzrQgh267jkXOHlkR7eCteqf33iW7dfCBR0" ],
              "12" : true,
              "14" : true,
              "16" : true,
              "18" : true,
              "21" : true,
              "65" : false
            },
            "family_name" : "MUSTERMANN",
            "given_name" : "ERIKA",
            "birthdate" : "1964-08-12",
            "age_birth_year" : 1964,
            "age_in_years" : 60,
            "birth_family_name" : "GABLER",
            "nationalities" : [ "DE" ]
          },
          "credential_format" : "dc+sd-jwt",
          "document_type" : "https://demo.pid-issuer.bundesdruckerei.de/credentials/pid/1.0",
          "id" : 101,
          "title" : "MUSTERMANN ERIKA",
          "subtitle" : "ID Card"
        }, {
          "paths" : {
            "issuance_date" : "2025-04-04",
            "expiry_date" : "2026-04-14",
            "issuing_authority" : "DE",
            "issuing_country" : "DE",
            "nbf" : 1743724800,
            "exp" : 1776124800,
            "cnf" : {
              "jwk" : {
                "kty" : "EC",
                "crv" : "P-256",
                "x" : "s5Wbbstf7iHpn-4QV1NaMPG9gUkF-83yAaQi32NYPSI",
                "y" : "fiA-44LQXiQH1leEoLDQ68UCRuy3yo1q47uc9Didu84"
              }
            },
            "iss" : "https://funke.animo.id",
            "iat" : 1745245556,
            "_sd" : [ "2DIiazxU3LunjvLYXLIE8OqYVWBj3e0OAKr_BFHuhdk", "ovrVNkKteMYOTo1WHSQaMaNStxf1LMIO_olVhzE-6Lo", "qrfawSMehfWlUs8GH4igBWUE2vQxP-80tDpD1L5megk" ],
            "_sd_alg" : "sha-256",
            "health_insurance_id" : "A123456780101575519DE",
            "affiliation_country" : "DE",
            "wallet_e_prescription_code" : "160.000.033.491.352.56&94c75e15e4c4dd6b50e3c18b92b4754e88fec4ab144e86a1b95df1209767978b&medication name"
          },
          "credential_format" : "dc+sd-jwt",
          "document_type" : "https://example.eudi.ec.europa.eu/hiid/1",
          "id" : 102,
          "title" : "Health-ID",
          "subtitle" : ""
        }, {
          "paths" : {
            "issuance_date" : "2025-04-04",
            "expiry_date" : "2026-04-14",
            "issuing_authority" : "DE",
            "issuing_country" : "DE",
            "nbf" : 1743724800,
            "exp" : 1776124800,
            "cnf" : {
              "jwk" : {
                "kty" : "EC",
                "crv" : "P-256",
                "x" : "bAveMB3_9l4ev2MzVnDZ_bgYR6qm9zH_pOSBNJr85GE",
                "y" : "5N5QcbNgNuvTFdwcKHJgUUZtGxtXpfOQVyV1u1o8fyg"
              }
            },
            "iss" : "https://funke.animo.id",
            "iat" : 1745245556,
            "_sd" : [ "6s1mUlk75N3qxPXOJsQ8iuTDPHcSCIoRjw4CJ7eZ0Vo", "B2wwnvLDEO3n_5uIZRerOF90z8keenMBN-OPyygzJwQ", "LvDxOn4VuVZPJvquL8yY15NpCy4MqpkQw2xPM4u57vY" ],
            "_sd_alg" : "sha-256",
            "health_insurance_id" : "A123456780101575519DE",
            "affiliation_country" : "DE",
            "wallet_e_prescription_code" : "160.000.033.491.352.56&94c75e15e4c4dd6b50e3c18b92b4754e88fec4ab144e86a1b95df1209767978b&medication name"
          },
          "credential_format" : "dc+sd-jwt",
          "document_type" : "https://example.eudi.ec.europa.eu/hiid/1",
          "id" : 103,
          "title" : "Health-ID",
          "subtitle" : ""
        }, {
          "paths" : {
            "issuance_date" : "2025-04-04",
            "expiry_date" : "2026-04-14",
            "issuing_authority" : "DE",
            "issuing_country" : "DE",
            "nbf" : 1743724800,
            "exp" : 1776124800,
            "cnf" : {
              "jwk" : {
                "kty" : "EC",
                "crv" : "P-256",
                "x" : "3jBbDQhvvETFi3Az9Fw0rdCg-fYvbNNrW-fyQrEo2K8",
                "y" : "KQb18Dwr08IR6w-aQORmskz2XAsmpdvISA89vPjlxFA"
              }
            },
            "iss" : "https://funke.animo.id",
            "iat" : 1745245556,
            "_sd" : [ "5Y75M0wkflLwGgtF-d9QfGCQGKKOpQqnA2-C8KzowuE", "6CngagYn9DN3QU243wTs5MopULIWw-w584ge-Hs11BY", "npw7nYyToT_qSEViNxMJoCuF49thzxTmYwBTrGXtS0k" ],
            "_sd_alg" : "sha-256",
            "health_insurance_id" : "A123456780101575519DE",
            "affiliation_country" : "DE",
            "wallet_e_prescription_code" : "160.000.033.491.352.56&94c75e15e4c4dd6b50e3c18b92b4754e88fec4ab144e86a1b95df1209767978b&medication name"
          },
          "credential_format" : "dc+sd-jwt",
          "document_type" : "https://example.eudi.ec.europa.eu/hiid/1",
          "id" : 104,
          "title" : "Health-ID",
          "subtitle" : ""
        }, {
          "paths" : {
            "issuance_date" : "2025-04-04",
            "expiry_date" : "2026-04-14",
            "issuing_authority" : "DE",
            "issuing_country" : "DE",
            "nbf" : 1743724800,
            "exp" : 1776124800,
            "cnf" : {
              "jwk" : {
                "kty" : "EC",
                "crv" : "P-256",
                "x" : "LZVKHzvVFRPO2ybszFmkXGGCj4XxNOKFhvVF6Nir2Yo",
                "y" : "NTl1MpyYXV-O4To_uB9e7p-xVaWLCEvR9vEWQ8GN5cs"
              }
            },
            "iss" : "https://funke.animo.id",
            "iat" : 1745245556,
            "_sd" : [ "3urbGNCPULEHv74lAo63d_hjyPxaymvNo5cM4aJUk34", "6riK6xzDEVHK0f4mClPsR0DIkgpsGu2UFY6Mpy5srV0", "7GwjJpOB6Uu-CXCpW3344_rocDgoIuarB57D1_lGnKw" ],
            "_sd_alg" : "sha-256",
            "health_insurance_id" : "A123456780101575519DE",
            "affiliation_country" : "DE",
            "wallet_e_prescription_code" : "160.000.033.491.352.56&94c75e15e4c4dd6b50e3c18b92b4754e88fec4ab144e86a1b95df1209767978b&medication name"
          },
          "credential_format" : "dc+sd-jwt",
          "document_type" : "https://example.eudi.ec.europa.eu/hiid/1",
          "id" : 105,
          "title" : "Health-ID",
          "subtitle" : ""
        }, {
          "paths" : {
            "issuance_date" : "2025-04-04",
            "expiry_date" : "2026-04-14",
            "issuing_authority" : "DE",
            "issuing_country" : "DE",
            "nbf" : 1743724800,
            "exp" : 1776124800,
            "cnf" : {
              "jwk" : {
                "kty" : "EC",
                "crv" : "P-256",
                "x" : "khZxSYBnVORp0ZNWfc8v6Q03p8m0rACnP7ypuTpNvHw",
                "y" : "Cr60GyCJv9ybyZIzHwKSoq1-Lzmovx9zrr_-nqfKeEE"
              }
            },
            "iss" : "https://funke.animo.id",
            "iat" : 1745245556,
            "_sd" : [ "OzLcx0PiQ80H2NxwPwfzPyfUA-Ay_BU6PXcsVfwt1Fc", "q_LjLY9yC1eEjsgxGrJLUvp_IQJYplrxnn-Uwt1H7tY", "w87gsuombcI6cmjJV-PId03t4zKasgljW3_7fFi2yi8" ],
            "_sd_alg" : "sha-256",
            "health_insurance_id" : "A123456780101575519DE",
            "affiliation_country" : "DE",
            "wallet_e_prescription_code" : "160.000.033.491.352.56&94c75e15e4c4dd6b50e3c18b92b4754e88fec4ab144e86a1b95df1209767978b&medication name"
          },
          "credential_format" : "dc+sd-jwt",
          "document_type" : "https://example.eudi.ec.europa.eu/hiid/1",
          "id" : 106,
          "title" : "Health-ID",
          "subtitle" : ""
        } ]"#;
        let a = UbiqueWalletDatabaseFormat;
        a.parse(&u).unwrap();
    }
}
