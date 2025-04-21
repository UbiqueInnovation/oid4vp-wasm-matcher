use std::fmt::{Display, Formatter};

use serde_json::Value;

use super::models::{Pointer, PointerPart};

#[derive(Debug)]
pub enum QueryError {
    InvalidType,
    InvalidIndex,
    NoElementsFound,
}
impl Display for QueryError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str("{self:?}")
    }
}
pub trait Selector: Send + Sync {
    fn select(&self, v: Value) -> Result<Vec<Value>, QueryError>;
    fn resolve_ptr(&self, v: Value) -> Result<Vec<Pointer>, QueryError>;
}

impl Selector for Pointer {
    fn select(&self, v: Value) -> Result<Vec<Value>, QueryError> {
        let s = selector(self);
        s(&v)
    }

    fn resolve_ptr(&self, v: Value) -> Result<Vec<Pointer>, QueryError> {
        let mut current_pointers = vec![vec![]];
        let mut the_pointer = vec![];
        for p in self {
            match p {
                PointerPart::Null(_) => {
                    let element = the_pointer.select(v.clone())?;
                    if element.len() > 1 || element.is_empty() {
                        return Ok(vec![]);
                    }
                    if !element[0].is_array() {
                        return Ok(vec![]);
                    }
                    let element_size = element[0].as_array().unwrap_or(&Vec::new()).len();
                    let mut new_pointers = vec![];
                    for ptrs in &current_pointers {
                        for i in 0..element_size {
                            let mut p = ptrs.clone();
                            p.push(PointerPart::Index(i as u64));
                            new_pointers.push(p)
                        }
                    }
                    current_pointers = new_pointers;
                }
                _ => {
                    for ptr in &mut current_pointers {
                        ptr.push(p.clone())
                    }
                }
            }
            the_pointer.push(p.clone());
            let _ = the_pointer.select(v.clone())?;
        }
        Ok(current_pointers)
    }
}

pub fn selector(path: &Pointer) -> impl Fn(&Value) -> Result<Vec<Value>, QueryError> + '_ {
    move |input| {
        let mut currently_selected = vec![input.clone()];
        for part in path {
            match part {
                PointerPart::String(key) if currently_selected.iter().all(|a| a.is_object()) => {
                    currently_selected = currently_selected
                        .iter()
                        .flat_map(|a| a.get(key))
                        .cloned()
                        .collect()
                }
                PointerPart::Index(i) if currently_selected.iter().all(|a| a.is_array()) => {
                    currently_selected = currently_selected
                        .iter()
                        .flat_map(|a| a.get(*i as usize))
                        .cloned()
                        .collect()
                }
                PointerPart::Null(_) if currently_selected.iter().all(|a| a.is_array()) => {
                    currently_selected = currently_selected
                        .iter()
                        .filter_map(|a| a.as_array())
                        .flatten()
                        .cloned()
                        .collect()
                }
                _ => return Err(QueryError::InvalidType),
            }
            if currently_selected.is_empty() {
                return Err(QueryError::NoElementsFound);
            }
        }
        Ok(currently_selected)
    }
}

#[macro_export]
macro_rules! pointer {
    ($($e:expr),+) => {
        vec![$(
            $crate::models::PointerPart::from($e),
        )*
        ]
    };
}
