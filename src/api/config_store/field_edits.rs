//! Structural edits to allowlisted scalar fields and literal map keys.

use super::*;
use toml_edit::{DocumentMut, Item, Table};

pub(in crate::api) struct FieldEdit {
    pub path: Vec<String>,
    pub value: Option<toml::Value>,
}

impl FieldEdit {
    pub fn new(path: &[&str], value: Option<toml::Value>) -> Self {
        Self {
            path: path.iter().map(|part| (*part).to_owned()).collect(),
            value,
        }
    }
}

pub(in crate::api) struct OwnedSourceEdit {
    pub owner_path: PathBuf,
    pub expected_owner_contents: String,
    pub owner_contents: String,
}

fn conflict() -> ApiFailure {
    ApiFailure::new(
        hyper::StatusCode::CONFLICT,
        "config_patch_not_atomic",
        "Mutation requires one independently writable config source",
    )
}

fn at_path<'a>(document: &'a DocumentMut, path: &[String]) -> Option<&'a Item> {
    path.iter()
        .try_fold(document.as_item(), |item, key| item.get(key))
}

fn edit(item: &mut Item, path: &[String], value: Option<&toml::Value>) -> Result<(), ApiFailure> {
    let Some((key, rest)) = path.split_first() else {
        return Err(ApiFailure::internal("Empty configuration edit path"));
    };
    let table = item.as_table_like_mut().ok_or_else(conflict)?;
    if rest.is_empty() {
        if let Some(value) = value {
            let mut value = value
                .to_string()
                .parse::<toml_edit::Value>()
                .map_err(|_| ApiFailure::internal("Cannot render configuration value"))?;
            if let Some(old) = table.get(key).and_then(Item::as_value) {
                *value.decor_mut() = old.decor().clone();
            }
            table.insert(key, Item::Value(value));
        } else {
            table.remove(key);
        }
    } else {
        if !table.contains_key(key) {
            if value.is_none() {
                return Ok(());
            }
            table.insert(key, Item::Table(Table::new()));
        }
        edit(table.get_mut(key).ok_or_else(conflict)?, rest, value)?;
    }
    Ok(())
}

/// Exact leaf ownership wins; insertion uses the nearest existing parent.
/// Literal map keys are separate path components, including dots and CIDRs.
pub(in crate::api) fn prepare_field_edits(
    loaded: &ParsedConfigSource,
    config_path: &Path,
    edits: &[FieldEdit],
) -> Result<Option<OwnedSourceEdit>, ApiFailure> {
    if edits.is_empty() {
        return Ok(None);
    }
    if loaded
        .source_contents
        .values()
        .any(|source| has_include_inside_table(source))
    {
        return Err(conflict());
    }
    let mut sources = loaded
        .source_contents
        .iter()
        .map(|(path, source)| {
            source
                .parse::<DocumentMut>()
                .map(|document| (path.clone(), document))
                .map_err(|_| conflict())
        })
        .collect::<Result<BTreeMap<_, _>, _>>()?;
    let mut owners = BTreeSet::new();
    let mut effective = Vec::new();
    for change in edits {
        if change.path.is_empty() {
            return Err(ApiFailure::internal("Empty configuration edit path"));
        }
        let mut found = BTreeSet::new();
        for length in (1..=change.path.len()).rev() {
            found = sources
                .iter()
                .filter(|(_, document)| at_path(document, &change.path[..length]).is_some())
                .map(|(path, _)| path.clone())
                .collect();
            if !found.is_empty() {
                break;
            }
            // Removing an absent field is a no-op, not an insertion into a parent.
            if change.value.is_none() {
                break;
            }
        }
        if found.len() > 1 {
            return Err(conflict());
        }
        if found.is_empty() && change.value.is_none() {
            continue;
        }
        owners.insert(
            found
                .into_iter()
                .next()
                .unwrap_or_else(|| normalize_source_path(config_path)),
        );
        effective.push(change);
    }
    if effective.is_empty() {
        return Ok(None);
    }
    if owners.len() != 1 {
        return Err(conflict());
    }
    let owner_path = owners.into_iter().next().ok_or_else(conflict)?;
    let document = sources.get_mut(&owner_path).ok_or_else(conflict)?;
    for change in effective {
        edit(document.as_item_mut(), &change.path, change.value.as_ref())?;
    }
    let expected_owner_contents = loaded
        .source_contents
        .get(&owner_path)
        .ok_or_else(conflict)?
        .clone();
    Ok(Some(OwnedSourceEdit {
        owner_path,
        expected_owner_contents,
        owner_contents: document.to_string(),
    }))
}
