//! Preserve sibling source bytes when editing the one API-owned network key.

use std::collections::BTreeMap;

use serde::Deserialize;
use toml::{Spanned, Value};

use crate::api::model::ApiFailure;

#[derive(Deserialize)]
struct Source {
    network: Option<Spanned<BTreeMap<String, Spanned<Value>>>>,
}

pub(in crate::api) fn upsert_dns_overrides(
    source: &str,
    entries: &[String],
) -> Result<String, ApiFailure> {
    let parsed: Source = toml::from_str(source)
        .map_err(|_| ApiFailure::internal("Cannot locate network.dns_overrides in its source"))?;
    let value = Value::Array(entries.iter().cloned().map(Value::String).collect()).to_string();
    let newline = if source.contains("\r\n") {
        "\r\n"
    } else {
        "\n"
    };
    let mut out = source.to_owned();
    match parsed.network {
        Some(network) => {
            if let Some(existing) = network.get_ref().get("dns_overrides") {
                // Parser byte spans cover the value, including multiline arrays,
                // but exclude the key, surrounding comments and sibling fields.
                out.replace_range(existing.span(), &value);
            } else {
                let span = network.span();
                let representation = &source[span.clone()];
                if representation.starts_with('{') {
                    let separator = if network.get_ref().is_empty() {
                        ""
                    } else {
                        ", "
                    };
                    out.insert_str(
                        span.start + 1,
                        &format!("dns_overrides = {value}{separator}"),
                    );
                } else if representation.starts_with('[') {
                    // The table span ends at ']', before any trailing comment.
                    let end = source[span.end..]
                        .find('\n')
                        .map(|offset| span.end + offset + 1);
                    if let Some(end) = end {
                        out.insert_str(end, &format!("dns_overrides = {value}{newline}"));
                    } else {
                        out.push_str(&format!("{newline}dns_overrides = {value}{newline}"));
                    }
                } else {
                    // A dotted network key creates an implicit table at root.
                    // Insert beside that declaration, not inside a later table.
                    let start = source[..span.start]
                        .rfind('\n')
                        .map_or(0, |offset| offset + 1);
                    out.insert_str(start, &format!("network.dns_overrides = {value}{newline}"));
                }
            }
        }
        None => {
            if !out.is_empty() && !out.ends_with('\n') {
                out.push_str(newline);
            }
            out.push_str(&format!(
                "[network]{newline}dns_overrides = {value}{newline}"
            ));
        }
    }
    Ok(out)
}
