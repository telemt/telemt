//! Source inventory complements typed serialization for omitted Options and
//! empty maps. This deliberately supports the repository's declaration style;
//! an unfamiliar field declaration fails instead of silently losing coverage.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use regex::Regex;

struct Field {
    name: String,
    ty: String,
    flattened: bool,
}

fn read_sources(directory: &Path, sources: &mut Vec<String>) {
    for entry in std::fs::read_dir(directory).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            read_sources(&path, sources);
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            sources.push(std::fs::read_to_string(path).unwrap());
        }
    }
}

#[test]
fn declared_fields_including_omitted_options_and_maps_have_metadata() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/config");
    let mut sources = vec![std::fs::read_to_string(root.join("load.rs")).unwrap()];
    read_sources(&root.join("types"), &mut sources);
    let declaration = Regex::new(r"pub(?:\([^)]*\))? struct (\w+)\s*\{").unwrap();
    let field = Regex::new(r"^pub(?:\([^)]*\))? (\w+): (.+),$").unwrap();
    let skipped = Regex::new(r"\bskip\b").unwrap();
    let mut structs = BTreeMap::new();
    for source in &sources {
        for found in declaration.captures_iter(source) {
            let start = found.get(0).unwrap().end();
            let body = source[start..].split_once("\n}").unwrap().0;
            let mut attributes = String::new();
            let mut fields = Vec::new();
            for line in body.lines().map(str::trim) {
                if line.starts_with("#[") || (!attributes.is_empty() && !attributes.ends_with(']'))
                {
                    attributes.push_str(line);
                } else if line.starts_with("pub ") || line.starts_with("pub(") {
                    let entry = field.captures(line).unwrap_or_else(|| {
                        panic!(
                            "extend discovery source inventory for {}: {line}",
                            &found[1]
                        )
                    });
                    if !skipped.is_match(&attributes) {
                        fields.push(Field {
                            name: entry[1].to_string(),
                            ty: entry[2].to_string(),
                            flattened: attributes.contains("flatten"),
                        });
                    }
                    attributes.clear();
                }
            }
            assert!(structs.insert(found[1].to_string(), fields).is_none());
        }
    }
    let catalog: BTreeSet<_> = super::config_schema()
        .unwrap()
        .fields
        .iter()
        .map(|field| field.spec.path.clone())
        .collect();
    let mut declared = BTreeSet::new();
    visit("ProxyConfig", "", &structs, &mut declared);
    // Empty collection defaults cannot reveal a new tagged variant. Check the
    // declarations as well as serializing every currently known variant.
    for (ty, path, tag, snake_case) in [
        ("UpstreamType", "upstreams[]", "type", false),
        ("WebDecoyConfig", "web.vhosts[].decoy", "mode", true),
    ] {
        check_tagged_variants(&sources, ty, path, tag, snake_case, &structs, &mut declared);
    }
    let missing: Vec<_> = declared.difference(&catalog).collect();
    assert!(
        missing.is_empty(),
        "unclassified declared fields: {missing:?}"
    );
    assert!(
        declared.len() > 400,
        "source inventory unexpectedly incomplete"
    );
}

fn check_tagged_variants(
    sources: &[String],
    ty: &str,
    path: &str,
    tag: &str,
    snake_case: bool,
    structs: &BTreeMap<String, Vec<Field>>,
    paths: &mut BTreeSet<String>,
) {
    let marker = format!("pub enum {ty} {{");
    let body = sources
        .iter()
        .find_map(|source| source.split_once(&marker))
        .unwrap()
        .1
        .split_once("\n}")
        .unwrap()
        .0;
    let tag_path = format!("{path}.{tag}");
    paths.insert(tag_path.clone());
    let schema = super::config_schema().unwrap();
    let field = schema
        .fields
        .iter()
        .find(|field| field.spec.path == tag_path)
        .unwrap();
    let variants: BTreeSet<_> = field.spec.value["enum"]
        .as_array()
        .unwrap()
        .iter()
        .map(|value| value.as_str().unwrap().to_owned())
        .collect();
    let variant = Regex::new(r"(?m)^    (\w+)\s*(?:\{|,)").unwrap();
    let boundary = Regex::new(r"([a-z0-9])([A-Z])").unwrap();
    let declared: BTreeSet<_> = variant
        .captures_iter(body)
        .map(|value| {
            if snake_case {
                boundary.replace_all(&value[1], "${1}_${2}").to_lowercase()
            } else {
                value[1].to_lowercase()
            }
        })
        .collect();
    assert_eq!(variants, declared, "unclassified tagged variants in {ty}");
    let field = Regex::new(r"(?m)^        (\w+): (.+),$").unwrap();
    for field in field.captures_iter(body) {
        let path = format!("{path}.{}", &field[1]);
        paths.insert(path.clone());
        visit(&field[2], &path, structs, paths);
    }
}

fn visit(
    ty: &str,
    path: &str,
    structs: &BTreeMap<String, Vec<Field>>,
    paths: &mut BTreeSet<String>,
) {
    if let Some(inner) = ty
        .strip_prefix("Option<")
        .and_then(|ty| ty.strip_suffix('>'))
    {
        visit(inner, path, structs, paths);
    } else if let Some(inner) = ty.strip_prefix("Vec<").and_then(|ty| ty.strip_suffix('>')) {
        visit(inner, &format!("{path}[]"), structs, paths);
    } else if let Some(inner) = ty
        .strip_prefix("HashMap<")
        .and_then(|ty| ty.strip_suffix('>'))
    {
        let (_, value) = inner.split_once(',').unwrap();
        let key = match path {
            "dc_overrides" => "{dc}",
            "censorship.exclusive_mask" => "{hostname}",
            "access.cidr_rate_limits" => "{cidr}",
            _ => "{username}",
        };
        let path = format!("{path}.{key}");
        paths.insert(path.clone());
        visit(value.trim(), &path, structs, paths);
    } else if let Some(fields) = structs.get(ty) {
        for field in fields {
            let next = if field.flattened {
                path.to_string()
            } else if path.is_empty() {
                field.name.clone()
            } else {
                format!("{path}.{}", field.name)
            };
            if !field.flattened {
                paths.insert(next.clone());
            }
            visit(&field.ty, &next, structs, paths);
        }
    }
    // Tagged enum children are exercised through all typed variants by the
    // serialization inventory test; scalar custom deserializers have no children.
}
