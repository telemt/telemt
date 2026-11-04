use super::*;

/// Completes legacy synchronous loads without performing hostname resolution.
#[cfg(test)]
pub(super) fn load_source_graph(graph: ConfigSourceGraph) -> Result<LoadedConfig> {
    finish(parse_source_graph(graph)?)
}

/// Normalizes source while leaving DNS and immutable site acquisition to preparation.
pub(super) fn parse_source_graph(graph: ConfigSourceGraph) -> Result<ParsedConfigSource> {
    let (mut config, source_files, source_contents, processed) =
        decode::decode_source_graph(graph)?;
    validate_core::validate(&mut config)?;
    validate_runtime::validate(&mut config)?;
    validate_me::validate(&mut config)?;
    validate_server::validate(&mut config)?;
    validate_web::validate_source(&mut config)?;
    effective::apply(&mut config)?;
    Ok(ParsedConfigSource {
        config,
        source_files: source_files.into_iter().collect(),
        source_contents,
        rendered_hash: hash_rendered_snapshot(&processed),
    })
}

/// Completes synchronous validation and static acquisition after DNS is captured.
pub(super) fn finish(mut parsed: ParsedConfigSource) -> Result<LoadedConfig> {
    parsed.config.validate_effective_web()?;
    parsed.config.rebuild_runtime_web()?;
    Ok(LoadedConfig {
        config: parsed.config,
        source_files: parsed.source_files,
        source_contents: parsed.source_contents,
        rendered_hash: parsed.rendered_hash,
    })
}

impl ParsedConfigSource {
    /// Resolves each unique decoy origin once, then builds a fully validated candidate.
    pub(crate) async fn prepare(mut self) -> Result<LoadedConfig> {
        decoy_dns::prepare(&mut self.config, |host, port| async move {
            tokio::net::lookup_host((host.as_str(), port))
                .await
                .map(|answers| answers.collect())
        })
        .await?;
        tokio::task::spawn_blocking(move || finish(self))
            .await
            .map_err(|error| ProxyError::Config(format!("config preparation failed: {error}")))?
    }
}
