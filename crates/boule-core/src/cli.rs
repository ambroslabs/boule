use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OutputFormat {
    #[default]
    Human,

    Toml,

    Json,
}

impl OutputFormat {
    pub fn parse(s: &str) -> anyhow::Result<Self> {
        match s.to_ascii_lowercase().as_str() {
            "human" => Ok(Self::Human),
            "toml" => Ok(Self::Toml),
            "json" => Ok(Self::Json),
            other => anyhow::bail!("unknown output format '{other}' (expected: human, json, toml)"),
        }
    }
}

pub fn resolve_structured_format(
    cli_override: Option<OutputFormat>,
    config_default: OutputFormat,
    human_fallback: OutputFormat,
) -> OutputFormat {
    let chosen = cli_override.unwrap_or(config_default);
    match chosen {
        OutputFormat::Human => human_fallback,
        f => f,
    }
}

pub fn render_structured<T: Serialize>(value: &T, format: OutputFormat) -> anyhow::Result<String> {
    match format {
        OutputFormat::Toml => {
            toml::to_string_pretty(value).map_err(|e| anyhow::anyhow!("serializing as TOML: {e}"))
        }
        OutputFormat::Json => serde_json::to_string_pretty(value)
            .map_err(|e| anyhow::anyhow!("serializing as JSON: {e}")),
        OutputFormat::Human => anyhow::bail!(
            "render_structured received OutputFormat::Human; \
             callers must resolve the human fallback first via \
             resolve_structured_format"
        ),
    }
}
