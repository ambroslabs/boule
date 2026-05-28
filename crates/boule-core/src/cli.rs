//! CLI-shared helpers — output formatting in particular.
//!
//! Output formatting is a cross-cutting concern: every subcommand that
//! produces a *structured* payload (`config` today, future `status`,
//! `peers list`, `key list`, ...) routes it through this module so
//! operators get one consistent `--format` flag and one global
//! `[ui] output_format` config default to learn rather than a different
//! convention per subcommand.
//!
//! # Contract for new subcommand authors
//!
//! 1. Build the subcommand's output as a value implementing
//!    [`serde::Serialize`].
//! 2. Accept a per-invocation `--format <human|json|toml>` flag, parsed
//!    via [`OutputFormat::parse`]. Treat the absent flag as
//!    `Option::None` (do **not** default to `Human` at parse time —
//!    that would clobber the operator's `[ui] output_format` setting).
//! 3. Resolve the effective format with [`resolve_structured_format`],
//!    passing the parsed CLI override, the loaded
//!    [`crate::config::UiConfig::output_format`], and a per-subcommand
//!    fallback for `human` (which must itself be a structured format —
//!    `Toml` or `Json`). For example, the `config` subcommand uses
//!    `Toml` as its human fallback because that mirrors the source
//!    schema.
//! 4. Render with [`render_structured`] and print the result.
//!
//! Subcommands that produce only free-form output (e.g. `init`'s
//! status messages, `start`'s logs) ignore this module entirely — their
//! output is meant for terminal reading and is not pipeable through
//! `jq` regardless.

use serde::Serialize;

/// One of `human`, `json`, `toml`. The TOML representation is
/// lowercase, matching the value an operator writes in
/// `[ui] output_format = "..."`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OutputFormat {
    /// Free-form text suitable for terminal reading. The default for
    /// `[ui] output_format` and for `--format` when neither is given.
    /// Subcommands with inherently structured payloads pick a sensible
    /// per-subcommand fallback (see [`resolve_structured_format`]);
    /// subcommands with genuine human-readable output use this directly.
    #[default]
    Human,
    /// TOML, mirroring the config file schema. The natural default for
    /// the `config` subcommand's human fallback.
    Toml,
    /// JSON, the natural pipe target for `jq`.
    Json,
}

impl OutputFormat {
    /// Parse the `--format <value>` argument. Lowercased before matching
    /// so `JSON`, `Json`, `json` all work.
    pub fn parse(s: &str) -> anyhow::Result<Self> {
        match s.to_ascii_lowercase().as_str() {
            "human" => Ok(Self::Human),
            "toml" => Ok(Self::Toml),
            "json" => Ok(Self::Json),
            other => anyhow::bail!("unknown output format '{other}' (expected: human, json, toml)"),
        }
    }
}

/// Pick the effective format for a subcommand whose payload is
/// inherently structured (i.e. it has no natural free-form rendering of
/// its own — the canonical example is `config`, where the underlying
/// data is the TOML config file itself).
///
/// Resolution order:
///
/// 1. Per-invocation CLI override (`--format`) wins if given.
/// 2. Otherwise, `[ui] output_format` from the config wins.
/// 3. If the resolved choice is [`OutputFormat::Human`], we fall back
///    to `human_fallback`.
///
/// `human_fallback` must be a structured format (`Toml` or `Json`).
/// Passing `Human` here is a programming error and the caller will
/// fail later in [`render_structured`].
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

/// Serialize `value` in `format`. Errors if `format` is
/// [`OutputFormat::Human`] — structured-payload subcommands must
/// resolve the human fallback first via [`resolve_structured_format`].
///
/// Trailing newline behaviour is left to the caller — the helper
/// mirrors what `toml`/`serde_json` produce, which is "ends with one
/// newline for TOML, no trailing newline for `to_string_pretty` on
/// JSON". Callers typically `print!` the result and emit a newline if
/// the rendered string didn't already end with one.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_accepts_each_variant_case_insensitively() {
        assert_eq!(OutputFormat::parse("human").unwrap(), OutputFormat::Human);
        assert_eq!(OutputFormat::parse("HUMAN").unwrap(), OutputFormat::Human);
        assert_eq!(OutputFormat::parse("Json").unwrap(), OutputFormat::Json);
        assert_eq!(OutputFormat::parse("toml").unwrap(), OutputFormat::Toml);
    }

    #[test]
    fn parse_rejects_unknown() {
        let err = OutputFormat::parse("yaml").unwrap_err().to_string();
        assert!(err.contains("yaml"));
        assert!(err.contains("human"));
        assert!(err.contains("json"));
        assert!(err.contains("toml"));
    }

    #[test]
    fn resolve_prefers_cli_override() {
        let r = resolve_structured_format(
            Some(OutputFormat::Json),
            OutputFormat::Toml,
            OutputFormat::Toml,
        );
        assert_eq!(r, OutputFormat::Json);
    }

    #[test]
    fn resolve_uses_config_default_when_no_cli_override() {
        let r = resolve_structured_format(None, OutputFormat::Json, OutputFormat::Toml);
        assert_eq!(r, OutputFormat::Json);
    }

    #[test]
    fn resolve_falls_back_for_human() {
        // [ui] output_format = "human" (default) → fallback applies.
        let r = resolve_structured_format(None, OutputFormat::Human, OutputFormat::Toml);
        assert_eq!(r, OutputFormat::Toml);

        // Explicit `--format human` also falls back.
        let r = resolve_structured_format(
            Some(OutputFormat::Human),
            OutputFormat::Json,
            OutputFormat::Json,
        );
        assert_eq!(r, OutputFormat::Json);
    }

    #[test]
    fn render_structured_human_is_an_error() {
        let v = serde_json::json!({"a": 1});
        let err = render_structured(&v, OutputFormat::Human).unwrap_err();
        assert!(err.to_string().contains("Human"));
    }

    #[test]
    fn render_structured_toml_and_json_round_trip() {
        #[derive(serde::Serialize, serde::Deserialize, PartialEq, Debug)]
        struct V {
            x: u32,
            y: String,
        }
        let v = V {
            x: 7,
            y: "hi".into(),
        };

        let toml_text = render_structured(&v, OutputFormat::Toml).unwrap();
        let back: V = toml::from_str(&toml_text).unwrap();
        assert_eq!(back, v);

        let json_text = render_structured(&v, OutputFormat::Json).unwrap();
        let back: V = serde_json::from_str(&json_text).unwrap();
        assert_eq!(back, v);
    }

    #[test]
    fn output_format_serializes_lowercase_in_toml() {
        // Round-trip via TOML to confirm `[ui] output_format = "json"`
        // is the on-disk representation operators write.
        #[derive(serde::Serialize, serde::Deserialize)]
        struct Wrap {
            f: OutputFormat,
        }
        let s = toml::to_string(&Wrap {
            f: OutputFormat::Json,
        })
        .unwrap();
        assert!(s.contains("f = \"json\""), "got: {s}");
        let back: Wrap = toml::from_str("f = \"human\"\n").unwrap();
        assert_eq!(back.f, OutputFormat::Human);
    }
}
