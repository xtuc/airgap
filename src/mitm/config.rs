//! The MitM header-rewrite config: a YAML rule set matched against the request
//! `Host` header. Kept separate from the netstack/proxy plumbing.

use std::collections::BTreeMap;
use std::path::Path;

use anyhow::{Context, Result};
use serde::Deserialize;

/// The YAML config: a list of rules. A request whose `Host` matches a rule's
/// domains gets that rule's headers overridden/added (existing ones preserved).
#[derive(Debug, Deserialize)]
pub(super) struct Config {
    #[serde(default)]
    rules: Vec<Rule>,
}

#[derive(Debug, Deserialize)]
pub(super) struct Rule {
    /// The HTTP `Host` to match, exactly (case-insensitive). Subdomains do not
    /// match: `example.com` matches only `example.com`, not `api.example.com`.
    host: String,
    /// Header name -> value to set (override if present, add if not).
    #[serde(default)]
    pub(super) headers: BTreeMap<String, String>,
}

impl Config {
    /// Load the config from `path`. There is no default location and no
    /// fallback: the caller passed this path explicitly, so a missing or
    /// malformed file is an error rather than a silent "no rules".
    pub(super) fn load(path: &Path) -> Result<Config> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("reading MitM config {}", path.display()))?;
        serde_yaml_ng::from_str(&text)
            .with_context(|| format!("parsing MitM config {}", path.display()))
    }

    /// How many rules were loaded (for logging).
    pub(super) fn len(&self) -> usize {
        self.rules.len()
    }

    /// First rule matching `host` (expected already lowercased, no port).
    pub(super) fn matching(&self, host: &str) -> Option<&Rule> {
        self.rules.iter().find(|r| host_matches(&r.host, host))
    }
}

/// True if request `host` matches the rule's `pattern` exactly (case-insensitive;
/// `host` is expected already lowercased and port-stripped). Subdomains do not
/// match — the Host header must equal the configured host.
fn host_matches(pattern: &str, host: &str) -> bool {
    let pattern = pattern.trim().trim_matches('.').to_ascii_lowercase();
    !pattern.is_empty() && host == pattern
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_matches_exactly() {
        assert!(host_matches("example.com", "example.com"));
        assert!(host_matches("Example.COM", "example.com")); // case-insensitive
        assert!(host_matches(".example.com.", "example.com")); // stray dots tolerated
    }

    #[test]
    fn host_does_not_match_subdomains_or_unrelated() {
        assert!(!host_matches("example.com", "api.example.com")); // subdomains excluded
        assert!(!host_matches("example.com", "a.b.example.com"));
        assert!(!host_matches("example.com", "example.org"));
        assert!(!host_matches("example.com", "notexample.com"));
        assert!(!host_matches("example.com", "example.com.evil.com"));
        assert!(!host_matches("", "example.com"));
    }
}
