//! Per-file content handlers: pure transforms over bytes, kept separate from the
//! FUSE / mount plumbing so the security-critical parts are cheap to test.
//!
//! Read side: `original contents -> redacted contents`.
//! Write side: `(original, edited-redacted-buffer) -> new original` (a merge).
//!
//! A handler is selected by either trigger:
//! - **by filename** — e.g. `.env`;
//! - **by content sniffing** — leading bytes matching a known signature, e.g. a
//!   private-key header.
//!
//! **Fail closed.** When a handler cannot redact/merge safely (malformed input)
//! it returns an error; the caller must surface that as a failure (`read`/write
//! error) and, on write, leave the original untouched. The only acceptable
//! outcomes are "redacted"/"persisted" or "error" — never "raw" and never a
//! corrupted original.

use std::collections::HashMap;
use std::ffi::OsStr;
use std::fmt;
use std::io::Cursor;

/// A handler could not produce redacted/merged output. The caller fails closed.
#[derive(Debug)]
pub struct RedactError(pub String);

impl fmt::Display for RedactError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Which handler matched, for dispatch (read/write behaviour) and logging.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum HandlerKind {
    /// `.env`: redact values on read, merge edits back on write.
    Env,
    /// Private key: redact the body on read; read-only.
    PrivateKey,
}

/// Private-key header lines we recognise by content sniffing. A file whose first
/// line is exactly one of these is treated as a secret regardless of filename.
const KEY_HEADERS: &[&str] = &[
    "-----BEGIN OPENSSH PRIVATE KEY-----",
    "-----BEGIN RSA PRIVATE KEY-----",
    "-----BEGIN PRIVATE KEY-----",
    "-----BEGIN EC PRIVATE KEY-----",
    "-----BEGIN PGP PRIVATE KEY BLOCK-----",
];

/// The placeholder substituted for every redacted secret value. In `.env` output
/// it is quoted; the literal value (what a parser yields back) is this string.
pub const PLACEHOLDER: &str = "<redacted value>";

/// Whether a filename denotes a dotenv file: `.env` itself or any
/// `.env.<suffix>` variant (e.g. `.env.local`, `.env.production`). Does not
/// match unrelated names like `.envrc`.
pub fn is_env_file(file_name: &OsStr) -> bool {
    match file_name.to_str() {
        Some(name) => name == ".env" || name.starts_with(".env."),
        None => false,
    }
}

/// Decide which handler applies, cheaply, without reading the whole file: by
/// filename, or by sniffing the leading bytes for a private-key header (`prefix`
/// only needs to contain the first line). Returns `None` for ordinary files.
pub fn detect(file_name: &OsStr, prefix: &[u8]) -> Option<HandlerKind> {
    if is_env_file(file_name) {
        return Some(HandlerKind::Env);
    }
    let first_line = prefix.split(|&b| b == b'\n').next().unwrap_or(prefix);
    let line = String::from_utf8_lossy(first_line);
    if KEY_HEADERS.contains(&line.trim_end()) {
        return Some(HandlerKind::PrivateKey);
    }
    None
}

/// Parse `.env` bytes into ordered key/value pairs, failing closed on any
/// malformed line. Parses the contents we hold (never touching the environment
/// or locating a file on disk).
fn parse_env(bytes: &[u8]) -> Result<Vec<(String, String)>, RedactError> {
    let mut pairs = Vec::new();
    for item in dotenvy::from_read_iter(Cursor::new(bytes)) {
        pairs.push(item.map_err(|e| RedactError(format!("parse error: {e}")))?);
    }
    Ok(pairs)
}

/// Format a value for an `.env` line, quoting when needed so the line round-trips.
fn format_value(v: &str) -> String {
    if v.is_empty() || v.contains(|c: char| c.is_whitespace() || matches!(c, '#' | '"' | '\'')) {
        let escaped = v.replace('\\', "\\\\").replace('"', "\\\"");
        format!("\"{escaped}\"")
    } else {
        v.to_string()
    }
}

/// Redact every value in a `.env` file, producing one `KEY="<redacted value>"`
/// line per entry (quoted so the embedded space is unambiguous). Comments, blank
/// lines, and formatting are not preserved. Fails closed on malformed input.
pub fn redact_env(original: &[u8]) -> Result<Vec<u8>, RedactError> {
    let mut out = String::new();
    for (key, _value) in parse_env(original)? {
        out.push_str(&key);
        out.push_str("=\"");
        out.push_str(PLACEHOLDER);
        out.push_str("\"\n");
    }
    Ok(out.into_bytes())
}

/// Merge the child's edited (redacted) buffer back onto the original `.env`.
///
/// The child sees the redacted view, so we diff its written buffer against it:
/// - value still the placeholder → keep the original secret value;
/// - value changed → persist it verbatim;
/// - key absent from the original → append (added);
/// - key present in the original but absent from the buffer → drop (deleted).
///
/// Fails closed: if either side is malformed, returns an error and the caller
/// must leave the original file unmodified.
pub fn merge_env(original: &[u8], written: &[u8]) -> Result<Vec<u8>, RedactError> {
    let original_pairs = parse_env(original)?;
    let written_pairs = parse_env(written)?;
    let original_map: HashMap<&str, &str> = original_pairs
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();

    let mut out = String::new();
    for (key, value) in &written_pairs {
        // Placeholder means "no change": restore the original secret if we have
        // one; otherwise it's an added key whose literal value is the placeholder.
        let resolved = if value == PLACEHOLDER {
            original_map.get(key.as_str()).copied().unwrap_or(value)
        } else {
            value
        };
        out.push_str(key);
        out.push('=');
        out.push_str(&format_value(resolved));
        out.push('\n');
    }
    Ok(out.into_bytes())
}

/// If `original` begins with a recognised private-key header, redact it: keep
/// the begin/end marker lines verbatim (so the key *type* stays visible) and
/// collapse everything between them to a single `<redacted value>` line.
/// Returns `None` for anything that isn't a private key, leaving it untouched.
pub fn redact_private_key(original: &[u8]) -> Option<Vec<u8>> {
    let text = std::str::from_utf8(original).ok()?;
    let begin = text.lines().next()?;
    if !KEY_HEADERS.contains(&begin) {
        return None;
    }
    let end = text
        .lines()
        .find(|l| l.starts_with("-----END") && l.ends_with("-----"))
        .map(str::to_owned)
        .unwrap_or_else(|| begin.replacen("BEGIN", "END", 1));

    Some(format!("{begin}\n{PLACEHOLDER}\n{end}\n").into_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn env_redacts_values_keeps_keys_quoted() {
        let input = b"# a comment\nAPI_KEY=secret123\n\nDB_URL=postgres://u:p@host/db\n";
        let out = String::from_utf8(redact_env(input).unwrap()).unwrap();
        assert_eq!(
            out,
            "API_KEY=\"<redacted value>\"\nDB_URL=\"<redacted value>\"\n"
        );
    }

    #[test]
    fn env_empty_input_yields_empty_output() {
        assert!(redact_env(b"").unwrap().is_empty());
    }

    #[test]
    fn env_fails_closed_on_malformed_input() {
        let bad = b"not a valid env line\n";
        assert!(redact_env(bad).is_err());
        // `.env` is still detected (by name); redaction is what fails closed.
        assert_eq!(detect(OsStr::new(".env"), bad), Some(HandlerKind::Env));
    }

    // --- write / merge ---

    #[test]
    fn merge_keeps_placeholder_values() {
        let original = b"API_KEY=secret123\nDB=top\n";
        let written = b"API_KEY=\"<redacted value>\"\nDB=\"<redacted value>\"\n";
        let out = String::from_utf8(merge_env(original, written).unwrap()).unwrap();
        // Untouched values: originals preserved.
        assert_eq!(out, "API_KEY=secret123\nDB=top\n");
    }

    #[test]
    fn merge_persists_edited_value() {
        let original = b"API_KEY=secret123\n";
        let written = b"API_KEY=brandnew\n";
        let out = String::from_utf8(merge_env(original, written).unwrap()).unwrap();
        assert_eq!(out, "API_KEY=brandnew\n");
    }

    #[test]
    fn merge_appends_added_key() {
        let original = b"API_KEY=secret123\n";
        let written = b"API_KEY=\"<redacted value>\"\nNEW_KEY=added\n";
        let out = String::from_utf8(merge_env(original, written).unwrap()).unwrap();
        assert_eq!(out, "API_KEY=secret123\nNEW_KEY=added\n");
    }

    #[test]
    fn merge_deletes_removed_key() {
        let original = b"API_KEY=secret123\nDROP_ME=gone\n";
        let written = b"API_KEY=\"<redacted value>\"\n";
        let out = String::from_utf8(merge_env(original, written).unwrap()).unwrap();
        // DROP_ME absent from the written buffer → deleted from the original.
        assert_eq!(out, "API_KEY=secret123\n");
    }

    #[test]
    fn merge_fails_closed_on_malformed_buffer() {
        let original = b"API_KEY=secret123\n";
        // Malformed written buffer → error; caller must leave original alone.
        assert!(merge_env(original, b"this is not valid\n").is_err());
        // Malformed original also errors (never serve/keep raw on a bad parse).
        assert!(merge_env(b"bad original line\n", b"API_KEY=x\n").is_err());
    }

    // --- private key ---

    fn sample_key(begin: &str, end: &str) -> Vec<u8> {
        format!("{begin}\nAAAAB3NzaC1yc2EAAAADAQAB\nQUJDREVGRw==\n{end}\n").into_bytes()
    }

    #[test]
    fn private_key_redacted_for_each_format() {
        let cases = [
            (
                "-----BEGIN OPENSSH PRIVATE KEY-----",
                "-----END OPENSSH PRIVATE KEY-----",
            ),
            (
                "-----BEGIN RSA PRIVATE KEY-----",
                "-----END RSA PRIVATE KEY-----",
            ),
            ("-----BEGIN EC PRIVATE KEY-----", "-----END EC PRIVATE KEY-----"),
            (
                "-----BEGIN PGP PRIVATE KEY BLOCK-----",
                "-----END PGP PRIVATE KEY BLOCK-----",
            ),
        ];
        for (begin, end) in cases {
            let out = redact_private_key(&sample_key(begin, end))
                .unwrap_or_else(|| panic!("detection should fire for {begin}"));
            let out = String::from_utf8(out).unwrap();
            assert_eq!(out, format!("{begin}\n<redacted value>\n{end}\n"));
        }
    }

    #[test]
    fn private_key_synthesizes_end_marker_if_missing() {
        let out = redact_private_key(b"-----BEGIN RSA PRIVATE KEY-----\ndeadbeef\n").unwrap();
        assert_eq!(
            String::from_utf8(out).unwrap(),
            "-----BEGIN RSA PRIVATE KEY-----\n<redacted value>\n-----END RSA PRIVATE KEY-----\n"
        );
    }

    #[test]
    fn non_key_content_is_untouched() {
        assert!(redact_private_key(b"hello world\nnot a key\n").is_none());
        assert!(redact_private_key(b"prefix -----BEGIN RSA PRIVATE KEY-----\n").is_none());
    }

    #[test]
    fn selection_by_filename_and_by_content() {
        // `.env` matches by name regardless of content.
        assert_eq!(detect(OsStr::new(".env"), b"K=v\n"), Some(HandlerKind::Env));
        // `.env.<suffix>` variants match by name too.
        assert_eq!(
            detect(OsStr::new(".env.local"), b"K=v\n"),
            Some(HandlerKind::Env)
        );
        assert_eq!(
            detect(OsStr::new(".env.production"), b"K=v\n"),
            Some(HandlerKind::Env)
        );
        // A private key matches by content, regardless of filename.
        let key = b"-----BEGIN OPENSSH PRIVATE KEY-----\nx\n-----END OPENSSH PRIVATE KEY-----\n";
        assert_eq!(
            detect(OsStr::new("id_ed25519"), key),
            Some(HandlerKind::PrivateKey)
        );
        // Ordinary files are passthrough.
        assert_eq!(detect(OsStr::new("notes.txt"), b"just text\n"), None);
    }

    #[test]
    fn env_file_name_matching() {
        assert!(is_env_file(OsStr::new(".env")));
        assert!(is_env_file(OsStr::new(".env.local")));
        assert!(is_env_file(OsStr::new(".env.production")));
        // Unrelated dotfiles are not env files.
        assert!(!is_env_file(OsStr::new(".envrc")));
        assert!(!is_env_file(OsStr::new(".environment")));
        assert!(!is_env_file(OsStr::new("env")));
        assert!(!is_env_file(OsStr::new("notes.txt")));
    }
}
