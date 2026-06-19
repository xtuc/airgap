//! Secret redaction: the per-file content handlers, pure transforms over bytes,
//! kept separate from the FUSE / mount plumbing so the security-critical parts
//! are cheap to test.
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
    /// `.npmrc`: redact auth-token/password values on read, merge edits back on
    /// write. Non-secret config (registries, scopes, comments) stays visible.
    Npmrc,
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

/// Whether a filename denotes an npm config file. npm reads project-local and
/// home (`~/.npmrc`) config from a file named exactly `.npmrc`.
pub fn is_npmrc_file(file_name: &OsStr) -> bool {
    file_name.to_str() == Some(".npmrc")
}

/// Decide which handler applies, cheaply, without reading the whole file: by
/// filename, or by sniffing the leading bytes for a private-key header (`prefix`
/// only needs to contain the first line). Returns `None` for ordinary files.
pub fn detect(file_name: &OsStr, prefix: &[u8]) -> Option<HandlerKind> {
    if is_env_file(file_name) {
        return Some(HandlerKind::Env);
    }
    if is_npmrc_file(file_name) {
        return Some(HandlerKind::Npmrc);
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

/// Redact a mergeable text secret for the read view, dispatching on `kind`.
/// Only the mergeable text kinds (`Env`, `Npmrc`) are valid here; private keys
/// use [`redact_private_key`]. Fails closed on an unexpected kind.
pub fn redact(kind: HandlerKind, original: &[u8]) -> Result<Vec<u8>, RedactError> {
    match kind {
        HandlerKind::Env => redact_env(original),
        HandlerKind::Npmrc => redact_npmrc(original),
        HandlerKind::PrivateKey => Err(RedactError("private keys are not mergeable".into())),
    }
}

/// Merge a child's edited (redacted) buffer back onto the original, dispatching
/// on `kind`. Counterpart to [`redact`]; fails closed on an unexpected kind.
pub fn merge(kind: HandlerKind, original: &[u8], written: &[u8]) -> Result<Vec<u8>, RedactError> {
    match kind {
        HandlerKind::Env => merge_env(original, written),
        HandlerKind::Npmrc => merge_npmrc(original, written),
        HandlerKind::PrivateKey => Err(RedactError("private keys are not mergeable".into())),
    }
}

/// Whether an npmrc line is a comment (`#` or `;`, ini-style), ignoring leading
/// whitespace. Comments are never treated as `key=value` pairs.
fn is_npmrc_comment(line: &str) -> bool {
    let t = line.trim_start();
    t.starts_with('#') || t.starts_with(';')
}

/// Whether an npmrc key (the text before the first `=`) names a credential.
/// Matches npm's secret config keys — `_authToken`, `_auth`, `_password` — in
/// both the legacy bare form and the per-registry form
/// (`//registry.example.com/:_authToken`). Case-insensitive.
fn is_npmrc_secret_key(key: &str) -> bool {
    let k = key.trim().to_ascii_lowercase();
    k.ends_with("_authtoken") || k.ends_with("_auth") || k.ends_with("_password")
}

/// Redact credential values in an `.npmrc`: every `key=value` line whose key is
/// a token/password (see [`is_npmrc_secret_key`]) has its value replaced with
/// the placeholder. Everything else — registries, scopes, `email`, comments,
/// blank lines, and exact formatting — is preserved verbatim so the file still
/// works for an agent reading it. Fails closed if the bytes are not UTF-8.
pub fn redact_npmrc(original: &[u8]) -> Result<Vec<u8>, RedactError> {
    let text = std::str::from_utf8(original)
        .map_err(|e| RedactError(format!("npmrc not utf-8: {e}")))?;
    let mut out = String::with_capacity(text.len());
    for (i, line) in text.split('\n').enumerate() {
        if i > 0 {
            out.push('\n');
        }
        match line.split_once('=') {
            Some((key, _value)) if !is_npmrc_comment(line) && is_npmrc_secret_key(key) => {
                out.push_str(key);
                out.push('=');
                out.push_str(PLACEHOLDER);
            }
            _ => out.push_str(line),
        }
    }
    Ok(out.into_bytes())
}

/// Merge the child's edited (redacted) `.npmrc` buffer back onto the original,
/// line by line:
/// - a secret line still holding the placeholder → restore the original value;
/// - a secret line with a changed value → persist it verbatim;
/// - any other line (registries, comments, …) → take the child's version,
///   so non-secret edits, additions, and deletions persist normally.
///
/// Fails closed if either side is not UTF-8.
pub fn merge_npmrc(original: &[u8], written: &[u8]) -> Result<Vec<u8>, RedactError> {
    let orig = std::str::from_utf8(original)
        .map_err(|e| RedactError(format!("npmrc not utf-8: {e}")))?;
    let writ = std::str::from_utf8(written)
        .map_err(|e| RedactError(format!("npmrc not utf-8: {e}")))?;

    // Map each original secret key (normalised) to its raw value, for restore.
    let mut secrets: HashMap<String, &str> = HashMap::new();
    for line in orig.split('\n') {
        if is_npmrc_comment(line) {
            continue;
        }
        if let Some((key, value)) = line.split_once('=') {
            if is_npmrc_secret_key(key) {
                secrets.insert(key.trim().to_ascii_lowercase(), value);
            }
        }
    }

    let mut out = String::with_capacity(writ.len());
    for (i, line) in writ.split('\n').enumerate() {
        if i > 0 {
            out.push('\n');
        }
        if is_npmrc_comment(line) {
            out.push_str(line);
            continue;
        }
        match line.split_once('=') {
            Some((key, value)) if is_npmrc_secret_key(key) => {
                // Placeholder means "unchanged": restore the original secret if
                // we have one; otherwise keep what the child wrote verbatim.
                if value == PLACEHOLDER {
                    if let Some(orig_value) = secrets.get(&key.trim().to_ascii_lowercase()) {
                        out.push_str(key);
                        out.push('=');
                        out.push_str(orig_value);
                        continue;
                    }
                }
                out.push_str(line);
            }
            _ => out.push_str(line),
        }
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
        // `.npmrc` matches by name regardless of content.
        assert_eq!(
            detect(OsStr::new(".npmrc"), b"registry=x\n"),
            Some(HandlerKind::Npmrc)
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

    // --- npmrc ---

    #[test]
    fn npmrc_file_name_matching() {
        assert!(is_npmrc_file(OsStr::new(".npmrc")));
        // Only the exact name; not suffixed or unrelated variants.
        assert!(!is_npmrc_file(OsStr::new("npmrc")));
        assert!(!is_npmrc_file(OsStr::new(".npmrc.bak")));
        assert!(!is_npmrc_file(OsStr::new(".yarnrc")));
    }

    #[test]
    fn npmrc_redacts_tokens_keeps_config_and_comments() {
        let input = b"; project config\n\
            registry=https://registry.npmjs.org/\n\
            //registry.npmjs.org/:_authToken=npm_aBcD1234\n\
            @myscope:registry=https://npm.pkg.github.com/\n\
            //npm.pkg.github.com/:_authToken=ghp_secrettoken\n\
            //registry.npmjs.org/:_password=aHVudGVyMg==\n\
            _auth=dXNlcjpwYXNz\n\
            email=me@example.com\n";
        let out = String::from_utf8(redact_npmrc(input).unwrap()).unwrap();
        assert_eq!(
            out,
            "; project config\n\
             registry=https://registry.npmjs.org/\n\
             //registry.npmjs.org/:_authToken=<redacted value>\n\
             @myscope:registry=https://npm.pkg.github.com/\n\
             //npm.pkg.github.com/:_authToken=<redacted value>\n\
             //registry.npmjs.org/:_password=<redacted value>\n\
             _auth=<redacted value>\n\
             email=me@example.com\n"
        );
    }

    #[test]
    fn npmrc_empty_input_yields_empty_output() {
        assert!(redact_npmrc(b"").unwrap().is_empty());
    }

    #[test]
    fn npmrc_comment_with_equals_is_not_redacted() {
        // A commented-out token line must stay verbatim, not get parsed.
        let input = b"# //registry.npmjs.org/:_authToken=npm_old\n";
        let out = String::from_utf8(redact_npmrc(input).unwrap()).unwrap();
        assert_eq!(out, "# //registry.npmjs.org/:_authToken=npm_old\n");
    }

    #[test]
    fn npmrc_fails_closed_on_non_utf8() {
        assert!(redact_npmrc(&[0xff, 0xfe, b'\n']).is_err());
        // Detection still fires by name; redaction is what fails closed.
        assert_eq!(detect(OsStr::new(".npmrc"), &[0xff]), Some(HandlerKind::Npmrc));
    }

    #[test]
    fn npmrc_merge_keeps_placeholder_values() {
        let original = b"registry=https://registry.npmjs.org/\n\
            //registry.npmjs.org/:_authToken=npm_secret\n";
        let written = b"registry=https://registry.npmjs.org/\n\
            //registry.npmjs.org/:_authToken=<redacted value>\n";
        let out = String::from_utf8(merge_npmrc(original, written).unwrap()).unwrap();
        // Unchanged token: original secret restored.
        assert_eq!(out, String::from_utf8(original.to_vec()).unwrap());
    }

    #[test]
    fn npmrc_merge_persists_edited_token() {
        let original = b"//registry.npmjs.org/:_authToken=npm_old\n";
        let written = b"//registry.npmjs.org/:_authToken=npm_new\n";
        let out = String::from_utf8(merge_npmrc(original, written).unwrap()).unwrap();
        assert_eq!(out, "//registry.npmjs.org/:_authToken=npm_new\n");
    }

    #[test]
    fn npmrc_merge_persists_non_secret_edits_and_additions() {
        let original = b"//registry.npmjs.org/:_authToken=npm_secret\n";
        let written = b"registry=https://example.com/\n\
            //registry.npmjs.org/:_authToken=<redacted value>\n";
        let out = String::from_utf8(merge_npmrc(original, written).unwrap()).unwrap();
        // Added registry line kept; redacted token restored to the real secret.
        assert_eq!(
            out,
            "registry=https://example.com/\n\
             //registry.npmjs.org/:_authToken=npm_secret\n"
        );
    }

    #[test]
    fn npmrc_merge_deletes_removed_token() {
        let original = b"registry=https://registry.npmjs.org/\n\
            //registry.npmjs.org/:_authToken=npm_secret\n";
        let written = b"registry=https://registry.npmjs.org/\n";
        let out = String::from_utf8(merge_npmrc(original, written).unwrap()).unwrap();
        // Token line absent from the written buffer → dropped from the original.
        assert_eq!(out, "registry=https://registry.npmjs.org/\n");
    }

    #[test]
    fn npmrc_merge_fails_closed_on_non_utf8() {
        let original = b"//registry.npmjs.org/:_authToken=npm_secret\n";
        assert!(merge_npmrc(original, &[0xff]).is_err());
        assert!(merge_npmrc(&[0xff], b"x=y\n").is_err());
    }
}
