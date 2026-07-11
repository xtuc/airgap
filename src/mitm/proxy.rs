//! The proxy connection handler: terminate the child's TLS (with a cert minted
//! for the SNI), rewrite the first request's headers per the config, open a real
//! TLS connection to the SNI host, and splice.

use std::collections::BTreeSet;
use std::sync::Arc;

use anyhow::{Context, Result, anyhow, bail};
use rustls::ClientConfig;
use rustls::pki_types::ServerName;
use tokio::io::{AsyncReadExt, AsyncWriteExt, copy_bidirectional};
use tokio::net::TcpStream;
use tokio_rustls::{TlsAcceptor, TlsConnector};

use super::config::Config;
use super::stream::SmoltcpStream;

pub(super) async fn handle_conn(
    stream: SmoltcpStream,
    port: u16,
    acceptor: TlsAcceptor,
    client_config: Arc<ClientConfig>,
    config: Arc<Config>,
) -> Result<()> {
    // Every port is treated as TLS: terminate the client's TLS (the resolver mints
    // a cert for the SNI), then forward upstream to the same port. Plaintext on
    // any port fails this handshake and is dropped — never forwarded in the clear.
    // That failure is expected (it's how we drop plaintext), so it's logged at
    // debug and not surfaced as a connection error.
    let mut client_tls = match acceptor.accept(stream).await {
        Ok(tls) => tls,
        Err(e) => {
            log::debug!("mitm: client TLS handshake failed (non-TLS or aborted): {e}");
            return Ok(());
        }
    };
    let sni = client_tls
        .get_ref()
        .1
        .server_name()
        .map(str::to_owned)
        .ok_or_else(|| anyhow!("client sent no SNI; can't determine upstream"))?;

    // Read the request head (up to the blank line).
    let mut buf = Vec::with_capacity(8192);
    let head_end = loop {
        let mut tmp = [0u8; 4096];
        let n = client_tls.read(&mut tmp).await?;
        if n == 0 {
            bail!("client closed before sending headers");
        }
        buf.extend_from_slice(&tmp[..n]);
        if let Some(pos) = find_headers_end(&buf) {
            break pos;
        }
        if buf.len() > 64 * 1024 {
            bail!("request headers too large");
        }
    };

    let new_head = rewrite_head(&buf[..head_end], &config)?;
    let leftover = &buf[head_end..];

    // Open a real TLS connection to the SNI host on the same port the child dialed
    // (init netns → real egress).
    let upstream_tcp = TcpStream::connect((sni.as_str(), port))
        .await
        .with_context(|| format!("connecting upstream {sni}:{port}"))?;
    let connector = TlsConnector::from(client_config);
    let server_name = ServerName::try_from(sni.clone())?;
    let mut upstream_tls = connector
        .connect(server_name, upstream_tcp)
        .await
        .context("upstream TLS handshake")?;

    upstream_tls.write_all(&new_head).await?;
    if !leftover.is_empty() {
        upstream_tls.write_all(leftover).await?;
    }
    upstream_tls.flush().await?;

    // Splice the rest (request body + response). Only this first request head is
    // rewritten, so `rewrite_head` forced `Connection: close` on matched hosts to
    // stop the child reusing the connection for an unrewritten request 2.
    // A reset/short close here is a normal way for either side to end the
    // exchange, so it's logged at debug rather than propagated as an error.
    if let Err(e) = copy_bidirectional(&mut client_tls, &mut upstream_tls).await {
        log::debug!("mitm: splice for {sni}:{port} ended: {e}");
    }
    Ok(())
}

/// Index just past the `\r\n\r\n` that ends the header block, if present.
fn find_headers_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n").map(|p| p + 4)
}

/// Parse the request head; if its `Host` matches a config rule, rebuild it with
/// that rule's headers overridden/added while preserving every other header. No
/// match → return the head unchanged.
fn rewrite_head(head: &[u8], config: &Config) -> Result<Vec<u8>> {
    let mut headers = [httparse::EMPTY_HEADER; 128];
    let mut req = httparse::Request::new(&mut headers);
    // If we can't parse it, we can't safely rewrite it — forward it untouched
    // rather than dropping the request.
    if req.parse(head).is_err() {
        log::debug!("mitm: unparseable request head; forwarding unchanged");
        return Ok(head.to_vec());
    }

    // Host header → lowercased, port stripped.
    let host = req
        .headers
        .iter()
        .find(|h| h.name.eq_ignore_ascii_case("host"))
        .and_then(|h| std::str::from_utf8(h.value).ok())
        .map(str::trim)
        .unwrap_or("");
    let host = host.rsplit_once(':').map_or(host, |(h, _)| h).to_ascii_lowercase();

    let overrides = match config.matching(&host) {
        Some(rule) => &rule.headers,
        // No rule for this host: forward the request exactly as received.
        None => return Ok(head.to_vec()),
    };
    log::debug!(
        "mitm: Host {host:?} matched rule; overriding {} header(s): {}",
        overrides.len(),
        overrides.keys().cloned().collect::<Vec<_>>().join(", ")
    );

    // Names we're going to set, lowercased, so we can drop existing copies.
    let override_names: BTreeSet<String> =
        overrides.keys().map(|k| k.to_ascii_lowercase()).collect();

    let method = req.method.ok_or_else(|| anyhow!("request missing method"))?;
    let path = req.path.ok_or_else(|| anyhow!("request missing path"))?;

    // We only ever rewrite the *first* request head on a connection, so a
    // keep-alive connection would let requests 2..N through unrewritten. Asking
    // the upstream to close instead means the child has to open a fresh
    // connection for its next request — and that one gets rewritten too. The
    // upstream's `Connection: close` response header rides back through the
    // splice, so a well-behaved client stops reusing the socket, and the
    // upstream's close ends the splice on its own (no response parsing needed).
    // Only matched hosts pay the extra handshake per request.
    const DROP: [&str; 2] = ["connection", "keep-alive"];

    let mut out = Vec::with_capacity(head.len() + 128);
    out.extend_from_slice(method.as_bytes());
    out.push(b' ');
    out.extend_from_slice(path.as_bytes());
    out.extend_from_slice(b" HTTP/1.1\r\n");
    // Preserve every header except the ones we're overriding or forcing.
    for h in req.headers.iter() {
        let lower = h.name.to_ascii_lowercase();
        if h.name.is_empty() || override_names.contains(&lower) || DROP.contains(&lower.as_str()) {
            continue;
        }
        out.extend_from_slice(h.name.as_bytes());
        out.extend_from_slice(b": ");
        out.extend_from_slice(h.value);
        out.extend_from_slice(b"\r\n");
    }
    // Add the configured headers (override or new).
    for (name, value) in overrides {
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(b": ");
        out.extend_from_slice(value.as_bytes());
        out.extend_from_slice(b"\r\n");
    }
    // A rule that sets `Connection` itself wins (e.g. to opt back into
    // keep-alive for a host where the perf matters more).
    if !override_names.contains("connection") {
        out.extend_from_slice(b"Connection: close\r\n");
    }
    out.extend_from_slice(b"\r\n");
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(yaml: &str) -> Config {
        serde_yaml_ng::from_str(yaml).unwrap()
    }

    fn head(host: &str, extra: &str) -> Vec<u8> {
        format!("GET /headers HTTP/1.1\r\nHost: {host}\r\nUser-Agent: curl/8\r\n{extra}\r\n")
            .into_bytes()
    }

    const CONF: &str = "\
rules:
  - host: httpbin.org
    headers:
      X-Airgap-Test: rewritten-by-airgap
      X-Injected-By: airgap
";

    #[test]
    fn overrides_existing_and_adds_new_preserving_others() {
        let out =
            rewrite_head(&head("httpbin.org", "X-Airgap-Test: original\r\n"), &cfg(CONF)).unwrap();
        let out = String::from_utf8(out).unwrap();
        // existing header overridden (old value gone, once)
        assert!(out.contains("X-Airgap-Test: rewritten-by-airgap"));
        assert!(!out.contains("X-Airgap-Test: original"));
        assert_eq!(out.matches("X-Airgap-Test:").count(), 1);
        // new header injected
        assert!(out.contains("X-Injected-By: airgap"));
        // unrelated header preserved
        assert!(out.contains("User-Agent: curl/8"));
        assert!(out.contains("Host: httpbin.org"));
    }

    #[test]
    fn matched_host_forces_connection_close() {
        // Keep-alive replaced, not duplicated: requests 2..N on the connection
        // would not be rewritten, so the child must reconnect for each one.
        let out =
            rewrite_head(&head("httpbin.org", "Connection: keep-alive\r\n"), &cfg(CONF)).unwrap();
        let out = String::from_utf8(out).unwrap();
        assert!(out.contains("Connection: close"));
        assert!(!out.contains("keep-alive"));
        assert_eq!(out.matches("Connection:").count(), 1);
    }

    #[test]
    fn rule_can_override_connection_header() {
        let conf = "\
rules:
  - host: httpbin.org
    headers:
      Connection: keep-alive
";
        let out = rewrite_head(&head("httpbin.org", ""), &cfg(conf)).unwrap();
        let out = String::from_utf8(out).unwrap();
        assert!(out.contains("Connection: keep-alive"));
        assert_eq!(out.matches("Connection:").count(), 1);
    }

    #[test]
    fn subdomain_host_does_not_match() {
        // Exact match only: a subdomain of the configured host is passed through.
        let input = head("api.httpbin.org", "");
        let out = rewrite_head(&input, &cfg(CONF)).unwrap();
        assert_eq!(out, input);
    }

    #[test]
    fn host_with_port_still_matches() {
        let out = rewrite_head(&head("httpbin.org:443", ""), &cfg(CONF)).unwrap();
        assert!(String::from_utf8(out).unwrap().contains("X-Injected-By: airgap"));
    }

    #[test]
    fn non_matching_host_passes_through_unchanged() {
        let input = head("other.com", "X-Airgap-Test: original\r\n");
        let out = rewrite_head(&input, &cfg(CONF)).unwrap();
        assert_eq!(out, input); // byte-for-byte identical
    }
}
