//! TLS certificate machinery for the MitM: an ephemeral CA that mints a leaf
//! per SNI on demand (for the client leg), plus the trust config used for the
//! real upstream leg. Kept separate from the netstack/proxy plumbing in the
//! rest of [`super`].

use std::collections::HashMap;
use std::sync::{Arc, Mutex, PoisonError};

use anyhow::Result;
use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair, KeyUsagePurpose};
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use rustls::{ClientConfig, RootCertStore};

/// An ephemeral CA plus a cache of the leaf certs it has minted per SNI.
pub(super) struct CertMinter {
    ca_cert: rcgen::Certificate,
    ca_key: KeyPair,
    cache: Mutex<HashMap<String, Arc<CertifiedKey>>>,
}

/// Build the CA and return (CA cert PEM, minter).
pub(super) fn build_cert_minter() -> Result<(String, CertMinter)> {
    let ca_key = KeyPair::generate()?;
    let mut ca_params = CertificateParams::new(Vec::<String>::new())?;
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    ca_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "airgap MitM CA");
    let ca_cert = ca_params.self_signed(&ca_key)?;
    let ca_pem = ca_cert.pem();

    Ok((
        ca_pem,
        CertMinter {
            ca_cert,
            ca_key,
            cache: Mutex::new(HashMap::new()),
        },
    ))
}

impl CertMinter {
    fn mint(&self, sni: &str) -> Result<Arc<CertifiedKey>> {
        // A poisoned cache mutex only means a previous mint panicked mid-insert;
        // the map itself is still consistent, so recover rather than propagate.
        if let Some(ck) = self
            .cache
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(sni)
        {
            return Ok(ck.clone());
        }
        let leaf_key = KeyPair::generate()?;
        let mut params = CertificateParams::new(vec![sni.to_string()])?;
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "airgap self signed cert");
        let leaf = params.signed_by(&leaf_key, &self.ca_cert, &self.ca_key)?;

        let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der()));
        let signing_key = rustls::crypto::aws_lc_rs::sign::any_supported_type(&key_der)?;
        let chain = vec![leaf.der().clone(), self.ca_cert.der().clone()];
        let ck = Arc::new(CertifiedKey::new(chain, signing_key));

        self.cache
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(sni.to_string(), ck.clone());
        Ok(ck)
    }
}

impl std::fmt::Debug for CertMinter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("CertMinter")
    }
}

impl ResolvesServerCert for CertMinter {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let sni = client_hello.server_name()?;
        match self.mint(sni) {
            Ok(ck) => Some(ck),
            Err(e) => {
                log::warn!("mitm: minting cert for {sni} failed: {e:#}");
                None
            }
        }
    }
}

/// Trust config for the upstream (real-server) leg: the host's native roots.
pub(super) fn build_upstream_client_config() -> Result<ClientConfig> {
    let mut roots = RootCertStore::empty();
    let native = rustls_native_certs::load_native_certs();
    for cert in native.certs {
        let _ = roots.add(cert);
    }
    Ok(ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth())
}
