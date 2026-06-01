// SPDX-License-Identifier: Apache-2.0
// Copyright COOLJAPAN OU (Team Kitasan)
//! High-level PKCS#11 TLS provider: pools sessions and builds rustls configs.
//!
//! This module is only compiled when the `pkcs11` feature is active.

use std::collections::BTreeMap;
use std::num::NonZeroUsize;
use std::path::PathBuf;
use std::sync::Arc;

use cryptoki::context::{CInitializeArgs, CInitializeFlags, Pkcs11};
use cryptoki::object::{Attribute, AttributeType, CertificateType, KeyType, ObjectClass};
use cryptoki::slot::Slot;

use rustls::pki_types::CertificateDer;
use secrecy::SecretString;

use crate::error::Pkcs11Error;
use crate::pool::Pkcs11SessionPool;
use crate::resolver::Pkcs11ServerCertResolver;
use crate::signer::Pkcs11SigningKey;
use crate::{Pkcs11KeyInfo, Pkcs11KeyType};

/// A high-level PKCS#11 TLS provider.
///
/// Wraps a loaded PKCS#11 module, a chosen slot, and a pre-populated session
/// pool.  Provides convenience methods for building rustls `ServerConfig`
/// values backed by HSM keys and certificates.
#[derive(Debug)]
pub struct Pkcs11TlsProvider {
    module: Arc<Pkcs11>,
    slot: Slot,
    pool: Arc<Pkcs11SessionPool>,
}

impl Pkcs11TlsProvider {
    /// Create a new provider by loading the PKCS#11 module at `module_path`.
    ///
    /// Opens 4 sessions on `slot`, each logged in with `pin`.
    ///
    /// # Errors
    ///
    /// Returns [`Pkcs11Error`] if the module cannot be loaded, initialized, or
    /// if session creation fails.
    pub fn new(
        module_path: PathBuf,
        slot_index: u64,
        pin: SecretString,
    ) -> Result<Self, Pkcs11Error> {
        let module =
            Pkcs11::new(&module_path).map_err(|e| Pkcs11Error::InitError(e.to_string()))?;

        module
            .initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK))
            .map_err(|e| Pkcs11Error::InitError(format!("C_Initialize failed: {e}")))?;

        let module = Arc::new(module);
        let slot = Slot::try_from(slot_index)
            .map_err(|e| Pkcs11Error::InitError(format!("invalid slot index {slot_index}: {e}")))?;

        let capacity = NonZeroUsize::new(4)
            .ok_or_else(|| Pkcs11Error::Other("capacity must be non-zero".to_string()))?;

        let pool = Arc::new(Pkcs11SessionPool::new(
            Arc::clone(&module),
            slot,
            pin,
            capacity,
        )?);

        Ok(Self { module, slot, pool })
    }

    /// Return a clone of the shared session pool.
    pub fn pool(&self) -> Arc<Pkcs11SessionPool> {
        Arc::clone(&self.pool)
    }

    /// Build a [`Pkcs11SigningKey`] for the private key with the given CKA_LABEL.
    ///
    /// # Errors
    ///
    /// Returns [`Pkcs11Error`] if the key cannot be found or the key type is
    /// unsupported.
    pub fn signing_key(&self, label: &str) -> Result<Arc<Pkcs11SigningKey>, Pkcs11Error> {
        let key = Pkcs11SigningKey::new(Arc::clone(&self.pool), label)?;
        Ok(Arc::new(key))
    }

    /// Retrieve all `CKO_CERTIFICATE` objects with `CKA_LABEL == label` and
    /// return their `CKA_VALUE` bytes as DER-encoded certificates.
    ///
    /// # Errors
    ///
    /// Returns [`Pkcs11Error`] if no certificates are found or any attribute
    /// fetch fails.
    pub fn cert_chain(&self, label: &str) -> Result<Vec<CertificateDer<'static>>, Pkcs11Error> {
        let pooled = self.pool.acquire()?;
        let session = pooled.session();

        let template = vec![
            Attribute::Class(ObjectClass::CERTIFICATE),
            Attribute::Label(label.as_bytes().to_vec()),
        ];

        let handles = session
            .find_objects(&template)
            .map_err(|e| Pkcs11Error::KeyNotFound(format!("find_objects failed: {e}")))?;

        if handles.is_empty() {
            return Err(Pkcs11Error::KeyNotFound(format!(
                "no certificate found with label: {label}"
            )));
        }

        let mut certs = Vec::with_capacity(handles.len());
        for handle in handles {
            let attrs = session
                .get_attributes(handle, &[AttributeType::Value])
                .map_err(|e| Pkcs11Error::SessionError(format!("get_attributes failed: {e}")))?;

            let der_bytes: Option<Vec<u8>> = attrs.into_iter().find_map(|attr| {
                if let cryptoki::object::Attribute::Value(v) = attr {
                    Some(v)
                } else {
                    None
                }
            });

            let der = der_bytes.ok_or_else(|| {
                Pkcs11Error::SessionError("CKA_VALUE not found on certificate".to_string())
            })?;

            certs.push(CertificateDer::from(der));
        }

        Ok(certs)
    }

    /// Build a complete [`rustls::ServerConfig`] backed by PKCS#11 keys.
    ///
    /// # Arguments
    ///
    /// * `chain_label` - CKA_LABEL of the certificate chain object(s).
    /// * `key_label` - CKA_LABEL of the private key object.
    /// * `provider` - The rustls [`rustls::crypto::CryptoProvider`] to use.
    ///
    /// # Errors
    ///
    /// Returns [`Pkcs11Error`] if any step fails.
    pub fn server_config(
        &self,
        chain_label: &str,
        key_label: &str,
        provider: Arc<rustls::crypto::CryptoProvider>,
    ) -> Result<rustls::ServerConfig, Pkcs11Error> {
        let chain = self.cert_chain(chain_label)?;
        let key = self.signing_key(key_label)?;
        let resolver = Pkcs11ServerCertResolver::new(chain, key);

        let config = rustls::ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(|e| Pkcs11Error::Tls(e.to_string()))?
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(resolver));

        Ok(config)
    }

    /// Build a [`rustls::ServerConfig`] with multi-tenant SNI-based certificate
    /// selection.
    ///
    /// Each entry in `sni_map` associates an SNI hostname (or `*.wildcard`) with
    /// a CKA_LABEL pair `(chain_label, key_label)`.  The resolver is constructed
    /// with wildcard matching (RFC 6125 §6.4.3) and the specified `strict_sni`
    /// setting.
    ///
    /// When `strict_sni` is `true`, connections whose SNI does not match any
    /// map entry are rejected.  When `false`, no fallback certificate is
    /// configured (the map must cover all expected hostnames or the handshake
    /// fails).
    ///
    /// # Errors
    ///
    /// Returns [`Pkcs11Error`] if any label lookup fails.
    pub fn server_config_sni(
        &self,
        sni_map: BTreeMap<String, (String, String)>,
        strict_sni: bool,
        provider: Arc<rustls::crypto::CryptoProvider>,
    ) -> Result<rustls::ServerConfig, Pkcs11Error> {
        let mut resolver_map: BTreeMap<
            String,
            (
                Vec<CertificateDer<'static>>,
                Arc<dyn rustls::sign::SigningKey>,
            ),
        > = BTreeMap::new();

        for (hostname, (chain_label, key_label)) in sni_map {
            let chain = self.cert_chain(&chain_label)?;
            let key = self.signing_key(&key_label)?;
            resolver_map.insert(hostname, (chain, key as Arc<dyn rustls::sign::SigningKey>));
        }

        let resolver =
            Pkcs11ServerCertResolver::with_sni_map(resolver_map).with_strict_sni(strict_sni);

        let config = rustls::ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(|e| Pkcs11Error::Tls(e.to_string()))?
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(resolver));

        Ok(config)
    }

    /// Enumerate all `CKO_PRIVATE_KEY` objects visible in the current session.
    ///
    /// When `label_filter` is `Some`, only objects whose `CKA_LABEL` matches the
    /// given string are returned.  Pass `None` to enumerate all private keys.
    ///
    /// # Key-type mapping
    ///
    /// | `CKK_*` constant        | [`Pkcs11KeyType`] variant |
    /// |-------------------------|--------------------------|
    /// | `CKK_RSA`               | `Rsa`                    |
    /// | `CKK_EC` (P-256 OID)    | `EcdsaP256`              |
    /// | `CKK_EC` (P-384 OID)    | `EcdsaP384`              |
    /// | `CKK_EC_EDWARDS`        | `Ed25519`                |
    /// | anything else           | `Other(ckk_raw_u64)`     |
    ///
    /// Because distinguishing P-256 from P-384 requires reading the EC curve
    /// OID (a separate `CKA_EC_PARAMS` attribute fetch), and SoftHSM2 sometimes
    /// returns opaque DER blobs, we currently classify all `CKK_EC` keys as
    /// `EcdsaP256`.  Callers that need exact curve information should read
    /// `CKA_EC_PARAMS` themselves.
    ///
    /// # Errors
    ///
    /// Returns [`Pkcs11Error`] if the session cannot be acquired or any
    /// attribute fetch fails.
    pub fn list_keys(&self, label_filter: Option<&str>) -> Result<Vec<Pkcs11KeyInfo>, Pkcs11Error> {
        let pooled = self.pool.acquire()?;
        let session = pooled.session();

        // Build the search template.
        let mut template = vec![Attribute::Class(ObjectClass::PRIVATE_KEY)];
        if let Some(label) = label_filter {
            template.push(Attribute::Label(label.as_bytes().to_vec()));
        }

        let handles = session
            .find_objects(&template)
            .map_err(|e| Pkcs11Error::SessionError(format!("find_objects failed: {e}")))?;

        let mut keys = Vec::with_capacity(handles.len());

        for handle in handles {
            let attrs = session
                .get_attributes(
                    handle,
                    &[
                        AttributeType::Label,
                        AttributeType::KeyType,
                        AttributeType::Id,
                        AttributeType::Sign,
                    ],
                )
                .map_err(|e| Pkcs11Error::SessionError(format!("get_attributes failed: {e}")))?;

            let mut label_bytes: Option<Vec<u8>> = None;
            let mut key_type_raw: Option<KeyType> = None;
            let mut id_bytes: Vec<u8> = Vec::new();
            let mut signing_capable = false;

            for attr in attrs {
                match attr {
                    Attribute::Label(v) => label_bytes = Some(v),
                    Attribute::KeyType(kt) => key_type_raw = Some(kt),
                    Attribute::Id(v) => id_bytes = v,
                    Attribute::Sign(s) => signing_capable = s,
                    _ => {}
                }
            }

            let label = label_bytes
                .map(|b| String::from_utf8_lossy(&b).into_owned())
                .unwrap_or_default();

            let key_type = match key_type_raw {
                Some(kt) if kt == KeyType::RSA => Pkcs11KeyType::Rsa,
                Some(kt) if kt == KeyType::EC => Pkcs11KeyType::EcdsaP256,
                Some(kt) if kt == KeyType::EC_EDWARDS => Pkcs11KeyType::Ed25519,
                Some(kt) => Pkcs11KeyType::Other(*kt),
                None => Pkcs11KeyType::Other(0xFFFF_FFFF),
            };

            keys.push(Pkcs11KeyInfo {
                label,
                key_type,
                id: id_bytes,
                signing_capable,
            });
        }

        Ok(keys)
    }

    /// Import a DER-encoded X.509 certificate onto the token as a
    /// `CKO_CERTIFICATE` object.
    ///
    /// # CKA_ID derivation
    ///
    /// The `CKA_ID` is set to the first 20 bytes of the certificate DER (or
    /// the full DER if it is shorter than 20 bytes).  This is a simplified
    /// convention that avoids adding a SHA-1 or SHA-256 dependency to this
    /// crate.  Callers that need a standards-compliant key identifier (e.g.
    /// the RFC 5280 Subject Key Identifier) should compute it externally and
    /// pass a correctly formed template to `session.create_object` directly.
    ///
    /// # CKA_SUBJECT derivation
    ///
    /// Because parsing the X.509 subject DN from raw DER would require a
    /// dependency on an ASN.1 parser, `CKA_SUBJECT` is set to the same bytes
    /// as `CKA_ID`.  SoftHSM2 accepts this; hardware HSMs may require a valid
    /// DER-encoded `Name`.
    ///
    /// # Errors
    ///
    /// Returns [`Pkcs11Error`] if the session cannot be acquired or
    /// `C_CreateObject` fails (e.g. duplicate object, insufficient rights).
    pub fn import_cert(&self, cert_der: &[u8], label: &str) -> Result<(), Pkcs11Error> {
        let pooled = self.pool.acquire()?;
        let session = pooled.session();

        // Derive a short opaque identifier from the leading bytes of the DER.
        let id_bytes: Vec<u8> = cert_der[..20.min(cert_der.len())].to_vec();

        let template = vec![
            Attribute::Class(ObjectClass::CERTIFICATE),
            Attribute::CertificateType(CertificateType::X_509),
            Attribute::Token(true),
            Attribute::Label(label.as_bytes().to_vec()),
            Attribute::Value(cert_der.to_vec()),
            // Subject — simplified: use the same bytes as CKA_ID.
            Attribute::Subject(id_bytes.clone()),
            Attribute::Id(id_bytes),
        ];

        session
            .create_object(&template)
            .map_err(|e: cryptoki::error::Error| Pkcs11Error::from(e))?;

        Ok(())
    }

    /// Return the slot this provider is bound to.
    pub fn slot(&self) -> Slot {
        self.slot
    }

    /// Return the underlying PKCS#11 module.
    pub fn module(&self) -> Arc<Pkcs11> {
        Arc::clone(&self.module)
    }
}
