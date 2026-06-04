//! ECHConfigList generation for deployable Encrypted Client Hello (RFC 9180 / TLS-ESNI draft-18).
//!
//! rustls parses `ECHConfigList` bytes but provides no generator. This module mints
//! a spec-correct list from a fresh HPKE keypair. The caller publishes `config_list`
//! (e.g. via DNS HTTPS record) and stores `private_key` as the long-term ECH key.

use rustls::crypto::hpke::Hpke;
use rustls::pki_types::EchConfigListBytes;

/// Output of [`generate_ech_config_list`].
pub struct GeneratedEchConfig {
    /// Serialised ECHConfigList bytes — feed directly into `with_ech_config_list()`.
    pub config_list: Vec<u8>,
    /// Raw private-key bytes — persist securely as the server's long-term ECH key.
    pub private_key: Vec<u8>,
    /// Raw public-key bytes (also embedded in `config_list`).
    pub public_key: Vec<u8>,
    /// The `config_id` written into the config.
    pub config_id: u8,
}

/// Numeric IDs extracted from an HPKE suite, used during ECHConfigList encoding.
struct SuiteIds {
    kem_id: u16,
    kdf_id: u16,
    aead_id: u16,
}

/// Encode raw ECHConfigContents bytes (the inner payload before version+length wrapping).
///
/// Layout per draft-ietf-tls-esni-18 §4 (big-endian):
///
/// ```text
/// HpkeKeyConfig:
///   u8   config_id
///   u16  kem_id
///   u16  public_key_length
///   byte public_key[public_key_length]
///   u16  cipher_suites_length  (1 entry × 4 bytes = 4)
///   HpkeSymmetricCipherSuite:
///     u16  kdf_id
///     u16  aead_id
/// u8   maximum_name_length
/// u8   public_name_length
/// byte public_name[public_name_length]
/// u16  extensions_length = 0  (empty)
/// ```
fn encode_contents(
    ids: &SuiteIds,
    config_id: u8,
    pk_bytes: &[u8],
    public_name_bytes: &[u8],
    maximum_name_length: u8,
) -> Result<Vec<u8>, rustls::Error> {
    let mut contents = Vec::new();

    // HpkeKeyConfig
    contents.push(config_id);
    contents.extend_from_slice(&ids.kem_id.to_be_bytes());
    let pk_len = u16::try_from(pk_bytes.len())
        .map_err(|_| rustls::Error::General("ECHConfig: public key length exceeds u16".into()))?;
    contents.extend_from_slice(&pk_len.to_be_bytes());
    contents.extend_from_slice(pk_bytes);
    // One cipher suite (4 bytes) → cipher_suites_length = 4
    contents.extend_from_slice(&4u16.to_be_bytes());
    contents.extend_from_slice(&ids.kdf_id.to_be_bytes());
    contents.extend_from_slice(&ids.aead_id.to_be_bytes());

    // maximum_name_length
    contents.push(maximum_name_length);

    // public_name (u8-length-prefixed)
    let pn_len = u8::try_from(public_name_bytes.len())
        .map_err(|_| rustls::Error::General("ECHConfig: public_name length exceeds u8".into()))?;
    contents.push(pn_len);
    contents.extend_from_slice(public_name_bytes);

    // extensions: empty list (u16 length = 0)
    contents.extend_from_slice(&0u16.to_be_bytes());

    Ok(contents)
}

/// Wrap ECHConfigContents in the outer ECHConfig and ECHConfigList envelopes.
///
/// Returns the final ECHConfigList bytes (u16 list-length prefix + ECHConfig entry).
fn wrap_config_list(contents: Vec<u8>) -> Result<Vec<u8>, rustls::Error> {
    // ECHConfig = version(u16) || contents_length(u16) || contents
    let contents_len = u16::try_from(contents.len())
        .map_err(|_| rustls::Error::General("ECHConfig: contents length exceeds u16".into()))?;
    let mut ech_config = Vec::with_capacity(4 + contents.len());
    ech_config.extend_from_slice(&0xfe0du16.to_be_bytes()); // version
    ech_config.extend_from_slice(&contents_len.to_be_bytes());
    ech_config.extend_from_slice(&contents);

    // ECHConfigList = list_length(u16) || ech_config[...]
    let list_len = u16::try_from(ech_config.len())
        .map_err(|_| rustls::Error::General("ECHConfigList: total length exceeds u16".into()))?;
    let mut config_list = Vec::with_capacity(2 + ech_config.len());
    config_list.extend_from_slice(&list_len.to_be_bytes());
    config_list.extend_from_slice(&ech_config);

    Ok(config_list)
}

/// Mint a spec-correct `ECHConfigList` (draft-ietf-tls-esni-18, version `0xfe0d`) using
/// a freshly generated HPKE keypair from `suite`.
///
/// The returned `config_list` is ready to pass to `ClientBuilder::with_ech_config_list()`.
/// The returned `private_key` bytes must be stored by the server operator; they are needed
/// to decrypt incoming `ClientHelloInner` once rustls gains server-side ECH support.
///
/// `public_name` is the ECH "public name" (a DNS hostname, e.g. `"public.example.com"`).
/// `maximum_name_length` is the maximum length of inner SNI the operator wishes to protect
/// (may be 0 if unspecified).
pub fn generate_ech_config_list(
    suite: &'static dyn Hpke,
    config_id: u8,
    public_name: &str,
    maximum_name_length: u8,
) -> Result<GeneratedEchConfig, rustls::Error> {
    // Generate a fresh HPKE keypair for this ECH config.
    let (pk, sk) = suite.generate_key_pair()?;
    let hs = suite.suite();

    // Extract numeric IDs from the suite.
    // The enum_builder macro generates From<HpkeKem> for u16, From<HpkeKdf> for u16,
    // and From<HpkeAead> for u16 automatically — so u16::from(hs.kem) works.
    let ids = SuiteIds {
        kem_id: u16::from(hs.kem),
        kdf_id: u16::from(hs.sym.kdf_id),
        aead_id: u16::from(hs.sym.aead_id),
    };

    let pk_bytes = pk.0.clone();
    let private_key_bytes = sk.secret_bytes().to_vec();

    let contents = encode_contents(
        &ids,
        config_id,
        &pk_bytes,
        public_name.as_bytes(),
        maximum_name_length,
    )?;
    let config_list = wrap_config_list(contents)?;

    // Self-validate: parse back through rustls before returning.
    // This catches any encoding error before the caller can use malformed bytes.
    let suites = crate::hpke::pure_hpke_suites();
    rustls::client::EchConfig::new(EchConfigListBytes::from(config_list.clone()), suites).map_err(
        |e| {
            rustls::Error::General(format!(
                "ECHConfig: self-validation failed (encoding bug): {e}"
            ))
        },
    )?;

    Ok(GeneratedEchConfig {
        config_list,
        private_key: private_key_bytes,
        public_key: pk_bytes,
        config_id,
    })
}
