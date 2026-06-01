//! Bridge between [`oxitls_core::KeyLogPolicy`] and [`rustls::KeyLog`].
//!
//! `KeyLogBridge` wraps a `KeyLogPolicy` and implements the `rustls::KeyLog`
//! trait so it can be installed on a `ClientConfig` or `ServerConfig` to
//! receive TLS session secrets.

use std::fmt;
use std::io::Write as _;

use oxitls_core::KeyLogPolicy;

/// Adapts an [`oxitls_core::KeyLogPolicy`] into a [`rustls::KeyLog`]
/// implementation.
///
/// Install on a config via:
/// ```ignore
/// config.key_log = std::sync::Arc::new(KeyLogBridge::new(policy));
/// ```
pub(crate) struct KeyLogBridge {
    policy: KeyLogPolicy,
}

impl fmt::Debug for KeyLogBridge {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "KeyLogBridge({:?})", self.policy)
    }
}

impl KeyLogBridge {
    /// Create a new bridge wrapping the given policy.
    pub(crate) fn new(policy: KeyLogPolicy) -> Self {
        Self { policy }
    }
}

impl rustls::KeyLog for KeyLogBridge {
    fn log(&self, label: &str, client_random: &[u8], secret: &[u8]) {
        match &self.policy {
            KeyLogPolicy::Disabled => {
                // no-op
            }
            KeyLogPolicy::File(path) => {
                // Open file in append mode; silently ignore I/O errors so a
                // logging failure never takes down the TLS handshake.
                if let Ok(mut file) = std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(path)
                {
                    let line = format!(
                        "{label} {client_random} {secret}\n",
                        client_random = hex_bytes(client_random),
                        secret = hex_bytes(secret),
                    );
                    let _ = file.write_all(line.as_bytes());
                }
            }
            KeyLogPolicy::Custom(arc) => {
                arc.log(label, client_random, secret);
            }
        }
    }

    fn will_log(&self, _label: &str) -> bool {
        !matches!(self.policy, KeyLogPolicy::Disabled)
    }
}

/// Encode a byte slice as lowercase hex without any external dependency.
fn hex_bytes(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut acc, b| {
        use std::fmt::Write as _;
        let _ = write!(acc, "{b:02x}");
        acc
    })
}
