//! HTTP/2 stream priority helpers.

/// Stream priority parameters for HTTP/2 PRIORITY frames.
///
/// See [RFC 7540 §5.3](https://httpwg.org/specs/rfc7540.html#StreamPriority) for details.
#[derive(Debug, Clone, Copy)]
pub struct StreamPriority {
    /// Stream dependency (parent stream ID). 0 means the connection itself.
    pub dependency: u32,
    /// If `true`, the stream becomes the sole dependency of the parent.
    pub exclusive: bool,
    /// Priority weight in \[1, 256\]. Default is 16.
    pub weight: u8,
}

impl StreamPriority {
    /// Create a new `StreamPriority`.
    pub fn new(dependency: u32, exclusive: bool, weight: u8) -> Self {
        Self {
            dependency,
            exclusive,
            weight,
        }
    }
}

impl Default for StreamPriority {
    fn default() -> Self {
        Self {
            dependency: 0,
            exclusive: false,
            weight: 16,
        }
    }
}
