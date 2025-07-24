#![doc = include_str!("../README.md")]
use std::fmt;

/// Error codes definition, most of the API returns a Result< , SrtpError>
///
/// Error names are self explanatory
#[derive(Debug, PartialEq)]
pub enum SrtpError {
    Encryption,
    Authentication,
    ContextNotReady,
    InvalidKeySize,
    TransformDispatch,
    KdfDispatch,
    InvalidPacket,
    InvalidProfile,
    InvalidPacketIndex,
    InvalidMki,
    StreamNotFound,
    /// KeyLimit error carries informations to identify the error source
    /// as it is passed as parameter to the key limit handler
    KeyLimit {
        /// identify if the error was generated from a RTP or RTCP operation
        is_rtp: bool,
        /// - true when the key reached the end of its lifetime
        /// - false when it reaches the soft limit (default to 2^16)
        ///
        /// Note: Soft limit error is only returned through the key limit handler when provided by the
        /// session user using [Session::set_key_limit_handler]
        is_dead: bool,
        /// mki used when the error was generated
        mki: Option<Vec<u8>>,
        /// ssrc of the stream that generated the error
        ssrc: u32,
    },
}

impl fmt::Display for SrtpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}
impl std::error::Error for SrtpError {}

mod header;
mod key_derivation;
mod protection_profile;
mod replay;
mod session;
mod stream;
mod transform;

pub use protection_profile::ProtectionProfile;
pub use session::{RecvSession, SendSession, Session};
pub use stream::{MasterKey, StreamConfig};
