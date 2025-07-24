use crate::SrtpError;
use crate::header::{RtcpHeader, RtpHeader};
use std::any::Any;

pub trait Transform: Send + Sync {
    fn rtp_protect(
        &self,
        plain: Vec<u8>,
        header: &RtpHeader,
        roc: u32,
    ) -> Result<Vec<u8>, SrtpError>;
    fn rtcp_protect(
        &self,
        plain: Vec<u8>,
        header: &RtcpHeader,
        index: u32,
    ) -> Result<Vec<u8>, SrtpError>;

    fn rtp_unprotect(
        &self,
        cipher: Vec<u8>,
        header: &RtpHeader,
        roc: u32,
    ) -> Result<Vec<u8>, SrtpError>;
    fn rtcp_unprotect(
        &self,
        cipher: Vec<u8>,
        header: &RtcpHeader,
        index: u32,
        trailer_len: usize,
    ) -> Result<Vec<u8>, SrtpError>;

    fn as_any(&self) -> &dyn Any;

    fn equals(&self, other: &dyn Transform) -> bool;
}

pub mod aes_cm_sha1; // Note: this module also implement null cipher
pub mod aes_gcm;
