use crate::SrtpError;
use crate::header::{RtcpHeader, RtpHeader};
use crate::key_derivation::{KdfLabel, aes_cm_kdf};
use crate::protection_profile::ProtectionProfile;

use constant_time_eq::constant_time_eq;
use ctr::cipher::{KeyIvInit, StreamCipher, generic_array::GenericArray};
use hmac::Mac;
use sha1::Sha1;
use std::any::Any;
use zeroize::{Zeroize, ZeroizeOnDrop};

type Aes128Ctr32BE = ctr::Ctr32BE<aes::Aes128>;
type Aes192Ctr32BE = ctr::Ctr32BE<aes::Aes192>;
type Aes256Ctr32BE = ctr::Ctr32BE<aes::Aes256>;
type HmacSha1 = hmac::Hmac<Sha1>;

// for NullCipher or NullAuth, we may not need either key/salt or auth_key
#[derive(PartialEq, Zeroize, ZeroizeOnDrop)]
struct SessionKeys {
    key: Option<Vec<u8>>,
    salt: Option<[u8; 14]>,
    auth_key: Option<[u8; 20]>,
}

#[derive(PartialEq)]
pub struct AesCmSha1 {
    rtp_profile: ProtectionProfile,
    rtcp_profile: ProtectionProfile,
    rtp_key: SessionKeys,
    rtcp_key: SessionKeys,
    mki: Option<Vec<u8>>,
}
impl AesCmSha1 {
    pub fn new(
        master_key: &[u8],
        master_salt: &[u8],
        mki: &Option<Vec<u8>>,
        rtp_profile: &ProtectionProfile,
        rtcp_profile: &ProtectionProfile,
    ) -> Result<Self, SrtpError> {
        // checks on key/salt size vs selected profile are done at an upper level, no need to
        // repeat that

        // Derive RTP session key
        let mut rtp_key = None;
        let mut rtp_salt = None;
        let mut rtp_auth_key = None;
        match rtp_profile {
            ProtectionProfile::Aes128CmHmacSha180
            | ProtectionProfile::Aes128CmHmacSha132
            | ProtectionProfile::Aes192CmHmacSha180
            | ProtectionProfile::Aes192CmHmacSha132
            | ProtectionProfile::Aes256CmHmacSha180
            | ProtectionProfile::Aes256CmHmacSha132 => {
                rtp_key = Some(aes_cm_kdf(KdfLabel::RtpEncrypt, master_key, master_salt)?);
                rtp_salt = Some(
                    aes_cm_kdf(KdfLabel::RtpSalt, master_key, master_salt)?
                        .try_into()
                        .map_err(|_| SrtpError::KdfDispatch)?,
                );
                rtp_auth_key = Some(
                    aes_cm_kdf(KdfLabel::RtpAuthTag, master_key, master_salt)?
                        .try_into()
                        .map_err(|_| SrtpError::KdfDispatch)?,
                );
            }
            ProtectionProfile::Aes128CmNullAuth
            | ProtectionProfile::Aes192CmNullAuth
            | ProtectionProfile::Aes256CmNullAuth => {
                rtp_key = Some(aes_cm_kdf(KdfLabel::RtpEncrypt, master_key, master_salt)?);
                rtp_salt = Some(
                    aes_cm_kdf(KdfLabel::RtpSalt, master_key, master_salt)?
                        .try_into()
                        .map_err(|_| SrtpError::KdfDispatch)?,
                );
            }
            ProtectionProfile::NullCipherHmacSha180 => {
                rtp_auth_key = Some(
                    aes_cm_kdf(KdfLabel::RtpAuthTag, master_key, master_salt)?
                        .try_into()
                        .map_err(|_| SrtpError::KdfDispatch)?,
                );
            }
            _ => {
                return Err(SrtpError::TransformDispatch);
            }
        }
        let rtp_keys = SessionKeys {
            key: rtp_key,
            salt: rtp_salt,
            auth_key: rtp_auth_key,
        };

        // Derive RTCP session key
        let mut rtcp_key = None;
        let mut rtcp_salt = None;
        let rtcp_auth_key;
        match rtcp_profile {
            ProtectionProfile::Aes128CmHmacSha180
            | ProtectionProfile::Aes192CmHmacSha180
            | ProtectionProfile::Aes256CmHmacSha180 => {
                rtcp_key = Some(aes_cm_kdf(KdfLabel::RtcpEncrypt, master_key, master_salt)?);
                rtcp_salt = Some(
                    aes_cm_kdf(KdfLabel::RtcpSalt, master_key, master_salt)?
                        .try_into()
                        .map_err(|_| SrtpError::KdfDispatch)?,
                );
                rtcp_auth_key = Some(
                    aes_cm_kdf(KdfLabel::RtcpAuthTag, master_key, master_salt)?
                        .try_into()
                        .map_err(|_| SrtpError::KdfDispatch)?,
                );
            }

            // RFC3711 section 3.4: Message authentication for RTCP is REQUIRED
            // section 5.2: for SRTCP, the pre-defined HMAC-SHA1 MUST NOT be
            // applied with a value of n_tag that are smaller than these defaults (80 bits)
            // Prevent forbidden profiles with RTCP
            ProtectionProfile::Aes128CmNullAuth
            | ProtectionProfile::Aes192CmNullAuth
            | ProtectionProfile::Aes256CmNullAuth
            | ProtectionProfile::Aes128CmHmacSha132
            | ProtectionProfile::Aes192CmHmacSha132
            | ProtectionProfile::Aes256CmHmacSha132 => {
                return Err(SrtpError::InvalidProfile);
            }
            ProtectionProfile::NullCipherHmacSha180 => {
                rtcp_auth_key = Some(
                    aes_cm_kdf(KdfLabel::RtcpAuthTag, master_key, master_salt)?
                        .try_into()
                        .map_err(|_| SrtpError::KdfDispatch)?,
                );
            }
            _ => {
                return Err(SrtpError::TransformDispatch);
            }
        }
        let rtcp_keys = SessionKeys {
            key: rtcp_key,
            salt: rtcp_salt,
            auth_key: rtcp_auth_key,
        };

        Ok(Self {
            rtp_profile: *rtp_profile,
            rtcp_profile: *rtcp_profile,
            rtp_key: rtp_keys,
            rtcp_key: rtcp_keys,
            mki: mki.clone(),
        })
    }

    fn rtp_encrypt(
        &self,
        rtp_packet: &mut [u8],
        header: &RtpHeader,
        roc: u32,
    ) -> Result<(), SrtpError> {
        let session_key = self
            .rtp_key
            .key
            .as_ref()
            .ok_or(SrtpError::ContextNotReady)?;
        let session_salt = self
            .rtp_key
            .salt
            .as_ref()
            .ok_or(SrtpError::ContextNotReady)?;

        // Compute IV = (k_s * 2^16) XOR (SSRC * 2^64) XOR (i * 2^16)  [RFC3711 - 4.1.1]
        // IV = 0x0 <4bytes> || SSRC <4bytes> || ROC <4bytes> || seqnum<2bytes> || 0x0 <2bytes>
        //    ^                         session salt <14 bytes>                 || 0x0 <2bytes>
        let mut iv: [u8; 16] = [0; 16];
        iv[..14].copy_from_slice(session_salt);
        let ssrc_bytes = header.ssrc().to_be_bytes();
        let roc_bytes = roc.to_be_bytes();
        let seq_num_bytes = header.seq_num().to_be_bytes();
        for i in 0..4 {
            iv[4 + i] ^= ssrc_bytes[i];
            iv[8 + i] ^= roc_bytes[i];
        }
        iv[12] ^= seq_num_bytes[0];
        iv[13] ^= seq_num_bytes[1];

        // Encryption
        match self.rtp_profile {
            ProtectionProfile::Aes128CmHmacSha180
            | ProtectionProfile::Aes128CmHmacSha132
            | ProtectionProfile::Aes128CmNullAuth => {
                let mut cipher =
                    Aes128Ctr32BE::new(GenericArray::from_slice(session_key), &iv.into());
                cipher.apply_keystream(&mut rtp_packet[header.len()..]);
            }

            ProtectionProfile::Aes192CmHmacSha180
            | ProtectionProfile::Aes192CmHmacSha132
            | ProtectionProfile::Aes192CmNullAuth => {
                let mut cipher =
                    Aes192Ctr32BE::new(GenericArray::from_slice(session_key), &iv.into());
                cipher.apply_keystream(&mut rtp_packet[header.len()..]);
            }

            ProtectionProfile::Aes256CmHmacSha180
            | ProtectionProfile::Aes256CmHmacSha132
            | ProtectionProfile::Aes256CmNullAuth => {
                let mut cipher =
                    Aes256Ctr32BE::new(GenericArray::from_slice(session_key), &iv.into());
                cipher.apply_keystream(&mut rtp_packet[header.len()..]);
            }

            _ => {
                return Err(SrtpError::TransformDispatch);
            }
        }
        Ok(())
    }

    fn rtcp_encrypt(
        &self,
        rtcp_packet: &mut [u8],
        header: &RtcpHeader,
        index: u32,
    ) -> Result<(), SrtpError> {
        let session_key = self
            .rtcp_key
            .key
            .as_ref()
            .ok_or(SrtpError::ContextNotReady)?;

        let session_salt = self
            .rtcp_key
            .salt
            .as_ref()
            .ok_or(SrtpError::ContextNotReady)?;

        // Compute IV = (k_s * 2^16) XOR (SSRC * 2^64) XOR (i * 2^16)  [RFC3711 - 4.1.1]
        // IV = 0x0 <4bytes> || SSRC <4bytes> || 0x0 <2bytes> || index <4bytes> || 0x0 <2bytes>
        //    ^                         session salt <14 bytes>                 || 0x0 <2bytes>
        let mut iv: [u8; 16] = [0; 16];
        iv[..14].copy_from_slice(session_salt);
        let ssrc_bytes = header.ssrc().to_be_bytes();
        let index_bytes = index.to_be_bytes();
        for i in 0..4 {
            iv[4 + i] ^= ssrc_bytes[i];
            iv[10 + i] ^= index_bytes[i];
        }

        // Encryption
        match self.rtcp_profile {
            ProtectionProfile::Aes128CmHmacSha180 => {
                let mut cipher =
                    Aes128Ctr32BE::new(GenericArray::from_slice(session_key), &iv.into());
                cipher.apply_keystream(&mut rtcp_packet[RtcpHeader::len()..]);
            }

            ProtectionProfile::Aes192CmHmacSha180 => {
                let mut cipher =
                    Aes192Ctr32BE::new(GenericArray::from_slice(session_key), &iv.into());
                cipher.apply_keystream(&mut rtcp_packet[RtcpHeader::len()..]);
            }

            ProtectionProfile::Aes256CmHmacSha180 => {
                let mut cipher =
                    Aes256Ctr32BE::new(GenericArray::from_slice(session_key), &iv.into());
                cipher.apply_keystream(&mut rtcp_packet[RtcpHeader::len()..]);
            }

            _ => {
                return Err(SrtpError::TransformDispatch);
            }
        }
        Ok(())
    }

    fn rtp_auth_tag(&self, authenticated_packet: &[u8], roc: u32) -> Result<Vec<u8>, SrtpError> {
        let session_auth_key = self
            .rtp_key
            .auth_key
            .as_ref()
            .ok_or(SrtpError::ContextNotReady)?;

        // RFC3711 4.2.1 tag is HmacSha1(session_auth_key, Packet || Roc)
        // return the left most bytes according to requested tag len
        let mut mac =
            HmacSha1::new_from_slice(session_auth_key).map_err(|_| SrtpError::Encryption)?;
        mac.update(authenticated_packet);
        mac.update(&roc.to_be_bytes());
        let tag = mac.finalize().into_bytes();
        if tag.len() < self.rtp_profile.tag_len() {
            return Err(SrtpError::Encryption);
        }
        Ok(tag[..self.rtp_profile.tag_len()].to_vec())
    }

    fn rtcp_auth_tag(&self, authenticated_packet: &[u8]) -> Result<Vec<u8>, SrtpError> {
        let session_auth_key = self
            .rtcp_key
            .auth_key
            .as_ref()
            .ok_or(SrtpError::ContextNotReady)?;

        // RFC3711 4.2 tag is HmacSha1(session_auth_key, Packet)
        // return the left most bytes according to requested tag len
        let mut mac =
            HmacSha1::new_from_slice(session_auth_key).map_err(|_| SrtpError::Encryption)?;
        mac.update(authenticated_packet);
        let tag = mac.finalize().into_bytes();
        if tag.len() < self.rtcp_profile.tag_len() {
            return Err(SrtpError::Encryption);
        }
        Ok(tag[..self.rtcp_profile.tag_len()].to_vec())
    }
}

impl super::Transform for AesCmSha1 {
    fn rtp_protect(
        &self,
        mut plain: Vec<u8>,
        header: &RtpHeader,
        roc: u32,
    ) -> Result<Vec<u8>, SrtpError> {
        // Encrypt only if profile requires it
        if self.rtp_profile.key_len() > 0 {
            self.rtp_encrypt(&mut plain, header, roc)?;
        }

        // Add mki if present
        let mut mki_len: usize = 0;
        if let Some(mki) = &self.mki {
            plain.extend(mki);
            mki_len = mki.len();
        }

        // Authenticate only if profile requires it, mki is not in the authenticated part
        if self.rtp_profile.tag_len() > 0 {
            plain.extend(&self.rtp_auth_tag(&plain[..plain.len() - mki_len], roc)?);
        }
        Ok(plain)
    }

    fn rtcp_protect(
        &self,
        mut plain: Vec<u8>,
        header: &RtcpHeader,
        index: u32,
    ) -> Result<Vec<u8>, SrtpError> {
        // Encrypt if profile requires it
        if self.rtcp_profile.key_len() > 0 {
            self.rtcp_encrypt(&mut plain, header, index)?;
            // set the E flag in trailer
            plain.extend((index | 0x80000000).to_be_bytes());
        } else {
            // no encryption requested: trailer is the index, make sure the E flag is 0
            plain.extend((index & 0x7fffffff).to_be_bytes());
        }

        // Add mki if present
        let mut mki_len: usize = 0;
        if let Some(mki) = &self.mki {
            plain.extend(mki);
            mki_len = mki.len();
        }

        // Authenticate (always required for RTCP)
        plain.extend(&self.rtcp_auth_tag(&plain[..plain.len() - mki_len])?);
        Ok(plain)
    }

    fn rtp_unprotect(
        &self,
        mut cipher: Vec<u8>,
        header: &RtpHeader,
        roc: u32,
    ) -> Result<Vec<u8>, SrtpError> {
        // Compute trailer len : mki + auth tag
        let mut trailer_len: usize = self.rtp_profile.tag_len();
        if let Some(mki) = &self.mki {
            trailer_len += mki.len();
        }

        // make sure the packet is long at least the header size + mki_len + requested tag size
        if cipher.len() < header.len() + trailer_len {
            return Err(SrtpError::InvalidPacket);
        }

        // Authenticate only if profile requires it
        if self.rtp_profile.tag_len() > 0
            && !constant_time_eq(
                &cipher[cipher.len() - self.rtp_profile.tag_len()..],
                &self.rtp_auth_tag(&cipher[..cipher.len() - trailer_len], roc)?,
            )
        {
            return Err(SrtpError::Authentication);
        }

        // Remove trailer
        cipher.truncate(cipher.len() - trailer_len);

        // Decrypt only if profile requires it
        if self.rtp_profile.key_len() > 0 {
            // Ctr mode: encrypt and decrypt are the same operation
            self.rtp_encrypt(&mut cipher, header, roc)?;
        }
        Ok(cipher)
    }

    fn rtcp_unprotect(
        &self,
        mut cipher: Vec<u8>,
        header: &RtcpHeader,
        index: u32,
        trailer_len: usize,
    ) -> Result<Vec<u8>, SrtpError> {
        // packet size is checked at stream level when retrieving the index
        // no need to repeat

        // Authenticate (always required for RTCP)
        // tag is at the end of the packet and index (4 bytes) is the only part of the trailer
        // being authenticated
        if !constant_time_eq(
            &cipher[cipher.len() - self.rtcp_profile.tag_len()..],
            &self.rtcp_auth_tag(&cipher[..cipher.len() - trailer_len + 4])?,
        ) {
            return Err(SrtpError::Authentication);
        }

        // Remove trailer
        cipher.truncate(cipher.len() - trailer_len);

        // Decrypt only if profile requires it
        if self.rtcp_profile.key_len() > 0 {
            // CTR: encrypt and decrypt are the same operations
            self.rtcp_encrypt(&mut cipher, header, index)?;
        }
        Ok(cipher)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn equals(&self, other: &dyn super::Transform) -> bool {
        // downcast `other` to `AesCmSha1`
        if let Some(other) = other.as_any().downcast_ref::<AesCmSha1>() {
            self == other
        } else {
            // other is not an AesCmSha1, they can't be equals
            false
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::transform::Transform;

    #[test]
    fn nullcipher() -> Result<(), SrtpError> {
        // patterns from libsrtp/test/srtp_driver.c:srtp_validate_null()
        let pattern_rtp_packet = vec![
            0x80, 0x0f, 0x12, 0x34, 0xde, 0xca, 0xfb, 0xad, 0xca, 0xfe, 0xba, 0xbe, 0xab, 0xab,
            0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
        ];

        let pattern_srtp_packet = vec![
            0x80, 0x0f, 0x12, 0x34, 0xde, 0xca, 0xfb, 0xad, 0xca, 0xfe, 0xba, 0xbe, 0xab, 0xab,
            0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
            0xab, 0xa1, 0x36, 0x27, 0x0b, 0x67, 0x91, 0x34, 0xce, 0x9b,
        ];

        let pattern_rtcp_packet = vec![
            0x81, 0xc8, 0x00, 0x0b, 0xca, 0xfe, 0xba, 0xbe, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
            0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
        ];

        let pattern_srtcp_packet = vec![
            0x81, 0xc8, 0x00, 0x0b, 0xca, 0xfe, 0xba, 0xbe, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
            0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0x00, 0x00, 0x00, 0x01,
            0xfe, 0x88, 0xc7, 0xfd, 0xfd, 0x37, 0xeb, 0xce, 0x61, 0x5d,
        ];

        let master_key = vec![
            0xe1, 0xf9, 0x7a, 0x0d, 0x3e, 0x01, 0x8b, 0xe0, 0xd6, 0x4f, 0xa3, 0x2c, 0x06, 0xde,
            0x41, 0x39,
        ];
        let master_salt = vec![
            0x0e, 0xc6, 0x75, 0xad, 0x49, 0x8a, 0xfe, 0xeb, 0xb6, 0x96, 0x0b, 0x3a, 0xab, 0xe6,
        ];

        let e = AesCmSha1::new(
            &master_key,
            &master_salt,
            &None,
            &ProtectionProfile::NullCipherHmacSha180,
            &ProtectionProfile::NullCipherHmacSha180,
        )?;

        let hdr = RtpHeader::new(&pattern_rtp_packet)?;
        let rtcp_hdr = RtcpHeader::new(&pattern_rtcp_packet)?;

        let srtp_packet = e.rtp_protect(pattern_rtp_packet.clone(), &hdr, 0)?;

        assert_eq!(
            srtp_packet, pattern_srtp_packet,
            "Fail to encrypt rtp packet with with null cipher hmac sha1 80:\n{pattern_rtp_packet:?}\n",
        );

        let rtp_packet = e.rtp_unprotect(srtp_packet, &hdr, 0)?;
        assert_eq!(
            rtp_packet, pattern_rtp_packet,
            "Fail to decrypt srtp packet with with null cipher hmac sha1 80:\n{pattern_srtp_packet:?}\n",
        );

        // Note: index is set to 1, as patterns comes from libsrtp which updates the index before
        // encryption so effectively starts at index 1.
        let srtcp_packet = e.rtcp_protect(pattern_rtcp_packet.clone(), &rtcp_hdr, 1)?;
        assert_eq!(
            srtcp_packet, pattern_srtcp_packet,
            "Fail to encrypt rtcp packet with with null cipher hmac sha1 80:\n{pattern_rtcp_packet:?}\n",
        );
        let rtcp_packet = e.rtcp_unprotect(srtcp_packet, &rtcp_hdr, 1, 14)?;
        assert_eq!(
            rtcp_packet, pattern_rtcp_packet,
            "Fail to decrypt srtp packet with with null cipher hmac sha1 80:\n{pattern_srtp_packet:?}\n",
        );
        Ok(())
    }

    #[test]
    fn aes128() -> Result<(), SrtpError> {
        // patterns from libsrtp/test/srtp_driver.c:srtp_validate()
        let pattern_rtp_packet = vec![
            0x80, 0x0f, 0x12, 0x34, 0xde, 0xca, 0xfb, 0xad, 0xca, 0xfe, 0xba, 0xbe, 0xab, 0xab,
            0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
        ];

        let pattern_srtp_packet = vec![
            0x80, 0x0f, 0x12, 0x34, 0xde, 0xca, 0xfb, 0xad, 0xca, 0xfe, 0xba, 0xbe, 0x4e, 0x55,
            0xdc, 0x4c, 0xe7, 0x99, 0x78, 0xd8, 0x8c, 0xa4, 0xd2, 0x15, 0x94, 0x9d, 0x24, 0x02,
            0xb7, 0x8d, 0x6a, 0xcc, 0x99, 0xea, 0x17, 0x9b, 0x8d, 0xbb,
        ];

        let pattern_rtcp_packet = vec![
            0x81, 0xc8, 0x00, 0x0b, 0xca, 0xfe, 0xba, 0xbe, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
            0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
        ];

        let pattern_srtcp_packet = vec![
            0x81, 0xc8, 0x00, 0x0b, 0xca, 0xfe, 0xba, 0xbe, 0x71, 0x28, 0x03, 0x5b, 0xe4, 0x87,
            0xb9, 0xbd, 0xbe, 0xf8, 0x90, 0x41, 0xf9, 0x77, 0xa5, 0xa8, 0x80, 0x00, 0x00, 0x01,
            0x99, 0x3e, 0x08, 0xcd, 0x54, 0xd6, 0xc1, 0x23, 0x07, 0x98,
        ];

        let master_key = vec![
            0xe1, 0xf9, 0x7a, 0x0d, 0x3e, 0x01, 0x8b, 0xe0, 0xd6, 0x4f, 0xa3, 0x2c, 0x06, 0xde,
            0x41, 0x39,
        ];
        let master_salt = vec![
            0x0e, 0xc6, 0x75, 0xad, 0x49, 0x8a, 0xfe, 0xeb, 0xb6, 0x96, 0x0b, 0x3a, 0xab, 0xe6,
        ];

        let hdr = RtpHeader::new(&pattern_rtp_packet)?;
        let rtcp_hdr = RtcpHeader::new(&pattern_rtcp_packet)?;

        // no auth
        let e = AesCmSha1::new(
            &master_key,
            &master_salt,
            &None,
            &ProtectionProfile::Aes128CmNullAuth,
            &ProtectionProfile::Aes128CmHmacSha180,
        )?;

        let srtp_packet = e.rtp_protect(pattern_rtp_packet.clone(), &hdr, 0)?;
        assert_eq!(
            srtp_packet,
            pattern_srtp_packet[0..pattern_rtp_packet.len()],
            "Fail to encrypt rtp packet with with aes128cm null auth:\n{pattern_rtp_packet:?}\n",
        );

        let rtp_packet = e.rtp_unprotect(srtp_packet, &hdr, 0)?;
        assert_eq!(
            rtp_packet, pattern_rtp_packet,
            "Fail to decrypt srtp packet with with aes128cm null auth:\n{pattern_srtp_packet:?}\n",
        );

        // hmac sha1 32
        let e = AesCmSha1::new(
            &master_key,
            &master_salt,
            &None,
            &ProtectionProfile::Aes128CmHmacSha132,
            &ProtectionProfile::Aes128CmHmacSha180,
        )?;

        let srtp_packet = e.rtp_protect(pattern_rtp_packet.clone(), &hdr, 0)?;

        assert_eq!(
            srtp_packet,
            pattern_srtp_packet[0..pattern_rtp_packet.len() + 4],
            "Fail to encrypt rtp packet with with aes128cm hmac sha1 32:\n{pattern_rtp_packet:?}\n",
        );

        let rtp_packet = e.rtp_unprotect(srtp_packet, &hdr, 0)?;
        assert_eq!(
            rtp_packet, pattern_rtp_packet,
            "Fail to decrypt srtp packet with with aes128cm hmac sha1 32:\n{pattern_srtp_packet:?}\n",
        );

        // hmac sha1 80
        let e = AesCmSha1::new(
            &master_key,
            &master_salt,
            &None,
            &ProtectionProfile::Aes128CmHmacSha180,
            &ProtectionProfile::Aes128CmHmacSha180,
        )?;

        let mut srtp_packet = e.rtp_protect(pattern_rtp_packet.clone(), &hdr, 0)?;

        assert_eq!(
            srtp_packet, pattern_srtp_packet,
            "Fail to encrypt rtp packet with with aes128cm hmac sha1 80:\n{pattern_rtp_packet:?}\n",
        );

        let rtp_packet = e.rtp_unprotect(srtp_packet.clone(), &hdr, 0)?;
        assert_eq!(
            rtp_packet, pattern_rtp_packet,
            "Fail to decrypt srtp packet with with aes128cm hmac sha1 80:\n{pattern_srtp_packet:?}\n",
        );

        // Note: index is set to 1, as patterns comes from libsrtp which updates the index before
        // encryption so effectively starts at index 1.
        let mut srtcp_packet = e.rtcp_protect(pattern_rtcp_packet.clone(), &rtcp_hdr, 1)?;
        assert_eq!(
            srtcp_packet, pattern_srtcp_packet,
            "Fail to encrypt rtcp packet with with aes128cm hmac sha1 80:\n{pattern_rtcp_packet:?}\n",
        );
        let rtcp_packet = e.rtcp_unprotect(srtcp_packet.clone(), &rtcp_hdr, 1, 14)?;
        assert_eq!(
            rtcp_packet, pattern_rtcp_packet,
            "Fail to decrypt srtp packet with with aes128cm hmac sha1 80:\n{pattern_srtp_packet:?}\n",
        );

        // failed auth
        // missing a byte
        assert_eq!(
            e.rtp_unprotect(srtp_packet[..srtp_packet.len() - 1].to_vec(), &hdr, 0),
            Err(SrtpError::Authentication)
        );
        assert_eq!(
            e.rtcp_unprotect(
                srtcp_packet[..srtcp_packet.len() - 1].to_vec(),
                &rtcp_hdr,
                1,
                14
            ),
            Err(SrtpError::Authentication)
        );

        // wrong tag
        let last_byte_index = srtp_packet.len() - 1;
        srtp_packet[last_byte_index] ^= 0xff;
        assert_eq!(
            e.rtp_unprotect(srtp_packet.clone(), &hdr, 0),
            Err(SrtpError::Authentication)
        );
        let last_byte_index = srtcp_packet.len() - 1;
        srtcp_packet[last_byte_index] ^= 0xff;
        assert_eq!(
            e.rtcp_unprotect(srtcp_packet, &rtcp_hdr, 1, 14),
            Err(SrtpError::Authentication)
        );

        // too short : check only for rtp as rtcp check on this one is performed at stream level
        assert_eq!(
            e.rtp_unprotect(srtp_packet[..hdr.len() + 5].to_vec(), &hdr, 0),
            Err(SrtpError::InvalidPacket)
        );

        Ok(())
    }

    #[test]
    fn aes192() -> Result<(), SrtpError> {
        // master keys and salt are useless here: use directly session keys and session salt
        // provided in RFC6188 - section 7.3
        let session_key = vec![
            0xea, 0xb2, 0x34, 0x76, 0x4e, 0x51, 0x7b, 0x2d, 0x3d, 0x16, 0x0d, 0x58, 0x7d, 0x8c,
            0x86, 0x21, 0x97, 0x40, 0xf6, 0x5f, 0x99, 0xb6, 0xbc, 0xf7,
        ];
        let session_salt = [
            0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd,
        ];
        let rtp_keys = SessionKeys {
            key: Some(session_key),
            salt: Some(session_salt),
            auth_key: None,
        };
        let rtcp_keys = SessionKeys {
            key: None,
            salt: None,
            auth_key: None,
        };

        // zeroised payload, seq_num and SSRC
        let pattern_rtp_packet = vec![
            0x80, 0x0f, 0x00, 0x00, 0xde, 0xca, 0xfb, 0xad, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
        ];

        let pattern_srtp_packet = vec![
            0x80, 0x0f, 0x00, 0x00, 0xde, 0xca, 0xfb, 0xad, 0x00, 0x00, 0x00, 0x00, 0x35, 0x09,
            0x6c, 0xba, 0x46, 0x10, 0x02, 0x8d, 0xc1, 0xb5, 0x75, 0x03, 0x80, 0x4c, 0xe3, 0x7c,
            0x5d, 0xe9, 0x86, 0x29, 0x1d, 0xcc, 0xe1, 0x61, 0xd5, 0x16, 0x5e, 0xc4, 0x56, 0x8f,
            0x5c, 0x9a, 0x47, 0x4a, 0x40, 0xc7, 0x78, 0x94, 0xbc, 0x17, 0x18, 0x02, 0x02, 0x27,
            0x2a, 0x4c, 0x26, 0x4d,
        ];

        let hdr = RtpHeader::new(&pattern_rtp_packet)?;

        let e = AesCmSha1 {
            rtp_profile: ProtectionProfile::Aes192CmNullAuth, // do not provide auth
            rtcp_profile: ProtectionProfile::Aes192CmHmacSha180, // we do not care about rtcp
            rtp_key: rtp_keys,
            rtcp_key: rtcp_keys,
            mki: None,
        };

        let srtp_packet = e.rtp_protect(pattern_rtp_packet.clone(), &hdr, 0)?;

        assert_eq!(
            srtp_packet.clone(),
            pattern_srtp_packet.clone()[0..pattern_rtp_packet.len()],
            "Fail to encrypt rtp packet with with aes192cm null auth {pattern_rtp_packet:?}"
        );

        Ok(())
    }

    #[test]
    fn aes256() -> Result<(), SrtpError> {
        let master_key = vec![
            0xf0, 0xf0, 0x49, 0x14, 0xb5, 0x13, 0xf2, 0x76, 0x3a, 0x1b, 0x1f, 0xa1, 0x30, 0xf1,
            0x0e, 0x29, 0x98, 0xf6, 0xf6, 0xe4, 0x3e, 0x43, 0x09, 0xd1, 0xe6, 0x22, 0xa0, 0xe3,
            0x32, 0xb9, 0xf1, 0xb6,
        ];

        let master_salt = vec![
            0x3b, 0x04, 0x80, 0x3d, 0xe5, 0x1e, 0xe7, 0xc9, 0x64, 0x23, 0xab, 0x5b, 0x78, 0xd2,
        ];
        let pattern_rtp_packet = vec![
            0x80, 0x0f, 0x12, 0x34, 0xde, 0xca, 0xfb, 0xad, 0xca, 0xfe, 0xba, 0xbe, 0xab, 0xab,
            0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
        ];

        let pattern_srtp_packet = vec![
            0x80, 0x0f, 0x12, 0x34, 0xde, 0xca, 0xfb, 0xad, 0xca, 0xfe, 0xba, 0xbe, 0xf1, 0xd9,
            0xde, 0x17, 0xff, 0x25, 0x1f, 0xf1, 0xaa, 0x00, 0x77, 0x74, 0xb0, 0xb4, 0xb4, 0x0d,
            0xa0, 0x8d, 0x9d, 0x9a, 0x5b, 0x3a, 0x55, 0xd8, 0x87, 0x3b,
        ];

        let hdr = RtpHeader::new(&pattern_rtp_packet)?;

        // No auth
        let e = AesCmSha1::new(
            &master_key,
            &master_salt,
            &None,
            &ProtectionProfile::Aes256CmNullAuth,
            &ProtectionProfile::Aes256CmHmacSha180,
        )?;

        let srtp_packet = e.rtp_protect(pattern_rtp_packet.clone(), &hdr, 0)?;

        assert_eq!(
            srtp_packet,
            pattern_srtp_packet[0..pattern_rtp_packet.len()],
            "Fail to encrypt rtp packet with with aes256cm null auth:\n{pattern_rtp_packet:?}\n",
        );

        let rtp_packet = e.rtp_unprotect(srtp_packet, &hdr, 0)?;
        assert_eq!(
            rtp_packet, pattern_rtp_packet,
            "Fail to decrypt srtp packet with with aes256cm null auth:\n{pattern_srtp_packet:?}\n",
        );

        // hmac sha1 32
        let e = AesCmSha1::new(
            &master_key,
            &master_salt,
            &None,
            &ProtectionProfile::Aes256CmHmacSha132,
            &ProtectionProfile::Aes256CmHmacSha180,
        )?;

        let srtp_packet = e.rtp_protect(pattern_rtp_packet.clone(), &hdr, 0)?;

        assert_eq!(
            srtp_packet,
            pattern_srtp_packet[0..pattern_rtp_packet.len() + 4],
            "Fail to encrypt rtp packet with with aes256cm hmac sha1 32:\n{pattern_rtp_packet:?}\n",
        );

        let rtp_packet = e.rtp_unprotect(srtp_packet, &hdr, 0)?;
        assert_eq!(
            rtp_packet, pattern_rtp_packet,
            "Fail to decrypt srtp packet with with aes256cm hmac sha1 32 auth:\n{pattern_srtp_packet:?}\n",
        );

        // hmac sha1 80
        let e = AesCmSha1::new(
            &master_key,
            &master_salt,
            &None,
            &ProtectionProfile::Aes256CmHmacSha180,
            &ProtectionProfile::Aes256CmHmacSha180,
        )?;

        let srtp_packet = e.rtp_protect(pattern_rtp_packet.clone(), &hdr, 0)?;

        assert_eq!(
            srtp_packet, pattern_srtp_packet,
            "Fail to encrypt rtp packet with with aes256cm null auth:\n{pattern_rtp_packet:?}\n",
        );

        let rtp_packet = e.rtp_unprotect(srtp_packet, &hdr, 0)?;
        assert_eq!(
            rtp_packet, pattern_rtp_packet,
            "Fail to decrypt srtp packet with with aes256cm hmac sha1 80 auth:\n{pattern_srtp_packet:?}\n",
        );

        Ok(())
    }

    #[test]
    fn mki() -> Result<(), SrtpError> {
        // patterns from libsrtp/test/srtp_driver.c:srtp_validate_mki()
        let pattern_rtp_packet = vec![
            0x80, 0x0f, 0x12, 0x34, 0xde, 0xca, 0xfb, 0xad, 0xca, 0xfe, 0xba, 0xbe, 0xab, 0xab,
            0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
        ];

        let pattern_srtp_packet = vec![
            0x80, 0x0f, 0x12, 0x34, 0xde, 0xca, 0xfb, 0xad, 0xca, 0xfe, 0xba, 0xbe, 0x4e, 0x55,
            0xdc, 0x4c, 0xe7, 0x99, 0x78, 0xd8, 0x8c, 0xa4, 0xd2, 0x15, 0x94, 0x9d, 0x24, 0x02,
            0xe1, 0xf9, 0x7a, 0x0d, 0xb7, 0x8d, 0x6a, 0xcc, 0x99, 0xea, 0x17, 0x9b, 0x8d, 0xbb,
        ];

        let pattern_rtcp_packet = vec![
            0x81, 0xc8, 0x00, 0x0b, 0xca, 0xfe, 0xba, 0xbe, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
            0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
        ];

        let pattern_srtcp_packet = vec![
            0x81, 0xc8, 0x00, 0x0b, 0xca, 0xfe, 0xba, 0xbe, 0x71, 0x28, 0x03, 0x5b, 0xe4, 0x87,
            0xb9, 0xbd, 0xbe, 0xf8, 0x90, 0x41, 0xf9, 0x77, 0xa5, 0xa8, 0x80, 0x00, 0x00, 0x01,
            0xe1, 0xf9, 0x7a, 0x0d, 0x99, 0x3e, 0x08, 0xcd, 0x54, 0xd6, 0xc1, 0x23, 0x07, 0x98,
        ];

        let master_key = vec![
            0xe1, 0xf9, 0x7a, 0x0d, 0x3e, 0x01, 0x8b, 0xe0, 0xd6, 0x4f, 0xa3, 0x2c, 0x06, 0xde,
            0x41, 0x39,
        ];
        let master_salt = vec![
            0x0e, 0xc6, 0x75, 0xad, 0x49, 0x8a, 0xfe, 0xeb, 0xb6, 0x96, 0x0b, 0x3a, 0xab, 0xe6,
        ];

        let mki_id = vec![0xe1, 0xf9, 0x7a, 0x0d];

        let hdr = RtpHeader::new(&pattern_rtp_packet)?;
        let rtcp_hdr = RtcpHeader::new(&pattern_rtcp_packet)?;

        let e = AesCmSha1::new(
            &master_key,
            &master_salt,
            &Some(mki_id),
            &ProtectionProfile::Aes128CmHmacSha180,
            &ProtectionProfile::Aes128CmHmacSha180,
        )?;

        let srtp_packet = e.rtp_protect(pattern_rtp_packet.clone(), &hdr, 0)?;

        assert_eq!(
            srtp_packet, pattern_srtp_packet,
            "Fail to encrypt rtp packet with with aes128cm hmac sha1 80:\n{pattern_rtp_packet:?}\n",
        );

        let rtp_packet = e.rtp_unprotect(srtp_packet, &hdr, 0)?;
        assert_eq!(
            rtp_packet, pattern_rtp_packet,
            "Fail to decrypt srtp packet with with aes128cm hmac sha1 80:\n{pattern_srtp_packet:?}\n",
        );

        // Note: index is set to 1, as patterns comes from libsrtp which updates the index before
        // encryption so effectively starts at index 1.
        let srtcp_packet = e.rtcp_protect(pattern_rtcp_packet.clone(), &rtcp_hdr, 1)?;
        assert_eq!(
            srtcp_packet, pattern_srtcp_packet,
            "Fail to encrypt rtcp packet with with aes128cm hmac sha1 80:\n{pattern_rtcp_packet:?}\n",
        );
        let rtcp_packet = e.rtcp_unprotect(srtcp_packet, &rtcp_hdr, 1, 18)?;
        assert_eq!(
            rtcp_packet, pattern_rtcp_packet,
            "Fail to decrypt srtp packet with with aes128cm hmac sha1 80:\n{pattern_srtp_packet:?}\n",
        );

        Ok(())
    }
}
