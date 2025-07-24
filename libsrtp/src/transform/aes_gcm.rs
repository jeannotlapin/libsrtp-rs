use crate::SrtpError;
use crate::header::{RtcpHeader, RtpHeader};
use crate::key_derivation::{KdfLabel, aes_cm_kdf};
use crate::protection_profile::ProtectionProfile;
use aes_gcm::{AeadInPlace, Aes128Gcm, Aes256Gcm, Key, Nonce, Tag, aead::KeyInit};
use std::any::Any;

use zeroize::{Zeroize, ZeroizeOnDrop};

// all transforms described in RFC 7714 have a tag length of 16 bytes
// The tag is integrated to the payload and not managed as a separated auth tag
const AES_GCM_TAG_LEN: usize = 16;

#[derive(PartialEq, Zeroize, ZeroizeOnDrop)]
struct SessionKeys {
    key: Vec<u8>,
    salt: [u8; 12],
}

#[derive(PartialEq)]
pub struct AesGcm {
    rtp_profile: ProtectionProfile,
    rtcp_profile: ProtectionProfile,
    rtp_key: SessionKeys,
    rtcp_key: SessionKeys,
    mki: Option<Vec<u8>>,
}

impl AesGcm {
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
        if !(*rtp_profile == ProtectionProfile::AeadAes128Gcm
            || *rtp_profile == ProtectionProfile::AeadAes256Gcm)
        {
            return Err(SrtpError::TransformDispatch);
        }
        // Gcm use AES-CM prf -> salt output is 14 bytes long while we only need 12: truncate
        let mut salt = aes_cm_kdf(KdfLabel::RtpSalt, master_key, master_salt)?;
        salt.truncate(rtp_profile.salt_len());
        let rtp_keys = SessionKeys {
            key: aes_cm_kdf(KdfLabel::RtpEncrypt, master_key, master_salt)?,
            salt: salt
                .as_slice()
                .try_into()
                .map_err(|_| SrtpError::KdfDispatch)?,
        };

        // Derive RTCP session key
        if !(*rtcp_profile == ProtectionProfile::AeadAes128Gcm
            || *rtcp_profile == ProtectionProfile::AeadAes256Gcm)
        {
            return Err(SrtpError::TransformDispatch);
        }
        let mut salt = aes_cm_kdf(KdfLabel::RtcpSalt, master_key, master_salt)?;
        salt.truncate(rtcp_profile.salt_len());
        let rtcp_keys = SessionKeys {
            key: aes_cm_kdf(KdfLabel::RtcpEncrypt, master_key, master_salt)?,
            salt: salt.try_into().map_err(|_| SrtpError::KdfDispatch)?,
        };

        Ok(Self {
            rtp_profile: *rtp_profile,
            rtcp_profile: *rtcp_profile,
            rtp_key: rtp_keys,
            rtcp_key: rtcp_keys,
            mki: mki.clone(),
        })
    }

    fn get_rtp_iv(&self, header: &RtpHeader, roc: u32) -> [u8; 12] {
        // Compute IV = (k_s * 2^16) XOR (SSRC * 2^64) XOR (i * 2^16)  [RFC7714 - 8.1]
        // IV = 0x0 <2bytes> || SSRC <4bytes> || ROC <4bytes> || seqnum<2bytes>
        //    ^                         session salt <12 bytes>
        let mut iv: [u8; 12] = self.rtp_key.salt;
        let ssrc_bytes = header.ssrc().to_be_bytes();
        let roc_bytes = roc.to_be_bytes();
        let seq_num_bytes = header.seq_num().to_be_bytes();
        for i in 0..4 {
            iv[2 + i] ^= ssrc_bytes[i];
            iv[6 + i] ^= roc_bytes[i];
        }
        iv[10] ^= seq_num_bytes[0];
        iv[11] ^= seq_num_bytes[1];

        iv
    }

    fn get_rtcp_iv(&self, header: &RtcpHeader, index: u32) -> [u8; 12] {
        // Compute IV = (k_s * 2^16) XOR (SSRC * 2^64) XOR (i * 2^16)  [RFC7714 - 9.1]
        // IV = 0x0 <2bytes> || SSRC <4bytes> || 0x0 <2bytes> || index <4bytes>
        //    ^                         session salt <12 bytes>
        let mut iv: [u8; 12] = self.rtcp_key.salt;
        let ssrc_bytes = header.ssrc().to_be_bytes();
        let index_bytes = index.to_be_bytes();
        for i in 0..4 {
            iv[2 + i] ^= ssrc_bytes[i];
            iv[8 + i] ^= index_bytes[i];
        }
        iv
    }

    fn rtp_encrypt(
        &self,
        rtp_packet: &mut Vec<u8>,
        header: &RtpHeader,
        roc: u32,
    ) -> Result<(), SrtpError> {
        let iv = self.get_rtp_iv(header, roc);
        let nonce = Nonce::from_slice(&iv);
        let (ad, payload) = rtp_packet.split_at_mut(header.len());
        // Encryption
        match self.rtp_profile {
            ProtectionProfile::AeadAes128Gcm => {
                let cipher = Aes128Gcm::new(Key::<Aes128Gcm>::from_slice(&self.rtp_key.key));
                let tag = cipher
                    .encrypt_in_place_detached(nonce, ad, payload)
                    .map_err(|_| SrtpError::Encryption)?;
                rtp_packet.extend_from_slice(tag.as_slice());
            }
            ProtectionProfile::AeadAes256Gcm => {
                let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&self.rtp_key.key));
                let tag = cipher
                    .encrypt_in_place_detached(nonce, ad, payload)
                    .map_err(|_| SrtpError::Encryption)?;
                rtp_packet.extend_from_slice(tag.as_slice());
            }

            _ => {
                return Err(SrtpError::TransformDispatch);
            }
        }
        Ok(())
    }

    fn rtp_decrypt(
        &self,
        srtp_packet: &mut Vec<u8>,
        header: &RtpHeader,
        roc: u32,
    ) -> Result<(), SrtpError> {
        let iv = self.get_rtp_iv(header, roc);
        let nonce = Nonce::from_slice(&iv);
        let (ad, payload_tag) = srtp_packet.split_at_mut(header.len());
        let (payload, tag) = payload_tag.split_at_mut(payload_tag.len() - AES_GCM_TAG_LEN);
        let tag = Tag::from_slice(tag);
        // Decryption
        match self.rtp_profile {
            ProtectionProfile::AeadAes128Gcm => {
                let cipher = Aes128Gcm::new(Key::<Aes128Gcm>::from_slice(&self.rtp_key.key));
                cipher
                    .decrypt_in_place_detached(nonce, ad, payload, tag)
                    .map_err(|_| SrtpError::Authentication)?;
            }
            ProtectionProfile::AeadAes256Gcm => {
                let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&self.rtp_key.key));
                cipher
                    .decrypt_in_place_detached(nonce, ad, payload, tag)
                    .map_err(|_| SrtpError::Authentication)?;
            }
            _ => {
                return Err(SrtpError::TransformDispatch);
            }
        }
        srtp_packet.truncate(srtp_packet.len() - AES_GCM_TAG_LEN);
        Ok(())
    }

    fn rtcp_encrypt(
        &self,
        rtcp_packet: &mut Vec<u8>,
        header: &RtcpHeader,
        index: u32,
        esrtcp: &[u8],
    ) -> Result<(), SrtpError> {
        let iv = self.get_rtcp_iv(header, index);
        let nonce = Nonce::from_slice(&iv);
        let (ad, payload) = rtcp_packet.split_at_mut(RtcpHeader::len());
        // Append the esrtcp word to the header to form the AD
        let mut ad = ad.to_vec();
        ad.extend(esrtcp);
        // Encryption
        match self.rtcp_profile {
            ProtectionProfile::AeadAes128Gcm => {
                let cipher = Aes128Gcm::new(Key::<Aes128Gcm>::from_slice(&self.rtcp_key.key));
                let tag = cipher
                    .encrypt_in_place_detached(nonce, &ad, payload)
                    .map_err(|_| SrtpError::Encryption)?;
                rtcp_packet.extend_from_slice(tag.as_slice());
            }
            ProtectionProfile::AeadAes256Gcm => {
                let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&self.rtcp_key.key));
                let tag = cipher
                    .encrypt_in_place_detached(nonce, &ad, payload)
                    .map_err(|_| SrtpError::Encryption)?;
                rtcp_packet.extend_from_slice(tag.as_slice());
            }

            _ => {
                return Err(SrtpError::TransformDispatch);
            }
        }
        Ok(())
    }

    fn rtcp_decrypt(
        &self,
        srtcp_packet: &mut Vec<u8>,
        header: &RtcpHeader,
        index: u32,
    ) -> Result<(), SrtpError> {
        let iv = self.get_rtcp_iv(header, index);
        let nonce = Nonce::from_slice(&iv);
        let (ad, payload_tag) = srtcp_packet.split_at_mut(RtcpHeader::len());
        let (payload, tag) = payload_tag.split_at_mut(payload_tag.len() - AES_GCM_TAG_LEN);
        let tag = Tag::from_slice(tag);
        // Append the esrtcp word to the header to form the AD
        let mut ad = ad.to_vec();
        ad.extend((index | 0x80000000).to_be_bytes());
        // Decryption
        match self.rtp_profile {
            ProtectionProfile::AeadAes128Gcm => {
                let cipher = Aes128Gcm::new(Key::<Aes128Gcm>::from_slice(&self.rtcp_key.key));
                cipher
                    .decrypt_in_place_detached(nonce, &ad, payload, tag)
                    .map_err(|_| SrtpError::Authentication)?;
            }
            ProtectionProfile::AeadAes256Gcm => {
                let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&self.rtcp_key.key));
                cipher
                    .decrypt_in_place_detached(nonce, &ad, payload, tag)
                    .map_err(|_| SrtpError::Authentication)?;
            }
            _ => {
                return Err(SrtpError::TransformDispatch);
            }
        }
        srtcp_packet.truncate(srtcp_packet.len() - AES_GCM_TAG_LEN);
        Ok(())
    }
}

impl super::Transform for AesGcm {
    fn rtp_protect(
        &self,
        mut plain: Vec<u8>,
        header: &RtpHeader,
        roc: u32,
    ) -> Result<Vec<u8>, SrtpError> {
        self.rtp_encrypt(&mut plain, header, roc)?;

        // Add mki if present
        if let Some(mki) = &self.mki {
            plain.extend(mki);
        }
        Ok(plain)
    }

    fn rtcp_protect(
        &self,
        mut plain: Vec<u8>,
        header: &RtcpHeader,
        index: u32,
    ) -> Result<Vec<u8>, SrtpError> {
        // compute the trailer : E flag | index
        let esrtcp = (index | 0x80000000).to_be_bytes();
        self.rtcp_encrypt(&mut plain, header, index, &esrtcp)?;
        // set the E flag in trailer and index
        plain.extend(esrtcp);

        // Add mki if present
        if let Some(mki) = &self.mki {
            plain.extend(mki);
        }
        Ok(plain)
    }

    fn rtp_unprotect(
        &self,
        mut cipher: Vec<u8>,
        header: &RtpHeader,
        roc: u32,
    ) -> Result<Vec<u8>, SrtpError> {
        // Compute trailer len : mki
        let mut trailer_len: usize = 0;
        if let Some(mki) = &self.mki {
            trailer_len += mki.len();
        }

        // make sure the packet is long at least the header size + gcm auth tag + trailer
        if cipher.len() < header.len() + trailer_len + AES_GCM_TAG_LEN {
            return Err(SrtpError::InvalidPacket);
        }

        // Remove trailer
        cipher.truncate(cipher.len() - trailer_len);

        // Auth and decrypt
        self.rtp_decrypt(&mut cipher, header, roc)?;
        Ok(cipher)
    }

    fn rtcp_unprotect(
        &self,
        mut cipher: Vec<u8>,
        header: &RtcpHeader,
        index: u32,
        trailer_len: usize,
    ) -> Result<Vec<u8>, SrtpError> {
        // make sure the packet is long at least the header size + gcm auth tag + trailer
        if cipher.len() < RtcpHeader::len() + trailer_len + AES_GCM_TAG_LEN {
            return Err(SrtpError::InvalidPacket);
        }

        // Remove trailer
        cipher.truncate(cipher.len() - trailer_len);

        // Auth and decrypt
        self.rtcp_decrypt(&mut cipher, header, index)?;
        Ok(cipher)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn equals(&self, other: &dyn super::Transform) -> bool {
        // downcast `other` to `AesGcm`
        if let Some(other) = other.as_any().downcast_ref::<AesGcm>() {
            self == other
        } else {
            // other is not an AesGcm, they can't be equals
            false
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::transform::Transform;

    #[test]
    fn aes128() -> Result<(), SrtpError> {
        // patterns from RFC 7714 - 16.1 and 17.1
        let pattern_rtp_packet = vec![
            0x80, 0x40, 0xf1, 0x7b, 0x80, 0x41, 0xf8, 0xd3, 0x55, 0x01, 0xa0, 0xb2, 0x47, 0x61,
            0x6c, 0x6c, 0x69, 0x61, 0x20, 0x65, 0x73, 0x74, 0x20, 0x6f, 0x6d, 0x6e, 0x69, 0x73,
            0x20, 0x64, 0x69, 0x76, 0x69, 0x73, 0x61, 0x20, 0x69, 0x6e, 0x20, 0x70, 0x61, 0x72,
            0x74, 0x65, 0x73, 0x20, 0x74, 0x72, 0x65, 0x73,
        ];

        let pattern_srtp_packet = vec![
            0x80, 0x40, 0xf1, 0x7b, 0x80, 0x41, 0xf8, 0xd3, 0x55, 0x01, 0xa0, 0xb2, 0xf2, 0x4d,
            0xe3, 0xa3, 0xfb, 0x34, 0xde, 0x6c, 0xac, 0xba, 0x86, 0x1c, 0x9d, 0x7e, 0x4b, 0xca,
            0xbe, 0x63, 0x3b, 0xd5, 0x0d, 0x29, 0x4e, 0x6f, 0x42, 0xa5, 0xf4, 0x7a, 0x51, 0xc7,
            0xd1, 0x9b, 0x36, 0xde, 0x3a, 0xdf, 0x88, 0x33, 0x89, 0x9d, 0x7f, 0x27, 0xbe, 0xb1,
            0x6a, 0x91, 0x52, 0xcf, 0x76, 0x5e, 0xe4, 0x39, 0x0c, 0xce,
        ];

        let pattern_rtcp_packet = vec![
            0x81, 0xc8, 0x00, 0x0d, 0x4d, 0x61, 0x72, 0x73, 0x4e, 0x54, 0x50, 0x31, 0x4e, 0x54,
            0x50, 0x32, 0x52, 0x54, 0x50, 0x20, 0x00, 0x00, 0x04, 0x2a, 0x00, 0x00, 0xe9, 0x30,
            0x4c, 0x75, 0x6e, 0x61, 0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef, 0xde, 0xad,
            0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef,
        ];

        let pattern_srtcp_packet = vec![
            0x81, 0xc8, 0x00, 0x0d, 0x4d, 0x61, 0x72, 0x73, 0x63, 0xe9, 0x48, 0x85, 0xdc, 0xda,
            0xb6, 0x7c, 0xa7, 0x27, 0xd7, 0x66, 0x2f, 0x6b, 0x7e, 0x99, 0x7f, 0xf5, 0xc0, 0xf7,
            0x6c, 0x06, 0xf3, 0x2d, 0xc6, 0x76, 0xa5, 0xf1, 0x73, 0x0d, 0x6f, 0xda, 0x4c, 0xe0,
            0x9b, 0x46, 0x86, 0x30, 0x3d, 0xed, 0x0b, 0xb9, 0x27, 0x5b, 0xc8, 0x4a, 0xa4, 0x58,
            0x96, 0xcf, 0x4d, 0x2f, 0xc5, 0xab, 0xf8, 0x72, 0x45, 0xd9, 0xea, 0xde, 0x80, 0x00,
            0x05, 0xd4,
        ];

        // key and salt are actually session key and session salt in the RFC test
        // vectors
        let master_key = vec![
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f,
        ];
        let master_salt = [
            0x51, 0x75, 0x69, 0x64, 0x20, 0x70, 0x72, 0x6f, 0x20, 0x71, 0x75, 0x6f,
        ];

        let hdr = RtpHeader::new(&pattern_rtp_packet)?;
        let rtcp_hdr = RtcpHeader::new(&pattern_rtcp_packet)?;

        let mut e = AesGcm::new(
            &master_key,
            &master_salt,
            &None,
            &ProtectionProfile::AeadAes128Gcm,
            &ProtectionProfile::AeadAes128Gcm,
        )?;

        // key and salt are actually session key and session salt in the RFC test
        // vectors
        e.rtp_key = SessionKeys {
            key: master_key.clone(),
            salt: master_salt,
        };
        e.rtcp_key = SessionKeys {
            key: master_key.clone(),
            salt: master_salt,
        };

        let mut srtp_packet = e.rtp_protect(pattern_rtp_packet.clone(), &hdr, 0)?;
        assert_eq!(
            srtp_packet, pattern_srtp_packet,
            "Fail to encrypt rtp packet with with aes128gcm:\n{pattern_rtp_packet:?}\n",
        );

        let rtp_packet = e.rtp_unprotect(srtp_packet.clone(), &hdr, 0)?;
        assert_eq!(
            rtp_packet, pattern_rtp_packet,
            "Fail to decrypt srtp packet with with aes128cm:\n{pattern_srtp_packet:?}\n",
        );

        let mut srtcp_packet =
            e.rtcp_protect(pattern_rtcp_packet.clone(), &rtcp_hdr, 0x000005d4)?;
        assert_eq!(
            srtcp_packet, pattern_srtcp_packet,
            "Fail to encrypt rtcp packet with with aes128gcm:\n{pattern_rtcp_packet:?}\n",
        );

        let rtcp_packet = e.rtcp_unprotect(srtcp_packet.clone(), &rtcp_hdr, 0x000005d4, 4)?;
        assert_eq!(
            rtcp_packet, pattern_rtcp_packet,
            "Fail to decrypt srtcp packet with with aes128cm:\n{pattern_srtcp_packet:?}\n",
        );

        // wrong tag
        let last_byte_index = srtp_packet.len() - 1;
        srtp_packet[last_byte_index] ^= 0xff;
        assert_eq!(
            e.rtp_unprotect(srtp_packet.clone(), &hdr, 0),
            Err(SrtpError::Authentication)
        );
        let last_byte_index = srtcp_packet.len() - 5; // rtcp : tag is before the trailer of size 4
        srtcp_packet[last_byte_index] ^= 0xff;
        assert_eq!(
            e.rtcp_unprotect(srtcp_packet.clone(), &rtcp_hdr, 0x000005d4, 4),
            Err(SrtpError::Authentication)
        );

        // too short
        assert_eq!(
            e.rtp_unprotect(srtp_packet[..hdr.len() + 5].to_vec(), &hdr, 0),
            Err(SrtpError::InvalidPacket)
        );
        assert_eq!(
            e.rtcp_unprotect(
                srtcp_packet[..hdr.len() + 5].to_vec(),
                &rtcp_hdr,
                0x000005d4,
                4
            ),
            Err(SrtpError::InvalidPacket)
        );

        Ok(())
    }

    #[test]
    fn aes256() -> Result<(), SrtpError> {
        // patterns from RFC 7714 - 16.2 and 17.2
        let pattern_rtp_packet = vec![
            0x80, 0x40, 0xf1, 0x7b, 0x80, 0x41, 0xf8, 0xd3, 0x55, 0x01, 0xa0, 0xb2, 0x47, 0x61,
            0x6c, 0x6c, 0x69, 0x61, 0x20, 0x65, 0x73, 0x74, 0x20, 0x6f, 0x6d, 0x6e, 0x69, 0x73,
            0x20, 0x64, 0x69, 0x76, 0x69, 0x73, 0x61, 0x20, 0x69, 0x6e, 0x20, 0x70, 0x61, 0x72,
            0x74, 0x65, 0x73, 0x20, 0x74, 0x72, 0x65, 0x73,
        ];

        let pattern_srtp_packet = vec![
            0x80, 0x40, 0xf1, 0x7b, 0x80, 0x41, 0xf8, 0xd3, 0x55, 0x01, 0xa0, 0xb2, 0x32, 0xb1,
            0xde, 0x78, 0xa8, 0x22, 0xfe, 0x12, 0xef, 0x9f, 0x78, 0xfa, 0x33, 0x2e, 0x33, 0xaa,
            0xb1, 0x80, 0x12, 0x38, 0x9a, 0x58, 0xe2, 0xf3, 0xb5, 0x0b, 0x2a, 0x02, 0x76, 0xff,
            0xae, 0x0f, 0x1b, 0xa6, 0x37, 0x99, 0xb8, 0x7b, 0x7a, 0xa3, 0xdb, 0x36, 0xdf, 0xff,
            0xd6, 0xb0, 0xf9, 0xbb, 0x78, 0x78, 0xd7, 0xa7, 0x6c, 0x13,
        ];

        let pattern_rtcp_packet = vec![
            0x81, 0xc8, 0x00, 0x0d, 0x4d, 0x61, 0x72, 0x73, 0x4e, 0x54, 0x50, 0x31, 0x4e, 0x54,
            0x50, 0x32, 0x52, 0x54, 0x50, 0x20, 0x00, 0x00, 0x04, 0x2a, 0x00, 0x00, 0xe9, 0x30,
            0x4c, 0x75, 0x6e, 0x61, 0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef, 0xde, 0xad,
            0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef,
        ];

        let pattern_srtcp_packet = vec![
            0x81, 0xc8, 0x00, 0x0d, 0x4d, 0x61, 0x72, 0x73, 0xd5, 0x0a, 0xe4, 0xd1, 0xf5, 0xce,
            0x5d, 0x30, 0x4b, 0xa2, 0x97, 0xe4, 0x7d, 0x47, 0x0c, 0x28, 0x2c, 0x3e, 0xce, 0x5d,
            0xbf, 0xfe, 0x0a, 0x50, 0xa2, 0xea, 0xa5, 0xc1, 0x11, 0x05, 0x55, 0xbe, 0x84, 0x15,
            0xf6, 0x58, 0xc6, 0x1d, 0xe0, 0x47, 0x6f, 0x1b, 0x6f, 0xad, 0x1d, 0x1e, 0xb3, 0x0c,
            0x44, 0x46, 0x83, 0x9f, 0x57, 0xff, 0x6f, 0x6c, 0xb2, 0x6a, 0xc3, 0xbe, 0x80, 0x00,
            0x05, 0xd4,
        ];

        // key and salt are actually session key and session salt in the RFC test
        // vectors
        let master_key = vec![
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
            0x1c, 0x1d, 0x1e, 0x1f,
        ];
        let master_salt = [
            0x51, 0x75, 0x69, 0x64, 0x20, 0x70, 0x72, 0x6f, 0x20, 0x71, 0x75, 0x6f,
        ];

        let hdr = RtpHeader::new(&pattern_rtp_packet)?;
        let rtcp_hdr = RtcpHeader::new(&pattern_rtcp_packet)?;

        let mut e = AesGcm::new(
            &master_key,
            &master_salt,
            &None,
            &ProtectionProfile::AeadAes256Gcm,
            &ProtectionProfile::AeadAes256Gcm,
        )?;

        // key and salt are actually session key and session salt in the RFC test
        // vectors
        e.rtp_key = SessionKeys {
            key: master_key.clone(),
            salt: master_salt,
        };
        e.rtcp_key = SessionKeys {
            key: master_key.clone(),
            salt: master_salt,
        };

        let srtp_packet = e.rtp_protect(pattern_rtp_packet.clone(), &hdr, 0)?;
        assert_eq!(
            srtp_packet, pattern_srtp_packet,
            "Fail to encrypt rtp packet with with aes256gcm:\n{pattern_rtp_packet:?}\n",
        );

        let rtp_packet = e.rtp_unprotect(srtp_packet, &hdr, 0)?;
        assert_eq!(
            rtp_packet, pattern_rtp_packet,
            "Fail to decrypt srtp packet with with aes256cm:\n{pattern_srtp_packet:?}\n",
        );

        let srtcp_packet = e.rtcp_protect(pattern_rtcp_packet.clone(), &rtcp_hdr, 0x000005d4)?;
        assert_eq!(
            srtcp_packet, pattern_srtcp_packet,
            "Fail to encrypt rtcp packet with with aes256gcm:\n{pattern_rtcp_packet:?}\n",
        );

        let rtcp_packet = e.rtcp_unprotect(srtcp_packet, &rtcp_hdr, 0x000005d4, 4)?;
        assert_eq!(
            rtcp_packet, pattern_rtcp_packet,
            "Fail to decrypt srtcp packet with with aes256cm:\n{pattern_srtcp_packet:?}\n",
        );

        Ok(())
    }
}
