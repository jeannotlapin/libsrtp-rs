use super::SrtpError;
use ctr::cipher::{KeyIvInit, StreamCipher, generic_array::GenericArray};

// Session salt is always 14 bytes for any derivation type
const SESSION_SALT_SIZE: usize = 14;
// Session auth Key is always 20 bytes for any derivation type that requires it
const SESSION_AUTH_KEY_SIZE: usize = 20;

#[repr(u8)]
pub enum KdfLabel {
    RtpEncrypt = 0x00,
    RtpAuthTag = 0x01,
    RtpSalt = 0x02,
    RtcpEncrypt = 0x03,
    RtcpAuthTag = 0x04,
    RtcpSalt = 0x05,
}

type Aes128Ctr32BE = ctr::Ctr32BE<aes::Aes128>;
type Aes192Ctr32BE = ctr::Ctr32BE<aes::Aes192>;
type Aes256Ctr32BE = ctr::Ctr32BE<aes::Aes256>;

impl KdfLabel {
    // Output size depends on type of key and master key size for encryption key
    fn output_size(&self, key_size: usize) -> usize {
        match self {
            KdfLabel::RtpEncrypt | KdfLabel::RtcpEncrypt => key_size,
            KdfLabel::RtpSalt | KdfLabel::RtcpSalt => SESSION_SALT_SIZE,
            KdfLabel::RtpAuthTag | KdfLabel::RtcpAuthTag => SESSION_AUTH_KEY_SIZE,
        }
    }
}

pub fn aes_cm_kdf(
    label: KdfLabel,
    master_key: &[u8],
    master_salt: &[u8],
) -> Result<Vec<u8>, SrtpError> {
    // Prepare a vector with the correct output size (computed from the key label and possibly the
    // master key size) Use it as zeroed input stream for the AES-CTR so we get they keystream we
    // need
    let mut out = vec![0u8; label.output_size(master_key.len())];
    // Build prf input: key derivation rate different than zero is not supported
    // So prf input is left to: master_salt || 0x00 || 0x00
    // the 16 bytes buffer is xored at index 7 with label
    let mut prf_input: [u8; 16] = [0; 16];
    // master salt can be an empty vector, is such case it is considered all 0 so the next line
    // will do nothing
    prf_input[..master_salt.len()].copy_from_slice(master_salt);
    prf_input[7] ^= label as u8;
    // master key must be 16, 24 or 32 bytes long, proper AES is selected based on master key size
    match master_key.len() {
        16 => {
            let mut cipher =
                Aes128Ctr32BE::new(GenericArray::from_slice(master_key), &prf_input.into());
            cipher.apply_keystream(&mut out);
            Ok(out)
        }
        24 => {
            let mut cipher =
                Aes192Ctr32BE::new(GenericArray::from_slice(master_key), &prf_input.into());
            cipher.apply_keystream(&mut out);
            Ok(out)
        }

        32 => {
            let mut cipher =
                Aes256Ctr32BE::new(GenericArray::from_slice(master_key), &prf_input.into());
            cipher.apply_keystream(&mut out);
            Ok(out)
        }
        _ => Err(SrtpError::InvalidKeySize),
    }
}

#[cfg(test)]
mod test {
    use super::*;

    // Test patterns from RFC3711 - appendix B.3
    #[test]
    fn aes_cm_128_session_keys() -> Result<(), SrtpError> {
        let master_key = vec![
            0xE1, 0xF9, 0x7A, 0x0D, 0x3E, 0x01, 0x8B, 0xE0, 0xD6, 0x4F, 0xA3, 0x2C, 0x06, 0xDE,
            0x41, 0x39,
        ];
        let master_salt = [
            0x0Eu8, 0xC6, 0x75, 0xAD, 0x49, 0x8A, 0xFE, 0xEB, 0xB6, 0x96, 0x0B, 0x3A, 0xAB, 0xE6,
        ];
        let pattern_session_key = vec![
            0xC6, 0x1E, 0x7A, 0x93, 0x74, 0x4F, 0x39, 0xEE, 0x10, 0x73, 0x4A, 0xFE, 0x3F, 0xF7,
            0xA0, 0x87,
        ];
        let pattern_session_salt = vec![
            0x30, 0xCB, 0xBC, 0x08, 0x86, 0x3D, 0x8C, 0x85, 0xD4, 0x9D, 0xB3, 0x4A, 0x9A, 0xE1,
        ];
        let pattern_session_auth_key = vec![
            0xCE, 0xBE, 0x32, 0x1F, 0x6F, 0xF7, 0x71, 0x6B, 0x6F, 0xD4, 0xAB, 0x49, 0xAF, 0x25,
            0x6A, 0x15, 0x6D, 0x38, 0xBA, 0xA4,
        ];

        let session_key = aes_cm_kdf(KdfLabel::RtpEncrypt, &master_key, &master_salt)?;
        assert_eq!(
            session_key, pattern_session_key,
            "Computed session key:\n{session_key:?} \ndoes not match pattern:\n{pattern_session_key:?}\n",
        );

        let session_salt = aes_cm_kdf(KdfLabel::RtpSalt, &master_key, &master_salt)?;
        assert_eq!(
            session_salt, pattern_session_salt,
            "Computed session salt:\n{session_salt:?} does not match pattern:\n{pattern_session_salt:?}"
        );

        let session_auth_key = aes_cm_kdf(KdfLabel::RtpAuthTag, &master_key, &master_salt)?;
        assert_eq!(
            session_auth_key, pattern_session_auth_key,
            "Computed session auth tag {session_auth_key:?} does not match pattern {pattern_session_auth_key:?}",
        );

        Ok(())
    }

    // Test patterns from RFC6188 - 7.4
    #[test]
    fn aes_cm_192_session_keys() -> Result<(), SrtpError> {
        let master_key = vec![
            0x73, 0xed, 0xc6, 0x6c, 0x4f, 0xa1, 0x57, 0x76, 0xfb, 0x57, 0xf9, 0x50, 0x5c, 0x17,
            0x13, 0x65, 0x50, 0xff, 0xda, 0x71, 0xf3, 0xe8, 0xe5, 0xf1,
        ];
        let master_salt = [
            0xc8, 0x52, 0x2f, 0x3a, 0xcd, 0x4c, 0xe8, 0x6d, 0x5a, 0xdd, 0x78, 0xed, 0xbb, 0x11,
        ];
        let pattern_session_key = vec![
            0x31, 0x87, 0x47, 0x36, 0xa8, 0xf1, 0x14, 0x38, 0x70, 0xc2, 0x6e, 0x48, 0x57, 0xd8,
            0xa5, 0xb2, 0xc4, 0xa3, 0x54, 0x40, 0x7f, 0xaa, 0xda, 0xbb,
        ];
        let pattern_session_salt = vec![
            0x23, 0x72, 0xb8, 0x2d, 0x63, 0x9b, 0x6d, 0x85, 0x03, 0xa4, 0x7a, 0xdc, 0x0a, 0x6c,
        ];
        let pattern_session_auth_key = vec![
            0x35, 0x5b, 0x10, 0x97, 0x3c, 0xd9, 0x5b, 0x9e, 0xac, 0xf4, 0x06, 0x1c, 0x7e, 0x1a,
            0x71, 0x51, 0xe7, 0xcf, 0xbf, 0xcb,
        ];

        let session_key = aes_cm_kdf(KdfLabel::RtpEncrypt, &master_key, &master_salt)?;
        assert_eq!(
            session_key, pattern_session_key,
            "Computed session key:\n{session_key:?} \ndoes not match pattern:\n{pattern_session_key:?}\n",
        );

        let session_salt = aes_cm_kdf(KdfLabel::RtpSalt, &master_key, &master_salt)?;
        assert_eq!(
            session_salt, pattern_session_salt,
            "Computed session salt:\n{session_salt:?} does not match pattern:\n{pattern_session_salt:?}"
        );

        let session_auth_key = aes_cm_kdf(KdfLabel::RtpAuthTag, &master_key, &master_salt)?;
        assert_eq!(
            session_auth_key, pattern_session_auth_key,
            "Computed session auth tag {session_auth_key:?} does not match pattern {pattern_session_auth_key:?}",
        );

        Ok(())
    }

    // Test patterns from RFC6188 - 7.2
    #[test]
    fn aes_cm_256_session_keys() -> Result<(), SrtpError> {
        let master_key = vec![
            0xf0, 0xf0, 0x49, 0x14, 0xb5, 0x13, 0xf2, 0x76, 0x3a, 0x1b, 0x1f, 0xa1, 0x30, 0xf1,
            0x0e, 0x29, 0x98, 0xf6, 0xf6, 0xe4, 0x3e, 0x43, 0x09, 0xd1, 0xe6, 0x22, 0xa0, 0xe3,
            0x32, 0xb9, 0xf1, 0xb6,
        ];
        let master_salt = [
            0x3b, 0x04, 0x80, 0x3d, 0xe5, 0x1e, 0xe7, 0xc9, 0x64, 0x23, 0xab, 0x5b, 0x78, 0xd2,
        ];
        let pattern_session_key = vec![
            0x5b, 0xa1, 0x06, 0x4e, 0x30, 0xec, 0x51, 0x61, 0x3c, 0xad, 0x92, 0x6c, 0x5a, 0x28,
            0xef, 0x73, 0x1e, 0xc7, 0xfb, 0x39, 0x7f, 0x70, 0xa9, 0x60, 0x65, 0x3c, 0xaf, 0x06,
            0x55, 0x4c, 0xd8, 0xc4,
        ];
        let pattern_session_salt = vec![
            0xfa, 0x31, 0x79, 0x16, 0x85, 0xca, 0x44, 0x4a, 0x9e, 0x07, 0xc6, 0xc6, 0x4e, 0x93,
        ];
        let pattern_session_auth_key = vec![
            0xfd, 0x9c, 0x32, 0xd3, 0x9e, 0xd5, 0xfb, 0xb5, 0xa9, 0xdc, 0x96, 0xb3, 0x08, 0x18,
            0x45, 0x4d, 0x13, 0x13, 0xdc, 0x05,
        ];

        let session_key = aes_cm_kdf(KdfLabel::RtpEncrypt, &master_key, &master_salt)?;
        assert_eq!(
            session_key, pattern_session_key,
            "Computed session key:\n{session_key:?} \ndoes not match pattern:\n{pattern_session_key:?}\n",
        );

        let session_salt = aes_cm_kdf(KdfLabel::RtpSalt, &master_key, &master_salt)?;
        assert_eq!(
            session_salt, pattern_session_salt,
            "Computed session salt:\n{session_salt:?} does not match pattern:\n{pattern_session_salt:?}"
        );

        let session_auth_key = aes_cm_kdf(KdfLabel::RtpAuthTag, &master_key, &master_salt)?;
        assert_eq!(
            session_auth_key, pattern_session_auth_key,
            "Computed session auth tag {session_auth_key:?} does not match pattern {pattern_session_auth_key:?}",
        );

        Ok(())
    }
}
