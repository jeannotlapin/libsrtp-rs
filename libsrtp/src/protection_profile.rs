/// Supported protection profiles
///
/// - NullCipher and AES128CM based from [RFC3711](https://datatracker.ietf.org/doc/html/rfc3711)
/// - AES192CM and AES256CM based from [RFC 6188](https://datatracker.ietf.org/doc/html/rfc6188)
/// - AES-GCM based from [RFC 7714](https://datatracker.ietf.org/doc/html/rfc7714)
#[derive(Default, Debug, Clone, Copy, PartialEq)]
pub enum ProtectionProfile {
    #[default]
    NullCipherHmacSha180,
    Aes128CmHmacSha180,
    Aes128CmHmacSha132,
    Aes128CmNullAuth,
    Aes192CmHmacSha180,
    Aes192CmHmacSha132,
    Aes192CmNullAuth,
    Aes256CmHmacSha180,
    Aes256CmHmacSha132,
    Aes256CmNullAuth,
    AeadAes128Gcm,
    AeadAes256Gcm,
}

impl ProtectionProfile {
    pub fn tag_len(&self) -> usize {
        match self {
            ProtectionProfile::NullCipherHmacSha180
            | ProtectionProfile::Aes128CmHmacSha180
            | ProtectionProfile::Aes192CmHmacSha180
            | ProtectionProfile::Aes256CmHmacSha180 => 10,
            ProtectionProfile::Aes128CmHmacSha132
            | ProtectionProfile::Aes192CmHmacSha132
            | ProtectionProfile::Aes256CmHmacSha132 => 4,
            ProtectionProfile::Aes128CmNullAuth
            | ProtectionProfile::Aes192CmNullAuth
            | ProtectionProfile::Aes256CmNullAuth => 0,
            // for aes gcm, the auth tag is actually included in the cipher text so there is no
            // auth tag as a part of the SRTP packet trailer like for AES-CM with HmacSha1 tag
            ProtectionProfile::AeadAes128Gcm | ProtectionProfile::AeadAes256Gcm => 0,
        }
    }

    pub fn key_len(&self) -> usize {
        match self {
            ProtectionProfile::NullCipherHmacSha180 => 0,
            ProtectionProfile::Aes128CmNullAuth
            | ProtectionProfile::Aes128CmHmacSha132
            | ProtectionProfile::Aes128CmHmacSha180
            | ProtectionProfile::AeadAes128Gcm => 16,
            ProtectionProfile::Aes192CmNullAuth
            | ProtectionProfile::Aes192CmHmacSha132
            | ProtectionProfile::Aes192CmHmacSha180 => 24,
            ProtectionProfile::Aes256CmNullAuth
            | ProtectionProfile::Aes256CmHmacSha132
            | ProtectionProfile::Aes256CmHmacSha180
            | ProtectionProfile::AeadAes256Gcm => 32,
        }
    }

    pub fn salt_len(&self) -> usize {
        match self {
            ProtectionProfile::NullCipherHmacSha180
            | ProtectionProfile::Aes128CmNullAuth
            | ProtectionProfile::Aes128CmHmacSha132
            | ProtectionProfile::Aes128CmHmacSha180
            | ProtectionProfile::Aes192CmNullAuth
            | ProtectionProfile::Aes192CmHmacSha132
            | ProtectionProfile::Aes192CmHmacSha180
            | ProtectionProfile::Aes256CmNullAuth
            | ProtectionProfile::Aes256CmHmacSha132
            | ProtectionProfile::Aes256CmHmacSha180 => 14,
            ProtectionProfile::AeadAes128Gcm | ProtectionProfile::AeadAes256Gcm => 12,
        }
    }
}
