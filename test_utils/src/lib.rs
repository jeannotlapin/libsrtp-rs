use libsrtp::ProtectionProfile;
use rand::{Rng, random, seq::SliceRandom};
pub fn create_rtp_packet(payload_size: usize, ssrc: u32, seqnum: u16) -> Vec<u8> {
    // create header - no extension, payload type 0x0f
    let mut rtp = vec![0x80, 0x0f];
    // add seqnum
    rtp.extend(seqnum.to_be_bytes());
    // add timestamp (4 bytes): use seqnum<<10
    rtp.extend(((seqnum as u32) << 10).to_be_bytes());
    // add ssrc
    rtp.extend(ssrc.to_be_bytes());
    // add random payload
    let mut rng = rand::rng();
    let payload: Vec<u8> = (0..payload_size).map(|_| rng.random()).collect();
    rtp.extend(payload);
    rtp
}

pub fn create_rtcp_packet(payload_size: usize, ssrc: u32) -> Vec<u8> {
    // create header :
    // - payload type 200, length set to anything(0x1234), srtp does not use it anyway
    let mut rtcp = vec![0x80, 200, 0x12, 0x34];
    // add ssrc
    rtcp.extend(ssrc.to_be_bytes());
    // add random payload : force the size to be a multiple of 4
    let mut rng = rand::rng();
    let payload: Vec<u8> = (0..(payload_size / 4) * 4).map(|_| rng.random()).collect();
    rtcp.extend(payload);
    rtcp
}

pub fn generate_keys(profile: &ProtectionProfile) -> (Vec<u8>, Vec<u8>) {
    let mut rng = rand::rng();
    // NullCipher profile still needs a key and salt to derive the auth tag key, use aes128
    let master_key: Vec<u8> = (0..std::cmp::max(profile.key_len(), 16))
        .map(|_| rng.random())
        .collect();
    let master_salt: Vec<u8> = match profile.salt_len() {
        0 => (0..14).map(|_| rng.random()).collect(),
        _ => (0..profile.salt_len()).map(|_| rng.random()).collect(),
    };
    (master_key, master_salt)
}

pub fn rnd_range(begin: usize, end: usize) -> Vec<usize> {
    let mut indices: Vec<usize> = (begin..end).collect();
    indices.shuffle(&mut rand::rng());
    indices
}

// generate a vector of random seq_num, first bit must be 0
pub fn get_seq_nums(size: usize) -> Vec<u16> {
    let mut seq_nums = Vec::<u16>::new();
    for _ in 0..size {
        seq_nums.push(random::<u16>() & 0x7fff_u16);
    }
    seq_nums
}

// generate a vector of random ssrc
pub fn get_ssrcs(size: usize) -> Vec<u32> {
    let mut ssrcs = Vec::<u32>::new();
    for _ in 0..size {
        ssrcs.push(random::<u32>());
    }
    ssrcs
}

pub const VALID_PROFILES: [(ProtectionProfile, ProtectionProfile); 15] = [
    (
        ProtectionProfile::NullCipherHmacSha180,
        ProtectionProfile::NullCipherHmacSha180,
    ),
    (
        ProtectionProfile::Aes128CmHmacSha180,
        ProtectionProfile::Aes128CmHmacSha180,
    ),
    (
        ProtectionProfile::Aes128CmHmacSha132,
        ProtectionProfile::Aes128CmHmacSha180,
    ),
    (
        ProtectionProfile::Aes128CmNullAuth,
        ProtectionProfile::Aes128CmHmacSha180,
    ),
    (
        ProtectionProfile::Aes128CmHmacSha180,
        ProtectionProfile::NullCipherHmacSha180,
    ),
    (
        ProtectionProfile::Aes192CmHmacSha180,
        ProtectionProfile::Aes192CmHmacSha180,
    ),
    (
        ProtectionProfile::Aes192CmHmacSha132,
        ProtectionProfile::Aes192CmHmacSha180,
    ),
    (
        ProtectionProfile::Aes192CmNullAuth,
        ProtectionProfile::Aes192CmHmacSha180,
    ),
    (
        ProtectionProfile::Aes192CmHmacSha180,
        ProtectionProfile::NullCipherHmacSha180,
    ),
    (
        ProtectionProfile::Aes256CmHmacSha180,
        ProtectionProfile::Aes256CmHmacSha180,
    ),
    (
        ProtectionProfile::Aes256CmHmacSha132,
        ProtectionProfile::Aes256CmHmacSha180,
    ),
    (
        ProtectionProfile::Aes256CmNullAuth,
        ProtectionProfile::Aes256CmHmacSha180,
    ),
    (
        ProtectionProfile::Aes256CmHmacSha180,
        ProtectionProfile::NullCipherHmacSha180,
    ),
    (
        ProtectionProfile::AeadAes128Gcm,
        ProtectionProfile::AeadAes128Gcm,
    ),
    (
        ProtectionProfile::AeadAes256Gcm,
        ProtectionProfile::AeadAes256Gcm,
    ),
];
