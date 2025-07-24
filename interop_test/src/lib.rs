#[repr(i32)]
#[derive(Debug, Clone, Copy)]
pub enum CryptoPolicyKind {
    Aes128CmHmacSha180 = 0,
    Aes128CmHmacSha132 = 1,
    Aes128CmNullAuth = 2,
    Aes192CmHmacSha180 = 3,
    Aes192CmHmacSha132 = 4,
    Aes192CmNullAuth = 5,
    Aes256CmHmacSha180 = 6,
    Aes256CmHmacSha132 = 7,
    Aes256CmNullAuth = 8,
    NullCipherHmacSha180 = 9,
    AeadAes128Gcm = 10,
    AeadAes256Gcm = 11,
}

#[repr(C)]
pub struct CSrtpMasterKey {
    pub key: *const u8,
    pub key_len: i32,
    pub mki: *const u8,
    pub mki_len: i32,
}

unsafe extern "C" {
    pub fn c_srtp_create_session(
        key: *const u8,
        inbound: i32,
        rtp_policy_kind: i32,
        rtcp_policy_kind: i32,
    ) -> *mut std::os::raw::c_void;

    pub fn c_srtp_protect(ctx: *mut std::os::raw::c_void, pkt: *mut u8, pkt_len: *mut i32) -> i32;
    pub fn c_srtp_unprotect(ctx: *mut std::os::raw::c_void, pkt: *mut u8, pkt_len: *mut i32)
    -> i32;
    pub fn c_srtp_protect_rtcp(
        ctx: *mut std::os::raw::c_void,
        pkt: *mut u8,
        pkt_len: *mut i32,
    ) -> i32;
    pub fn c_srtp_unprotect_rtcp(
        ctx: *mut std::os::raw::c_void,
        pkt: *mut u8,
        pkt_len: *mut i32,
    ) -> i32;

    pub fn c_srtp_free_session(ctx: *mut std::os::raw::c_void);

    pub fn c_srtp_create_session_mki(
        keys: *const CSrtpMasterKey,
        num_keys: i32,
        inbound: i32,
        rtp_policy_kind: i32,
        rtcp_policy_kind: i32,
    ) -> *mut ::std::os::raw::c_void;

    pub fn c_srtp_unprotect_mki(
        session: *mut ::std::os::raw::c_void,
        pkt: *mut u8,
        pkt_len: *mut i32,
    ) -> i32;

    pub fn c_srtp_unprotect_rtcp_mki(
        session: *mut ::std::os::raw::c_void,
        pkt: *mut u8,
        pkt_len: *mut i32,
    ) -> i32;

    pub fn c_srtp_get_version_number() -> u32;
}
