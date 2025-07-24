use crate::SrtpError;
use crate::header::{RtcpHeader, RtpHeader};
use crate::protection_profile::ProtectionProfile;
use crate::replay::{RtcpReplayDb, RtpReplayDb};
use crate::transform::Transform;
use crate::transform::aes_cm_sha1::AesCmSha1;
use crate::transform::aes_gcm::AesGcm;
use std::collections::hash_map::Entry;
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::sync::Arc;
use zeroize::{Zeroize, ZeroizeOnDrop};

const DEFAULT_REPLAY_WINDOW_SIZE: u16 = 128u16;
const MAX_RTP_SESSION_KEY_LIVES: u64 = 1u64 << 48;
const MAX_RTCP_SESSION_KEY_LIVES: u32 = 1u32 << 31;
const DEFAULT_RTP_SESSION_KEY_SOFT_LIMIT: u64 = 1u64 << 16;
const DEFAULT_RTCP_SESSION_KEY_SOFT_LIMIT: u32 = 1u32 << 16;

/// A stream master key
///
/// Composed of the key, salt, an optional MKI and key life time
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct MasterKey {
    key: Vec<u8>,
    #[zeroize(skip)]
    salt: Vec<u8>,
    #[zeroize(skip)]
    mki: Option<Vec<u8>>,
    #[zeroize(skip)]
    lifetime: KeysLifetime,
}

/// Debug redacting secret key
impl fmt::Debug for MasterKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MasterKey")
            .field("key", &"[REDACTED]")
            .field("salt", &self.salt)
            .field("mki", &self.mki)
            .finish()
    }
}

impl MasterKey {
    /// create a stream master key
    ///
    /// The key is created with default lifetime (2^48 for RTP, 2^31 for RTCP) and default soft
    /// limits (2^16 for both RTP and RTCP)
    ///
    /// # Arguments
    /// - key: the master key
    /// - salt: the master salt, this field can be an empty slice, in that case the master salt is
    ///   considered all 0.
    /// - mki: optionnal master key id - see RFC 3711 - section 3.1
    pub fn new(key: &[u8], salt: &[u8], mki: &Option<Vec<u8>>) -> Self {
        Self {
            key: key.to_vec(),
            salt: salt.to_vec(),
            mki: mki.clone(),
            lifetime: KeysLifetime::default(),
        }
    }

    /// Set the session keys lifetime and soft limit
    ///
    /// # Arguments
    /// * rtp : number of lives a session key gets on RTP stream. Must be <= 2^48
    /// * rtp_limit : when the lives left is under this limit, raise an alert. Must be < rtp
    /// * rtcp : number of lives a session key gets on RTCP stream. Must be <= 2^31
    /// * rtcp_limit : when the lives left is under this limit, raise an alert. Must be < rtcp
    ///
    /// # Returns one of:
    /// * Ok
    /// * InvalidProfile when the arguments don't match the requirements
    ///
    /// # Notes
    /// * When a master key is used by several streams (from a stream template):
    ///     * Each one will start with the same lifetime.
    ///     * The lifetime countdown is not shared on the master key but on each stream.
    ///     * When a stream reaches it's end of life, all the other streams derived from the master
    ///       key are killed.
    ///
    /// * When a stream reaches the end of one of its key(RTP/RTCP) lifetime, it is disabled for
    ///   both types.
    ///
    /// * For streams using mki, when the soft or hard limit is reached it applies to one
    ///   master key, the stream can keep going using others mki after one is dead.
    ///
    pub fn set_keys_lifetime(
        &mut self,
        rtp: u64,
        rtp_limit: u64,
        rtcp: u32,
        rtcp_limit: u32,
    ) -> Result<(), SrtpError> {
        // Check key lives and soft limit: lives must be <= 2^48 for rtp, 2^31 for rtcp
        // soft limit must be < lifes
        if rtp > MAX_RTP_SESSION_KEY_LIVES || rtcp > MAX_RTCP_SESSION_KEY_LIVES {
            return Err(SrtpError::InvalidProfile);
        }
        if rtp < rtp_limit || rtcp < rtcp_limit {
            return Err(SrtpError::InvalidProfile);
        }

        self.lifetime.rtp = rtp;
        self.lifetime.rtp_limit = rtp_limit;
        self.lifetime.rtcp = rtcp;
        self.lifetime.rtcp_limit = rtcp_limit;

        Ok(())
    }
}

/// The stream configuration
#[derive(Debug, Clone)]
pub struct StreamConfig {
    /// one or more (if mki is used) master key/master salt
    keys: Vec<MasterKey>,
    /// rtp protection profile
    rtp_profile: ProtectionProfile,
    /// rtcp protection profile: short or no auth tag profiles are not valid
    rtcp_profile: ProtectionProfile,
    /// replay windows size : (default to 128)
    replay_window_size: u16,
    /// allow_send_repeat : default false, is ignored on recv session streams
    allow_send_repeat: bool,
}

impl Default for StreamConfig {
    fn default() -> Self {
        Self {
            keys: Vec::new(),
            rtp_profile: ProtectionProfile::Aes128CmHmacSha180,
            rtcp_profile: ProtectionProfile::Aes128CmHmacSha180,
            replay_window_size: DEFAULT_REPLAY_WINDOW_SIZE,
            allow_send_repeat: false,
        }
    }
}
impl StreamConfig {
    /// create a stream config
    ///
    /// # Arguments
    /// - keys: the stream master key(s). If mki is not used, only one key
    /// - rtp_profile: the encryption profile to apply to the RTP stream
    /// - rtcp_profile: the encryption profile to apply to the RTCP stream
    ///
    /// # Default values
    /// - allow_send_repeat: false,
    /// - replay_windows_size: 128
    pub fn new(
        keys: Vec<MasterKey>,
        rtp_profile: &ProtectionProfile,
        rtcp_profile: &ProtectionProfile,
    ) -> Self {
        Self {
            keys,
            rtp_profile: *rtp_profile,
            rtcp_profile: *rtcp_profile,
            ..Default::default()
        }
    }

    /// Set the replay window size in the stream configuration
    ///
    /// The default replay window size is 128
    ///
    /// The replay window keeps track of the packet index already processed. It starts at the
    /// highest index processed yet.
    ///
    /// It applies to RTP on send and recv sides, to RTCP on recv side only.
    ///
    /// Any packet older than the replay window limit(highest index processed yet - window size) is considered too old and discarded.
    pub fn set_replay_window_size(&mut self, size: u16) {
        self.replay_window_size = size;
    }

    /// Get the replay window size currently configured for this stream
    pub fn get_replay_window_size(&self) -> u16 {
        self.replay_window_size
    }

    /// Set the authorization flag to disable replay check on RTP sender stream
    ///
    /// # Arguments
    /// * allow: set to true to disable the replay check during RTP's encryption
    pub fn allow_send_repeat(&mut self, allow: bool) {
        self.allow_send_repeat = allow;
    }

    /// Set the session keys lifetime and soft limit
    ///
    /// this setting is applied to each of the master keys present in the stream configuration
    /// see [MasterKey::set_keys_lifetime] for details.
    ///
    /// # Arguments
    /// * rtp : number of lives a session key gets on RTP stream. Must be <= 2^48
    /// * rtp_limit : when the lives left is under this limit, raise an alert. Must be < rtp
    /// * rtcp : number of lives a session key gets on RTCP stream. Must be <= 2^31
    /// * rtp_limit : when the lives left is under this limit, raise an alert. Must be < rtcp
    ///
    /// # Returns Ok or InvalidProfile when the arguments does not match the requirements
    pub fn set_keys_lifetime(
        &mut self,
        rtp: u64,
        rtp_limit: u64,
        rtcp: u32,
        rtcp_limit: u32,
    ) -> Result<(), SrtpError> {
        for key in &mut self.keys {
            key.set_keys_lifetime(rtp, rtp_limit, rtcp, rtcp_limit)?;
        }
        Ok(())
    }

    // Same as above but apply only to a specific mki
    pub(super) fn set_keys_lifetime_mki(
        &mut self,
        rtp: u64,
        rtp_limit: u64,
        rtcp: u32,
        rtcp_limit: u32,
        mki: &Option<Vec<u8>>,
    ) -> Result<(), SrtpError> {
        for key in &mut self.keys {
            if key.mki == *mki {
                key.set_keys_lifetime(rtp, rtp_limit, rtcp, rtcp_limit)?;
                return Ok(());
            }
        }
        Err(SrtpError::InvalidMki)
    }

    /// Check the configuration is valid.
    ///
    /// This check is always performed before adding a stream, you do not need to call it yourself
    /// before passing the configuration to the add_stream function
    ///
    /// Check
    /// - RTCP profile: must have long auth tag
    /// - mki(if used) is consistent: same id size, no duplicates
    /// - profile and key( and salt if provided) size match
    pub fn validate(&self) -> Result<(), SrtpError> {
        // RTCP profile cannot have a short auth tag, Aead have no tag but auth is part of the
        // transform
        if self.rtcp_profile.tag_len() < 10
            && self.rtcp_profile != ProtectionProfile::AeadAes128Gcm
            && self.rtcp_profile != ProtectionProfile::AeadAes256Gcm
        {
            return Err(SrtpError::InvalidProfile);
        }

        // Do we have keys
        if self.keys.is_empty() {
            return Err(SrtpError::InvalidProfile);
        }

        // do they all have the same key/salt/mki size and check that no mki is repeated
        let key_size = self.keys[0].key.len();
        let salt_size = self.keys[0].salt.len();
        if self.keys.len() > 1 {
            // we have several keys/mki
            let mut mki_size: usize = 0;
            let mut mki_seen = HashSet::new();
            for key in &self.keys {
                match &key.mki {
                    // no mki can be None as we have several keys
                    None => {
                        return Err(SrtpError::InvalidProfile);
                    }
                    Some(mki) => {
                        // first iteration
                        if mki_size == 0 {
                            mki_size = mki.len()
                        } else {
                            // ensure all mkis have the same size
                            if mki_size != mki.len() {
                                return Err(SrtpError::InvalidProfile);
                            }
                        }
                        // detect duplicated mki
                        if mki_seen.contains(mki) {
                            return Err(SrtpError::InvalidProfile);
                        }
                        mki_seen.insert(mki.clone());
                    }
                }

                // check key and salt sizes are all equals
                if key.key.len() != key_size || key.salt.len() != salt_size {
                    return Err(SrtpError::InvalidProfile);
                }
            }
        }

        // check rtp profile and key size match, no check for null cipher profile
        if self.rtp_profile.key_len() > 0 && self.rtp_profile.key_len() != key_size {
            return Err(SrtpError::InvalidProfile);
        }

        // check rtcp profile and key size match, no check for null cipher profile
        if self.rtcp_profile.key_len() > 0 && self.rtcp_profile.key_len() != key_size {
            return Err(SrtpError::InvalidProfile);
        }

        // in case both rtp and rtcp have a null cipher, check the key size is one of 16,24,32
        if self.rtp_profile.key_len() == 0
            && self.rtcp_profile.key_len() == 0
            && key_size != 16
            && key_size != 24
            && key_size != 32
        {
            return Err(SrtpError::InvalidProfile);
        }

        // check master salt: it can be empty
        if salt_size != 0 {
            if self.rtp_profile.salt_len() > 0 && self.rtp_profile.salt_len() != salt_size {
                return Err(SrtpError::InvalidProfile);
            }
            if self.rtcp_profile.salt_len() > 0 && self.rtcp_profile.salt_len() != salt_size {
                return Err(SrtpError::InvalidProfile);
            }
        }

        Ok(())
    }
}

/// a structure to hold the number of key uses left and their soft limit
#[derive(Debug, Clone)]
struct KeysLifetime {
    /// how many rtp transform left with this key
    rtp: u64,
    /// when lives left are below this limit, raise an alert
    rtp_limit: u64,
    /// how many rtp transform left with this key
    rtcp: u32,
    /// when lives left are below this limit, raise an alert
    rtcp_limit: u32,
}

impl Default for KeysLifetime {
    fn default() -> Self {
        Self {
            rtp: MAX_RTP_SESSION_KEY_LIVES,
            rtp_limit: DEFAULT_RTP_SESSION_KEY_SOFT_LIMIT,
            rtcp: MAX_RTCP_SESSION_KEY_LIVES,
            rtcp_limit: DEFAULT_RTCP_SESSION_KEY_SOFT_LIMIT,
        }
    }
}

impl KeysLifetime {
    // Decrease lifes left on a key
    // when the life count left hit 0 make sure we cannot use this key anymore even for the other
    // type of transform (see RFC 3711 - 9.2)
    fn decrease_rtp(&mut self) {
        self.rtp -= 1;
        if self.rtp == 0 {
            self.rtcp = 0;
        }
    }
    fn decrease_rtcp(&mut self) {
        self.rtcp -= 1;
        if self.rtcp == 0 {
            self.rtp = 0;
        }
    }
}

/// Type for the closure reporting a key limit reached
/// # Closure Arguments:
/// - SrtpError::KeyLimit variant
pub type KeyLimitHandler = Arc<dyn Fn(SrtpError) + Send + Sync>;

pub trait StreamInterface {
    fn new(
        ssrc: u32,
        config: &StreamConfig,
        handler: Option<KeyLimitHandler>,
    ) -> Result<Self, SrtpError>
    where
        Self: Sized;
    fn update(&mut self, config: &StreamConfig) -> Result<(), SrtpError>;
    fn get_roc(&self) -> u32;
    fn kill_session_keys(&mut self, mki: &Option<Vec<u8>>) -> Result<(), SrtpError>;
}

/// transforms are indexed by mki(if used) and stored along the keys usage tracking struct
type MkiIndexedTransform = HashMap<Option<Vec<u8>>, (Box<dyn Transform>, KeysLifetime)>;
/// Some common behavior shared by sender and receiver streams
struct BaseStream {
    /// the ssrc identifiying this stream - use to report to key limit handler
    ssrc: u32,
    /// the cryptographic transform and associated key usage tracking, indexed by mki
    transforms: MkiIndexedTransform,
    /// size of mki in use (0 when mki is not used)
    mki_len: usize,
    /// store the current rtp index (ROC || seq_num) and manage replay
    rtp_index: RtpReplayDb,
    /// optionnal callback to report a key uses limit reached
    key_limit_handler: Option<KeyLimitHandler>,
    /// would a sender stream allow to repeat transmission of packet with the same index
    allow_send_repeat: bool,
}

impl BaseStream {
    fn new(
        ssrc: u32,
        config: &StreamConfig,
        handler: Option<KeyLimitHandler>,
    ) -> Result<Self, SrtpError> {
        Ok(Self {
            ssrc,
            transforms: get_transforms(config)?,
            mki_len: match &config.keys[0].mki {
                None => 0,
                Some(mki) => mki.len(),
            },
            rtp_index: RtpReplayDb::new(config.replay_window_size),
            key_limit_handler: handler,
            allow_send_repeat: config.allow_send_repeat,
        })
    }

    fn update(&mut self, config: &StreamConfig) -> Result<(), SrtpError> {
        // we can update only if the mki policy is compatible: same mki size
        match &config.keys[0].mki {
            None => {
                // new config has no mki
                if self.mki_len > 0 {
                    // if the current config uses mki
                    return Err(SrtpError::InvalidProfile);
                }
            }
            Some(mki) => {
                // new config uses mki: check it it the same size as current one
                if mki.len() != self.mki_len {
                    return Err(SrtpError::InvalidProfile);
                }
            }
        };

        // recreate the transforms hashmap and merge it to the existing one
        let new_transforms = get_transforms(config)?;
        for (mki, transform_lives) in new_transforms {
            match self.transforms.entry(mki) {
                Entry::Vacant(entry) => {
                    entry.insert(transform_lives);
                }
                Entry::Occupied(entry) => {
                    let (new_transform, _lives) = transform_lives;
                    let (transform, _lives) = entry.get();
                    if !new_transform.as_ref().equals(transform.as_ref()) {
                        return Err(SrtpError::InvalidProfile);
                    }
                }
            }
        }
        // update replay window size
        self.rtp_index.set_window_size(config.replay_window_size);
        // update the allow_send_repeat
        self.allow_send_repeat = config.allow_send_repeat;
        Ok(())
    }

    fn get_mki_len(&self) -> usize {
        self.mki_len
    }

    fn get_roc(&self) -> u32 {
        self.rtp_index.get_roc()
    }

    fn check_key_limit(&self, is_rtp: bool, mki: &Option<Vec<u8>>) -> Result<(), SrtpError> {
        let (_, keys_lifetime) = self.transforms.get(mki).ok_or(SrtpError::InvalidMki)?;
        let (lifetime, limit) = if is_rtp {
            (keys_lifetime.rtp, keys_lifetime.rtp_limit)
        } else {
            (
                u64::from(keys_lifetime.rtcp),
                u64::from(keys_lifetime.rtcp_limit),
            )
        };

        // when there is a handler and we are under the soft limit
        if lifetime <= limit
            && let Some(handler) = &self.key_limit_handler
        {
            // call the handler
            handler(SrtpError::KeyLimit {
                is_dead: lifetime == 0,
                is_rtp,
                ssrc: self.ssrc,
                mki: mki.clone(),
            });
        }

        // when we're dead we also return an error
        if lifetime == 0 {
            return Err(SrtpError::KeyLimit {
                is_dead: true,
                is_rtp,
                ssrc: self.ssrc,
                mki: mki.clone(),
            });
        }
        Ok(())
    }

    fn kill_session_keys(&mut self, mki: &Option<Vec<u8>>) -> Result<(), SrtpError> {
        let (_, keys_lifetime) = self.transforms.get_mut(mki).ok_or(SrtpError::InvalidMki)?;
        keys_lifetime.rtp = 0;
        keys_lifetime.rtcp = 0;
        Ok(())
    }
}

/// Sending stream is based on BaseStream, extend it with specific sender members
pub struct SendStream {
    /// transforms and rtp index db
    base: BaseStream,
    /// current rtcp_index: managed by the sender stream
    rtcp_index: u32,
}

/// Receiver stream is based on BaseStream, extend it with specific receiver members
pub struct RecvStream {
    /// transforms and rtp index db
    base: BaseStream,
    /// manage rtcp replay
    rtcp_index: RtcpReplayDb,
    /// the rtp tag len associated to the selected rtp protection profile,
    rtp_tag_len: usize,
    /// the rtcp tag len associated to the selected rtcp protection profile,
    rtcp_tag_len: usize,
}

impl SendStream {
    pub fn rtp_protect(
        &mut self,
        header: &RtpHeader,
        plain: Vec<u8>,
        mki: &Option<Vec<u8>>,
    ) -> Result<Vec<u8>, SrtpError> {
        // estimate index and check for replay
        let index = self.base.rtp_index.estimate_index(header.seq_num());
        if !self.base.allow_send_repeat && self.base.rtp_index.seen_index(index) {
            return Err(SrtpError::InvalidPacketIndex);
        }

        // check key lives
        self.base.check_key_limit(true, mki)?;

        // retrieve transform and apply
        let (transform, keys_lifetime) = self
            .base
            .transforms
            .get_mut(mki)
            .ok_or(SrtpError::InvalidMki)?;
        let cipher = transform.rtp_protect(plain, header, (index >> 16) as u32)?;
        keys_lifetime.decrease_rtp();

        // update replay db
        self.base.rtp_index.add_index(index);

        Ok(cipher)
    }

    pub fn rtcp_protect(
        &mut self,
        header: &RtcpHeader,
        plain: Vec<u8>,
        mki: &Option<Vec<u8>>,
    ) -> Result<Vec<u8>, SrtpError> {
        // check key lives
        self.base.check_key_limit(false, mki)?;

        // retrieve transform and apply
        let (transform, keys_lifetime) = self
            .base
            .transforms
            .get_mut(mki)
            .ok_or(SrtpError::InvalidMki)?;
        let res = transform.rtcp_protect(plain, header, self.rtcp_index)?;
        keys_lifetime.decrease_rtcp();

        // increase index, wrap it at 2^31. Counting is performed by the key_limit
        self.rtcp_index = (self.rtcp_index + 1) & 0x7fffffff;

        Ok(res)
    }
}
impl RecvStream {
    /// extract mki from an encrypted packet
    fn get_mki(
        &self,
        cipher: &[u8],
        header_len: usize,
        is_rtp: bool,
    ) -> Result<Option<Vec<u8>>, SrtpError> {
        let mki_len = self.base.get_mki_len();
        if mki_len == 0 {
            Ok(None)
        } else {
            let tag_len = if is_rtp {
                self.rtp_tag_len
            } else {
                self.rtcp_tag_len
            };
            // retrieve the mki
            if cipher.len() < header_len + mki_len + tag_len {
                return Err(SrtpError::InvalidPacket);
            }
            Ok(Some(
                cipher[cipher.len() - tag_len - mki_len..cipher.len() - tag_len].to_vec(),
            ))
        }
    }

    pub fn set_roc(&mut self, roc: u32) -> Result<(), SrtpError> {
        // make sure we are not trying to set a roc lower than the current one
        if roc < self.get_roc() {
            return Err(SrtpError::InvalidPacketIndex);
        }
        self.base.rtp_index.set_roc(roc);
        Ok(())
    }

    pub fn rtp_unprotect(
        &mut self,
        header: &RtpHeader,
        cipher: Vec<u8>,
    ) -> Result<Vec<u8>, SrtpError> {
        // estimate index and check for replay
        let index = self.base.rtp_index.estimate_index(header.seq_num());
        if self.base.rtp_index.seen_index(index) {
            return Err(SrtpError::InvalidPacketIndex);
        }

        // get mki from packet
        let mki = self.get_mki(&cipher, header.len(), true)?;

        // check key lives
        self.base.check_key_limit(true, &mki)?;

        // retrieve transform and apply
        let (transform, keys_lifetime) = self
            .base
            .transforms
            .get_mut(&mki)
            .ok_or(SrtpError::InvalidMki)?;
        let res = transform.rtp_unprotect(cipher, header, (index >> 16) as u32)?;
        keys_lifetime.decrease_rtp();

        // update replay db
        self.base.rtp_index.add_index(index);

        Ok(res)
    }

    pub fn rtcp_unprotect(
        &mut self,
        header: &RtcpHeader,
        cipher: Vec<u8>,
    ) -> Result<Vec<u8>, SrtpError> {
        // retrieve the index from packet:
        // RTCP trailer is :
        // Index <4 bytes>  (big endian)
        // Mki <optional, custom size>
        // auth tag < size depend on the selected transform >
        let trailer_len = 4 + self.rtcp_tag_len + self.base.get_mki_len();
        if cipher.len() < RtcpHeader::len() + trailer_len {
            return Err(SrtpError::InvalidPacket);
        }
        let pos = cipher.len() - trailer_len; // position of the index in cipher buffer
        let index = u32::from_be_bytes([
            cipher[pos],
            cipher[pos + 1],
            cipher[pos + 2],
            cipher[pos + 3],
        ]) & 0x7fffffff; // clear the E flag

        // Check for replay
        if self.rtcp_index.seen_index(index) {
            return Err(SrtpError::InvalidPacketIndex);
        }

        let mki = self.get_mki(&cipher, RtcpHeader::len(), false)?;
        // check key lives
        self.base.check_key_limit(false, &mki)?;
        // retrieve transform and apply
        let (transform, keys_lifetime) = self
            .base
            .transforms
            .get_mut(&mki)
            .ok_or(SrtpError::InvalidMki)?;
        let res = transform.rtcp_unprotect(cipher, header, index, trailer_len)?;
        keys_lifetime.decrease_rtcp();

        // update replay db
        self.rtcp_index.add_index(index);

        Ok(res)
    }
}

// Explicit Stream Interface delegation
impl StreamInterface for SendStream {
    fn new(
        ssrc: u32,
        config: &StreamConfig,
        handler: Option<KeyLimitHandler>,
    ) -> Result<Self, SrtpError> {
        Ok(Self {
            base: BaseStream::new(ssrc, config, handler)?,
            rtcp_index: 0,
        })
    }

    fn update(&mut self, config: &StreamConfig) -> Result<(), SrtpError> {
        self.base.update(config)
    }

    fn get_roc(&self) -> u32 {
        self.base.get_roc()
    }

    fn kill_session_keys(&mut self, mki: &Option<Vec<u8>>) -> Result<(), SrtpError> {
        self.base.kill_session_keys(mki)
    }
}
impl StreamInterface for RecvStream {
    fn new(
        ssrc: u32,
        config: &StreamConfig,
        handler: Option<KeyLimitHandler>,
    ) -> Result<Self, SrtpError> {
        Ok(Self {
            base: BaseStream::new(ssrc, config, handler)?,
            rtcp_index: RtcpReplayDb::new(config.replay_window_size),
            rtp_tag_len: config.rtp_profile.tag_len(),
            rtcp_tag_len: config.rtcp_profile.tag_len(),
        })
    }

    fn update(&mut self, config: &StreamConfig) -> Result<(), SrtpError> {
        self.base.update(config)?;
        self.rtcp_index.set_window_size(config.replay_window_size);
        Ok(())
    }

    fn get_roc(&self) -> u32 {
        self.base.get_roc()
    }

    fn kill_session_keys(&mut self, mki: &Option<Vec<u8>>) -> Result<(), SrtpError> {
        self.base.kill_session_keys(mki)
    }
}

// local helpers functions
fn get_transforms(config: &StreamConfig) -> Result<MkiIndexedTransform, SrtpError> {
    match config.rtp_profile {
        // AesCmSha1 module also provides null cipher
        ProtectionProfile::Aes128CmHmacSha180
        | ProtectionProfile::Aes128CmHmacSha132
        | ProtectionProfile::Aes192CmHmacSha180
        | ProtectionProfile::Aes192CmHmacSha132
        | ProtectionProfile::Aes256CmHmacSha180
        | ProtectionProfile::Aes256CmHmacSha132
        | ProtectionProfile::Aes128CmNullAuth
        | ProtectionProfile::Aes192CmNullAuth
        | ProtectionProfile::Aes256CmNullAuth
        | ProtectionProfile::NullCipherHmacSha180 => {
            let mut transforms = MkiIndexedTransform::new();
            for key in &config.keys {
                transforms.insert(
                    key.mki.clone(),
                    (
                        Box::new(AesCmSha1::new(
                            &key.key,
                            &key.salt,
                            &key.mki,
                            &config.rtp_profile,
                            &config.rtcp_profile,
                        )?),
                        key.lifetime.clone(),
                    ),
                );
            }
            Ok(transforms)
        }
        ProtectionProfile::AeadAes128Gcm | ProtectionProfile::AeadAes256Gcm => {
            let mut transforms = MkiIndexedTransform::new();
            for key in &config.keys {
                transforms.insert(
                    key.mki.clone(),
                    (
                        Box::new(AesGcm::new(
                            &key.key,
                            &key.salt,
                            &key.mki,
                            &config.rtp_profile,
                            &config.rtcp_profile,
                        )?),
                        key.lifetime.clone(),
                    ),
                );
            }
            Ok(transforms)
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use std::sync::{Arc, Mutex};

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

        let ssrc: u32 = 0xcafebabe;

        let hdr = RtpHeader::new(&pattern_rtp_packet)?;
        let rtcp_hdr = RtcpHeader::new(&pattern_rtcp_packet)?;

        let config = StreamConfig::new(
            vec![MasterKey::new(&master_key, &master_salt, &None)],
            &ProtectionProfile::NullCipherHmacSha180,
            &ProtectionProfile::NullCipherHmacSha180,
        );

        let mut s = SendStream::new(ssrc, &config, None)?;
        // Note: rtcp index is set to 1, as patterns comes from libsrtp which updates the index before
        // encryption so effectively starts at index 1.
        s.rtcp_index = 1;

        let mut r = RecvStream::new(ssrc, &config, None)?;

        let srtp_packet = s.rtp_protect(&hdr, pattern_rtp_packet.clone(), &None)?;

        assert_eq!(
            srtp_packet, pattern_srtp_packet,
            "Fail to encrypt rtp packet with with null cipher hmac sha1 80:\n{pattern_rtp_packet:?}\n",
        );

        let rtp_packet = r.rtp_unprotect(&hdr, srtp_packet)?;
        assert_eq!(
            rtp_packet, pattern_rtp_packet,
            "Fail to decrypt srtp packet with with null cipher hmac sha1 80:\n{pattern_srtp_packet:?}\n",
        );

        let srtcp_packet = s.rtcp_protect(&rtcp_hdr, pattern_rtcp_packet.clone(), &None)?;
        assert_eq!(
            srtcp_packet, pattern_srtcp_packet,
            "Fail to encrypt rtcp packet with with null cipher hmac sha1 80:\n{pattern_rtcp_packet:?}\n",
        );
        let rtcp_packet = r.rtcp_unprotect(&rtcp_hdr, srtcp_packet)?;
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

        let ssrc: u32 = 0xcafebabe;

        let hdr = RtpHeader::new(&pattern_rtp_packet)?;
        let rtcp_hdr = RtcpHeader::new(&pattern_rtcp_packet)?;

        let config = StreamConfig::new(
            vec![MasterKey::new(&master_key, &master_salt, &None)],
            &ProtectionProfile::Aes128CmNullAuth,
            &ProtectionProfile::Aes128CmHmacSha180,
        );

        // no auth - rtp only
        let mut s = SendStream::new(ssrc, &config, None)?;
        let mut r = RecvStream::new(ssrc, &config, None)?;

        let srtp_packet = s.rtp_protect(&hdr, pattern_rtp_packet.clone(), &None)?;

        assert_eq!(
            srtp_packet,
            pattern_srtp_packet[0..pattern_rtp_packet.len()],
            "Fail to encrypt rtp packet with with aes128cm null auth:\n{pattern_rtp_packet:?}\n",
        );

        let rtp_packet = r.rtp_unprotect(&hdr, srtp_packet)?;
        assert_eq!(
            rtp_packet, pattern_rtp_packet,
            "Fail to decrypt srtp packet with with aes128cm null auth:\n{pattern_srtp_packet:?}\n",
        );

        // hmac sha1 32 - rtp only
        let config = StreamConfig::new(
            vec![MasterKey::new(&master_key, &master_salt, &None)],
            &ProtectionProfile::Aes128CmHmacSha132,
            &ProtectionProfile::Aes128CmHmacSha180,
        );
        let mut s = SendStream::new(ssrc, &config, None)?;
        let mut r = RecvStream::new(ssrc, &config, None)?;

        let srtp_packet = s.rtp_protect(&hdr, pattern_rtp_packet.clone(), &None)?;

        assert_eq!(
            srtp_packet,
            pattern_srtp_packet[0..pattern_rtp_packet.len() + 4],
            "Fail to encrypt rtp packet with with aes128cm hmac sha1 32:\n{pattern_rtp_packet:?}\n",
        );

        let rtp_packet = r.rtp_unprotect(&hdr, srtp_packet)?;
        assert_eq!(
            rtp_packet, pattern_rtp_packet,
            "Fail to decrypt srtp packet with with aes128cm hmac sha1 32:\n{pattern_srtp_packet:?}\n",
        );

        // hmac sha1 80
        let config = StreamConfig::new(
            vec![MasterKey::new(&master_key, &master_salt, &None)],
            &ProtectionProfile::Aes128CmHmacSha180,
            &ProtectionProfile::Aes128CmHmacSha180,
        );
        let mut s = SendStream::new(ssrc, &config, None)?;
        // Note: rtcp index is set to 1, as patterns comes from libsrtp which updates the index before
        // encryption so effectively starts at index 1.
        s.rtcp_index = 1;
        let mut r = RecvStream::new(ssrc, &config, None)?;

        let mut srtp_packet = s.rtp_protect(&hdr, pattern_rtp_packet.clone(), &None)?;

        assert_eq!(
            srtp_packet, pattern_srtp_packet,
            "Fail to encrypt rtp packet with with aes128cm hmac sha1 80:\n{pattern_rtp_packet:?}\n",
        );

        let rtp_packet = r.rtp_unprotect(&hdr, srtp_packet.clone())?;
        assert_eq!(
            rtp_packet, pattern_rtp_packet,
            "Fail to decrypt srtp packet with with aes128cm hmac sha1 80:\n{pattern_srtp_packet:?}\n",
        );

        let mut srtcp_packet = s.rtcp_protect(&rtcp_hdr, pattern_rtcp_packet.clone(), &None)?;
        assert_eq!(
            srtcp_packet, pattern_srtcp_packet,
            "Fail to encrypt rtcp packet with with aes128cm hmac sha1 80:\n{pattern_rtcp_packet:?}\n",
        );
        let rtcp_packet = r.rtcp_unprotect(&rtcp_hdr, srtcp_packet.clone())?;
        assert_eq!(
            rtcp_packet, pattern_rtcp_packet,
            "Fail to decrypt srtp packet with with aes128cm hmac sha1 80:\n{pattern_srtp_packet:?}\n",
        );

        // failed auth
        let mut r = RecvStream::new(ssrc, &config, None)?; // so we don't hit a replay error

        // missing a byte
        assert_eq!(
            r.rtp_unprotect(&hdr, srtp_packet[..srtp_packet.len() - 1].to_vec()),
            Err(SrtpError::Authentication)
        );
        assert_eq!(
            r.rtcp_unprotect(&rtcp_hdr, srtcp_packet[..srtcp_packet.len() - 1].to_vec()),
            Err(SrtpError::Authentication)
        );

        // wrong tag
        let last_byte_index = srtp_packet.len() - 1;
        srtp_packet[last_byte_index] ^= 0xff;
        assert_eq!(
            r.rtp_unprotect(&hdr, srtp_packet.clone()),
            Err(SrtpError::Authentication)
        );
        let last_byte_index = srtcp_packet.len() - 1;
        srtcp_packet[last_byte_index] ^= 0xff;
        assert_eq!(
            r.rtcp_unprotect(&rtcp_hdr, srtcp_packet.clone()),
            Err(SrtpError::Authentication)
        );

        // too short
        assert_eq!(
            r.rtp_unprotect(&hdr, srtp_packet[..16].to_vec()),
            Err(SrtpError::InvalidPacket)
        );
        assert_eq!(
            r.rtcp_unprotect(&rtcp_hdr, srtcp_packet[..RtcpHeader::len() + 5].to_vec()),
            Err(SrtpError::InvalidPacket)
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

        let ssrc: u32 = 0xcafebabe;

        let hdr = RtpHeader::new(&pattern_rtp_packet)?;

        // no auth - rtp only
        let config = StreamConfig::new(
            vec![MasterKey::new(&master_key, &master_salt, &None)],
            &ProtectionProfile::Aes256CmNullAuth,
            &ProtectionProfile::Aes256CmHmacSha180,
        );
        let mut s = SendStream::new(ssrc, &config, None)?;
        let mut r = RecvStream::new(ssrc, &config, None)?;

        let srtp_packet = s.rtp_protect(&hdr, pattern_rtp_packet.clone(), &None)?;

        assert_eq!(
            srtp_packet,
            pattern_srtp_packet[0..pattern_rtp_packet.len()],
            "Fail to encrypt rtp packet with with aes256cm null auth:\n{pattern_rtp_packet:?}\n",
        );

        let rtp_packet = r.rtp_unprotect(&hdr, srtp_packet)?;
        assert_eq!(
            rtp_packet, pattern_rtp_packet,
            "Fail to decrypt srtp packet with with aes256cm null auth:\n{pattern_srtp_packet:?}\n",
        );

        // hmac sha1 32
        let config = StreamConfig::new(
            vec![MasterKey::new(&master_key, &master_salt, &None)],
            &ProtectionProfile::Aes256CmHmacSha132,
            &ProtectionProfile::Aes256CmHmacSha180,
        );
        let mut s = SendStream::new(ssrc, &config, None)?;
        let mut r = RecvStream::new(ssrc, &config, None)?;

        let srtp_packet = s.rtp_protect(&hdr, pattern_rtp_packet.clone(), &None)?;

        assert_eq!(
            srtp_packet,
            pattern_srtp_packet[0..pattern_rtp_packet.len() + 4],
            "Fail to encrypt rtp packet with with aes256cm hmac sha1 32:\n{pattern_rtp_packet:?}\n",
        );

        let rtp_packet = r.rtp_unprotect(&hdr, srtp_packet)?;
        assert_eq!(
            rtp_packet, pattern_rtp_packet,
            "Fail to decrypt srtp packet with with aes256cm hmac sha1 32 auth:\n{pattern_srtp_packet:?}\n",
        );

        // hmac sha1 80
        let config = StreamConfig::new(
            vec![MasterKey::new(&master_key, &master_salt, &None)],
            &ProtectionProfile::Aes256CmHmacSha180,
            &ProtectionProfile::Aes256CmHmacSha180,
        );
        let mut s = SendStream::new(ssrc, &config, None)?;
        let mut r = RecvStream::new(ssrc, &config, None)?;

        let srtp_packet = s.rtp_protect(&hdr, pattern_rtp_packet.clone(), &None)?;

        assert_eq!(
            srtp_packet, pattern_srtp_packet,
            "Fail to encrypt rtp packet with with aes256cm null auth:\n{pattern_rtp_packet:?}\n",
        );

        let rtp_packet = r.rtp_unprotect(&hdr, srtp_packet)?;
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

        let pattern_srtp_packet_id_2 = vec![
            0x80, 0x0f, 0x12, 0x34, 0xde, 0xca, 0xfb, 0xad, 0xca, 0xfe, 0xba, 0xbe, 0x4e, 0x55,
            0xdc, 0x4c, 0xe7, 0x99, 0x78, 0xd8, 0x8c, 0xa4, 0xd2, 0x15, 0x94, 0x9d, 0x24, 0x02,
            0xf3, 0xa1, 0x46, 0x71, 0xb7, 0x8d, 0x6a, 0xcc, 0x99, 0xea, 0x17, 0x9b, 0x8d, 0xbb,
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

        let pattern_srtcp_packet_id_2 = vec![
            0x81, 0xc8, 0x00, 0x0b, 0xca, 0xfe, 0xba, 0xbe, 0x71, 0x28, 0x03, 0x5b, 0xe4, 0x87,
            0xb9, 0xbd, 0xbe, 0xf8, 0x90, 0x41, 0xf9, 0x77, 0xa5, 0xa8, 0x80, 0x00, 0x00, 0x01,
            0xf3, 0xa1, 0x46, 0x71, 0x99, 0x3e, 0x08, 0xcd, 0x54, 0xd6, 0xc1, 0x23, 0x07, 0x98,
        ];

        let master_key = vec![
            0xe1, 0xf9, 0x7a, 0x0d, 0x3e, 0x01, 0x8b, 0xe0, 0xd6, 0x4f, 0xa3, 0x2c, 0x06, 0xde,
            0x41, 0x39,
        ];
        let master_salt = vec![
            0x0e, 0xc6, 0x75, 0xad, 0x49, 0x8a, 0xfe, 0xeb, 0xb6, 0x96, 0x0b, 0x3a, 0xab, 0xe6,
        ];

        let mki_id = Some(vec![0xe1, 0xf9, 0x7a, 0x0d]);
        let mki_id_2 = Some(vec![0xf3, 0xa1, 0x46, 0x71]);
        let mki_id_too_short = Some(vec![0xf3, 0xa1]);

        let ssrc: u32 = 0xcafebabe;

        let hdr = RtpHeader::new(&pattern_rtp_packet)?;
        let rtcp_hdr = RtcpHeader::new(&pattern_rtcp_packet)?;

        let config = StreamConfig::new(
            vec![MasterKey::new(&master_key, &master_salt, &mki_id)],
            &ProtectionProfile::Aes128CmHmacSha180,
            &ProtectionProfile::Aes128CmHmacSha180,
        );
        let mut s = SendStream::new(ssrc, &config, None)?;
        // Note: rtcp index is set to 1, as patterns comes from libsrtp which updates the index before
        // encryption so effectively starts at index 1.
        s.rtcp_index = 1;
        let mut r = RecvStream::new(ssrc, &config, None)?;

        let srtp_packet = s.rtp_protect(&hdr, pattern_rtp_packet.clone(), &mki_id)?;

        assert_eq!(
            srtp_packet, pattern_srtp_packet,
            "Fail to encrypt rtp packet with with aes128cm hmac sha1 80:\n{pattern_rtp_packet:?}\n",
        );

        let rtp_packet = r.rtp_unprotect(&hdr, srtp_packet)?;
        assert_eq!(
            rtp_packet, pattern_rtp_packet,
            "Fail to decrypt srtp packet with with aes128cm hmac sha1 80:\n{pattern_srtp_packet:?}\n",
        );

        let srtcp_packet = s.rtcp_protect(&rtcp_hdr, pattern_rtcp_packet.clone(), &mki_id)?;
        assert_eq!(
            srtcp_packet, pattern_srtcp_packet,
            "Fail to encrypt rtcp packet with with aes128cm hmac sha1 80:\n{pattern_rtcp_packet:?}\n",
        );
        let rtcp_packet = r.rtcp_unprotect(&rtcp_hdr, srtcp_packet)?;
        assert_eq!(
            rtcp_packet, pattern_rtcp_packet,
            "Fail to decrypt srtp packet with with aes128cm hmac sha1 80:\n{pattern_srtp_packet:?}\n",
        );

        // Try to update with a mki None -> it should fail as we use mki
        let config = StreamConfig::new(
            vec![MasterKey::new(&master_key, &master_salt, &None)],
            &ProtectionProfile::Aes128CmHmacSha180,
            &ProtectionProfile::Aes128CmHmacSha180,
        );

        assert_eq!(s.update(&config), Err(SrtpError::InvalidProfile));

        // Try to update with a mki of different size
        let config = StreamConfig::new(
            vec![MasterKey::new(&master_key, &master_salt, &mki_id_too_short)],
            &ProtectionProfile::Aes128CmHmacSha180,
            &ProtectionProfile::Aes128CmHmacSha180,
        );

        assert_eq!(s.update(&config), Err(SrtpError::InvalidProfile));

        // Recreate streams so we don't hit replay detection, use two mkis
        let config = StreamConfig::new(
            vec![
                MasterKey::new(&master_key, &master_salt, &mki_id),
                MasterKey::new(&master_key, &master_salt, &mki_id_2),
            ],
            &ProtectionProfile::Aes128CmHmacSha180,
            &ProtectionProfile::Aes128CmHmacSha180,
        );
        let mut s = SendStream::new(ssrc, &config, None)?;
        // Note: rtcp index is set to 1, as patterns comes from libsrtp which updates the index before
        // encryption so effectively starts at index 1.
        s.rtcp_index = 1;
        let mut r = RecvStream::new(ssrc, &config, None)?;

        // encrypt/decrypt with it
        let srtp_packet = s.rtp_protect(&hdr, pattern_rtp_packet.clone(), &mki_id_2)?;

        assert_eq!(
            srtp_packet, pattern_srtp_packet_id_2,
            "Fail to encrypt rtp packet with with aes128cm hmac sha1 80:\n{pattern_rtp_packet:?}\n",
        );

        let rtp_packet = r.rtp_unprotect(&hdr, srtp_packet)?;
        assert_eq!(
            rtp_packet, pattern_rtp_packet,
            "Fail to decrypt srtp packet with with aes128cm hmac sha1 80:\n{pattern_srtp_packet:?}\n",
        );

        let srtcp_packet = s.rtcp_protect(&rtcp_hdr, pattern_rtcp_packet.clone(), &mki_id_2)?;
        assert_eq!(
            srtcp_packet, pattern_srtcp_packet_id_2,
            "Fail to encrypt rtcp packet with with aes128cm hmac sha1 80:\n{pattern_rtcp_packet:?}\n",
        );
        let rtcp_packet = r.rtcp_unprotect(&rtcp_hdr, srtcp_packet)?;
        assert_eq!(
            rtcp_packet, pattern_rtcp_packet,
            "Fail to decrypt srtp packet with with aes128cm hmac sha1 80:\n{pattern_srtp_packet:?}\n",
        );

        Ok(())
    }

    #[test]
    fn key_limit() -> Result<(), SrtpError> {
        let ssrc: u32 = 0xcafebabe;

        let master_key = vec![
            0xe1, 0xf9, 0x7a, 0x0d, 0x3e, 0x01, 0x8b, 0xe0, 0xd6, 0x4f, 0xa3, 0x2c, 0x06, 0xde,
            0x41, 0x39,
        ];
        let master_salt = vec![
            0x0e, 0xc6, 0x75, 0xad, 0x49, 0x8a, 0xfe, 0xeb, 0xb6, 0x96, 0x0b, 0x3a, 0xab, 0xe6,
        ];

        let mut pattern_rtp_packet = vec![
            0x80, 0x0f, 0x12, 0x34, 0xde, 0xca, 0xfb, 0xad, 0xca, 0xfe, 0xba, 0xbe, 0xab, 0xab,
            0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
        ];

        let pattern_rtcp_packet = vec![
            0x81, 0xc8, 0x00, 0x0b, 0xca, 0xfe, 0xba, 0xbe, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
            0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
        ];

        // create configs
        let mut s_config = StreamConfig::new(
            vec![MasterKey::new(&master_key, &master_salt, &None)],
            &ProtectionProfile::Aes128CmHmacSha180,
            &ProtectionProfile::Aes128CmHmacSha180,
        );
        // sender configuration will trigger a key soft limit when 2 lives are left
        s_config.set_keys_lifetime(3, 2, 3, 2)?;

        let mut r_config = StreamConfig::new(
            vec![MasterKey::new(&master_key, &master_salt, &None)],
            &ProtectionProfile::Aes128CmHmacSha180,
            &ProtectionProfile::Aes128CmHmacSha180,
        );
        r_config.set_keys_lifetime(2, 1, 2, 1)?;

        let soft_limit_count = Arc::new(Mutex::new(0u32));
        let hard_limit_count = Arc::new(Mutex::new(0u32));
        let soft_limit_clone = soft_limit_count.clone();
        let hard_limit_clone = hard_limit_count.clone();

        let handler = Arc::new(move |err: SrtpError| match err {
            SrtpError::KeyLimit {
                is_dead,
                ssrc: err_ssrc,
                ..
            } => {
                if is_dead {
                    *hard_limit_clone.lock().unwrap() += 1;
                } else {
                    *soft_limit_clone.lock().unwrap() += 1;
                }
                assert_eq!(ssrc, err_ssrc);
            }
            _ => {
                panic!("unexpected error received by key limit handler : {:?}", err);
            }
        });
        let mut s = SendStream::new(ssrc, &s_config, Some(handler.clone()))?;
        let mut r = RecvStream::new(ssrc, &r_config, Some(handler.clone()))?;

        // encrypt a first message, the soft limit count is still 0
        let hdr = RtpHeader::new(&pattern_rtp_packet)?;
        let srtp_packet = s.rtp_protect(&hdr, pattern_rtp_packet.clone(), &None)?;
        assert_eq!(*soft_limit_count.lock().unwrap(), 0);
        r.rtp_unprotect(&hdr, srtp_packet)?;
        assert_eq!(*soft_limit_count.lock().unwrap(), 0);
        // encrypt a second message, the soft limit count should be 1
        pattern_rtp_packet[3] += 1; // increase seq_num to avoid replay detection
        let hdr = RtpHeader::new(&pattern_rtp_packet)?;
        let srtp_packet = s.rtp_protect(&hdr, pattern_rtp_packet.clone(), &None)?;
        assert_eq!(*soft_limit_count.lock().unwrap(), 1);
        r.rtp_unprotect(&hdr, srtp_packet)?;
        assert_eq!(*soft_limit_count.lock().unwrap(), 2);
        // encrypt a third message, the soft limit count should increase again
        pattern_rtp_packet[3] += 1; // increase seq_num to avoid replay detection
        let hdr = RtpHeader::new(&pattern_rtp_packet)?;
        let srtp_packet = s.rtp_protect(&hdr, pattern_rtp_packet.clone(), &None)?;
        assert_eq!(*soft_limit_count.lock().unwrap(), 3);
        assert_eq!(*hard_limit_count.lock().unwrap(), 0);
        // encrypt a fourth message, we reach the hard limit
        pattern_rtp_packet[3] += 1; // increase seq_num to avoid replay detection
        let hdr = RtpHeader::new(&pattern_rtp_packet)?;
        assert!(matches!(
            s.rtp_protect(&hdr, pattern_rtp_packet.clone(), &None),
            Err(SrtpError::KeyLimit {
                is_dead: true,
                is_rtp: true,
                mki: None,
                ..
            })
        ));
        assert_eq!(*soft_limit_count.lock().unwrap(), 3);
        assert_eq!(*hard_limit_count.lock().unwrap(), 1);
        // decrypt the third message with key lives to 1 so we get a and hard limit error
        assert!(matches!(
            r.rtp_unprotect(&hdr, srtp_packet),
            Err(SrtpError::KeyLimit {
                is_dead: true,
                is_rtp: true,
                mki: None,
                ..
            })
        ));
        assert_eq!(*soft_limit_count.lock().unwrap(), 3);
        assert_eq!(*hard_limit_count.lock().unwrap(), 2);

        // Try encrypting RTCP packet -> it shall fail as RTP already reached hard limit
        let hdr = RtcpHeader::new(&pattern_rtcp_packet)?;
        assert!(matches!(
            s.rtcp_protect(&hdr, pattern_rtcp_packet.clone(), &None),
            Err(SrtpError::KeyLimit {
                is_dead: true,
                is_rtp: false,
                mki: None,
                ..
            })
        ));

        // repeat for rtcp resetting sessions
        let mut s = SendStream::new(ssrc, &s_config, Some(handler.clone()))?;
        let mut r = RecvStream::new(ssrc, &r_config, Some(handler.clone()))?;
        *soft_limit_count.lock().unwrap() = 0;
        *hard_limit_count.lock().unwrap() = 0;
        let srtcp_packet = s.rtcp_protect(&hdr, pattern_rtcp_packet.clone(), &None)?;
        assert_eq!(*soft_limit_count.lock().unwrap(), 0);
        r.rtcp_unprotect(&hdr, srtcp_packet)?;
        assert_eq!(*soft_limit_count.lock().unwrap(), 0);
        // encrypt a second message, the soft limit count should be 1
        let srtcp_packet = s.rtcp_protect(&hdr, pattern_rtp_packet.clone(), &None)?;
        assert_eq!(*soft_limit_count.lock().unwrap(), 1);
        r.rtcp_unprotect(&hdr, srtcp_packet)?;
        assert_eq!(*soft_limit_count.lock().unwrap(), 2);
        // encrypt a third message, the soft limit count should increase again
        let srtcp_packet = s.rtcp_protect(&hdr, pattern_rtp_packet.clone(), &None)?;
        assert_eq!(*soft_limit_count.lock().unwrap(), 3);
        assert_eq!(*hard_limit_count.lock().unwrap(), 0);
        // encrypt a fourth message, we reach the hard limit
        assert!(matches!(
            s.rtcp_protect(&hdr, pattern_rtp_packet.clone(), &None),
            Err(SrtpError::KeyLimit {
                is_dead: true,
                is_rtp: false,
                mki: None,
                ..
            })
        ));
        assert_eq!(*soft_limit_count.lock().unwrap(), 3);
        assert_eq!(*hard_limit_count.lock().unwrap(), 1);
        // decrypt the third message with key lives to 1 so we get a and hard limit error
        assert!(matches!(
            r.rtcp_unprotect(&hdr, srtcp_packet),
            Err(SrtpError::KeyLimit {
                is_dead: true,
                is_rtp: false,
                mki: None,
                ..
            })
        ));
        assert_eq!(*soft_limit_count.lock().unwrap(), 3);
        assert_eq!(*hard_limit_count.lock().unwrap(), 2);

        // Try encrypting RTP packet -> it shall fail as RTCP already reached hard limit
        let hdr = RtpHeader::new(&pattern_rtp_packet)?;
        assert!(matches!(
            s.rtp_protect(&hdr, pattern_rtp_packet.clone(), &None),
            Err(SrtpError::KeyLimit {
                is_dead: true,
                is_rtp: true,
                mki: None,
                ..
            })
        ));

        Ok(())
    }
}
