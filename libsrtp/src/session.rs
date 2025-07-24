use crate::SrtpError;
use crate::header::{RtcpHeader, RtpHeader};
use crate::stream::{KeyLimitHandler, RecvStream, SendStream, StreamConfig, StreamInterface};
use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::sync::Arc;

/// Do not use this struct directly, use [SendSession] or [RecvSession] instead
///
/// Common interface to sender and receiver sessions
pub struct Session<T: StreamInterface> {
    /// indexed by ssrc store streams and flag set to true when this stream was spawn from the
    /// template stream config
    streams: HashMap<u32, (T, bool)>,
    /// the current template stream config
    template_config: Option<StreamConfig>,
    /// optionnal callback to report a key uses limit reached
    key_limit_handler: Option<KeyLimitHandler>,
}

impl<T: StreamInterface> Default for Session<T> {
    fn default() -> Self {
        Self {
            streams: HashMap::new(),
            template_config: None,
            key_limit_handler: None,
        }
    }
}

/// Common API for sender and receiver sessions
impl<T: StreamInterface> Session<T> {
    /// Create a new session that can hold several streams
    ///
    /// A session can hold:
    /// - several streams directly identified by their SSRC. These streams are independants and may differ in
    ///   protection profile used.
    /// - one stream template used to spawn a stream when a new SSRC is found in a packet header
    ///
    pub fn new() -> Self {
        Self::default()
    }

    /// Set a handler called when a key reaches the soft or hard uses limit
    ///
    /// The limits are fixed: 2^31 for RTCP, 2^48 for RTP. See RFC 3711 - 9.2
    ///
    /// SoftLimit alert is raised when there is less than 2^16 uses left
    ///
    /// # handler argument:
    /// - SrtpError: the handler is always called with a KeyLimit error. See
    ///   [SrtpError::KeyLimit] for details
    ///
    /// # Notes:
    /// - This handler must be set before any stream is added to the session.
    pub fn set_key_limit_handler<F>(&mut self, handler: F) -> Result<(), SrtpError>
    where
        F: Fn(SrtpError) + Send + Sync + 'static,
    {
        if !self.streams.is_empty() {
            return Err(SrtpError::ContextNotReady);
        }
        self.key_limit_handler = Some(Arc::new(handler));
        Ok(())
    }

    /// Add (or update) a stream
    ///
    /// if the given ssrc match an existing stream, update it, otherwise add it.
    ///
    /// On update (used for re-keying), mki policy must be compatible with current one.
    ///
    /// # Arguments
    /// * ssrc: the SSRC that identify the stream, when None: refers to the stream template
    /// * config: configuration for this stream
    /// # Returns
    /// Ok or an error if the stream cannot be added or updated
    pub fn add_stream(
        &mut self,
        ssrc: Option<u32>,
        config: &StreamConfig,
    ) -> Result<(), SrtpError> {
        config.validate()?;

        match ssrc {
            None => {
                // no ssrc, this is the template stream
                // update the templated_ssrcs
                for (stream, from_template) in self.streams.values_mut() {
                    if *from_template {
                        stream.update(config)?; // check config compat and update
                    }
                }
                // store the template config
                self.template_config = Some(config.clone());
            }
            Some(ssrc) => {
                // some ssrc, this is a regular stream
                match self.streams.get_mut(&ssrc) {
                    None => {
                        // stream not present, add it
                        self.streams.insert(
                            ssrc,
                            (T::new(ssrc, config, self.key_limit_handler.clone())?, false),
                        );
                    }
                    Some((stream, from_template)) => {
                        // this stream already exits, try to update
                        stream.update(config)?;
                        *from_template = false; // make sure this flag is not set as spwaned from template
                    }
                }
            }
        }
        Ok(())
    }

    /// remove a stream
    /// # Arguments
    /// * ssrc: the SSRC that identify the stream
    /// # Returns
    /// Ok or a StreamNotFound error
    pub fn remove_stream(&mut self, ssrc: u32) -> Result<(), SrtpError> {
        self.streams
            .remove(&ssrc)
            .ok_or(SrtpError::StreamNotFound)?;
        Ok(())
    }

    /// get the current ROC from a specific stream
    ///
    /// # Arguments
    /// - ssrc: the ssrc identifying the stream
    ///
    /// # Returns
    /// the ROC if the stream is found, a StreamNotFound error otherwise
    pub fn get_roc(&self, ssrc: u32) -> Result<u32, SrtpError> {
        let (stream, _from_template) = self.streams.get(&ssrc).ok_or(SrtpError::StreamNotFound)?;
        Ok(stream.get_roc())
    }

    /// Get a stream
    /// If the stream is not found, try to create it using the configuration template
    /// # Arguments
    /// * `ssrc` - the SSRC that identify the stream
    /// # Returns
    /// * stream: a mutable reference to the stream
    /// * from_template : a flag set to true if this stream was created from template
    /// * pending: a flag set to true if the stream was just created from template
    ///
    /// or an error when the stream is not found
    fn get_stream(&mut self, ssrc: u32) -> Result<(&mut T, bool, bool), SrtpError> {
        match self.streams.entry(ssrc) {
            // found the stream
            Entry::Occupied(entry) => {
                let (stream, from_template) = entry.into_mut();
                Ok((stream, *from_template, false))
            }
            // stream not found: try to add it using the template
            Entry::Vacant(entry) => {
                let template_config = self
                    .template_config
                    .as_ref()
                    .ok_or(SrtpError::StreamNotFound)?;
                let (stream, _from_template) = entry.insert((
                    T::new(ssrc, template_config, self.key_limit_handler.clone())?,
                    true,
                ));
                Ok((stream, true, true))
            }
        }
    }

    /// handler for stream operation returning an error:
    /// * if the stream was pending, remove it
    /// * if this is an error signaling hard limit reached in a key usage -> block other stream
    ///   that derives from the same master key. For hard limit, the error carries the mki value,
    ///   remap it to the hard limit error without mki
    ///
    /// # Arguments
    /// * e: the error returned by the stream operation
    /// * from_template: flag true when the stream derives from template config
    /// * pending: true is this stream was newly spawned from template
    fn handle_stream_error(
        &mut self,
        e: &SrtpError,
        ssrc: u32,
        from_template: bool,
        pending: bool,
    ) {
        // when stream is newly spawned, we failed to confirm its validity, remove it
        if pending {
            let _ = self.remove_stream(ssrc);
        }
        // when a templated stream raise a hard limit error
        if from_template
            && let SrtpError::KeyLimit {
                mki, is_dead: true, ..
            } = e
        {
            for (stream, from_template) in self.streams.values_mut() {
                if *from_template {
                    // kill all the templated streams derived from the same key
                    let _ = stream.kill_session_keys(mki);
                }
            }
            // we must also disable this key in the template config
            if let Some(cfg) = self.template_config.as_mut() {
                let _ = cfg.set_keys_lifetime_mki(0, 0, 0, 0, mki);
            }
        };
    }
}

/// Session type used for sending streams
pub type SendSession = Session<SendStream>;
/// Session type used for receiving streams
pub type RecvSession = Session<RecvStream>;

impl SendSession {
    /// Encrypt a RTP packet
    ///
    /// Packet is encrypted in place, the function gets packet ownership and gives it back
    ///
    /// # Arguments
    /// - plain : the plain RTP packet
    /// - mki: optional mki to be used. It must match a mki configured in a stream with a SSRC
    ///   matching the one present in the packet header
    ///
    /// # Returns
    /// the encrypted packet or an error
    pub fn rtp_protect_mki(
        &mut self,
        plain: Vec<u8>,
        mki: &Option<Vec<u8>>,
    ) -> Result<Vec<u8>, SrtpError> {
        // parse header to get ssrc
        let header = RtpHeader::new(&plain)?;
        // get the stream, pending is true when the stream just got created from template
        let (stream, from_template, pending) = self.get_stream(header.ssrc())?;
        // apply the protect
        stream
            .rtp_protect(&header, plain, mki)
            .inspect_err(|e| self.handle_stream_error(e, header.ssrc(), from_template, pending))
    }

    /// Encrypt a RTP packet: convenience wrapper when mki is not used
    pub fn rtp_protect(&mut self, plain: Vec<u8>) -> Result<Vec<u8>, SrtpError> {
        self.rtp_protect_mki(plain, &None)
    }

    /// Encrypt a RTCP packet
    ///
    /// Packet is encrypted in place, the function gets packet ownership and gives it back
    ///
    /// # Arguments
    /// - plain : the plain RTP packet
    /// - mki: optional mki to be used. It must match a mki configured in a stream with a SSRC
    ///   matching the one present in the packet header
    ///
    /// # Returns
    /// the encrypted packet or an error
    pub fn rtcp_protect_mki(
        &mut self,
        plain: Vec<u8>,
        mki: &Option<Vec<u8>>,
    ) -> Result<Vec<u8>, SrtpError> {
        // parse header to get ssrc
        let header = RtcpHeader::new(&plain)?;
        let (stream, from_template, pending) = self.get_stream(header.ssrc())?;
        stream
            .rtcp_protect(&header, plain, mki)
            .inspect_err(|e| self.handle_stream_error(e, header.ssrc(), from_template, pending))
    }
    /// Encrypt a RTCP packet: convenience wrapper when mki is not used
    pub fn rtcp_protect(&mut self, plain: Vec<u8>) -> Result<Vec<u8>, SrtpError> {
        self.rtcp_protect_mki(plain, &None)
    }
}

impl RecvSession {
    /// set the ROC on a specific stream
    ///
    /// Used for late joiners to a multicasted stream. This function is usually called just after
    /// the stream is added otherwise unprotect will fail.
    ///
    /// The ROC is confirmed in the stream after the next successfull unprotect operation
    ///
    /// The given ROC must be lower or equal than the current one (which should be 0 if this is
    /// called just after the stream is added to the session)
    ///
    /// # Arguments
    /// - ssrc: the ssrc identifying the stream
    /// - roc: the roc value
    ///
    /// # Returns Ok or
    /// * StreamNotFound: no stream matching this SSRC in the session
    /// * InvalidPacketIndex: given ROC < current ROC
    pub fn set_roc(&mut self, ssrc: u32, roc: u32) -> Result<(), SrtpError> {
        let (stream, _from_template) = self
            .streams
            .get_mut(&ssrc)
            .ok_or(SrtpError::StreamNotFound)?;
        stream.set_roc(roc)?;
        Ok(())
    }

    /// Decrypt a RTP packet
    ///
    /// Packet is decrypted in place, the function gets packet ownership and gives it back
    ///
    /// # Arguments
    /// - cipher : the encrypted RTP packet
    ///
    /// # Returns
    /// the decrypted RP packet or an error
    pub fn rtp_unprotect(&mut self, cipher: Vec<u8>) -> Result<Vec<u8>, SrtpError> {
        // parse header to get ssrc
        let header = RtpHeader::new(&cipher)?;
        // get (or create from template) stream and apply the transform
        let (stream, from_template, pending) = self.get_stream(header.ssrc())?;
        stream
            .rtp_unprotect(&header, cipher)
            .inspect_err(|e| self.handle_stream_error(e, header.ssrc(), from_template, pending))
    }

    /// Decrypt a RTCP packet
    ///
    /// Packet is decrypted in place, the function gets packet ownership and gives it back
    ///
    /// # Arguments
    /// - cipher : the encrypted RTCP packet
    ///
    /// # Returns
    /// the decrypted RTCP packet or an error
    pub fn rtcp_unprotect(&mut self, cipher: Vec<u8>) -> Result<Vec<u8>, SrtpError> {
        // parse header to get ssrc
        let header = RtcpHeader::new(&cipher)?;
        // get (or create from template) stream and apply the transform
        let (stream, from_template, pending) = self.get_stream(header.ssrc())?;
        stream
            .rtcp_unprotect(&header, cipher)
            .inspect_err(|e| self.handle_stream_error(e, header.ssrc(), from_template, pending))
    }
}
