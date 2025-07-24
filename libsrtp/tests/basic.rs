use anyhow::{Context, bail};
use libsrtp::{MasterKey, ProtectionProfile, RecvSession, SendSession, SrtpError, StreamConfig};
use test_utils::*;

fn one_stream(
    packet_num: usize,   // number of packets
    payload_size: usize, // payload size of each packet
    seq_num: u16,        // initial seqnum
    ssrc: u32,           // ssrc to use
    rtp_profile: ProtectionProfile,
    rtcp_profile: ProtectionProfile,
    unordered_decrypt: bool,
) -> anyhow::Result<(SendSession, RecvSession)> {
    // create send and recv sessions
    let mut s = SendSession::new();
    let mut r = RecvSession::new();

    // create config
    let (master_key, master_salt) = generate_keys(&rtp_profile);
    let mut config = StreamConfig::new(
        vec![MasterKey::new(&master_key, &master_salt, &None)],
        &rtp_profile,
        &rtcp_profile,
    );

    // add streams
    s.add_stream(Some(ssrc), &config)
        .map_err(anyhow::Error::from)
        .with_context(|| "failed to add send stream".to_string())?;

    // when decrypting is unordered, make sure we cannot be out of the replay window
    if unordered_decrypt && config.get_replay_window_size() < packet_num as u16 {
        config.set_replay_window_size((packet_num + 1) as u16);
    }
    r.add_stream(Some(ssrc), &config)
        .map_err(anyhow::Error::from)
        .with_context(|| ("failed to add recv stream").to_string())?;

    // encrypt and store in stream
    let mut rtp_stream = Vec::<Vec<u8>>::new();
    let mut rtcp_stream = Vec::<Vec<u8>>::new();
    let mut srtp_stream = Vec::<Vec<u8>>::new();
    let mut srtcp_stream = Vec::<Vec<u8>>::new();
    for i in 0..packet_num {
        let seq = seq_num.wrapping_add(i as u16); // seq must wrap around 2^16
        // create packets
        let rtp = create_rtp_packet(payload_size, ssrc, seq);
        let rtcp = create_rtcp_packet(payload_size / 4, ssrc);
        // encrypt
        srtp_stream.push(
            s.rtp_protect(rtp.clone())
                .map_err(anyhow::Error::from)
                .with_context(|| ("rtp protect failed").to_string())?,
        );
        rtp_stream.push(rtp);
        srtcp_stream.push(
            s.rtcp_protect(rtcp.clone())
                .map_err(anyhow::Error::from)
                .with_context(|| ("rtcp protect failed").to_string())?,
        );
        rtcp_stream.push(rtcp);
    }

    // decrypt
    let mut range: Vec<usize> = (0..packet_num).collect();
    if unordered_decrypt {
        range = rnd_range(0, packet_num);
    }
    let penultimate_index = range[range.len() - 2];
    for i in range {
        if r.rtp_unprotect(srtp_stream[i].clone())
            .map_err(anyhow::Error::from)
            .with_context(|| ("rtp unprotect failed").to_string())?
            != rtp_stream[i]
        {
            bail!("rtp decrypt didn't match plain");
        }
        if r.rtcp_unprotect(srtcp_stream[i].clone())
            .map_err(anyhow::Error::from)
            .with_context(|| ("rtcp unprotect failed").to_string())?
            != rtcp_stream[i]
        {
            bail!("rtcp decrypt didn't match plain");
        }
    }

    // try to replay an already decrypted packet
    if r.rtp_unprotect(srtp_stream[penultimate_index].clone()) != Err(SrtpError::InvalidPacketIndex)
    {
        bail!("rtp fails to detect replay");
    }
    if r.rtcp_unprotect(srtcp_stream[penultimate_index].clone())
        != Err(SrtpError::InvalidPacketIndex)
    {
        bail!("rtcp fails to detect replay");
    }
    Ok((s, r))
}

#[test]
fn simple_stream() -> anyhow::Result<()> {
    let packet_num: usize = 42;
    let payload_size: usize = 123;
    let ssrc: u32 = 0xcafebabe;
    let seq_num: u16 = 0x0123;

    // test all available transforms
    for (rtp_profile, rtcp_profile) in VALID_PROFILES {
        one_stream(
            packet_num,
            payload_size,
            seq_num,
            ssrc,
            rtp_profile,
            rtcp_profile,
            false,
        )
        .with_context(|| {
            format!(
                "failed with profiles {:?}/{:?} packet num {packet_num}",
                rtp_profile, rtcp_profile,
            )
        })?;
    }
    Ok(())
}

#[test]
fn empty_payload() -> anyhow::Result<()> {
    let packet_num: usize = 42;
    let payload_size: usize = 0;
    let ssrc: u32 = 0xcafebabe;
    let seq_num: u16 = 0x0123;

    // test all available transforms
    for (rtp_profile, rtcp_profile) in VALID_PROFILES {
        one_stream(
            packet_num,
            payload_size,
            seq_num,
            ssrc,
            rtp_profile,
            rtcp_profile,
            false,
        )
        .with_context(|| {
            format!(
                "failed with profiles {:?}/{:?} packet num {packet_num}",
                rtp_profile, rtcp_profile,
            )
        })?;
    }

    Ok(())
}

#[test]
fn simple_stream_unordered_decrypt() -> anyhow::Result<()> {
    let packet_num: usize = 142; // more than default replay window size so it fails if we do not
    // set the windows size correctly
    // Do not put more than what can fit in a u16
    let payload_size: usize = 123;
    let ssrc: u32 = 0xcafebabe;
    let seq_num: u16 = 0x0123;

    // test all available transforms
    for (rtp_profile, rtcp_profile) in VALID_PROFILES {
        one_stream(
            packet_num,
            payload_size,
            seq_num,
            ssrc,
            rtp_profile,
            rtcp_profile,
            true,
        )
        .with_context(|| {
            format!(
                "failed with profiles {:?}/{:?} packet num {packet_num}",
                rtp_profile, rtcp_profile,
            )
        })?;
    }
    Ok(())
}

#[test]
fn roc_rollover() -> anyhow::Result<()> {
    let packet_num: usize = 42;
    let payload_size: usize = 123;
    let ssrc: u32 = 0xcafebabe;
    let seq_num: u16 = 0xfff0; // seq_num + packet num makes it wrap around

    let (s, r) = one_stream(
        packet_num,
        payload_size,
        seq_num,
        ssrc,
        ProtectionProfile::Aes128CmHmacSha180,
        ProtectionProfile::Aes128CmHmacSha180,
        false,
    )
    .with_context(|| ("roc rollover failed").to_string())?;

    // check the roc is now 1 on send and recv context
    assert_eq!(
        s.get_roc(ssrc)
            .expect("failed to fetch roc from send context"),
        1,
        "Roc is not what expected"
    );
    assert_eq!(
        r.get_roc(ssrc)
            .expect("failed to fetch roc from recv context"),
        1,
        "Roc is not what expected"
    );
    Ok(())
}

fn multi_stream(
    packet_num: usize,    // number of packets
    payload_size: usize,  // payload size of each packet
    stream_number: usize, // number of streams to deploy
    rtp_profile: ProtectionProfile,
    rtcp_profile: ProtectionProfile,
) -> anyhow::Result<()> {
    // create send and recv sessions
    let mut s = SendSession::new();
    let mut r = RecvSession::new();

    // create config
    let (master_key, master_salt) = generate_keys(&rtp_profile);
    let mut config = StreamConfig::new(
        vec![MasterKey::new(&master_key, &master_salt, &None)],
        &rtp_profile,
        &rtcp_profile,
    );
    // we allways decrypt in random order so check the replay window is large enough
    if (config.get_replay_window_size() as usize) < packet_num {
        config.set_replay_window_size((packet_num + 1) as u16);
    }

    // add templated streams
    s.add_stream(None, &config)
        .map_err(anyhow::Error::from)
        .with_context(|| ("failed to add send stream").to_string())?;

    r.add_stream(None, &config)
        .map_err(anyhow::Error::from)
        .with_context(|| ("failed to add recv stream").to_string())?;

    // encrypt and store in stream
    let mut rtp_stream = Vec::<Vec<u8>>::new();
    let mut rtcp_stream = Vec::<Vec<u8>>::new();
    let mut srtp_stream = Vec::<Vec<u8>>::new();
    let mut srtcp_stream = Vec::<Vec<u8>>::new();
    let seq_nums = get_seq_nums(stream_number);
    let ssrcs = get_ssrcs(stream_number);

    for i in 0..packet_num {
        for j in 0..stream_number {
            let seq = seq_nums[j].wrapping_add(i as u16); // seq must wrap around 2^16

            // create packets
            let rtp = create_rtp_packet(payload_size, ssrcs[j], seq);
            let rtcp = create_rtcp_packet(payload_size / 4, ssrcs[j]);
            // encrypt
            srtp_stream.push(
                s.rtp_protect(rtp.clone())
                    .map_err(anyhow::Error::from)
                    .with_context(|| ("rtp protect failed").to_string())?,
            );
            rtp_stream.push(rtp);
            srtcp_stream.push(
                s.rtcp_protect(rtcp.clone())
                    .map_err(anyhow::Error::from)
                    .with_context(|| ("rtcp protect failed").to_string())?,
            );
            rtcp_stream.push(rtcp);
        }
    }

    // decrypt
    let range: Vec<usize> = rnd_range(0, packet_num * stream_number);
    for i in range {
        if r.rtp_unprotect(srtp_stream[i].clone())
            .map_err(anyhow::Error::from)
            .with_context(|| ("rtp unprotect failed").to_string())?
            != rtp_stream[i]
        {
            bail!("rtp decrypt didn't match plain");
        }
        if r.rtcp_unprotect(srtcp_stream[i].clone())
            .map_err(anyhow::Error::from)
            .with_context(|| ("rtcp unprotect failed").to_string())?
            != rtcp_stream[i]
        {
            bail!("rtcp decrypt didn't match plain");
        }
    }

    Ok(())
}

#[test]
fn multi_stream_unordered_decrypt() -> anyhow::Result<()> {
    let packet_num: usize = 150;
    let payload_size: usize = 42;
    let stream_number = 4;

    // test all available transforms
    for (rtp_profile, rtcp_profile) in VALID_PROFILES {
        multi_stream(
            packet_num,
            payload_size,
            stream_number,
            rtp_profile,
            rtcp_profile,
        )
        .with_context(|| {
            format!(
                "failed with profiles {:?}/{:?} packet num {packet_num}",
                rtp_profile, rtcp_profile,
            )
        })?;
    }
    Ok(())
}

#[test]
fn roc_update() {
    let ssrc: u32 = 0xcafebabe;
    // create send and recv streams
    let mut s = SendSession::new();
    let mut r = RecvSession::new();

    // create config
    let (master_key, master_salt) = generate_keys(&ProtectionProfile::Aes128CmHmacSha180);
    let config = StreamConfig::new(
        vec![MasterKey::new(&master_key, &master_salt, &None)],
        &ProtectionProfile::Aes128CmHmacSha180,
        &ProtectionProfile::Aes128CmHmacSha180,
    );

    // add streams
    s.add_stream(Some(ssrc), &config)
        .expect("failed to add send stream");
    r.add_stream(Some(ssrc), &config)
        .expect("failed to add recv stream");

    // create and encrypt rtp packet with seq num 0xfffe and 0x0001
    s.rtp_protect(create_rtp_packet(123, ssrc, 0xfffe))
        .expect("failed to encrypt packet");
    s.rtp_protect(create_rtp_packet(123, ssrc, 0x0001))
        .expect("failed to encrypt packet");
    // check the current sending roc is 1
    assert_eq!(s.get_roc(ssrc).expect("failed to get roc"), 1);
    // create rtp packet with seq num 0x0002
    let rtp = create_rtp_packet(123, ssrc, 0x0002);
    let srtp = s
        .rtp_protect(rtp.clone())
        .expect("failed to encrypt packet");
    // try to decrypt the packet, it shall fail as the decrypt context is expecting the roc to be 0
    assert_eq!(
        r.rtp_unprotect(srtp.clone()),
        Err(SrtpError::Authentication)
    );
    // set the roc to be 1 on the recv side
    r.set_roc(ssrc, 1).expect("failed to set roc");
    // try again to decrypt the packet, it shall succeed
    assert_eq!(
        r.rtp_unprotect(srtp).expect("failed to decrytp"),
        rtp,
        "decrypted srtp packet mismatch plain"
    );
}

#[test]
fn allow_send_repeat() {
    let ssrc: u32 = 0xcafebabe;
    // create send and recv streams
    let mut s = SendSession::new();

    // create config
    let (master_key, master_salt) = generate_keys(&ProtectionProfile::Aes128CmHmacSha180);
    let mut config = StreamConfig::new(
        vec![MasterKey::new(&master_key, &master_salt, &None)],
        &ProtectionProfile::Aes128CmHmacSha180,
        &ProtectionProfile::Aes128CmHmacSha180,
    );

    // add streams
    s.add_stream(Some(ssrc), &config)
        .expect("failed to add send stream");

    // create a packet
    let rtp = create_rtp_packet(123, ssrc, 0xabcd);
    s.rtp_protect(rtp.clone())
        .expect("failed to encrypt packet");

    // try to encrypt again the same packet
    assert_eq!(
        s.rtp_protect(rtp.clone()),
        Err(SrtpError::InvalidPacketIndex)
    );

    // update stream: the replay db is untouched
    s.add_stream(Some(ssrc), &config)
        .expect("failed to update send stream");
    assert_eq!(
        s.rtp_protect(rtp.clone()),
        Err(SrtpError::InvalidPacketIndex)
    );

    // update stream allowing retransmission
    config.allow_send_repeat(true);
    s.add_stream(Some(ssrc), &config)
        .expect("failed to update send stream");

    s.rtp_protect(rtp.clone())
        .expect("failed to encrypt packet");
    s.rtp_protect(rtp.clone())
        .expect("failed to encrypt packet");
}
