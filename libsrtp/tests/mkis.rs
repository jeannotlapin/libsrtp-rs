use anyhow::{Context, bail};
use libsrtp::{MasterKey, ProtectionProfile, RecvSession, SendSession, SrtpError, StreamConfig};
use std::sync::{Arc, Mutex};
use test_utils::*;

fn one_stream_mki(
    packet_num: usize,   // number of packets
    payload_size: usize, // payload size of each packet
    seq_num: u16,        // initial seqnum
    ssrc: u32,           // ssrc to use
    rtp_profile: ProtectionProfile,
    rtcp_profile: ProtectionProfile,
    unordered_decrypt: bool,
) -> anyhow::Result<()> {
    // create send and recv sessions
    let mut s = SendSession::new();
    let mut r = RecvSession::new();

    // create config, use 3 mkis
    let (master_key1, master_salt1) = generate_keys(&rtp_profile);
    let (master_key2, master_salt2) = generate_keys(&rtp_profile);
    let (master_key3, master_salt3) = generate_keys(&rtp_profile);
    let mkis = vec![
        Some(vec![0x01, 0x23, 0x45]),
        Some(vec![0x67, 0x89, 0xab]),
        Some(vec![0xcd, 0xef, 0x01]),
    ];
    let mut config = StreamConfig::new(
        vec![
            MasterKey::new(&master_key1, &master_salt1, &mkis[0]),
            MasterKey::new(&master_key2, &master_salt2, &mkis[1]),
            MasterKey::new(&master_key3, &master_salt3, &mkis[2]),
        ],
        &rtp_profile,
        &rtcp_profile,
    );

    // add streams
    s.add_stream(Some(ssrc), &config)
        .map_err(anyhow::Error::from)
        .with_context(|| ("failed to add send stream").to_string())?;
    // when decrypting is unordered, make sure we cannot be out of the replay window
    if unordered_decrypt && (config.get_replay_window_size() as usize) < packet_num * mkis.len() {
        config.set_replay_window_size((packet_num * mkis.len() + 1) as u16);
    }

    r.add_stream(Some(ssrc), &config)
        .map_err(anyhow::Error::from)
        .with_context(|| ("failed to add recv stream").to_string())?;

    // encrypt and store in stream
    let mut rtp_stream = Vec::<Vec<u8>>::new();
    let mut rtcp_stream = Vec::<Vec<u8>>::new();
    let mut srtp_stream = Vec::<Vec<u8>>::new();
    let mut srtcp_stream = Vec::<Vec<u8>>::new();

    let mut seq = seq_num;
    for mki in &mkis {
        for _i in 0..packet_num {
            // create packets
            let rtp = create_rtp_packet(payload_size, ssrc, seq);
            let rtcp = create_rtcp_packet(payload_size / 4, ssrc);
            // encrypt
            srtp_stream.push(
                s.rtp_protect_mki(rtp.clone(), mki)
                    .map_err(anyhow::Error::from)
                    .with_context(|| ("rtp protect failed").to_string())?,
            );
            rtp_stream.push(rtp);
            srtcp_stream.push(
                s.rtcp_protect_mki(rtcp.clone(), mki)
                    .map_err(anyhow::Error::from)
                    .with_context(|| ("rtcp protect failed").to_string())?,
            );
            rtcp_stream.push(rtcp);
            seq = seq.wrapping_add(1); // seq must wrap around 2^16
        }
    }

    // decrypt
    let mut range: Vec<usize> = (0..packet_num * mkis.len()).collect();
    if unordered_decrypt {
        range = rnd_range(0, packet_num * mkis.len());
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

    Ok(())
}

#[test]
fn simple_stream() -> anyhow::Result<()> {
    let packet_num: usize = 42;
    let payload_size: usize = 123;
    let ssrc: u32 = 0xcafebabe;
    let seq_num: u16 = 0x0123;

    // test all available transforms
    for (rtp_profile, rtcp_profile) in VALID_PROFILES {
        one_stream_mki(
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

    for (rtp_profile, rtcp_profile) in VALID_PROFILES {
        one_stream_mki(
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
    let packet_num: usize = 45;
    let payload_size: usize = 123;
    let ssrc: u32 = 0xcafebabe;
    let seq_num: u16 = 0x0123;

    // test all available transforms
    for (rtp_profile, rtcp_profile) in VALID_PROFILES {
        one_stream_mki(
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

/// scenario:
/// - add a stream using mki, with one key
/// - encrypt packet_num packets with that one mki
/// - try to encrypt packet with a mki not set yet -> it shall fail
/// - update the stream with to new master keys
/// - encrypt packet_num packets for each of the mki (including the first one)
/// - decrypt everything (possible in random order)
fn one_stream_mki_update(
    packet_num: usize,   // number of packets
    payload_size: usize, // payload size of each packet
    seq_num: u16,        // initial seqnum
    ssrc: u32,           // ssrc to use
    rtp_profile: ProtectionProfile,
    rtcp_profile: ProtectionProfile,
) -> anyhow::Result<()> {
    // create send and recv sessions
    let mut s = SendSession::new();
    let mut r = RecvSession::new();

    // add receiver stream
    // create config, with 3 mkis
    let (master_key1, master_salt1) = generate_keys(&rtp_profile);
    let (master_key2, master_salt2) = generate_keys(&rtp_profile);
    let (master_key3, master_salt3) = generate_keys(&rtp_profile);
    let mkis = [
        Some(vec![0x01, 0x23, 0x45]),
        Some(vec![0x67, 0x89, 0xab]),
        Some(vec![0xcd, 0xef, 0x01]),
    ];

    let mut r_config = StreamConfig::new(
        vec![
            MasterKey::new(&master_key1, &master_salt1, &mkis[0]),
            MasterKey::new(&master_key2, &master_salt2, &mkis[1]),
            MasterKey::new(&master_key3, &master_salt3, &mkis[2]),
        ],
        &rtp_profile,
        &rtcp_profile,
    );
    // decrypting is unordered, make sure we cannot be out of the replay window
    if (r_config.get_replay_window_size() as usize) < (packet_num * (mkis.len() + 1) + 1) {
        r_config.set_replay_window_size((packet_num * (mkis.len() + 1) + 1) as u16);
    }
    r.add_stream(Some(ssrc), &r_config)
        .map_err(anyhow::Error::from)
        .with_context(|| ("failed to add recv stream").to_string())?;

    // add sending streams, use one mki first
    let s_config = StreamConfig::new(
        vec![MasterKey::new(&master_key1, &master_salt1, &mkis[0])],
        &rtp_profile,
        &rtcp_profile,
    );

    // add streams
    s.add_stream(Some(ssrc), &s_config)
        .map_err(anyhow::Error::from)
        .with_context(|| ("failed to add send stream").to_string())?;

    // encrypt and store in stream
    let mut rtp_stream = Vec::<Vec<u8>>::new();
    let mut rtcp_stream = Vec::<Vec<u8>>::new();
    let mut srtp_stream = Vec::<Vec<u8>>::new();
    let mut srtcp_stream = Vec::<Vec<u8>>::new();

    let mut seq = seq_num;
    // encrypt using the first mki
    for _i in 0..packet_num {
        // create packets
        let rtp = create_rtp_packet(payload_size, ssrc, seq);
        let rtcp = create_rtcp_packet(payload_size / 4, ssrc);
        // encrypt
        srtp_stream.push(
            s.rtp_protect_mki(rtp.clone(), &mkis[0])
                .map_err(anyhow::Error::from)
                .with_context(|| ("rtp protect failed").to_string())?,
        );
        rtp_stream.push(rtp);
        srtcp_stream.push(
            s.rtcp_protect_mki(rtcp.clone(), &mkis[0])
                .map_err(anyhow::Error::from)
                .with_context(|| ("rtcp protect failed").to_string())?,
        );
        rtcp_stream.push(rtcp);
        seq = seq.wrapping_add(1); // seq must wrap around 2^16
    }
    // Try to protect using mki[1] which is not yet in stream context, it shall fail
    let rtp = create_rtp_packet(payload_size, ssrc, seq);
    assert_eq!(s.rtp_protect_mki(rtp, &mkis[1]), Err(SrtpError::InvalidMki));

    // update the stream to add the second and third mki
    let s_config = StreamConfig::new(
        vec![
            MasterKey::new(&master_key2, &master_salt2, &mkis[1]),
            MasterKey::new(&master_key3, &master_salt3, &mkis[2]),
        ],
        &rtp_profile,
        &rtcp_profile,
    );

    // add streams
    s.add_stream(Some(ssrc), &s_config)
        .map_err(anyhow::Error::from)
        .with_context(|| ("failed to add send stream").to_string())?;
    // encrypt with all mkis
    for _i in 0..packet_num {
        for mki in &mkis {
            // create packets
            let rtp = create_rtp_packet(payload_size, ssrc, seq);
            let rtcp = create_rtcp_packet(payload_size / 4, ssrc);
            // encrypt
            srtp_stream.push(
                s.rtp_protect_mki(rtp.clone(), mki)
                    .map_err(anyhow::Error::from)
                    .with_context(|| ("rtp protect failed").to_string())?,
            );
            rtp_stream.push(rtp);
            srtcp_stream.push(
                s.rtcp_protect_mki(rtcp.clone(), mki)
                    .map_err(anyhow::Error::from)
                    .with_context(|| ("rtcp protect failed").to_string())?,
            );
            rtcp_stream.push(rtcp);
            seq = seq.wrapping_add(1); // seq must wrap around 2^16
        }
    }

    // decrypt
    let range = rnd_range(0, packet_num * mkis.len());
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

    Ok(())
}

#[test]
fn simple_stream_with_update() -> anyhow::Result<()> {
    let packet_num: usize = 45;
    let payload_size: usize = 123;
    let ssrc: u32 = 0xcafebabe;
    let seq_num: u16 = 0x0123;

    // test all available transforms
    for (rtp_profile, rtcp_profile) in VALID_PROFILES {
        one_stream_mki_update(
            packet_num,
            payload_size,
            seq_num,
            ssrc,
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

/// scenario:
/// - add a stream template using mki, with one key and hard limit to packet_num
/// - encrypt packet_num - 1 packets with that one mki on stream_number streams
/// - update the stream with to new master keys, hard limit to packet_num for both
/// - encrypt packet_num -1 packets on each stream using the 2 new mkis
/// - encrypt one more rtp packet on stream 0 with mki 0, it works
/// - encrypt one more rtp packet on stream 0 with mki 0, hard limit error
/// - check we cannot use mki 0 for any operation on any stream
/// - encrypt 2 rtcp packets on stream 1 with mki 1, the second fails
/// - check we cannot use mki 1 for any operation on any stream
/// - decrypt everything that was encrypted, in random order and check it matches the plain text
fn multi_stream_mki_update_with_key_limit(
    packet_num: usize,    // number of packets
    payload_size: usize,  // payload size of each packet
    stream_number: usize, // number of streams
    rtp_profile: ProtectionProfile,
    rtcp_profile: ProtectionProfile,
) -> anyhow::Result<()> {
    // create send and recv sessions
    let mut s = SendSession::new();
    let mut r = RecvSession::new();

    // define a handler for the key limit, attach it to the sender stream
    let soft_limit_count = Arc::new(Mutex::new(0u32));
    let hard_limit_count = Arc::new(Mutex::new(0u32));
    let last_ssrc_alert = Arc::new(Mutex::new(0u32));
    let last_mki_alert: Arc<Mutex<Option<Vec<u8>>>> = Arc::new(Mutex::new(None));
    let soft_limit_clone = soft_limit_count.clone();
    let hard_limit_clone = hard_limit_count.clone();
    let last_ssrc_clone = last_ssrc_alert.clone();
    let last_mki_clone = last_mki_alert.clone();
    let handler = move |err: SrtpError| match err {
        SrtpError::KeyLimit {
            is_dead, ssrc, mki, ..
        } => {
            if is_dead {
                *hard_limit_clone.lock().unwrap() += 1;
            } else {
                *soft_limit_clone.lock().unwrap() += 1;
            }
            *last_ssrc_clone.lock().unwrap() = ssrc;
            *last_mki_clone.lock().unwrap() = mki;
        }
        _ => {
            panic!("unexpected error received by key limit handler : {:?}", err);
        }
    };
    s.set_key_limit_handler(handler).unwrap();

    // add receiver stream
    // create config, with 3 mkis
    let (master_key1, master_salt1) = generate_keys(&rtp_profile);
    let (master_key2, master_salt2) = generate_keys(&rtp_profile);
    let (master_key3, master_salt3) = generate_keys(&rtp_profile);
    let mkis = [
        Some(vec![0x01, 0x23, 0x45]),
        Some(vec![0x67, 0x89, 0xab]),
        Some(vec![0xcd, 0xef, 0x01]),
    ];

    let mut r_config = StreamConfig::new(
        vec![
            MasterKey::new(&master_key1, &master_salt1, &mkis[0]),
            MasterKey::new(&master_key2, &master_salt2, &mkis[1]),
            MasterKey::new(&master_key3, &master_salt3, &mkis[2]),
        ],
        &rtp_profile,
        &rtcp_profile,
    );
    // decrypting is unordered, make sure we cannot be out of the replay window
    if (r_config.get_replay_window_size() as usize) < (packet_num * mkis.len() + 1) {
        r_config.set_replay_window_size((packet_num * mkis.len() + 1) as u16);
    }
    r.add_stream(None, &r_config) // add stream as a template
        .map_err(anyhow::Error::from)
        .with_context(|| ("failed to add recv stream").to_string())?;

    // add sending streams, use one mki first
    let mut s_config = StreamConfig::new(
        vec![MasterKey::new(&master_key1, &master_salt1, &mkis[0])],
        &rtp_profile,
        &rtcp_profile,
    );
    s_config
        .set_keys_lifetime(packet_num as u64, 5, packet_num as u32, 2)
        .expect("fail to set keys lifetime");

    // add sending stream
    s.add_stream(None, &s_config)
        .map_err(anyhow::Error::from)
        .with_context(|| ("failed to add send stream").to_string())?;

    // encrypt and store in stream
    let mut rtp_stream = Vec::<Vec<u8>>::new();
    let mut rtcp_stream = Vec::<Vec<u8>>::new();
    let mut srtp_stream = Vec::<Vec<u8>>::new();
    let mut srtcp_stream = Vec::<Vec<u8>>::new();

    let mut seq_nums = get_seq_nums(stream_number);
    let ssrcs = get_ssrcs(stream_number);
    // encrypt using the first mki, encrypt all the packets but one
    for _i in 0..(packet_num - 1) {
        for j in 0..stream_number {
            // create packets
            let rtp = create_rtp_packet(payload_size, ssrcs[j], seq_nums[j]);
            let rtcp = create_rtcp_packet(payload_size / 4, ssrcs[j]);
            // encrypt
            srtp_stream.push(
                s.rtp_protect_mki(rtp.clone(), &mkis[0])
                    .map_err(anyhow::Error::from)
                    .with_context(|| ("rtp protect failed").to_string())?,
            );
            rtp_stream.push(rtp);
            srtcp_stream.push(
                s.rtcp_protect_mki(rtcp.clone(), &mkis[0])
                    .map_err(anyhow::Error::from)
                    .with_context(|| ("rtcp protect failed").to_string())?,
            );
            rtcp_stream.push(rtcp);
            seq_nums[j] = seq_nums[j].wrapping_add(1u16); // seq must wrap around 2^16
        }
    }
    // Now we have one life left on RTP and RTCP with mkis[0]
    // Check we have 5 soft alerts (4 from RTP, 1 from RTCP) for each stream
    assert_eq!(
        *soft_limit_count.lock().unwrap(),
        (5 * stream_number) as u32
    );
    assert_eq!(*last_ssrc_alert.lock().unwrap(), *ssrcs.last().unwrap());
    assert_eq!(*last_mki_alert.lock().unwrap(), mkis[0]);

    // update the stream to add the second and third mki
    let mut s_config = StreamConfig::new(
        vec![
            MasterKey::new(&master_key2, &master_salt2, &mkis[1]),
            MasterKey::new(&master_key3, &master_salt3, &mkis[2]),
        ],
        &rtp_profile,
        &rtcp_profile,
    );
    s_config
        .set_keys_lifetime(packet_num as u64, 5, packet_num as u32, 2)
        .expect("fail to set keys lifetime");
    s.add_stream(None, &s_config) // we update the template -> that should not modify the mki
        // already used
        .map_err(anyhow::Error::from)
        .with_context(|| ("failed to add send stream").to_string())?;
    // encrypt all the packets -1 with mkis 1 and 2
    for _i in 0..packet_num - 1 {
        for mki in mkis.iter().skip(1) {
            for j in 0..stream_number {
                // create packets
                let rtp = create_rtp_packet(payload_size, ssrcs[j], seq_nums[j]);
                let rtcp = create_rtcp_packet(payload_size / 4, ssrcs[j]);
                // encrypt
                srtp_stream.push(
                    s.rtp_protect_mki(rtp.clone(), mki)
                        .map_err(anyhow::Error::from)
                        .with_context(|| ("rtp protect failed").to_string())?,
                );
                rtp_stream.push(rtp);
                srtcp_stream.push(
                    s.rtcp_protect_mki(rtcp.clone(), mki)
                        .map_err(anyhow::Error::from)
                        .with_context(|| ("rtcp protect failed").to_string())?,
                );
                rtcp_stream.push(rtcp);
                seq_nums[j] = seq_nums[j].wrapping_add(1u16); // seq must wrap around 2^16
            }
        }
    }
    // Check we have 5 soft alerts (4 from RTP, 1 from RTCP) for each stream and for each mki
    assert_eq!(
        *soft_limit_count.lock().unwrap(),
        (5 * stream_number * mkis.len()) as u32
    );
    assert_eq!(*last_ssrc_alert.lock().unwrap(), *ssrcs.last().unwrap());
    assert_eq!(*last_mki_alert.lock().unwrap(), mkis[2]);

    // now encrypt another rtp packet with ssrcs[0] and mkis[0], it shall work and raise a soft limit
    let rtp = create_rtp_packet(payload_size, ssrcs[0], seq_nums[0]);
    let rtcp = create_rtcp_packet(payload_size / 4, ssrcs[0]);
    srtp_stream.push(
        s.rtp_protect_mki(rtp.clone(), &mkis[0])
            .map_err(anyhow::Error::from)
            .with_context(|| ("rtp protect failed").to_string())?,
    );
    rtp_stream.push(rtp);
    seq_nums[0] += 1;
    assert_eq!(
        *soft_limit_count.lock().unwrap(),
        (5 * stream_number * mkis.len() + 1) as u32
    );
    // now encrypt another rtp packet with mkis[0], it shall fail -> we reached hard limit
    let rtp = create_rtp_packet(payload_size, ssrcs[0], seq_nums[0]);
    assert!(matches!(
        s.rtp_protect_mki(rtp.clone(), &mkis[0]),
        Err(SrtpError::KeyLimit { is_dead: true, is_rtp: true, mki: ref err_mki, ssrc})
        if err_mki.as_slice() == mkis[0].as_slice() && ssrc == ssrcs[0]
    ));
    // try to encrypt a rtcp packet with mkis[0], it shall fail -> we reached hard limit on rtp for
    // the same master key
    assert!(matches!(
        s.rtcp_protect_mki(rtcp.clone(), &mkis[0]),
        Err(SrtpError::KeyLimit { is_dead: true, is_rtp: false, mki: ref err_mki, ssrc})
        if err_mki.as_slice() == mkis[0].as_slice() && ssrc == ssrcs[0]
    ));
    assert_eq!(*hard_limit_count.lock().unwrap(), 2);

    // ssrc[0] is blocked for mkis[0] so that master key shall also be blocked for others streams
    // derived from the template
    let rtp = create_rtp_packet(payload_size, ssrcs[1], seq_nums[1]);
    assert!(matches!(
        s.rtp_protect_mki(rtp.clone(), &mkis[0]),
        Err(SrtpError::KeyLimit { is_dead: true, is_rtp: true, mki: ref err_mki, ssrc})
        if err_mki.as_slice() == mkis[0].as_slice() && ssrc == ssrcs[1]
    ));

    // but we can still use mkis[1], try it on ssrcs[1]
    let rtcp = create_rtcp_packet(payload_size / 4, ssrcs[1]);
    srtcp_stream.push(
        s.rtcp_protect_mki(rtcp.clone(), &mkis[1])
            .map_err(anyhow::Error::from)
            .with_context(|| ("rtcp protect failed").to_string())?,
    );
    rtcp_stream.push(rtcp);
    // trying one more time kills mkis[1] for all streams on both RTP and RTCP
    let rtcp = create_rtcp_packet(payload_size / 4, ssrcs[1]);
    assert!(matches!(
        s.rtcp_protect_mki(rtcp.clone(), &mkis[1]),
        Err(SrtpError::KeyLimit { is_dead: true, is_rtp: false, mki: ref err_mki, ssrc})
        if err_mki.as_slice() == mkis[1].as_slice() && ssrc == ssrcs[1]
    ));
    // try RTP with mkis[1] on ssrcs[0]
    let rtp = create_rtp_packet(payload_size, ssrcs[0], seq_nums[0]);
    assert!(matches!(
        s.rtp_protect_mki(rtp.clone(), &mkis[1]),
        Err(SrtpError::KeyLimit { is_dead: true, is_rtp: true, mki: ref err_mki, ssrc})
        if err_mki.as_slice() == mkis[1].as_slice() && ssrc == ssrcs[0]
    ));
    // try RTP mkis[1] on a new ssrc: the newly created stream should not be able to use mkis[1]
    // derived key
    let new_ssrcs = get_ssrcs(1);
    let rtp = create_rtp_packet(payload_size, new_ssrcs[0], 0x1234);
    assert!(matches!(
        s.rtp_protect_mki(rtp.clone(), &mkis[1]),
        Err(SrtpError::KeyLimit { is_dead: true, is_rtp: true, mki: ref err_mki, ssrc})
        if err_mki.as_slice() == mkis[1].as_slice() && ssrc == new_ssrcs[0]
    ));

    // decrypt
    let range = rnd_range(0, srtp_stream.len());
    for i in range {
        if r.rtp_unprotect(srtp_stream[i].clone())
            .map_err(anyhow::Error::from)
            .with_context(|| ("rtp unprotect failed").to_string())?
            != rtp_stream[i]
        {
            bail!("rtp decrypt didn't match plain");
        }
    }
    let range = rnd_range(0, srtcp_stream.len());
    for i in range {
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
fn multi_stream_mki_key_limit() -> anyhow::Result<()> {
    let packet_num: usize = 6;
    let payload_size: usize = 42;
    let stream_number = 2;

    // test all available transforms
    for (rtp_profile, rtcp_profile) in VALID_PROFILES {
        multi_stream_mki_update_with_key_limit(
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
