use anyhow::{Context, bail};
use interop_test::*;
use libsrtp::{MasterKey, ProtectionProfile, SendSession, StreamConfig};
use serial_test::serial;
use test_utils::*;

fn profile_to_libsrtp_policy(profile: &ProtectionProfile) -> CryptoPolicyKind {
    match profile {
        ProtectionProfile::Aes128CmHmacSha180 => CryptoPolicyKind::Aes128CmHmacSha180,
        ProtectionProfile::Aes128CmHmacSha132 => CryptoPolicyKind::Aes128CmHmacSha132,
        ProtectionProfile::Aes128CmNullAuth => CryptoPolicyKind::Aes128CmNullAuth,
        ProtectionProfile::Aes192CmHmacSha180 => CryptoPolicyKind::Aes192CmHmacSha180,
        ProtectionProfile::Aes192CmHmacSha132 => CryptoPolicyKind::Aes192CmHmacSha132,
        ProtectionProfile::Aes192CmNullAuth => CryptoPolicyKind::Aes192CmNullAuth,
        ProtectionProfile::Aes256CmHmacSha180 => CryptoPolicyKind::Aes256CmHmacSha180,
        ProtectionProfile::Aes256CmHmacSha132 => CryptoPolicyKind::Aes256CmHmacSha132,
        ProtectionProfile::Aes256CmNullAuth => CryptoPolicyKind::Aes256CmNullAuth,
        ProtectionProfile::NullCipherHmacSha180 => CryptoPolicyKind::NullCipherHmacSha180,
        ProtectionProfile::AeadAes128Gcm => CryptoPolicyKind::AeadAes128Gcm,
        ProtectionProfile::AeadAes256Gcm => CryptoPolicyKind::AeadAes256Gcm,
    }
}

fn one_stream(
    packet_num: usize,   // number of packets
    payload_size: usize, // payload size of each packet
    seq_num: u16,        // initial seqnum
    ssrc: u32,           // ssrc to use
    rtp_profile: ProtectionProfile,
    rtcp_profile: ProtectionProfile,
) -> anyhow::Result<()> {
    // create send and recv streams
    let mut s = SendSession::new();

    // create config
    let (mut master_key, master_salt) = generate_keys(&rtp_profile);
    let config = StreamConfig::new(
        vec![MasterKey::new(&master_key, &master_salt, &None)],
        &rtp_profile,
        &rtcp_profile,
    );

    // add streams
    s.add_stream(Some(ssrc), &config)
        .map_err(anyhow::Error::from)
        .with_context(|| format!("failed to add send stream"))?;

    // Receiver using libsrtp
    // concat master key and master salt
    master_key.extend(master_salt);
    let r = unsafe {
        c_srtp_create_session(
            master_key.as_ptr(),
            //master_key.len() as i32,
            1, // 1 for inbound session
            profile_to_libsrtp_policy(&rtp_profile) as i32,
            profile_to_libsrtp_policy(&rtcp_profile) as i32,
        )
    };
    assert!(!r.is_null());

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
                .with_context(|| format!("rtp protect failed"))?,
        );
        rtp_stream.push(rtp);
        srtcp_stream.push(
            s.rtcp_protect(rtcp.clone())
                .map_err(anyhow::Error::from)
                .with_context(|| format!("rtcp protect failed"))?,
        );
        rtcp_stream.push(rtcp);
    }

    // decrypt
    for i in 0..packet_num {
        let mut pkt_len = srtp_stream[i].len() as i32;
        let status = unsafe { c_srtp_unprotect(r, srtp_stream[i].as_mut_ptr(), &mut pkt_len) };
        if status != 0 {
            bail!("fail to decrypt rtp");
        }
        srtp_stream[i].truncate(pkt_len as usize); // input buffer size is not modified by C code
        if srtp_stream[i] != rtp_stream[i] {
            bail!("rtp decrypt mismatch plain");
        }

        let mut pkt_len = srtcp_stream[i].len() as i32;
        let status =
            unsafe { c_srtp_unprotect_rtcp(r, srtcp_stream[i].as_mut_ptr(), &mut pkt_len) };
        if status != 0 {
            bail!("fail to decrypt rtcp");
        }
        srtcp_stream[i].truncate(pkt_len as usize); // input buffer size is not modified by C code
        if srtcp_stream[i] != rtcp_stream[i] {
            bail!("rtcp decrypt mismatch plain");
        }
    }
    unsafe {
        c_srtp_free_session(r);
    }

    Ok(())
}
fn one_stream_mki(
    packet_num: usize,   // number of packets
    payload_size: usize, // payload size of each packet
    seq_num: u16,        // initial seqnum
    ssrc: u32,           // ssrc to use
    rtp_profile: ProtectionProfile,
    rtcp_profile: ProtectionProfile,
) -> anyhow::Result<()> {
    // create send and recv streams
    let mut s = SendSession::new();

    // create config, use 3 mkis
    let (mut master_key1, master_salt1) = generate_keys(&rtp_profile);
    let (mut master_key2, master_salt2) = generate_keys(&rtp_profile);
    let (mut master_key3, master_salt3) = generate_keys(&rtp_profile);
    let mkis = vec![
        vec![0x01, 0x23, 0x45],
        vec![0x67, 0x89, 0xab],
        vec![0xcd, 0xef, 0x01],
    ];
    let config = StreamConfig::new(
        vec![
            MasterKey::new(&master_key1, &master_salt1, &Some(mkis[0].clone())),
            MasterKey::new(&master_key2, &master_salt2, &Some(mkis[1].clone())),
            MasterKey::new(&master_key3, &master_salt3, &Some(mkis[2].clone())),
        ],
        &rtp_profile,
        &rtcp_profile,
    );

    // add streams
    s.add_stream(Some(ssrc), &config)
        .map_err(anyhow::Error::from)
        .with_context(|| format!("failed to add send stream"))?;

    // Receiver using libsrtp
    // concat master key and master salt
    master_key1.extend(master_salt1);
    master_key2.extend(master_salt2);
    master_key3.extend(master_salt3);
    let keys = [
        CSrtpMasterKey {
            key: master_key1.as_ptr(),
            key_len: master_key1.len() as i32,
            mki: mkis[0].as_ptr(),
            mki_len: mkis[0].len() as i32,
        },
        CSrtpMasterKey {
            key: master_key2.as_ptr(),
            key_len: master_key2.len() as i32,
            mki: mkis[1].as_ptr(),
            mki_len: mkis[1].len() as i32,
        },
        CSrtpMasterKey {
            key: master_key3.as_ptr(),
            key_len: master_key3.len() as i32,
            mki: mkis[2].as_ptr(),
            mki_len: mkis[2].len() as i32,
        },
    ];
    let r = unsafe {
        c_srtp_create_session_mki(
            keys.as_ptr(),
            keys.len() as i32,
            1, // 1 for inbound session
            profile_to_libsrtp_policy(&rtp_profile) as i32,
            profile_to_libsrtp_policy(&rtcp_profile) as i32,
        )
    };
    assert!(!r.is_null());

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
                s.rtp_protect_mki(rtp.clone(), &Some(mki.to_vec()))
                    .map_err(anyhow::Error::from)
                    .with_context(|| format!("rtp protect failed"))?,
            );
            rtp_stream.push(rtp);
            srtcp_stream.push(
                s.rtcp_protect_mki(rtcp.clone(), &Some(mki.to_vec()))
                    .map_err(anyhow::Error::from)
                    .with_context(|| format!("rtcp protect failed"))?,
            );
            rtcp_stream.push(rtcp);
            seq = seq.wrapping_add(1); // seq must wrap around 2^16
        }
    }

    // decrypt
    for i in 0..packet_num * mkis.len() {
        let mut pkt_len = srtp_stream[i].len() as i32;
        let status = unsafe { c_srtp_unprotect_mki(r, srtp_stream[i].as_mut_ptr(), &mut pkt_len) };
        if status != 0 {
            bail!("fail to decrypt rtp");
        }
        srtp_stream[i].truncate(pkt_len as usize); // input buffer size is not modified by C code
        if srtp_stream[i] != rtp_stream[i] {
            bail!("rtp decrypt mismatch plain");
        }

        let mut pkt_len = srtcp_stream[i].len() as i32;
        let status =
            unsafe { c_srtp_unprotect_rtcp_mki(r, srtcp_stream[i].as_mut_ptr(), &mut pkt_len) };
        if status != 0 {
            bail!("fail to decrypt rtcp");
        }
        srtcp_stream[i].truncate(pkt_len as usize); // input buffer size is not modified by C code
        if srtcp_stream[i] != rtcp_stream[i] {
            bail!("rtcp decrypt mismatch plain");
        }
    }

    Ok(())
}

#[test]
#[serial]
fn interop_stream() -> anyhow::Result<()> {
    let packet_num: usize = 42;
    let payload_size: usize = 123;
    let ssrc: u32 = 0xcafebabe;
    let seq_num: u16 = 0x0123;

    // test all available transforms
    for (rtp_profile, rtcp_profile) in VALID_PROFILES {
        if rtp_profile.key_len() == 24 {
            /* libsrtp2 is not compliant to the RFC6188 for AES192CM - cannot interop */
            continue;
        }

        println!(
            "interop with profiles{:?}/{:?}\n",
            rtp_profile, rtcp_profile,
        );

        one_stream(
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

#[test]
#[serial]
fn interop_stream_mki() -> anyhow::Result<()> {
    let packet_num: usize = 42;
    let payload_size: usize = 123;
    let ssrc: u32 = 0xcafebabe;
    let seq_num: u16 = 0x0123;

    let c_srtp_version = unsafe { c_srtp_get_version_number() };
    println!("libsrtp version is {:x?}", c_srtp_version);
    // test all available transforms
    for (rtp_profile, rtcp_profile) in VALID_PROFILES {
        /* libsrtp2 is not compliant to the RFC6188 for AES192CM - cannot interop
         * https://github.com/cisco/libsrtp/issues/763 */
        if rtp_profile.key_len() == 24 {
            continue;
        }
        /* before version 2.7.0 libsrtp2 fails when using mki and rtp tag length != rtcp tag length
         * https://github.com/cisco/libsrtp/pull/733 */
        if c_srtp_version < 0x02070000 && rtp_profile.tag_len() != rtcp_profile.tag_len() {
            continue;
        }

        println!(
            "interop mki with profiles{:?}/{:?}\n",
            rtp_profile, rtcp_profile,
        );
        one_stream_mki(
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
