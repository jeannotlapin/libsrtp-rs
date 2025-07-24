use anyhow::Context;
use libsrtp::{MasterKey, ProtectionProfile, RecvSession, SendSession, SrtpError, StreamConfig};
use std::sync::{Arc, Mutex, mpsc};
use std::thread;
use std::time::Duration;
use test_utils::*;

fn multi_thread(
    packet_num: usize,    // number of packets
    payload_size: usize,  // payload size of each packet
    stream_number: usize, // number of streams to deploy, one per stream
    rtp_profile: ProtectionProfile,
    rtcp_profile: ProtectionProfile,
) -> anyhow::Result<()> {
    // create send and recv sessions
    let r = Arc::new(Mutex::new(RecvSession::new()));
    let s = Arc::new(Mutex::new(SendSession::new()));

    // create config
    let (master_key, master_salt) = generate_keys(&rtp_profile);
    let mut conf = StreamConfig::new(
        vec![MasterKey::new(&master_key, &master_salt, &None)],
        &rtp_profile,
        &rtcp_profile,
    );
    // we allways decrypt in random order so check the replay window is large enough
    if (conf.get_replay_window_size() as usize) < packet_num {
        conf.set_replay_window_size((packet_num + 1) as u16);
    }

    let config = Arc::new(Mutex::new(conf));
    let ssrcs = get_ssrcs(stream_number);
    let seq_nums = get_seq_nums(stream_number);
    // for each stream, create a thread to encrypt and a thread to decrypt
    let mut handles = Vec::new();
    for i in 0..stream_number {
        let (tx, rx) = mpsc::channel();

        let config_s = Arc::clone(&config);
        let s = Arc::clone(&s);
        let seq_num = seq_nums[i];
        let ssrc = ssrcs[i];
        handles.push(thread::spawn(move || {
            let mut s = s.lock().unwrap();
            let config = config_s.lock().unwrap();
            s.add_stream(None, &config)
                .expect("fail to add send stream");
            drop(config); // do not lock that more than needed as it is shared
            for j in 0..packet_num {
                let seq = seq_num.wrapping_add(j as u16); // seq must wrap around 2^16
                let rtp = create_rtp_packet(payload_size, ssrc, seq);
                let srtp = s.rtp_protect(rtp).expect("fail to encrypt rtp");
                tx.send(srtp).unwrap();
                thread::sleep(Duration::from_micros(100));
            }
        }));

        let config_r = Arc::clone(&config);
        let r = Arc::clone(&r);

        handles.push(thread::spawn(move || {
            let mut r = r.lock().unwrap();
            let config = config_r.lock().unwrap();
            r.add_stream(None, &config)
                .expect("fail to add recv stream");
            drop(config); // do not lock that more than needed as it is shared
            for _ in 0..packet_num {
                let srtp = rx.recv().unwrap();
                r.rtp_unprotect(srtp).expect("fail to decrypt rtp");
                thread::sleep(Duration::from_micros(100));
            }
        }));
    }

    for handle in handles {
        handle.join().unwrap();
    }

    Ok(())
}

#[test]
fn multithread() -> anyhow::Result<()> {
    let packet_num: usize = 65;
    let payload_size: usize = 123;
    let stream_number: usize = 6;

    // test all available transforms
    for (rtp_profile, rtcp_profile) in VALID_PROFILES {
        multi_thread(
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

/// test scenario:
/// Create sender and receiver session, multi-thread ready (encapsulate the sessions in
/// Arc<Mutex<>>
/// The sender session gets a key limit handler that simply count the number of alerts received
/// spawn two threads, one for sending, one for receiving.
/// In the sending thread:
///     - create a stream with keys lifetime 2 and soft limit 1
///     - Encrypt a first message, check no alert was raised
///     - Encrypt a second message, check a soft limit alert is raised
///     - Encrypt a third message: it fails with a KeyLimit error and the hard limit alert is
///     raised in the key limit handler
/// In the receiver thread:
///     - just expect two messages and decrypt them on arrival
#[test]
fn multithread_key_limit() -> anyhow::Result<()> {
    let master_key = vec![
        0xe1, 0xf9, 0x7a, 0x0d, 0x3e, 0x01, 0x8b, 0xe0, 0xd6, 0x4f, 0xa3, 0x2c, 0x06, 0xde, 0x41,
        0x39,
    ];
    let master_salt = vec![
        0x0e, 0xc6, 0x75, 0xad, 0x49, 0x8a, 0xfe, 0xeb, 0xb6, 0x96, 0x0b, 0x3a, 0xab, 0xe6,
    ];
    let mut rtp_packet = vec![
        0x80, 0x0f, 0x12, 0x34, 0xde, 0xca, 0xfb, 0xad, 0xca, 0xfe, 0xba, 0xbe, 0xab, 0xab, 0xab,
        0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
    ];

    let ssrc: u32 = 0xcafebabe;

    // define a handler for the key limit
    let soft_limit_count = Arc::new(Mutex::new(0u32));
    let hard_limit_count = Arc::new(Mutex::new(0u32));
    let soft_limit_clone = soft_limit_count.clone();
    let hard_limit_clone = hard_limit_count.clone();
    let handler = move |err: SrtpError| match err {
        SrtpError::KeyLimit {
            is_dead,
            ssrc: handler_ssrc,
            ..
        } => {
            if is_dead {
                *hard_limit_clone.lock().unwrap() += 1;
            } else {
                *soft_limit_clone.lock().unwrap() += 1;
            }
            assert_eq!(ssrc, handler_ssrc);
        }
        _ => {
            panic!("unexpected error received by key limit handler : {:?}", err);
        }
    };

    // create send and recv sessions, assign the handler to the sending stream
    let r = Arc::new(Mutex::new(RecvSession::new()));
    let mut s = SendSession::new();
    s.set_key_limit_handler(handler).unwrap();
    let s = Arc::new(Mutex::new(s));

    // create config
    let mut conf = StreamConfig::new(
        vec![MasterKey::new(&master_key, &master_salt, &None)],
        &ProtectionProfile::Aes128CmHmacSha180,
        &ProtectionProfile::Aes128CmHmacSha180,
    );
    conf.set_keys_lifetime(2, 1, 2, 1)
        .expect("fail to set keys lifetime");

    let config = Arc::new(Mutex::new(conf));
    // create a thread to encrypt and a thread to decrypt
    let mut handles = Vec::new();
    let (tx, rx) = mpsc::channel();

    let config_s = Arc::clone(&config);
    let s = Arc::clone(&s);
    let soft_limit_clone = soft_limit_count.clone();
    let hard_limit_clone = hard_limit_count.clone();
    handles.push(thread::spawn(move || {
        let mut s = s.lock().unwrap();
        let config = config_s.lock().unwrap();
        s.add_stream(Some(ssrc), &config)
            .expect("fail to add send stream");
        drop(config); // do not lock that more than needed as it is shared
        // encrypt a first message shall be fine
        let srtp = s
            .rtp_protect(rtp_packet.clone())
            .expect("fail to encrypt rtp");
        tx.send(srtp).unwrap();
        thread::sleep(Duration::from_micros(100));
        assert_eq!(*soft_limit_clone.lock().unwrap(), 0);
        assert_eq!(*hard_limit_clone.lock().unwrap(), 0);

        // encrypt a second message shall be fine too, the handler shall be called
        rtp_packet[3] += 1; // increase seq num
        let srtp = s
            .rtp_protect(rtp_packet.clone())
            .expect("fail to encrypt rtp");
        tx.send(srtp).unwrap();
        thread::sleep(Duration::from_micros(100));
        assert_eq!(*soft_limit_clone.lock().unwrap(), 1);
        assert_eq!(*hard_limit_clone.lock().unwrap(), 0);

        // force rtp key limits to 1 and encrypt a message -> we shall get a hardlimit error
        rtp_packet[3] += 1; // increase seq num
        assert!(matches!(
            s.rtp_protect(rtp_packet.clone()),
            Err(SrtpError::KeyLimit {
                is_dead: true,
                is_rtp: true,
                mki: None,
                ..
            })
        ));
        assert_eq!(*soft_limit_clone.lock().unwrap(), 1);
        assert_eq!(*hard_limit_clone.lock().unwrap(), 1);
    }));

    let config_r = Arc::clone(&config);
    let r = Arc::clone(&r);

    handles.push(thread::spawn(move || {
        let mut r = r.lock().unwrap();
        let config = config_r.lock().unwrap();
        r.add_stream(None, &config)
            .expect("fail to add recv stream");
        drop(config); // do not lock that more than needed as it is shared
        for _ in 0..2 {
            // we expect the receive 2 packets from the sending stream
            let srtp = rx.recv().unwrap();
            r.rtp_unprotect(srtp).expect("fail to decrypt rtp");
            thread::sleep(Duration::from_micros(100));
        }
    }));

    for handle in handles {
        handle.join().unwrap();
    }

    Ok(())
}
