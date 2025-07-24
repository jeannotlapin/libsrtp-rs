![Crates.io](https://img.shields.io/crates/v/libsrtp.svg)
![Docs.rs](https://docs.rs/libsrtp/badge.svg)
![CI](https://github.com/jeannotlapin/libsrtp-rs/actions/workflows/ci.yml/badge.svg)
![Maintenance](https://img.shields.io/badge/maintenance-experimental-blueviolet.svg)
![License: MIT/Apache-2.0](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)

***A pure rust implementation of Secure Real-time Transport Protocol (SRTP)***

This crate implements [RFC 3711](https://datatracker.ietf.org/doc/html/rfc3711), [RFC 6188](https://datatracker.ietf.org/doc/html/rfc6188) and [RFC 7714](https://datatracker.ietf.org/doc/html/rfc7714)

# Features

This library supports all the mandatory features from RFC 3711, RFC 6188 and RFC 7714. The following optional features are not supported:
- key derivation rates
- AES in f8 mode
- master key selection based on packet index

This library aims to support the same set of features supported by Cisco's SRTP C library [libsrtp](https://github.com/cisco/libsrtp).

## Features list
 * Support for protection profiles:
    - Null Cipher with full auth tag. RFC 3711
    - AES128 Counter mode - with no, short or full auth tag. RFC 3711
    - AES192/256 Counter mode - with no, short or full auth tag. RFC6188
    - AES128/256 GCM with 16 bytes auth tag. RFC7714
    - **Notes**:
        - for RTCP, short or no auth tag is not supported as specified in RFC 3711
        - auth tag only is not supported for GCM. The only way avoid encryption while authenticating is to use the NullCipherHmacSha180 profile.
 * Master Key Identifier (MKI)
 * Replay protection (default window size is 128) - opt out possible on RTP sending side
 * Keys lifetime
    - keys lifetime can be set on a master key basis. The default values are 2^48 for RTP and 2^31 for RTCP, they can only be lowered.
    - keys lifetime is decreased on a stream/master key base, even for stream spawned from template and thus sharing the master key.
      Each templated stream gets it own life count, one for each mki(when used).
    - Any key reaching its end of life(on RTP or RCTP) will disable all keys derived from the same master key including:
        - the other component of the stream: RTP end of life disables RTCP, RTCP end of life disables RTP
        - the other streams spwaned from the same master key if any
        - when using mki, keys derived from others master key are not affected
 * Index rollback
    - due to re-keying (which does not reset RTP nor RTCP indexes), a key end of life does not necessarily happens on index rollback.
    - RTCP index rollback is supported: after sending 2^31 RTCP packets, provided several mkis were used, the next RTCP packet index will roll back to 0.
    - RTP index being on 48 bits, a rollback seem very unlikely in real life and is not supported.
 * Key limit alert
    - When provided, a key limit handler is called when a key life is nearing the end (2^16 lives left by default) or is over.
    - When a key reaches its end of life, any operation using it will:
        - call the key limit handler
        - fail returning a KeyLimit error
 * Multithreading
    - full support for multithreading operations
    - sessions can be shared among different thread, so each stream can run in its own thread

## Non supported features list
The following features are supported by Cisco's [libsrtp](https://github.com/cisco/libsrtp) but not yet by this library:
 * Encryption of Header Extensions [RFC 6904](https://datatracker.ietf.org/doc/html/rfc6904)
 * Completely Encrypting RTP Header Extensions and Contributing Sources [RFC 9335](https://datatracker.ietf.org/doc/html/rfc9335)

# Implementation note
The base cryptographic operations (HMAC-SHA1, AES-CTR, AES-GCM) are provided by [RustCrypto](https://github.com/RustCrypto/) crates.

# Testing
Testing requires helpers crates found on this [repository](https://github.com/jeannotlapin/libsrtp-rs)

Interoperability test with cisco's libsrtp are provided in a [dedicated crate](https://github.com/jeannotlapin/libsrtp-rs/tree/master/interop_test)

# Example

```rust
use libsrtp::{MasterKey, ProtectionProfile, RecvSession, SendSession, SrtpError, StreamConfig};
# fn main() {
#    let master_key = vec![
#        0xe1, 0xf9, 0x7a, 0x0d, 0x3e, 0x01, 0x8b, 0xe0, 0xd6, 0x4f, 0xa3, 0x2c, 0x06, 0xde,
#        0x41, 0x39,
#    ];
#    let master_salt = vec![
#        0x0e, 0xc6, 0x75, 0xad, 0x49, 0x8a, 0xfe, 0xeb, 0xb6, 0x96, 0x0b, 0x3a, 0xab, 0xe6,
#    ];
#    let mut packet = vec![
#        0x80, 0x0f, 0x12, 0x34, 0xde, 0xca, 0xfb, 0xad, 0xca, 0xfe, 0xba, 0xbe, 0xab, 0xab,
#        0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
#    ];
#    let ssrc : u32 = 0xcafebabe;

    // create a stream configuration
    // master_key and master_salt must be Vec<u8> of size matching the selected profiles
    let config = StreamConfig::new(
        // we use one master key, no mki
        vec![MasterKey::new(&master_key, &master_salt, &None)],
        // RTP and RTCP protection profiles are set to AES128CM with HmacSha1-80 authentication
        &ProtectionProfile::Aes128CmHmacSha180,
        &ProtectionProfile::Aes128CmHmacSha180,
    );

    /************ Sender Side *************************/
    // create a sender session and add a stream to it
    // this stream is added specifying its SSRC.
    // It will process only the packets with this SSRC in their header
    let mut s = SendSession::new();
    s.add_stream(Some(ssrc), &config).unwrap();

    // encrypt and authenticate the packet
    // the encryption is performed in place (get and give back the ownership)
    // packet is a Vec<u8> holding the whole RTP packet - header included
    packet = s.rtp_protect(packet).unwrap();


    /************ Receiver Side ***********************/
    // create a receiver session and add a stream to it
    // in a real context this would be performed on the other endpoint
    let mut r = RecvSession::new();
    // this stream is added without specifying a SSRC, it is a template stream
    // upon decryption of a packet with an unknown SSRC, it will spawn a stream for it
    r.add_stream(None, &config).unwrap();

    // authenticate and decrypt the packet
    // decryption is performed in place
    packet = r.rtp_unprotect(packet).unwrap();
# }
```

# License
This library is distributed under either of:
- [MIT licence](http://opensource.org/licenses/MIT)
- [Apache license, version 2](http://www.apache.org/licenses/LICENSE-2.0)

Copyright (c) 2025 Johan Pascal
