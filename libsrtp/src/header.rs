use crate::SrtpError;

// RTP header parser:
// Perform validity checks and get the ssrc, seq_num and header size
//
// a Rtp Header is composed of (RFC3550 - 5.1)
/*
  0                   1                   2                   3
  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |V=2|P|X|  CC   |M|     PT      |       sequence number         |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |                           timestamp                           |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |           synchronization source (SSRC) identifier            |
 +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
 |            contributing source (CSRC) identifiers             |
 |                             ....                              |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

// a Rtcp Header is composed of (RFC3550 - 6)
  0                   1                   2                   3
  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |V=2|P|    RC   |      PT       |             length            |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |                         SSRC of sender                        |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/
const FIXED_HEADER_SIZE: usize = 12;
const RTCP_MIN_SIZE: usize = 8; // packet cannot be less than 8 bytes: header + ssrc

#[derive(Debug)]
#[cfg_attr(test, derive(PartialEq))]
pub struct RtpHeader {
    seq_num: u16, // The sequence number
    ssrc: u32,    // source id
    len: usize,   // actual size of the header, with extension and and CSRC
}

#[derive(Debug)]
#[cfg_attr(test, derive(PartialEq))]
pub struct RtcpHeader {
    ssrc: u32, // source id
}

impl RtcpHeader {
    pub fn new(rtcp: &[u8]) -> Result<RtcpHeader, SrtpError> {
        let packet_size = rtcp.len();
        // packet can't be less than minimal size
        if packet_size < RTCP_MIN_SIZE {
            return Err(SrtpError::InvalidPacket);
        }
        // first two bits must be 10:
        if (rtcp[0] & 0xc0) != 0x80 {
            return Err(SrtpError::InvalidPacket);
        }

        // parse ssrc
        let ssrc = u32::from_be_bytes(
            rtcp[4..8]
                .try_into()
                .map_err(|_| SrtpError::InvalidPacket)?,
        );

        Ok(RtcpHeader { ssrc })
    }

    pub fn ssrc(&self) -> u32 {
        self.ssrc
    }

    /// RTCP header len is always 8 bytes
    pub fn len() -> usize {
        RTCP_MIN_SIZE
    }
}

impl RtpHeader {
    pub fn new(rtp: &[u8]) -> Result<RtpHeader, SrtpError> {
        let packet_size = rtp.len();
        // Header can't be less than HEADER_SIZE
        if packet_size < FIXED_HEADER_SIZE {
            return Err(SrtpError::InvalidPacket);
        }
        // first two bits must be 10:
        if (rtp[0] & 0xc0) != 0x80 {
            return Err(SrtpError::InvalidPacket);
        }

        let mut header_size: usize = FIXED_HEADER_SIZE;

        // check the CSRC
        let cc_size: usize = Into::<usize>::into(rtp[0] & 0x0f) * 4;
        if packet_size < FIXED_HEADER_SIZE + cc_size {
            return Err(SrtpError::InvalidPacket);
        }
        header_size += cc_size;

        // check the extension
        if rtp[0] & 0x10 != 0 {
            // there is an extension
            // RFC3550 - 5.3.1 :
            // 2 bytes ext profile || 2 bytes ext size (in 4 bytes words)
            // extension (size as declared)
            if packet_size < header_size + 4 {
                return Err(SrtpError::InvalidPacket);
            }
            header_size += 4;
            let x_size: usize = Into::<usize>::into(u16::from_be_bytes(
                rtp[header_size - 2..header_size]
                    .try_into()
                    .map_err(|_| SrtpError::InvalidPacket)?,
            )) * 4;
            if packet_size < header_size + x_size {
                return Err(SrtpError::InvalidPacket);
            }
            header_size += x_size;
        }

        // parse ssrc and seqnum
        let ssrc = u32::from_be_bytes(
            rtp[8..12]
                .try_into()
                .map_err(|_| SrtpError::InvalidPacket)?,
        );
        let seq_num =
            u16::from_be_bytes(rtp[2..4].try_into().map_err(|_| SrtpError::InvalidPacket)?);

        Ok(RtpHeader {
            seq_num,
            ssrc,
            len: header_size,
        })
    }

    pub fn ssrc(&self) -> u32 {
        self.ssrc
    }

    pub fn seq_num(&self) -> u16 {
        self.seq_num
    }

    pub fn len(&self) -> usize {
        self.len
    }
}

#[cfg(test)]
mod test {
    use super::*;

    // self generated test patterns
    #[test]
    fn no_ext_no_csrc() -> Result<(), SrtpError> {
        let rtp_packet = vec![
            0x80, 0x0f, 0x12, 0x34, 0xde, 0xca, 0xfb, 0xad, 0xca, 0xfe, 0xba, 0xbe, 0xab, 0xab,
            0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
        ];

        let pattern_hdr = RtpHeader {
            seq_num: 0x1234,
            ssrc: 0xcafebabe,
            len: 12,
        };

        let hdr = RtpHeader::new(&rtp_packet)?;
        assert_eq!(
            hdr, pattern_hdr,
            "Fail to parse Rtp Header in packet with no ext no csrc:\n{rtp_packet:?}\n",
        );

        Ok(())
    }

    #[test]
    fn no_ext_csrcs() -> Result<(), SrtpError> {
        let rtp_packet_1_csrc = vec![
            0x81, 0x0f, 0x12, 0x34, 0xde, 0xca, 0xfb, 0xad, 0xca, 0xfe, 0xba, 0xbe, 0x01, 0x02,
            0x03, 0x04, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
            0xab, 0xab, 0xab, 0xab,
        ];

        let pattern_hdr_1_csrc = RtpHeader {
            seq_num: 0x1234,
            ssrc: 0xcafebabe,
            len: 16,
        };

        let hdr = RtpHeader::new(&rtp_packet_1_csrc)?;
        assert_eq!(
            hdr, pattern_hdr_1_csrc,
            "Fail to parse Rtp Header in packet with no ext 1 csrc:\n{rtp_packet_1_csrc:?}\n",
        );

        let rtp_packet_3_csrc = vec![
            0x83, 0x0f, 0x12, 0x34, 0xde, 0xca, 0xfb, 0xad, 0xca, 0xfe, 0xba, 0xbe, 0x01, 0x02,
            0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0xab, 0xab, 0xab, 0xab,
            0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
        ];

        let pattern_hdr_3_csrc = RtpHeader {
            seq_num: 0x1234,
            ssrc: 0xcafebabe,
            len: 24,
        };

        let hdr = RtpHeader::new(&rtp_packet_3_csrc)?;
        assert_eq!(
            hdr, pattern_hdr_3_csrc,
            "Fail to parse Rtp Header in packet with no ext 3 csrc:\n{rtp_packet_3_csrc:?}\n",
        );

        Ok(())
    }

    #[test]
    fn ext_no_csrcs() -> Result<(), SrtpError> {
        let rtp_packet_ext_0_byte = vec![
            0x90, 0x0f, 0x12, 0x34, 0xde, 0xca, 0xfb, 0xad, 0xca, 0xfe, 0xba, 0xbe, 0xca, 0xfe,
            0x00, 0x00, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
            0xab, 0xab, 0xab, 0xab,
        ];

        let pattern_hdr_ext_0_byte = RtpHeader {
            seq_num: 0x1234,
            ssrc: 0xcafebabe,
            len: 16,
        };

        let hdr = RtpHeader::new(&rtp_packet_ext_0_byte)?;
        assert_eq!(
            hdr, pattern_hdr_ext_0_byte,
            "Fail to parse Rtp Header in packet with 0 byte ext:\n{rtp_packet_ext_0_byte:?}\n",
        );

        let rtp_packet_ext_4_bytes = vec![
            0x90, 0x0f, 0x12, 0x34, 0xde, 0xca, 0xfb, 0xad, 0xca, 0xfe, 0xba, 0xbe, 0xca, 0xfe,
            0x00, 0x01, 0x00, 0xff, 0x01, 0xfe, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
            0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
        ];

        let pattern_hdr_ext_4_bytes = RtpHeader {
            seq_num: 0x1234,
            ssrc: 0xcafebabe,
            len: 20,
        };

        let hdr = RtpHeader::new(&rtp_packet_ext_4_bytes)?;
        assert_eq!(
            hdr, pattern_hdr_ext_4_bytes,
            "Fail to parse Rtp Header in packet with 4 bytes ext:\n{rtp_packet_ext_4_bytes:?}\n",
        );

        Ok(())
    }

    #[test]
    fn ext_and_csrcs() -> Result<(), SrtpError> {
        let rtp_packet_1_csrc_ext_0_byte = vec![
            0x91, 0x0f, 0x12, 0x34, 0xde, 0xca, 0xfb, 0xad, 0xca, 0xfe, 0xba, 0xbe, 0x01, 0x02,
            0x03, 0x04, 0xca, 0xfe, 0x00, 0x00, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
            0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
        ];

        let pattern_hdr_1_csrc_ext_0_byte = RtpHeader {
            seq_num: 0x1234,
            ssrc: 0xcafebabe,
            len: 20,
        };

        let hdr = RtpHeader::new(&rtp_packet_1_csrc_ext_0_byte)?;
        assert_eq!(
            hdr, pattern_hdr_1_csrc_ext_0_byte,
            "Fail to parse Rtp Header in packet with 0 byte ext:\n{rtp_packet_1_csrc_ext_0_byte:?}\n",
        );

        let rtp_packet_3_csrc_ext_4_bytes = vec![
            0x93, 0x0f, 0x12, 0x34, 0xde, 0xca, 0xfb, 0xad, 0xca, 0xfe, 0xba, 0xbe, 0x01, 0x02,
            0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0xca, 0xfe, 0x00, 0x01,
            0x00, 0xff, 0x01, 0xfe, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
            0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
        ];

        let pattern_hdr_3_csrc_ext_4_bytes = RtpHeader {
            seq_num: 0x1234,
            ssrc: 0xcafebabe,
            len: 32,
        };

        let hdr = RtpHeader::new(&rtp_packet_3_csrc_ext_4_bytes)?;
        assert_eq!(
            hdr, pattern_hdr_3_csrc_ext_4_bytes,
            "Fail to parse Rtp Header in packet with 4 bytes ext:\n{rtp_packet_3_csrc_ext_4_bytes:?}\n",
        );

        Ok(())
    }

    #[test]
    fn invalid_packet() -> Result<(), SrtpError> {
        let rtp_packet_too_short = vec![0x80, 0x0f, 0x12, 0x34, 0xde, 0xca, 0xfe];
        assert!(
            matches!(
                RtpHeader::new(&rtp_packet_too_short),
                Err(SrtpError::InvalidPacket)
            ),
            "invalid packet too short parsed without error"
        );

        let rtp_packet_not_rtp = vec![
            0xe0, 0x0f, 0x12, 0x34, 0xde, 0xca, 0xfb, 0xad, 0xca, 0xfe, 0xba, 0xbe, 0xab, 0xab,
            0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
        ];
        assert!(
            matches!(
                RtpHeader::new(&rtp_packet_not_rtp),
                Err(SrtpError::InvalidPacket)
            ),
            "invalid packet not RTP parsed without error"
        );

        let rtp_packet_with_ext_too_short = vec![
            0x90, 0x0f, 0x12, 0x34, 0xde, 0xca, 0xfb, 0xad, 0xca, 0xfe, 0xba, 0xbe, 0xca, 0xfe,
            0x01, 0x00, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
            0xab, 0xab, 0xab, 0xab,
        ];
        assert!(
            matches!(
                RtpHeader::new(&rtp_packet_with_ext_too_short),
                Err(SrtpError::InvalidPacket)
            ),
            "invalid packet with ext too short parsed without error"
        );

        let rtp_packet_with_csrc_too_short = vec![
            0x85, 0x0f, 0x12, 0x34, 0xde, 0xca, 0xfb, 0xad, 0xca, 0xfe, 0xba, 0xbe, 0xab, 0xab,
            0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
        ];
        assert!(
            matches!(
                RtpHeader::new(&rtp_packet_with_csrc_too_short),
                Err(SrtpError::InvalidPacket)
            ),
            "invalid packet with csrc too short parsed without error"
        );

        Ok(())
    }
}
