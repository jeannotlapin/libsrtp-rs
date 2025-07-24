use num_bigint::BigUint;
use num_traits::One;

// Seq num is stored on 16 bits, packets may be processed out of order
// the maximum tolerated out of order packet gap is halt the size of max seq num
const MAX_SEQ_NUM_STEP: u64 = 0x8000;

/// Replay db and index management for RTP
/// Possible rollover of the rtp index over 2^48 is not forbidden by the RFC, it seems physically
/// impossible to reach such a number of RTP packets sent so this case is not considered
pub struct RtpReplayDb {
    /// current index (actually on 48 bits: ROC (32 bits) || seq num (16 bits))
    index: u64,
    /// pending roc: used when roc is forced
    pending_roc: Option<u32>,
    /// already seen indexes as bitmap relative to the current index
    /// bit 0 reflects the current index so is always set to 1
    window: BigUint,
    /// a bitmap with all bits set to 1 the size of the window
    window_mask: BigUint,
}

impl RtpReplayDb {
    pub fn new(window_size: u16) -> Self {
        Self {
            index: 0,
            pending_roc: None,
            window: BigUint::ZERO,
            // create a mask according to window size
            window_mask: (BigUint::one() << window_size) - BigUint::one(),
        }
    }

    /// Given a sequence number, return the most likely index
    pub fn estimate_index(&self, seq_num: u16) -> u64 {
        // when we have a pending roc, use it
        if let Some(roc) = self.pending_roc {
            return u64::from(roc) << 16 | u64::from(seq_num);
        };

        // guess the roc is unchanged
        let mut guess_index = (self.index & 0x0000FFFFFFFF0000_u64) | u64::from(seq_num);

        if self.index > MAX_SEQ_NUM_STEP && guess_index < self.index - MAX_SEQ_NUM_STEP {
            // guess index is too far behind -> increase roc
            guess_index += 0x10000;
        } else if guess_index > self.index + MAX_SEQ_NUM_STEP && self.index >= 0x10000 {
            // guess index is too far ahead (and we can decrease roc) -> decrease roc
            guess_index -= 0x10000;
        }
        guess_index
    }

    /// return the current roc
    pub fn get_roc(&self) -> u32 {
        (self.index >> 16) as u32
    }

    /// set the current roc (validated at next add_index operation)
    /// the set value should be > to the current one
    pub fn set_roc(&mut self, roc: u32) {
        self.pending_roc = Some(roc);
    }

    pub fn add_index(&mut self, index: u64) {
        if index > self.index {
            // index is bigger than current one: shift the windows
            let diff = index - self.index;
            // check it makes sense to shift as we shift then crop
            if diff < self.window_mask.bits() {
                self.window <<= diff;
                self.window &= &self.window_mask; // crop the window to its declared size
            } else {
                // diff is so large that we wipe out the replay window
                self.window = BigUint::ZERO;
            }
            self.window.set_bit(0, true); // 0 index in the window is the current index
            self.index = index;
        } else {
            // index is smaller than current one, just set it into the window
            let diff = self.index - index;
            if diff < self.window_mask.bits() {
                self.window.set_bit(diff, true);
            }
        }
        // make sure pending roc is reset
        self.pending_roc = None;
    }

    pub fn seen_index(&self, index: u64) -> bool {
        if index > self.index {
            // given index is in the future, cannot be in db
            false
        } else if self.index - index >= self.window_mask.bits() {
            // given index is so old it's out of the replay window, consider it is in db
            true
        } else {
            // if the difference is bigger than the actual window size (BigUint is of dynamic size)
            // bit will return false
            self.window.bit(self.index - index)
        }
    }

    // windows size is actually stored in the window_mask
    pub fn set_window_size(&mut self, size: u16) {
        self.window_mask = (BigUint::one() << size) - BigUint::one();
    }
}

// To manage RTCP index rollback :
// * RTCP index is reset to 0 when it reaches RTCP_ROLLBACK
// * Detect rollback then the step from/to last index is bigger than MAX_RTCP_STEP
const RTCP_ROLLBACK: u64 = 1u64 << 31;
const MAX_RTCP_STEP: u64 = 1u64 << 30;

/// Replay db and index management for RTCP
/// This replay db also manages possible rollover of its index on a 2^31 basis
pub struct RtcpReplayDb {
    /// last received index(actually on 31 bits)
    index: u32,
    /// already seen indexes as bitmap relative to the current index
    /// bit 0 reflects the current index so is always set to 1
    window: BigUint,
    /// a bitmap with all bits set to 1 the size of the window
    window_mask: BigUint,
}

impl RtcpReplayDb {
    pub fn new(window_size: u16) -> Self {
        Self {
            index: 0,
            window: BigUint::ZERO,
            // create a mask according to window size
            window_mask: (BigUint::one() << window_size) - BigUint::one(),
        }
    }

    // Explicit delegation to the replay struct
    pub fn add_index(&mut self, index: u32) {
        // index seems to be in the future
        if index > self.index {
            let diff = u64::from(index - self.index);
            // index is so far in the future that we must have rollback recently
            // it is in the past
            if diff >= MAX_RTCP_STEP {
                if RTCP_ROLLBACK - diff < self.window_mask.bits() {
                    self.window.set_bit(RTCP_ROLLBACK - diff, true);
                }
            } else {
                // index is in the future: shift the window
                // check it makes sense to shift as we shift then crop
                if diff < self.window_mask.bits() {
                    self.window <<= diff;
                    self.window &= &self.window_mask;
                } else {
                    // diff is so large that we wipe out the replay window
                    self.window = BigUint::ZERO;
                }
                self.window.set_bit(0, true); // 0 index in the window is the current index
                self.index = index;
            }
        } else {
            // index seems to be in the past
            let diff = u64::from(self.index - index);
            // index is smaller than current one and can fit in the window
            if diff < self.window_mask.bits() {
                self.window.set_bit(diff, true);
            }
            // index is so far in the past that we must have rolled back
            // it is actually in the future
            if diff >= MAX_RTCP_STEP {
                // check it makes sense to shift as we shift then crop
                if RTCP_ROLLBACK - diff < self.window_mask.bits() {
                    self.window <<= RTCP_ROLLBACK - diff;
                    self.window &= &self.window_mask;
                } else {
                    // diff is so large that we wipe out the replay window
                    self.window = BigUint::ZERO;
                }
                self.window.set_bit(0, true); // 0 index in the window is the current index
                self.index = index;
            }
        }
    }

    /// returns true when the given index is found in the replay db
    /// if the index is too old to be in the replay window, consider we've seen it
    pub fn seen_index(&self, index: u32) -> bool {
        if index > self.index {
            // index seems to be in the future
            let diff = u64::from(index - self.index);
            // index is so far in the future that we must have rolled back recently
            // it is actually in the past
            if diff > MAX_RTCP_STEP {
                // it's out of the replay window, consider it is in the db
                if RTCP_ROLLBACK - diff >= self.window_mask.bits() {
                    true
                } else {
                    self.window.bit(RTCP_ROLLBACK - diff)
                }
            } else {
                // given index is in the future, cannot be in db
                false
            }
        } else {
            // index seems to be in the past
            let diff = u64::from(self.index - index);
            // index is older than replay window size
            if diff >= self.window_mask.bits() {
                if diff >= MAX_RTCP_STEP {
                    // index is so far back that we must have rolled back: it is actually in the future
                    false
                } else {
                    // index is out of the replay window, consider we've seen it
                    true
                }
            } else {
                // index is in the replay window range
                self.window.bit(diff)
            }
        }
    }

    pub fn set_window_size(&mut self, size: u16) {
        self.window_mask = (BigUint::one() << size) - BigUint::one();
    }
}

#[cfg(test)]
mod test {
    use super::*;

    const TEST_WINDOW_SIZE: u16 = 128;

    #[test]
    fn rtp_replay() {
        let mut db = RtpReplayDb::new(TEST_WINDOW_SIZE);

        // set the index to 0xfffe -> roc is 0 and seq_num is 0xfffe
        db.add_index(0xfffe);
        assert!(db.seen_index(0xfffe)); // check the index is in the replay windows
        assert_eq!(
            db.estimate_index(0xffff),
            0xffff,
            "Fail to estimate index, current index is {:?} \n",
            db.index,
        );
        assert_eq!(
            db.estimate_index(0xfffa),
            0xfffa,
            "Fail to estimate index, current index is {:?} \n",
            db.index,
        );
        assert_eq!(db.get_roc(), 0,);
        assert_eq!(
            db.estimate_index(0x0001),
            0x10001,
            "Fail to estimate index, current index is {:?} \n",
            db.index,
        );
        // this one shall increase the roc
        db.add_index(0x10001); // now we have index 0xfffe and 0x10001 in db
        assert_eq!(db.get_roc(), 1,);
        assert!(db.seen_index(0xfffe));
        assert!(db.seen_index(0x10001));
        assert_eq!(
            // this simulate a late packet from previous roc
            db.estimate_index(0xfff0),
            0xfff0,
            "Fail to estimate index, current index is {:?} \n",
            db.index,
        );
        assert!(!db.seen_index(0xfff0)); // packet index not seen (in the past)
        assert!(!db.seen_index(0x10002)); // packet index not seen (in the future)
        assert!(!db.seen_index(0x10001_u64 - u64::from(TEST_WINDOW_SIZE) + 1)); // packet index just old enough
        assert!(db.seen_index(0x10001_u64 - u64::from(TEST_WINDOW_SIZE))); // packet index too old

        db.add_index(0xfffa); // add index in the past
        assert!(db.seen_index(0xfffa));
        assert_eq!(
            // check the current index is still 0x10001
            db.index,
            0x10001,
            "Failure after adding an index in the past, the current index is modified"
        );

        assert!(db.seen_index(0xfffa));
        assert!(db.seen_index(0xfffe));
        assert!(db.seen_index(0x10001));

        db.add_index(0x1000f); // move the index forward
        // check all the packets are still present in DB
        assert!(db.seen_index(0xfffa));
        assert!(db.seen_index(0xfffe));
        assert!(db.seen_index(0x10001));
        assert!(db.seen_index(0x1000f));

        // force a Roc increase
        assert_eq!(db.get_roc(), 1,);
        db.set_roc(2);
        assert_eq!(
            // roc is still the same, modified only when we add an index
            db.get_roc(),
            1,
        );
        assert_eq!(
            // we use the pending roc to compute the index
            db.estimate_index(0x0042),
            0x20042,
            "Fail to estimate index, current index is {:?} \n",
            db.index,
        );
        assert_eq!(db.get_roc(), 1,);
        db.add_index(0x20042); // move the index forward
        assert_eq!(db.get_roc(), 2,);

        // create a new db
        let mut db = RtpReplayDb::new(TEST_WINDOW_SIZE);
        // set ROC to 0xfffffffe, which is near ROC limit - this would normally never happens
        db.set_roc(0xfffffffe);
        let index = db.estimate_index(2);
        assert_eq!(index, 0xfffffffe0002); // check estimated index
        assert!(!db.seen_index(index)); // it shall not be in DB

        // create a new db
        let mut db = RtpReplayDb::new(TEST_WINDOW_SIZE);
        db.add_index(2);
        db.add_index(3);
        assert!(db.seen_index(2));
        assert!(db.seen_index(3));
        db.set_roc(3);
        let index = db.estimate_index(2);
        assert_eq!(index, 0x30002); // check estimated index
        assert!(!db.seen_index(index));
    }

    #[test]
    fn rtcp_roll_over() {
        // create a Rtcp DB, add the two biggest index possible, then rollback to a small one
        let mut db = RtcpReplayDb::new(TEST_WINDOW_SIZE);
        db.index = 0x7ffffffa; // force starting index otherwise we can't add index next to the
        // rollback point
        let mut index: u32 = 0x7ffffffe;
        // add an index next to the rollback
        db.add_index(index);
        assert_eq!(db.index, index);
        index += 1;
        db.add_index(index);
        // check both indexes are in DB
        assert!(db.seen_index(index - 1));
        assert!(db.seen_index(index));
        assert_eq!(db.index, index);
        // add an index point after the rollback
        index = 2;
        assert!(!db.seen_index(index)); // current index after the rollback is not in
        db.add_index(index);
        // check the current index is the added one and that we still see the 'old' ones
        assert_eq!(db.index, index);
        assert!(db.seen_index(index));
        assert!(db.seen_index(0x7ffffffe));
        assert!(db.seen_index(0x7fffffff));
        assert!(!db.seen_index(0x7ffffffd)); // this one was never there
        // add an index from before the rollback
        db.add_index(0x7ffffffd);
        assert!(db.seen_index(0x7ffffffd));
        assert_eq!(db.index, index); // current index is unchanged
    }

    #[test]
    fn rtp_set_roc() {}
}
