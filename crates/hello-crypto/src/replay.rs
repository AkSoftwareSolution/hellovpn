//! 64-slot sliding-window replay protection.
//!
//! # Algorithm
//!
//! A single `u64` bitmap tracks which of the 64 most-recent sequence numbers
//! have been received. Bit 0 (LSB) corresponds to `highest_seen`; bit N
//! corresponds to `highest_seen - N`.
//!
//! * Packets older than `highest_seen - 63` are unconditionally rejected
//!   (they are outside the window and cannot be verified).
//! * Packets whose bit is already set in the bitmap are replays → rejected.
//! * New valid packets advance the window and set their bit.
//!
//! # Security notes
//!
//! The window MUST be checked AFTER successful AEAD decryption, not before.
//! Checking before decryption allows an attacker to poison the window with
//! crafted packets that would cause legitimate packets to be dropped.
//!
//! The correct call order in `hello-packet`:
//! 1. Rough out-of-window check (drop if obviously too old — no window update)
//! 2. AEAD decrypt + verify tag
//! 3. `check_and_insert(seq)` — final window check + mark as seen
//!
//! This crate's `check_and_insert` performs both the window check and the
//! insertion atomically in a single call, which is safe provided callers
//! follow the above order.

use hello_core::SessionError;

/// 64-slot sliding-window replay protector.
#[derive(Debug)]
pub struct ReplayWindow {
    /// Bitmask: bit N = packet at (highest - N) has been received.
    bitmap: u64,
    /// Highest sequence number accepted so far.
    highest: u64,
    /// True after the first packet is received (window is "unseeded").
    seeded: bool,
}

impl Default for ReplayWindow {
    fn default() -> Self { Self::new() }
}

impl ReplayWindow {
    pub fn new() -> Self {
        Self { bitmap: 0, highest: 0, seeded: false }
    }

    /// Window size (number of slots).
    pub const WINDOW_SIZE: u64 = 64;

    /// Check if `seq` is acceptable (not a replay, not too old) and mark it
    /// as received.  Returns `Err(SessionError::Replay)` if the packet should
    /// be dropped.
    ///
    /// MUST be called after successful AEAD decryption.
    pub fn check_and_insert(&mut self, seq: u64) -> Result<(), SessionError> {
        if !self.seeded {
            // First ever packet — accept unconditionally.
            self.highest = seq;
            self.bitmap = 1; // bit 0 = highest = seq
            self.seeded = true;
            return Ok(());
        }

        if seq > self.highest {
            // Packet is ahead of our window — advance.
            let advance = seq - self.highest;
            if advance >= Self::WINDOW_SIZE {
                // Giant leap: entire old window is obsolete.
                self.bitmap = 0;
            } else {
                self.bitmap <<= advance;
            }
            self.highest = seq;
            self.bitmap |= 1; // mark current
            return Ok(());
        }

        // Packet is within or behind the current window.
        let behind = self.highest - seq;
        if behind >= Self::WINDOW_SIZE {
            // Too old — outside window.
            return Err(SessionError::Replay(seq));
        }

        let bit = 1u64 << behind;
        if self.bitmap & bit != 0 {
            // Already seen — replay.
            return Err(SessionError::Replay(seq));
        }

        self.bitmap |= bit;
        Ok(())
    }

    /// Rough check: would this sequence number be accepted without modifying state?
    /// Used for the pre-decryption fast-path reject (too-old check only).
    pub fn is_too_old(&self, seq: u64) -> bool {
        if !self.seeded { return false; }
        self.highest > seq && (self.highest - seq) >= Self::WINDOW_SIZE
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_in_order_sequence() {
        let mut w = ReplayWindow::new();
        for i in 0u64..10 {
            assert!(w.check_and_insert(i).is_ok(), "seq {i} should be accepted");
        }
    }

    #[test]
    fn rejects_duplicate() {
        let mut w = ReplayWindow::new();
        w.check_and_insert(5).unwrap();
        assert!(w.check_and_insert(5).is_err(), "duplicate seq 5 must be rejected");
    }

    #[test]
    fn rejects_too_old() {
        let mut w = ReplayWindow::new();
        w.check_and_insert(100).unwrap();
        // seq 100 - 64 = 36 is exactly at the edge (behind = 64 → rejected)
        assert!(w.check_and_insert(36).is_err());
        // seq 37 is inside the window (behind = 63 → accepted)
        assert!(w.check_and_insert(37).is_ok());
    }

    #[test]
    fn accepts_out_of_order_within_window() {
        let mut w = ReplayWindow::new();
        // Receive 5 then 3 then 4 — all within window
        w.check_and_insert(5).unwrap();
        w.check_and_insert(3).unwrap();
        w.check_and_insert(4).unwrap();
        // Duplicates rejected
        assert!(w.check_and_insert(3).is_err());
        assert!(w.check_and_insert(4).is_err());
        assert!(w.check_and_insert(5).is_err());
    }

    #[test]
    fn window_advances_correctly() {
        let mut w = ReplayWindow::new();
        for i in 0u64..70 {
            assert!(w.check_and_insert(i).is_ok(), "seq {i}");
        }
        // seq 0 is now 70 steps behind, outside the 64-slot window
        assert!(w.check_and_insert(0).is_err());
        // seq 6 (70 - 64 = 6) is exactly at the edge — rejected
        assert!(w.check_and_insert(6).is_err());
        // seq 7 is inside the window — but already received
        assert!(w.check_and_insert(7).is_err());
    }

    #[test]
    fn giant_leap_advances_window() {
        let mut w = ReplayWindow::new();
        w.check_and_insert(0).unwrap();
        // Jump far ahead — old window cleared
        w.check_and_insert(1_000_000).unwrap();
        // Seq 0 is now far behind — rejected
        assert!(w.check_and_insert(0).is_err());
    }

    #[test]
    fn is_too_old_check() {
        let mut w = ReplayWindow::new();
        w.check_and_insert(100).unwrap();
        assert!(w.is_too_old(35));   // 100 - 35 = 65 >= 64
        assert!(!w.is_too_old(37));  // 100 - 37 = 63 < 64
        assert!(!w.is_too_old(200)); // ahead of highest
    }
}
