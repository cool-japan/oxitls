//! Tests for the AntiReplayTicketer (RFC 8446 §8 single-use-ticket replay protection).

#[cfg(feature = "pure")]
mod tests {
    use std::sync::Arc;

    use oxitls::anti_replay::{AntiReplayTicketer, MockClock};
    use oxitls::ticketer::OxiTicketer;
    use rustls::server::ProducesTickets;

    fn make_ticketer() -> OxiTicketer {
        OxiTicketer::new().expect("OxiTicketer::new")
    }

    #[test]
    fn first_decrypt_succeeds() {
        let inner = make_ticketer();
        let ar = AntiReplayTicketer::new(inner);
        let plaintext = b"session-state";
        let ticket = ar.encrypt(plaintext).expect("encrypt");
        let result = ar.decrypt(&ticket);
        assert!(result.is_some(), "first decrypt should succeed");
        assert_eq!(result.unwrap(), plaintext);
    }

    #[test]
    fn immediate_replay_is_blocked() {
        let inner = make_ticketer();
        let ar = AntiReplayTicketer::new(inner);
        let plaintext = b"session-state";
        let ticket = ar.encrypt(plaintext).expect("encrypt");
        let first = ar.decrypt(&ticket);
        let replay = ar.decrypt(&ticket);
        assert!(first.is_some(), "first use must succeed");
        assert!(replay.is_none(), "immediate replay must be blocked");
    }

    #[test]
    fn two_distinct_tickets_are_independent() {
        let inner = make_ticketer();
        let ar = AntiReplayTicketer::new(inner);
        let t1 = ar.encrypt(b"state-1").expect("encrypt-1");
        let t2 = ar.encrypt(b"state-2").expect("encrypt-2");
        assert!(ar.decrypt(&t1).is_some(), "ticket 1 first use");
        assert!(ar.decrypt(&t2).is_some(), "ticket 2 first use");
    }

    #[test]
    fn window_expiry_allows_reuse() {
        let inner = make_ticketer();
        let clock = MockClock::new();
        let ar = AntiReplayTicketer::with_clock(inner, clock.clone());
        let plaintext = b"state";
        let ticket = ar.encrypt(plaintext).expect("encrypt");
        let _ = ar.decrypt(&ticket); // first use: records fingerprint
        let _ = ar.decrypt(&ticket); // replay: blocked

        // Advance past the window (lifetime() seconds + 1).
        let lifetime = ar.lifetime();
        clock.advance_secs(u64::from(lifetime) + 1);

        // Now the fingerprint has expired; ticket may be used again.
        let after_expiry = ar.decrypt(&ticket);
        assert!(
            after_expiry.is_some(),
            "after window expiry, ticket should be usable again"
        );
    }

    #[test]
    fn concurrent_decrypt_yields_exactly_one_success() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let inner = make_ticketer();
        let ar = Arc::new(AntiReplayTicketer::new(inner));
        let ticket = ar.encrypt(b"concurrent-state").expect("encrypt");
        let ticket = Arc::new(ticket);

        let success_count = Arc::new(AtomicUsize::new(0));
        let threads: Vec<_> = (0..8)
            .map(|_| {
                let ar = Arc::clone(&ar);
                let ticket = Arc::clone(&ticket);
                let count = Arc::clone(&success_count);
                std::thread::spawn(move || {
                    if ar.decrypt(&ticket).is_some() {
                        count.fetch_add(1, Ordering::Relaxed);
                    }
                })
            })
            .collect();
        for t in threads {
            t.join().expect("thread");
        }

        assert_eq!(
            success_count.load(Ordering::Relaxed),
            1,
            "exactly one thread should succeed; others should see replay"
        );
    }

    #[test]
    fn invalid_ticket_not_recorded() {
        // Garbage ticket: decrypt returns None from inner; fingerprint must NOT be recorded.
        let inner = make_ticketer();
        let ar = AntiReplayTicketer::new(inner);
        let garbage = b"this is not a valid encrypted ticket";
        let first = ar.decrypt(garbage); // inner says None
        let second = ar.decrypt(garbage); // same garbage again
                                          // Both should return None (no plaintext, inner rejected them; never recorded).
        assert!(first.is_none());
        assert!(second.is_none());
    }
}
