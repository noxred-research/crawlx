//! `loom` model of the round-robin turn barrier (lease races).
//!
//! The repositories grant a session's lease only when [`TurnBarrier::grantable`] holds for its
//! `schedule_slot` (`UPDATE … WHERE NOT EXISTS (lower non-terminal slot)`), and a finished
//! session's release wakes the waiters. This model runs one thread per role over that
//! protocol — a mutex-guarded slot board for the claim, a condvar for the release — and lets
//! loom explore every interleaving. It asserts, for every schedule:
//!
//! * at most one role is inside its turn at a time unless `parallel_roles_allowed`,
//! * turns start in slot order on a shared target,
//! * every role gets exactly one turn (a schedule in which a role never runs, or in which the
//!   threads block each other, fails: loom reports a deadlock when every thread is parked).
//!
//! The file compiles to nothing without the crate's `loom` feature (a global `--cfg loom`
//! would also switch third-party crates such as `event-listener` into their loom builds, so
//! the model is gated on a cargo feature instead). Run it with:
//!
//! ```text
//! cargo test -p crawlx-scheduler --features loom --test loom_turns --release
//! ```
#![cfg(feature = "loom")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use crawlx_core::repo::SessionStatus;
use crawlx_scheduler::TurnBarrier;
use loom::sync::{Arc, Condvar, Mutex};
use loom::thread;

/// What the repository row set looks like to the barrier, plus the invariants under test.
struct Board {
    /// `crawl_sessions.status` by `schedule_slot`.
    slots: Vec<SessionStatus>,
    /// Roles currently inside their turn.
    active: usize,
    /// Peak of `active`.
    max_active: usize,
    /// Slots in the order their turns started.
    started: Vec<u32>,
}

fn slot_statuses(slots: &[SessionStatus]) -> Vec<(u32, SessionStatus)> {
    slots
        .iter()
        .enumerate()
        .map(|(s, st)| (u32::try_from(s).unwrap(), *st))
        .collect()
}

/// Claim slot `slot` (block until the barrier grants it), run the turn, release it.
fn role_thread(barrier: TurnBarrier, board: &Arc<(Mutex<Board>, Condvar)>, slot: u32) {
    let (lock, released) = &**board;
    let mut b = lock.lock().unwrap();
    while !barrier.grantable(slot, slot_statuses(&b.slots)) {
        b = released.wait(b).unwrap();
    }
    assert_eq!(b.slots[slot as usize], SessionStatus::Pending);
    b.slots[slot as usize] = SessionStatus::Running;
    b.active += 1;
    b.max_active = b.max_active.max(b.active);
    b.started.push(slot);
    drop(b);

    // the turn itself: a scheduling point so other roles may try to claim meanwhile
    thread::yield_now();

    let mut b = lock.lock().unwrap();
    b.active -= 1;
    b.slots[slot as usize] = SessionStatus::Completed;
    released.notify_all();
}

fn explore(n_roles: u32, parallel_roles_allowed: bool) -> Vec<Vec<u32>> {
    let orders = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let sink = std::sync::Arc::clone(&orders);
    loom::model(move || {
        let barrier = TurnBarrier::new(parallel_roles_allowed);
        let board = Arc::new((
            Mutex::new(Board {
                slots: vec![SessionStatus::Pending; n_roles as usize],
                active: 0,
                max_active: 0,
                started: Vec::new(),
            }),
            Condvar::new(),
        ));
        let handles: Vec<_> = (0..n_roles)
            .map(|slot| {
                let board = Arc::clone(&board);
                thread::spawn(move || role_thread(barrier, &board, slot))
            })
            .collect();
        for h in handles {
            h.join().unwrap();
        }
        let b = board.0.lock().unwrap();
        assert!(
            b.slots.iter().all(|s| *s == SessionStatus::Completed),
            "a role never got its turn: {:?}",
            b.slots
        );
        assert_eq!(b.active, 0);
        assert_eq!(b.started.len(), n_roles as usize, "every role runs exactly once");
        if parallel_roles_allowed {
            let mut seen = b.started.clone();
            seen.sort_unstable();
            assert_eq!(seen, (0..n_roles).collect::<Vec<_>>());
        } else {
            assert_eq!(b.max_active, 1, "two roles were inside their turns at once");
            assert_eq!(
                b.started,
                (0..n_roles).collect::<Vec<_>>(),
                "turns did not start in slot order"
            );
        }
        sink.lock().unwrap().push(b.started.clone());
    });
    let out = orders.lock().unwrap().clone();
    out
}

#[test]
fn shared_target_serializes_three_roles_in_slot_order_under_every_interleaving() {
    let orders = explore(3, false);
    assert!(!orders.is_empty());
    assert!(orders.iter().all(|o| *o == [0, 1, 2]), "{orders:?}");
}

#[test]
fn per_role_replica_lets_roles_overlap_and_still_gives_every_role_a_turn() {
    let orders = explore(3, true);
    assert!(!orders.is_empty());
    // with the barrier lifted loom finds schedules where a higher slot starts first
    assert!(
        orders.iter().any(|o| o[0] != 0),
        "no interleaving let a later slot start first: {orders:?}"
    );
}
