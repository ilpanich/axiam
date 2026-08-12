//! Does SurrealDB serialise two concurrent read-modify-writes on one row?
//!
//! This is the probe behind ilpanich/axiam#302. Three single-use consume paths
//! (UMA permission tickets, RFC 8628 device grants, RFC 9126 PAR request_uris)
//! need "exactly one caller may redeem this row". The original implementation
//! asked the datastore for that guarantee, by wrapping the read-modify-write in
//! `BEGIN`/`COMMIT` and assuming a write-write conflict between two concurrent
//! redemptions would abort the loser.
//!
//! It does not, at least on the engine that was measured. This probe reduces
//! that claim to its smallest form so it can be checked against each storage
//! engine in turn, and so it can be handed upstream as a reproducer.
//!
//! Two mechanisms are implemented:
//!
//!   `tx`    — the original. One `UPDATE … WHERE consumed = false RETURN BEFORE`
//!             inside an explicit transaction. A racer "won" if its UPDATE
//!             matched. Correct iff the engine aborts all but one.
//!   `nonce` — what shipped instead (schema v31/v32). Every racer stamps its own
//!             nonce, then reads the row back outside the transaction; the racer
//!             whose nonce survived is the winner. Depends on no engine
//!             guarantee, and is included here only for a like-for-like number.
//!
//! Correct behaviour, for either mechanism, is EXACTLY ONE winner per round.
//! Zero winners is also a failure — a redemption that nobody may claim burns a
//! ticket a legitimate caller was entitled to.
//!
//! Usage:
//!   surreal-race-probe <engine> [mechanism] [rounds] [racers]
//!     engine     mem | surrealkv | rocksdb        (rocksdb needs --features rocksdb)
//!     mechanism  tx | nonce                        (default: tx)
//!     rounds     default 1200
//!     racers     default 8

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use surrealdb::engine::local::{Db, Mem, SurrealKv};
use surrealdb::Surreal;
use tokio::sync::Barrier;

/// One `UPDATE` guarded by `WHERE consumed = false`, inside an explicit
/// transaction. The engine is being asked to arbitrate.
const TX_SQL: &str = "\
BEGIN TRANSACTION;
LET $before = (UPDATE probe SET consumed = true \
    WHERE key = $key AND consumed = false RETURN BEFORE);
SELECT VALUE key FROM $before;
COMMIT TRANSACTION;";

/// Per-attempt nonce, written then read back OUTSIDE any transaction. Mirrors
/// `permission_ticket.consume` in `axiam-db`. Nothing is asked of the engine.
const NONCE_SQL: &str = "\
LET $before = (UPDATE probe SET consumed = true, redemption_id = $nonce \
    WHERE key = $key AND consumed = false RETURN BEFORE);
SELECT VALUE key FROM $before;
SELECT VALUE redemption_id FROM probe WHERE key = $key LIMIT 1;";

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mechanism {
    Tx,
    Nonce,
}

/// What one racer's attempt came to. The distinction between `Aborted` and
/// `NoMatch` is the whole finding: an abort is the engine arbitrating, a
/// no-match is the racer losing on data it read for itself.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Outcome {
    /// This racer believes it holds the single redemption.
    Won,
    /// The `WHERE consumed = false` guard matched nothing.
    NoMatch,
    /// The engine refused the transaction — a conflict, or a transaction
    /// already poisoned by one.
    Aborted,
}

async fn attempt(db: &Surreal<Db>, key: String, mechanism: Mechanism) -> Result<Outcome, String> {
    match mechanism {
        Mechanism::Tx => {
            let mut resp = match db.query(TX_SQL).bind(("key", key)).await {
                Ok(r) => r,
                Err(e) => {
                    return if is_lost(&e) {
                        Ok(Outcome::Aborted)
                    } else {
                        Err(e.to_string())
                    }
                }
            };
            // Statement indices shift depending on whether BEGIN/COMMIT occupy
            // response slots, so try the plausible ones rather than hard-coding
            // a guess. An abort surfaces HERE rather than at the query call,
            // and it means the engine did arbitrate — so it must be recognised,
            // not swallowed as a probe bug.
            let mut last = String::new();
            for idx in [1usize, 0, 2] {
                match resp.take::<Vec<String>>(idx) {
                    Ok(rows) => {
                        return Ok(if rows.is_empty() {
                            Outcome::NoMatch
                        } else {
                            Outcome::Won
                        })
                    }
                    Err(e) => {
                        if is_lost(&e) {
                            return Ok(Outcome::Aborted);
                        }
                        last = e.to_string();
                    }
                }
            }
            Err(format!("could not locate the SELECT response: {last}"))
        }
        Mechanism::Nonce => {
            let nonce = uuid::Uuid::new_v4().to_string();
            let mut resp = match db
                .query(NONCE_SQL)
                .bind(("key", key))
                .bind(("nonce", nonce.clone()))
                .await
            {
                Ok(r) => r,
                Err(e) => {
                    return if is_lost(&e) {
                        Ok(Outcome::Aborted)
                    } else {
                        Err(e.to_string())
                    }
                }
            };
            // LET = 0, SELECT rows = 1, SELECT nonce = 2.
            let matched: Vec<String> = match resp.take(1) {
                Ok(v) => v,
                Err(e) => {
                    return if is_lost(&e) {
                        Ok(Outcome::Aborted)
                    } else {
                        Err(e.to_string())
                    }
                }
            };
            if matched.is_empty() {
                return Ok(Outcome::NoMatch);
            }
            let stored: Vec<Option<String>> = match resp.take(2) {
                Ok(v) => v,
                Err(e) => {
                    return if is_lost(&e) {
                        Ok(Outcome::Aborted)
                    } else {
                        Err(e.to_string())
                    }
                }
            };
            Ok(
                if stored.into_iter().flatten().next().as_deref() == Some(nonce.as_str()) {
                    Outcome::Won
                } else {
                    Outcome::NoMatch
                },
            )
        }
    }
}

/// Every way the engine says "this attempt did not happen". A caller seeing any
/// of these has lost the race, and an application must translate it into
/// "someone else redeemed first" rather than into a server fault.
fn is_lost(e: &surrealdb::Error) -> bool {
    let s = e.to_string();
    s.contains("read or write conflict")
        || s.contains("Transaction conflict")
        || s.contains("not executed due to a failed transaction")
        || s.contains("Failed to commit transaction")
}

async fn open(engine: &str, dir: &str) -> Surreal<Db> {
    let db = match engine {
        "mem" => Surreal::new::<Mem>(()).await.expect("mem"),
        "surrealkv" => Surreal::new::<SurrealKv>(format!("{dir}/skv.db"))
            .await
            .expect("surrealkv"),
        #[cfg(feature = "rocksdb")]
        "rocksdb" => Surreal::new::<surrealdb::engine::local::RocksDb>(format!("{dir}/rocks.db"))
            .await
            .expect("rocksdb"),
        other => panic!("unknown or uncompiled engine {other:?} (rocksdb needs --features rocksdb)"),
    };
    db.use_ns("probe").use_db("probe").await.expect("use ns/db");
    db.query("DEFINE TABLE IF NOT EXISTS probe SCHEMALESS; DEFINE INDEX IF NOT EXISTS probe_key ON TABLE probe COLUMNS key")
        .await
        .expect("schema");
    db
}

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    let engine = args.get(1).cloned().unwrap_or_else(|| "mem".into());
    let mechanism = match args.get(2).map(String::as_str).unwrap_or("tx") {
        "tx" => Mechanism::Tx,
        "nonce" => Mechanism::Nonce,
        other => panic!("unknown mechanism {other:?}"),
    };
    let rounds: usize = args.get(3).and_then(|s| s.parse().ok()).unwrap_or(1200);
    let racers: usize = args.get(4).and_then(|s| s.parse().ok()).unwrap_or(8);

    let dir = std::env::var("PROBE_DIR").unwrap_or_else(|_| "/tmp/surreal-race-probe".into());
    let _ = std::fs::create_dir_all(&dir);

    let db = Arc::new(open(&engine, &dir).await);

    let mut double = 0usize; // > 1 winner: the defect under test
    let mut zero = 0usize; // 0 winners: a burned row nobody may claim
    let mut total_aborted = 0usize;
    let mut errors: Vec<String> = Vec::new();

    for round in 0..rounds {
        let key = format!("k{round}");
        db.query("CREATE type::record('probe', $key) SET key = $key, consumed = false")
            .bind(("key", key.clone()))
            .await
            .expect("create")
            .check()
            .expect("create ok");

        let barrier = Arc::new(Barrier::new(racers));
        let winners = Arc::new(AtomicUsize::new(0));
        let aborted = Arc::new(AtomicUsize::new(0));
        let failures: Arc<std::sync::Mutex<Vec<String>>> = Arc::new(std::sync::Mutex::new(vec![]));

        let mut handles = Vec::with_capacity(racers);
        for _ in 0..racers {
            let db = Arc::clone(&db);
            let barrier = Arc::clone(&barrier);
            let winners = Arc::clone(&winners);
            let aborted = Arc::clone(&aborted);
            let failures = Arc::clone(&failures);
            let key = key.clone();
            handles.push(tokio::spawn(async move {
                // Every racer arrives at the UPDATE together. This is the whole
                // point: the window only exists while two attempts overlap.
                barrier.wait().await;
                match attempt(&db, key, mechanism).await {
                    Ok(Outcome::Won) => {
                        winners.fetch_add(1, Ordering::SeqCst);
                    }
                    Ok(Outcome::Aborted) => {
                        aborted.fetch_add(1, Ordering::SeqCst);
                    }
                    Ok(Outcome::NoMatch) => {}
                    Err(e) => failures.lock().unwrap().push(e),
                }
            }));
        }
        for h in handles {
            let _ = h.await;
        }

        total_aborted += aborted.load(Ordering::SeqCst);
        let n = winners.load(Ordering::SeqCst);
        if n > 1 {
            double += 1;
            eprintln!("round {round}: {n} winners");
        } else if n == 0 {
            zero += 1;
            eprintln!("round {round}: 0 winners");
        }
        for f in failures.lock().unwrap().drain(..) {
            if errors.len() < 5 {
                errors.push(f);
            }
        }
    }

    let mech = if mechanism == Mechanism::Tx { "tx" } else { "nonce" };
    println!("\nengine={engine} mechanism={mech} rounds={rounds} racers={racers}");
    println!("  rounds with >1 winner : {double}");
    println!("  rounds with 0 winners : {zero}");
    println!(
        "  attempts aborted      : {total_aborted} of {} (the engine arbitrating)",
        rounds * racers
    );
    println!("  unexpected errors     : {}", errors.len());
    for e in &errors {
        println!("    {e}");
    }
    println!(
        "  VERDICT: {}",
        if double == 0 && zero == 0 {
            "exactly one winner in every round"
        } else {
            "SINGLE-USE VIOLATED"
        }
    );
}
