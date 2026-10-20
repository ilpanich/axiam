//! The dead-letter line bounds the client-sized fields whoever built the entry,
//! on a character boundary, and names its reason from a closed set.

use axiam_audit::dead_letter::{
    DeadLetterReason, DeadLetterRecord, MAX_ACTION_BYTES, MAX_ADDRESS_BYTES, bound_fields,
    decode_line, encode_line,
};
use axiam_core::models::audit::{ActorType, AuditOutcome, CreateAuditLogEntry};
use chrono::Utc;
use uuid::Uuid;

fn entry(action: String, ip_address: Option<String>) -> CreateAuditLogEntry {
    CreateAuditLogEntry {
        tenant_id: Uuid::new_v4(),
        actor_id: Uuid::new_v4(),
        actor_type: ActorType::System,
        action,
        resource_id: None,
        outcome: AuditOutcome::Failure,
        ip_address,
        metadata: None,
    }
}

#[test]
fn the_reasons_display_the_names_the_line_carries() {
    for (reason, name) in [
        (DeadLetterReason::ChannelFull, "channel_full"),
        (DeadLetterReason::ChannelClosed, "channel_closed"),
        (DeadLetterReason::DatastoreError, "datastore_error"),
    ] {
        assert_eq!(reason.as_str(), name);
        assert_eq!(reason.to_string(), name);
    }
}

/// A two-byte character straddling the cut moves the cut back to the boundary:
/// the result is valid UTF-8, within the bound, and marked.
#[test]
fn oversized_fields_are_cut_on_a_character_boundary_and_marked() {
    let action = "é".repeat(MAX_ACTION_BYTES); // 2 * MAX bytes
    let ip = "é".repeat(MAX_ADDRESS_BYTES);
    let mut cut = entry(action.clone(), Some(ip.clone()));
    bound_fields(&mut cut);

    let cut_ip = cut.ip_address.as_deref().unwrap();
    for (before, after, max) in [
        (&action, &cut.action, MAX_ACTION_BYTES),
        (&ip, &cut_ip.to_owned(), MAX_ADDRESS_BYTES),
    ] {
        assert!(after.len() <= max, "{} > {max}", after.len());
        assert!(after.ends_with("...[truncated]"), "{after}");
        assert!(before.starts_with(after.trim_end_matches("...[truncated]")));
    }

    let within = entry("POST /api/v1/users".into(), Some("203.0.113.9".into()));
    let mut unchanged = within.clone();
    bound_fields(&mut unchanged);
    assert_eq!(unchanged.action, within.action);
    assert_eq!(unchanged.ip_address, within.ip_address);
}

/// `encode_line` bounds the entry itself, so a caller that forgot to cannot
/// write an unbounded line; `decode_line` reads the bounded envelope back.
#[test]
fn the_encoded_line_is_bounded_and_decodes_to_the_bounded_entry() {
    let record = DeadLetterRecord::new(
        entry(
            "x".repeat(MAX_ACTION_BYTES * 4),
            Some("y".repeat(MAX_ADDRESS_BYTES * 4)),
        ),
        Utc::now(),
        DeadLetterReason::ChannelFull,
    );
    let line = encode_line(&record).unwrap();
    assert!(
        line.len() < MAX_ACTION_BYTES * 2 + 1024,
        "{} bytes",
        line.len()
    );

    let decoded = decode_line(&line).unwrap();
    assert_eq!(decoded.reason.as_deref(), Some("channel_full"));
    assert!(decoded.entry.action.len() <= MAX_ACTION_BYTES);
    assert!(decoded.entry.action.ends_with("...[truncated]"));
    assert!(decoded.entry.ip_address.unwrap().len() <= MAX_ADDRESS_BYTES);
    assert_eq!(decoded.entry.tenant_id, record.entry.tenant_id);
}
