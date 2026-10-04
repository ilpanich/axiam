//! The frame guard: every LDAP message a directory sends is measured, and its
//! BER structure checked, **before** `ldap3` sees a byte of it (P23W2-10,
//! T-295, T-331).
//!
//! # Why a guard beneath `ldap3`
//!
//! `ldap3 0.12`'s codec has no size limit. It buffers whatever arrives until the
//! message its first bytes declare is complete — a header claiming 4 GiB is a
//! promise the codec waits for, growing its buffer as the bytes come — and it
//! re-parses the whole buffer on every read. Its BER parser (`lber`) recurses
//! once per nested constructed element with no depth bound, so a few tens of
//! kilobytes of nesting overflow a worker's stack, which aborts the process —
//! every tenant's process, since one directory connector serves them all. And
//! its envelope decoder `expect`s a message id and an operation, so a
//! syntactically short message panics the connection's task.
//!
//! A tenant administrator chooses the directory. So every message is read here
//! first, from the decrypted TLS stream, and only a message that passes is
//! forwarded to `ldap3`:
//!
//! 1. **Declared length, before anything is allocated.** The outer tag must be
//!    an LDAPMessage `SEQUENCE` (`0x30`) with a definite length of at most four
//!    length octets; a declared length above the cap ([`DEFAULT_MAX_MESSAGE_BYTES`],
//!    deployment-configurable through [`MAX_MESSAGE_BYTES_ENV`]) ends the
//!    connection on the spot. Within the cap the buffer grows only as bytes
//!    actually arrive, so a server that declares the cap and stalls costs what
//!    it sent.
//! 2. **Well-formed to the last byte, at bounded depth.** Every element has a
//!    single-octet tag (LDAP uses no tag number above 30), a definite length
//!    that fits inside its parent, and constructed elements nest at most
//!    [`MAX_NESTING_DEPTH`] deep (a search result entry is five).
//! 3. **The envelope `ldap3` assumes.** A message id (`INTEGER`, one to four
//!    octets) followed by at least one more element (the operation).
//!
//! Anything else is a [`FrameError`] and the connection is closed in both
//! directions; the operation in flight fails as the directory being
//! unavailable. Requests AXIAM sends are not inspected: `ldap3` builds them.

use tokio::io::{AsyncRead, AsyncReadExt};

/// Default cap on one LDAP message from a directory, in bytes: 2 MiB.
///
/// Generous for every answer AXIAM asks for. The largest is an Active
/// Directory user's `memberOf`, which the server ranges at 1 500 values (a few
/// hundred kilobytes); every search requests named attributes only, and each
/// entry of a search is its own message.
pub const DEFAULT_MAX_MESSAGE_BYTES: usize = 2 * 1024 * 1024;
/// Smallest cap a deployment may configure (64 KiB).
pub const MIN_MAX_MESSAGE_BYTES: usize = 64 * 1024;
/// Largest cap a deployment may configure (16 MiB).
pub const MAX_MAX_MESSAGE_BYTES: usize = 16 * 1024 * 1024;
/// The environment variable that sets the cap, in bytes, clamped to
/// [`MIN_MAX_MESSAGE_BYTES`]`..=`[`MAX_MAX_MESSAGE_BYTES`].
pub const MAX_MESSAGE_BYTES_ENV: &str = "AXIAM__DIRECTORY__MAX_MESSAGE_BYTES";
/// Deepest nesting of constructed elements accepted in one message.
pub const MAX_NESTING_DEPTH: usize = 16;

/// How much of a message's content is reserved before any of it arrives; the
/// rest is allocated as it is read.
const INITIAL_CONTENT_RESERVE: usize = 16 * 1024;

/// Why a message from the directory was refused. Carries no directory data.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum FrameError {
    /// The declared length exceeds the cap.
    #[error("the directory declared a message longer than the configured cap")]
    TooLarge,
    /// The outer element is not an LDAPMessage `SEQUENCE`.
    #[error("the directory sent something that is not an LDAP message")]
    NotAMessage,
    /// An indefinite length, a length of more than four octets, a multi-octet
    /// tag, or an element that overruns its parent.
    #[error("the directory sent a malformed BER element")]
    Malformed,
    /// Constructed elements nested deeper than [`MAX_NESTING_DEPTH`].
    #[error("the directory sent a message nested too deeply")]
    TooDeep,
    /// No message id, or nothing after it.
    #[error("the directory sent an LDAP message without a message id and operation")]
    BadEnvelope,
    /// The stream ended in the middle of a message.
    #[error("the directory closed the connection in the middle of a message")]
    Truncated,
    /// Reading from the stream failed.
    #[error("reading from the directory failed")]
    Io,
}

/// Clamp a configured cap into the accepted range.
#[must_use]
pub fn clamp_max_message_bytes(configured: usize) -> usize {
    configured.clamp(MIN_MAX_MESSAGE_BYTES, MAX_MAX_MESSAGE_BYTES)
}

/// The cap from [`MAX_MESSAGE_BYTES_ENV`] as `raw` gives it (`None`: unset),
/// clamped; an unparseable value is the default. Returns the cap and whether
/// the configured value had to be changed, for the startup log.
#[must_use]
pub fn max_message_bytes_from(raw: Option<&str>) -> (usize, bool) {
    match raw.map(str::trim).filter(|value| !value.is_empty()) {
        None => (DEFAULT_MAX_MESSAGE_BYTES, false),
        Some(value) => match value.parse::<usize>() {
            Ok(parsed) => {
                let clamped = clamp_max_message_bytes(parsed);
                (clamped, clamped != parsed)
            }
            Err(_) => (DEFAULT_MAX_MESSAGE_BYTES, true),
        },
    }
}

/// Read one whole LDAP message from `reader`, checked as the module
/// documentation describes. `Ok(None)` is a clean end of stream between
/// messages.
///
/// # Errors
///
/// A [`FrameError`]; the caller closes the connection.
pub async fn read_message<R: AsyncRead + Unpin>(
    reader: &mut R,
    max_message_bytes: usize,
) -> Result<Option<Vec<u8>>, FrameError> {
    let mut header = Vec::with_capacity(6);
    let mut first = [0u8; 1];
    match reader.read(&mut first).await {
        Ok(0) => return Ok(None),
        Ok(_) => header.push(first[0]),
        Err(_) => return Err(FrameError::Io),
    }
    if first[0] != 0x30 {
        return Err(FrameError::NotAMessage);
    }
    let length_octet = read_byte(reader).await?;
    header.push(length_octet);
    let declared = if length_octet < 0x80 {
        usize::from(length_octet)
    } else {
        let count = usize::from(length_octet & 0x7f);
        // 0x80 is BER's indefinite form, which RFC 4511 §5.1 forbids; more than
        // four octets cannot be under any cap this module accepts.
        if count == 0 || count > 4 {
            return Err(FrameError::Malformed);
        }
        let mut value: usize = 0;
        for _ in 0..count {
            let octet = read_byte(reader).await?;
            header.push(octet);
            value = (value << 8) | usize::from(octet);
        }
        value
    };
    // The cap is on the whole message, header included — what `ldap3` would
    // have to buffer — and it is applied before a byte of content is reserved.
    if declared.saturating_add(header.len()) > max_message_bytes {
        return Err(FrameError::TooLarge);
    }

    let mut message = Vec::with_capacity(header.len() + declared.min(INITIAL_CONTENT_RESERVE));
    message.extend_from_slice(&header);
    let read = (&mut *reader)
        .take(declared as u64)
        .read_to_end(&mut message)
        .await
        .map_err(|_| FrameError::Io)?;
    if read != declared {
        return Err(FrameError::Truncated);
    }
    validate_message(&message)?;
    Ok(Some(message))
}

async fn read_byte<R: AsyncRead + Unpin>(reader: &mut R) -> Result<u8, FrameError> {
    let mut byte = [0u8; 1];
    match reader.read(&mut byte).await {
        Ok(0) => Err(FrameError::Truncated),
        Ok(_) => Ok(byte[0]),
        Err(_) => Err(FrameError::Io),
    }
}

/// One BER element inside a buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Element<'a> {
    /// The single tag octet (class, constructed bit, number).
    pub tag: u8,
    /// The content octets.
    pub content: &'a [u8],
}

impl Element<'_> {
    /// Whether the constructed bit is set.
    #[must_use]
    pub fn constructed(&self) -> bool {
        self.tag & 0x20 != 0
    }
}

/// Split one element off the front of `input`: the element and what follows.
///
/// # Errors
///
/// [`FrameError::Malformed`] for a multi-octet tag, an indefinite or
/// over-long length, or content that runs past the end of `input`.
pub fn split_element(input: &[u8]) -> Result<(Element<'_>, &[u8]), FrameError> {
    let (&tag, rest) = input.split_first().ok_or(FrameError::Malformed)?;
    if tag & 0x1f == 0x1f {
        return Err(FrameError::Malformed);
    }
    let (&length_octet, mut rest) = rest.split_first().ok_or(FrameError::Malformed)?;
    let length = if length_octet < 0x80 {
        usize::from(length_octet)
    } else {
        let count = usize::from(length_octet & 0x7f);
        if count == 0 || count > 4 || rest.len() < count {
            return Err(FrameError::Malformed);
        }
        let (octets, after) = rest.split_at(count);
        rest = after;
        octets
            .iter()
            .fold(0usize, |value, &octet| (value << 8) | usize::from(octet))
    };
    if rest.len() < length {
        return Err(FrameError::Malformed);
    }
    let (content, after) = rest.split_at(length);
    Ok((Element { tag, content }, after))
}

/// The elements a constructed element's content holds, in order.
///
/// # Errors
///
/// [`FrameError::Malformed`] when the content is not a whole number of
/// elements.
pub fn children(content: &[u8]) -> Result<Vec<Element<'_>>, FrameError> {
    let mut out = Vec::new();
    let mut rest = content;
    while !rest.is_empty() {
        let (element, after) = split_element(rest)?;
        out.push(element);
        rest = after;
    }
    Ok(out)
}

/// Check a whole message (header included) the way [`read_message`] does.
///
/// # Errors
///
/// A [`FrameError`] naming the first rule the message breaks.
pub fn validate_message(message: &[u8]) -> Result<(), FrameError> {
    let (outer, trailing) = split_element(message)?;
    if !trailing.is_empty() {
        return Err(FrameError::Malformed);
    }
    if outer.tag != 0x30 {
        return Err(FrameError::NotAMessage);
    }
    check_tree(outer.content)?;
    let parts = children(outer.content)?;
    match parts.as_slice() {
        [id, _operation, ..] if id.tag == 0x02 && (1..=4).contains(&id.content.len()) => Ok(()),
        _ => Err(FrameError::BadEnvelope),
    }
}

/// Walk every element under the outer `SEQUENCE` iteratively, refusing
/// malformed elements and nesting deeper than [`MAX_NESTING_DEPTH`]. No
/// recursion, so the walk itself cannot be driven into the stack it protects.
fn check_tree(content: &[u8]) -> Result<(), FrameError> {
    // Each entry is the unread remainder of one constructed element's content.
    let mut stack: Vec<&[u8]> = vec![content];
    while let Some(top) = stack.last_mut() {
        if top.is_empty() {
            stack.pop();
            continue;
        }
        let (element, after) = split_element(top)?;
        *top = after;
        if element.constructed() && !element.content.is_empty() {
            // The outer SEQUENCE is depth 1; its children start depth 2.
            if stack.len() + 1 >= MAX_NESTING_DEPTH {
                return Err(FrameError::TooDeep);
            }
            stack.push(element.content);
        }
    }
    Ok(())
}

/// The StartTLS extended request (RFC 4511 §4.14.1), message id 1:
/// `SEQUENCE { INTEGER 1, [APPLICATION 23] { [0] "1.3.6.1.4.1.1466.20037" } }`.
pub const STARTTLS_REQUEST: [u8; 31] = [
    0x30, 0x1d, // LDAPMessage, 29 octets
    0x02, 0x01, 0x01, // messageID 1
    0x77, 0x18, // ExtendedRequest, 24 octets
    0x80, 0x16, // requestName [0], 22 octets
    b'1', b'.', b'3', b'.', b'6', b'.', b'1', b'.', b'4', b'.', b'1', b'.', b'1', b'4', b'6', b'6',
    b'.', b'2', b'0', b'0', b'3', b'7',
];

/// Whether `message` (as [`read_message`] returned it) is a successful
/// response to [`STARTTLS_REQUEST`]: message id 1, an `ExtendedResponse`
/// whose `resultCode` is `success` (0).
#[must_use]
pub fn is_starttls_success(message: &[u8]) -> bool {
    let Ok((outer, _)) = split_element(message) else {
        return false;
    };
    let Ok(parts) = children(outer.content) else {
        return false;
    };
    let [id, response, ..] = parts.as_slice() else {
        return false;
    };
    if id.tag != 0x02 || id.content != [0x01] || response.tag != 0x78 {
        return false;
    }
    let Ok(fields) = children(response.content) else {
        return false;
    };
    matches!(fields.first(), Some(code) if code.tag == 0x0a && code.content == [0x00])
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A bind response: `SEQUENCE { INTEGER 2, [APPLICATION 1] { ENUM 0, "", "" } }`.
    fn bind_response() -> Vec<u8> {
        vec![
            0x30, 0x0c, 0x02, 0x01, 0x02, 0x61, 0x07, 0x0a, 0x01, 0x00, 0x04, 0x00, 0x04, 0x00,
        ]
    }

    async fn read(bytes: &[u8], cap: usize) -> Result<Option<Vec<u8>>, FrameError> {
        let mut reader = bytes;
        read_message(&mut reader, cap).await
    }

    #[tokio::test]
    async fn an_ordinary_message_passes_whole_and_the_stream_end_is_clean() {
        let message = bind_response();
        let mut stream = message.clone();
        stream.extend_from_slice(&message);
        let mut reader = stream.as_slice();
        assert_eq!(
            read_message(&mut reader, DEFAULT_MAX_MESSAGE_BYTES)
                .await
                .unwrap(),
            Some(message.clone())
        );
        assert_eq!(
            read_message(&mut reader, DEFAULT_MAX_MESSAGE_BYTES)
                .await
                .unwrap(),
            Some(message)
        );
        assert_eq!(
            read_message(&mut reader, DEFAULT_MAX_MESSAGE_BYTES)
                .await
                .unwrap(),
            None
        );
    }

    #[tokio::test]
    async fn a_declared_length_over_the_cap_is_refused_from_the_header_alone() {
        // 0x30 0x84 7f ff ff ff: "two gigabytes follow" — and nothing does.
        assert_eq!(
            read(
                &[0x30, 0x84, 0x7f, 0xff, 0xff, 0xff],
                DEFAULT_MAX_MESSAGE_BYTES
            )
            .await,
            Err(FrameError::TooLarge)
        );
        // Exactly at the cap is fine; one over is not (the header counts).
        let content = vec![0u8; 100];
        let mut at_cap = vec![0x30, 0x64];
        at_cap.extend_from_slice(&content);
        assert_eq!(read(&at_cap, 101).await, Err(FrameError::TooLarge));
    }

    #[tokio::test]
    async fn indefinite_and_over_long_lengths_and_foreign_tags_are_refused() {
        assert_eq!(
            read(&[0x30, 0x80, 0, 0], 1 << 20).await,
            Err(FrameError::Malformed)
        );
        assert_eq!(
            read(&[0x30, 0x85, 0, 0, 0, 0, 1], 1 << 20).await,
            Err(FrameError::Malformed)
        );
        assert_eq!(
            read(&[0x31, 0x00], 1 << 20).await,
            Err(FrameError::NotAMessage)
        );
        assert_eq!(read(&[0x30], 1 << 20).await, Err(FrameError::Truncated));
        assert_eq!(
            read(&[0x30, 0x05, 0x02], 1 << 20).await,
            Err(FrameError::Truncated)
        );
    }

    #[tokio::test]
    async fn envelopes_ldap3_would_panic_on_are_refused() {
        // An empty SEQUENCE, a message id alone, an operation without an id.
        for bytes in [
            vec![0x30, 0x00],
            vec![0x30, 0x03, 0x02, 0x01, 0x01],
            vec![0x30, 0x04, 0x61, 0x02, 0x0a, 0x00],
            vec![0x30, 0x04, 0x02, 0x00, 0x61, 0x00],
        ] {
            assert_eq!(
                read(&bytes, 1 << 20).await,
                Err(FrameError::BadEnvelope),
                "{bytes:02x?}"
            );
        }
    }

    #[test]
    fn nesting_is_bounded_without_recursion() {
        // SEQUENCE { INTEGER 1, [APP 1] { SEQUENCE { SEQUENCE { ... } } } }
        fn nested(levels: usize) -> Vec<u8> {
            // Built outermost-first in one pass: level `k` (counting from the
            // innermost, 1-based) wraps the 2-octet OCTET STRING plus `k - 1`
            // six-octet headers.
            let inner_len = |k: usize| u32::try_from(2 + 6 * (k - 1)).unwrap();
            let op_len = u32::try_from(2 + 6 * levels).unwrap();
            let mut message = vec![0x30, 0x84];
            message.extend_from_slice(&(3 + 6 + op_len).to_be_bytes());
            message.extend_from_slice(&[0x02, 0x01, 0x01, 0x61, 0x84]);
            message.extend_from_slice(&op_len.to_be_bytes());
            for k in (1..=levels).rev() {
                message.extend_from_slice(&[0x30, 0x84]);
                message.extend_from_slice(&inner_len(k).to_be_bytes());
            }
            message.extend_from_slice(&[0x04, 0x00]);
            message
        }
        assert_eq!(validate_message(&nested(4)), Ok(()));
        assert_eq!(validate_message(&nested(64)), Err(FrameError::TooDeep));
        // Far past any stack: refused, not overflowed.
        assert_eq!(validate_message(&nested(100_000)), Err(FrameError::TooDeep));
    }

    #[test]
    fn an_element_that_overruns_its_parent_is_malformed() {
        // The bind response with its inner length lying (0x07 -> 0x09).
        let mut lying = bind_response();
        lying[6] = 0x09;
        assert_eq!(validate_message(&lying), Err(FrameError::Malformed));
        // A multi-octet tag inside.
        let multi = vec![0x30, 0x06, 0x02, 0x01, 0x01, 0x7f, 0x81, 0x00];
        assert_eq!(validate_message(&multi), Err(FrameError::Malformed));
    }

    #[test]
    fn the_starttls_request_is_what_ldap3_proto_would_parse_and_success_is_recognised() {
        assert_eq!(validate_message(&STARTTLS_REQUEST), Ok(()));
        // ExtendedResponse { ENUM 0, "", "" } with message id 1.
        let ok = [
            0x30, 0x0c, 0x02, 0x01, 0x01, 0x78, 0x07, 0x0a, 0x01, 0x00, 0x04, 0x00, 0x04, 0x00,
        ];
        assert!(is_starttls_success(&ok));
        let mut unavailable = ok;
        unavailable[9] = 52;
        assert!(!is_starttls_success(&unavailable));
        let mut other_id = ok;
        other_id[4] = 0x02;
        assert!(!is_starttls_success(&other_id));
        assert!(!is_starttls_success(&bind_response()));
    }

    #[test]
    fn the_configured_cap_is_clamped_and_garbage_is_the_default() {
        assert_eq!(
            max_message_bytes_from(None),
            (DEFAULT_MAX_MESSAGE_BYTES, false)
        );
        assert_eq!(
            max_message_bytes_from(Some("  ")),
            (DEFAULT_MAX_MESSAGE_BYTES, false)
        );
        assert_eq!(max_message_bytes_from(Some("1048576")), (1_048_576, false));
        assert_eq!(
            max_message_bytes_from(Some("10")),
            (MIN_MAX_MESSAGE_BYTES, true)
        );
        assert_eq!(
            max_message_bytes_from(Some("999999999999")),
            (MAX_MAX_MESSAGE_BYTES, true)
        );
        assert_eq!(
            max_message_bytes_from(Some("2MiB")),
            (DEFAULT_MAX_MESSAGE_BYTES, true)
        );
    }
}
