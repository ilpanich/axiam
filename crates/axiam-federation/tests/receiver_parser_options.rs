//! The libxml options AXIAM parses every received SAML document with
//! (`receiver_parser_options`): they never load an external DTD subset, and
//! they read UTF-8 whatever the document declares without naming an encoding.
//!
//! libxml-rs 0.3's `no_def_dtd` is `XML_PARSE_DTDLOAD` for the XML parser, and
//! the receiver once set it. This is its own test binary on purpose: xmlsec,
//! once initialised (the first signature verified in a process), installs a
//! process-wide external-entity loader that refuses every input but the
//! document itself, which would hide a load the options ask for. Nothing here
//! touches xmlsec, so libxml's own loader is the one in place and the control
//! parse shows a load the options ask for really happens.
#![cfg(feature = "saml")]

use axiam_federation::saml_idp::request::{
    RequestError, receiver_parser_options, refuse_markup_declarations,
};
use libxml::parser::{Parser, ParserOptions};

#[test]
fn the_receiver_options_never_load_an_external_dtd() {
    let options = receiver_parser_options();
    assert!(!options.no_def_dtd, "no_def_dtd is XML_PARSE_DTDLOAD");
    assert!(!options.recover && options.no_net && options.ignore_enc);
    // libxml-rs 0.3.3 frees the encoding name before libxml2 reads it
    // (use-after-free); UTF-8 comes from `ignore_enc` instead — see below.
    assert_eq!(options.encoding, None);

    // A local, deliberately malformed DTD: reading it makes the document not
    // well-formed, so a successful parse proves it was never read.
    let dir = std::env::temp_dir().join(format!("axiam-dtdload-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&dir).expect("temp dir");
    let dtd = dir.join("external.dtd");
    std::fs::write(
        &dtd,
        "<!ELEMENT r (#PCDATA)> <!ENTITY broken \"unterminated>\n<!",
    )
    .expect("write dtd");
    let document = format!(
        r#"<?xml version="1.0"?><!DOCTYPE r SYSTEM "file://{}"><r>x</r>"#,
        dtd.display()
    );

    // Straight to the parser, past the byte-level refusal every receiver
    // applies first.
    let receiver =
        Parser::default().parse_string_with_options(document.as_bytes(), receiver_parser_options());
    let control = Parser::default().parse_string_with_options(
        document.as_bytes(),
        ParserOptions {
            no_def_dtd: true,
            ..receiver_parser_options()
        },
    );
    let _ = std::fs::remove_dir_all(&dir);

    let receiver = receiver.expect("the receiver options must not read the external subset");
    assert_eq!(
        receiver.get_root_element().map(|r| r.get_content()),
        Some("x".to_owned())
    );
    assert!(
        control.is_err(),
        "control: with XML_PARSE_DTDLOAD the malformed external subset is read and refused"
    );
    // On the path every receiver takes, the declaration is refused first.
    assert_eq!(
        refuse_markup_declarations(&document),
        Err(RequestError::Dtd)
    );
}

/// UTF-8 whatever the document declares, without naming an encoding: with
/// `ignore_enc` libxml skips the declaration and reads the text as UTF-8, so
/// `é` (two UTF-8 bytes) under a Latin-1 declaration is still `é`. The control
/// honours the declaration and reads the two bytes as two Latin-1 characters.
/// (Every receiver refuses such a declaration on the bytes first; this parses
/// straight through libxml.)
#[test]
fn the_receiver_options_read_utf8_whatever_the_declaration_says() {
    let document = r#"<?xml version="1.0" encoding="ISO-8859-1"?><r>é</r>"#;
    let content = |options: ParserOptions| {
        Parser::default()
            .parse_string_with_options(document.as_bytes(), options)
            .expect("parses")
            .get_root_element()
            .map(|r| r.get_content())
    };
    assert_eq!(content(receiver_parser_options()), Some("é".to_owned()));
    assert_eq!(
        content(ParserOptions {
            ignore_enc: false,
            ..receiver_parser_options()
        }),
        Some("Ã©".to_owned()),
        "control: the declaration honoured"
    );
}
