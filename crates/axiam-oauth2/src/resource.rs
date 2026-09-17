//! RFC 8707 resource indicators (T21.3).
//!
//! One question, asked in five places: *may this client name this target
//! service, and what is the audience if it may?* The authorization endpoint,
//! the PAR endpoint, the device-authorization endpoint and the token endpoint
//! all ask it, and they must all get the same answer — a `resource` accepted
//! at `/oauth2/par` and refused at `/oauth2/authorize` would hand the user
//! agent a `request_uri` standing for a request that cannot complete, which is
//! the failure [`crate::redirect_uri`] was written to avoid on the URI side.
//!
//! # What a resource is
//!
//! RFC 8707 §2:
//!
//! > The parameter value is an absolute URI ... The `resource` URI MUST NOT
//! > include a fragment component. It SHOULD NOT include a query component,
//! > but it MUST be a valid URI.
//!
//! So: absolute (a scheme and, for the hierarchical schemes clients actually
//! use, an authority), no fragment. A query is permitted and kept, because the
//! RFC only discourages it and a deployment that has one has one.
//!
//! # Why comparison is normalised and never prefixed
//!
//! The registered list is an allow-list of audiences, and a token's `aud` is
//! what a resource server checks to decide the token is for *it*. A prefix
//! match would make `https://mcp.example.com` authorise
//! `https://mcp.example.com.attacker.test` — the audience equivalent of the
//! open redirect that exact `redirect_uri` matching exists to prevent (T-52) —
//! so there is no prefix rule here and there must never be one.
//!
//! What there is instead is RFC 3986 §6.2.2 **syntax-based normalisation**,
//! and only that: case normalisation of the scheme and host (§6.2.2.1), and
//! removal of a default port and of dot segments (§6.2.2.3, §6.2.3). Those are
//! transformations RFC 3986 declares produce an *equivalent* URI, so applying
//! them compares what two strings mean rather than how they were typed.
//!
//! Nothing scheme-based is done — no trailing-slash forgiveness on a non-empty
//! path, no case folding of the path, no `https://host` to `https://host/`
//! guess beyond the RFC's own empty-path rule. Those would widen an
//! allow-list on a deployment's behalf, and an allow-list widened by the
//! server is one the operator cannot audit from what they wrote down.
//!
//! # The one §6.2.2 rule that is deliberately not applied
//!
//! §6.2.2.2 says a percent-encoded **unreserved** character should be decoded,
//! so `/%6Dcp` and `/mcp` are the same path. The `url` crate does not do this
//! in the path component, and this module does not add it, for the reason
//! [`crate::redirect_uri`] gives about normalising comparisons: a hand-rolled
//! decoder in front of a security check is a place for a decoder bug to become
//! an authorisation bug, and this one would be re-deriving a rule the URL
//! parser already had an opinion about.
//!
//! Skipping it fails **closed**. `/%6Dcp` and `/mcp` stay two resources, so a
//! client asking for one when the other is registered is refused; no request
//! is admitted that would not have been. The cost is an operator who registers
//! a needlessly-encoded URI and finds their client refused — which the
//! read-back of the stored, normalised list makes visible at registration
//! time, because the stored string is the one that will be compared.

use url::Url;

/// The URI scheme AXIAM's own audiences live under (`axiam:user`,
/// `axiam:m2m`). Reserved against use as a resource indicator — see
/// [`ResourceError::ReservedAudience`].
const RESERVED_AUDIENCE_SCHEME: &str = "axiam";

/// Why a `resource` value is not usable (RFC 8707 §2).
///
/// A type rather than a `bool` because the four refusals are different
/// operator-facing problems and the registration API should be able to say
/// which one it found. On the wire they all become `invalid_target`, which is
/// the only code RFC 8707 defines for a target the server will not serve.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResourceError {
    /// Not a URI at all, or a relative reference.
    NotAnAbsoluteUri,
    /// RFC 8707 §2 forbids a fragment: it is a client-side construct that
    /// never reaches a server, so two resources differing only by fragment are
    /// one resource wearing two names — and an allow-list that cannot tell
    /// them apart is an allow-list with a second entry nobody registered.
    HasFragment,
    /// Empty or whitespace-only. Distinguished from
    /// [`Self::NotAnAbsoluteUri`] because "you sent `resource=`" and "you sent
    /// something that is not a URI" are different mistakes.
    Empty,
    /// The value is in AXIAM's own audience namespace (MCP-02).
    ///
    /// `axiam:user` and `axiam:m2m` are the two audiences AXIAM's own
    /// extractors accept, and — because a scheme followed by a path is all an
    /// absolute URI needs — they are also perfectly well-formed resource
    /// indicators. Nothing else here would have refused them: the parser
    /// deliberately admits any scheme, because `urn:` resources are legitimate
    /// and an MCP server reached over loopback `http` during development is a
    /// resource like any other.
    ///
    /// Admitting them collapses the boundary I3 is built out of. The sharpest
    /// case is `client_credentials`, which mints `axiam:m2m` when no resource
    /// is named: naming `axiam:user` as the resource makes the *same* grant
    /// mint a token stamped with the user audience, which is the one claim the
    /// user-facing extractors gate on. The whole `axiam` scheme is reserved
    /// rather than the two literals, so that an audience added later is
    /// covered without anybody having to remember this rule exists.
    ReservedAudience,
}

impl ResourceError {
    /// A message in the voice the token endpoint's other refusals use.
    pub const fn message(self) -> &'static str {
        match self {
            Self::NotAnAbsoluteUri => {
                "resource must be an absolute URI (RFC 8707 section 2), for example \
                 https://mcp.example.com/mcp"
            }
            Self::HasFragment => "resource must not contain a fragment (RFC 8707 section 2)",
            Self::Empty => "resource must not be empty",
            Self::ReservedAudience => {
                "the axiam scheme is reserved for AXIAM's own token audiences and cannot be \
                 named as a resource; a resource server is identified by the URL it serves"
            }
        }
    }
}

/// Normalise `raw` under RFC 3986 §6.2.2, or say why it is not a resource.
///
/// The returned string is the **canonical form** used for every comparison and
/// for the `aud` claim that is ultimately minted, so a client that registers
/// `https://MCP.example.com:443/mcp` and asks for `https://mcp.example.com/mcp`
/// gets a token whose audience is one string and not two.
///
/// # What `Url::parse` does, and what is checked on top of it
///
/// `url` implements the WHATWG URL Standard, whose serialisation performs
/// §6.2.2's normalisations for the hierarchical schemes with one exception:
/// the scheme and host are lowercased, a default port is dropped and dot
/// segments are removed, but a percent-encoded unreserved character in the
/// path is left as it was written (see the module documentation for why that
/// is left alone rather than added here). It also **refuses a relative
/// reference** outright, which is the absolute-URI half of RFC 8707 §2. What
/// it does not do is refuse a fragment — a fragment is perfectly legal in a
/// URL and simply illegal in a *resource indicator* — so that is checked here.
pub fn normalise(raw: &str) -> Result<String, ResourceError> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(ResourceError::Empty);
    }
    let parsed = Url::parse(trimmed).map_err(|_| ResourceError::NotAnAbsoluteUri)?;
    if parsed.fragment().is_some() {
        return Err(ResourceError::HasFragment);
    }
    // MCP-02. Checked after parsing rather than on the raw string, so that the
    // comparison is against the scheme `url` actually resolved (it lowercases
    // it, so `AXIAM:user` cannot slip past a byte comparison on the input).
    if parsed.scheme() == RESERVED_AUDIENCE_SCHEME {
        return Err(ResourceError::ReservedAudience);
    }
    Ok(parsed.as_str().to_owned())
}

/// Whether `presented` is one of the resources `allowed` names.
///
/// Both sides are normalised before comparison, and an entry of `allowed` that
/// does not normalise is skipped rather than compared as a string: a stored
/// value this function cannot make sense of must not authorise anything, and
/// silently falling back to string equality is how a malformed row becomes a
/// second matching rule nobody reviewed.
///
/// An empty `allowed` matches nothing, which is the correct reading of a
/// client that registered no resources — and is why every client that predates
/// T21.3 is refused the parameter rather than granted the whole world with it.
pub fn is_allowed(allowed: &[String], presented: &str) -> bool {
    let Ok(target) = normalise(presented) else {
        return false;
    };
    allowed
        .iter()
        .filter_map(|entry| normalise(entry).ok())
        .any(|entry| entry == target)
}

/// Validate a list destined for `OAuth2Client::allowed_resources`, returning
/// the normalised list to store.
///
/// Storing the normalised form rather than the operator's spelling means the
/// read-back through the admin API shows exactly what will be compared, and
/// means a duplicate that differs only in case or default port is visible as a
/// duplicate. The error names the offending entry, because an operator
/// registering six resources needs to know which one is wrong.
pub fn normalise_registration(entries: &[String]) -> Result<Vec<String>, (String, ResourceError)> {
    entries
        .iter()
        .map(|e| normalise(e).map_err(|err| (e.clone(), err)))
        .collect()
}

/// Resolve the `resource` a request carries against a client's allow-list.
///
/// The **registration** gate, used wherever a client first names a target: the
/// authorization endpoint, PAR, device authorization, and the
/// `client_credentials` grant.
///
/// - Absent → `Ok(None)`, which is today's behaviour and the whole of I2: the
///   caller mints `axiam:user` or `axiam:m2m` exactly as it did before this
///   parameter existed.
/// - Present and registered → `Ok(Some(normalised))`, the string that becomes
///   the token's `aud`.
/// - Present and anything else → `invalid_target`, the code RFC 8707 §2
///   defines for a target the server will not issue a token for.
///
/// A malformed value and an unregistered one are both `invalid_target`, with
/// different descriptions. RFC 8707 gives no separate code for "that is not a
/// URI", and inventing `invalid_request` for it would make the two
/// distinguishable to a caller probing which resources a client may address —
/// a registration-enumeration oracle for whoever holds a `client_id`, which on
/// a public client is everybody.
pub fn resolve_requested(
    client_allowed: &[String],
    presented: Option<&str>,
) -> Result<Option<String>, crate::error::OAuth2Error> {
    let Some(raw) = presented.map(str::trim).filter(|r| !r.is_empty()) else {
        return Ok(None);
    };
    let normalised = normalise(raw).map_err(|e| {
        crate::error::OAuth2Error::InvalidTarget(format!("{} (RFC 8707 section 2)", e.message()))
    })?;
    if !is_allowed(client_allowed, &normalised) {
        return Err(crate::error::OAuth2Error::InvalidTarget(
            "the requested resource is not one this client may address; register it in              allowed_resources first"
                .into(),
        ));
    }
    Ok(Some(normalised))
}

/// Resolve the `resource` a token request carries against the one the grant is
/// already bound to.
///
/// The **redemption** gate, used wherever a credential minted earlier is spent:
/// the `authorization_code`, `refresh_token` and `device_code` grants. Its rule
/// is one sentence — *a grant's audience is decided when the grant is made* —
/// and the three cases fall out of it:
///
/// - The request repeats the bound value, or omits it → the bound value.
/// - The request names a different value → `invalid_target`.
/// - The grant is bound to nothing and the request names something →
///   `invalid_target`.
///
/// The third case is the one worth spelling out, because it is the one that
/// looks harmless. A refresh token issued for `axiam:user` represents a
/// consent the end user gave to a client acting *as them at AXIAM*; letting a
/// refresh add `resource=https://mcp.example.com` would mint a token for a
/// service the end user was never asked about, fifteen minutes after they
/// stopped watching. **A token cannot be widened by refreshing it**, and it
/// cannot be widened by redeeming a code either — which is why this function
/// never consults the client's allow-list. The allow-list was consulted when
/// the grant was made; consulting it again here would let a registration
/// edited in the meantime change what an outstanding grant means.
///
/// Comparison is by normalised form, so a client that pushes
/// `https://mcp.example.com:443/mcp` and redeems with
/// `https://mcp.example.com/mcp` is repeating its value, not changing it.
pub fn resolve_bound(
    bound: Option<&str>,
    presented: Option<&str>,
) -> Result<Option<String>, crate::error::OAuth2Error> {
    let bound = bound.map(str::to_owned);
    let Some(raw) = presented.map(str::trim).filter(|r| !r.is_empty()) else {
        return Ok(bound);
    };
    let requested = normalise(raw).map_err(|e| {
        crate::error::OAuth2Error::InvalidTarget(format!("{} (RFC 8707 section 2)", e.message()))
    })?;
    match bound {
        Some(ref b) if normalise(b).ok().as_deref() == Some(requested.as_str()) => Ok(bound),
        Some(_) => Err(crate::error::OAuth2Error::InvalidTarget(
            "this grant is bound to a different resource; a token cannot be re-addressed when              it is redeemed or refreshed. Start a new authorization for the other resource"
                .into(),
        )),
        None => Err(crate::error::OAuth2Error::InvalidTarget(
            "this grant was not issued for any resource, and a token cannot acquire one when              it is redeemed or refreshed. Start a new authorization that names the resource"
                .into(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The RFC 3986 §6.2.2 transformations, each asserted to produce the same
    /// canonical string as the form an operator would have typed instead.
    #[test]
    fn syntax_based_normalisation_makes_equivalent_uris_one_string() {
        for (a, b) in [
            // Case normalisation of scheme and host (§6.2.2.1).
            ("HTTPS://MCP.Example.COM/mcp", "https://mcp.example.com/mcp"),
            // Default port removed (§6.2.3, and what every client omits).
            (
                "https://mcp.example.com:443/mcp",
                "https://mcp.example.com/mcp",
            ),
            (
                "http://mcp.example.com:80/mcp",
                "http://mcp.example.com/mcp",
            ),
            // Dot segments removed (§6.2.2.3).
            (
                "https://mcp.example.com/a/../mcp",
                "https://mcp.example.com/mcp",
            ),
        ] {
            assert_eq!(
                normalise(a).unwrap(),
                normalise(b).unwrap(),
                "{a} and {b} are the same resource under RFC 3986 section 6.2.2"
            );
        }
    }

    /// Where normalisation stops, asserted as the property rather than left
    /// implicit — because every entry here is a pair a *widening*
    /// implementation would have collapsed.
    ///
    /// The first three are equivalences RFC 3986 leaves to scheme-based
    /// normalisation, which this module does not perform. The last is
    /// §6.2.2.2's percent-encoding rule, which the `url` crate does not apply
    /// to the path and which this module deliberately does not add: see the
    /// module documentation. Leaving it out keeps two spellings distinct,
    /// which refuses a request rather than admitting one.
    #[test]
    fn normalisation_stops_where_this_module_stops() {
        for (a, b) in [
            ("https://mcp.example.com/MCP", "https://mcp.example.com/mcp"),
            (
                "https://mcp.example.com/mcp/",
                "https://mcp.example.com/mcp",
            ),
            (
                "https://mcp.example.com/mcp",
                "https://mcp.example.com/mcp2",
            ),
            (
                "https://mcp.example.com/%6Dcp",
                "https://mcp.example.com/mcp",
            ),
        ] {
            assert_ne!(
                normalise(a).unwrap(),
                normalise(b).unwrap(),
                "{a} and {b} must stay distinct resources"
            );
        }
    }

    #[test]
    fn a_fragment_is_refused_and_a_query_is_not() {
        assert_eq!(
            normalise("https://mcp.example.com/mcp#tools"),
            Err(ResourceError::HasFragment)
        );
        // RFC 8707 §2 only discourages a query; a deployment that has one has
        // one, and refusing it would be stricter than the specification.
        assert_eq!(
            normalise("https://mcp.example.com/mcp?v=2").unwrap(),
            "https://mcp.example.com/mcp?v=2"
        );
    }

    #[test]
    fn a_relative_reference_is_not_a_resource() {
        for raw in ["/mcp", "mcp.example.com/mcp", "//mcp.example.com/mcp"] {
            assert_eq!(
                normalise(raw),
                Err(ResourceError::NotAnAbsoluteUri),
                "{raw} is not an absolute URI"
            );
        }
        assert_eq!(normalise("   "), Err(ResourceError::Empty));
    }

    /// A non-`https` absolute URI is accepted. RFC 8707 says "absolute URI",
    /// not "https URL", and an MCP server reached over `http` on a loopback
    /// interface during development is a resource like any other. The
    /// *transport* rule belongs to the deployment, not to this parser.
    /// MCP-02 — the one scheme that is not a resource, whatever its syntax
    /// says. Both audiences and both spellings, because `url` lowercases a
    /// scheme and a check on the raw input would have missed the second.
    #[test]
    fn axiams_own_audiences_are_refused_as_resources() {
        for raw in [
            "axiam:user",
            "axiam:m2m",
            "AXIAM:user",
            "axiam:anything-later",
        ] {
            assert_eq!(
                normalise(raw),
                Err(ResourceError::ReservedAudience),
                "{raw} must not be usable as a resource indicator"
            );
        }
        // And the refusal is a refusal everywhere the allow-list is consulted,
        // including for a value somebody managed to store.
        assert!(
            !is_allowed(&["axiam:user".to_string()], "axiam:user"),
            "a stored reserved value must not authorise itself either"
        );
    }

    #[test]
    fn any_absolute_uri_scheme_is_a_resource() {
        for raw in [
            "http://127.0.0.1:8931/mcp",
            "urn:example:orders",
            "https://orders.internal/v1",
        ] {
            assert!(normalise(raw).is_ok(), "{raw} should parse as a resource");
        }
    }

    /// The whole point of the module, stated as the test that would fail if
    /// anybody replaced the comparison with `starts_with`.
    #[test]
    fn matching_is_never_by_prefix() {
        let allowed = vec!["https://mcp.example.com".to_string()];
        for presented in [
            "https://mcp.example.com.attacker.test",
            "https://mcp.example.com/../../elsewhere",
            "https://mcp.example.community",
        ] {
            assert!(
                !is_allowed(&allowed, presented),
                "{presented} must not be authorised by a registered prefix"
            );
        }
    }

    #[test]
    fn matching_is_by_equivalence_not_by_spelling() {
        let allowed = vec!["https://mcp.example.com/mcp".to_string()];
        assert!(is_allowed(&allowed, "HTTPS://MCP.EXAMPLE.COM:443/mcp"));
        assert!(is_allowed(&allowed, "https://mcp.example.com/./mcp"));
        assert!(!is_allowed(&allowed, "https://mcp.example.com/mcp/"));
    }

    /// A client that registered nothing may name nothing — the property that
    /// keeps every pre-T21.3 client on its pre-T21.3 behaviour (I2).
    #[test]
    fn an_empty_allow_list_authorises_nothing() {
        assert!(!is_allowed(&[], "https://mcp.example.com/mcp"));
    }

    /// A stored entry that cannot be parsed authorises nothing, rather than
    /// falling back to string equality against itself.
    #[test]
    fn an_unparseable_registered_entry_matches_nothing() {
        let allowed = vec!["not a uri".to_string()];
        assert!(!is_allowed(&allowed, "not a uri"));
    }

    #[test]
    fn registration_normalises_and_names_the_bad_entry() {
        assert_eq!(
            normalise_registration(&["HTTPS://MCP.Example.com:443/mcp".to_string()]).unwrap(),
            vec!["https://mcp.example.com/mcp".to_string()]
        );
        let (entry, err) =
            normalise_registration(&["https://ok.example.com".into(), "nope#frag".into()])
                .unwrap_err();
        assert_eq!(entry, "nope#frag");
        assert_eq!(err, ResourceError::NotAnAbsoluteUri);
    }

    fn code(e: &crate::error::OAuth2Error) -> &'static str {
        e.error_code()
    }

    #[test]
    fn an_absent_resource_is_todays_behaviour_on_both_gates() {
        assert_eq!(resolve_requested(&[], None).unwrap(), None);
        assert_eq!(resolve_requested(&[], Some("  ")).unwrap(), None);
        assert_eq!(resolve_bound(None, None).unwrap(), None);
        assert_eq!(
            resolve_bound(Some("https://mcp.example.com/mcp"), None).unwrap(),
            Some("https://mcp.example.com/mcp".to_string())
        );
    }

    #[test]
    fn a_registered_resource_resolves_to_its_normalised_form() {
        let allowed = vec!["https://mcp.example.com/mcp".to_string()];
        assert_eq!(
            resolve_requested(&allowed, Some("HTTPS://MCP.example.com:443/mcp")).unwrap(),
            Some("https://mcp.example.com/mcp".to_string())
        );
    }

    #[test]
    fn an_unregistered_or_malformed_resource_is_invalid_target() {
        let allowed = vec!["https://mcp.example.com/mcp".to_string()];
        for presented in [
            "https://other.example.com/mcp",
            "https://mcp.example.com/mcp#frag",
            "/mcp",
            "https://mcp.example.com",
        ] {
            let err = resolve_requested(&allowed, Some(presented)).unwrap_err();
            assert_eq!(code(&err), "invalid_target", "{presented}");
        }
    }

    /// The rule the refresh grant rests on, asserted in all three directions.
    #[test]
    fn a_grant_cannot_be_re_addressed_when_it_is_redeemed() {
        let bound = "https://mcp.example.com/mcp";
        // Repeating it, in any equivalent spelling, is allowed.
        assert_eq!(
            resolve_bound(Some(bound), Some("https://MCP.example.com:443/mcp")).unwrap(),
            Some(bound.to_string())
        );
        // Naming a different one is not.
        assert_eq!(
            code(&resolve_bound(Some(bound), Some("https://other.example.com/mcp")).unwrap_err()),
            "invalid_target"
        );
        // Neither is acquiring one the grant never had — the widening case.
        assert_eq!(
            code(&resolve_bound(None, Some(bound)).unwrap_err()),
            "invalid_target"
        );
    }
}
