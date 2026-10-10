# OAuth2 RFC Compliance Matrix

**Standards:** RFC 6749 (OAuth2), RFC 7636 (PKCE), RFC 7009 (Token Revocation),
RFC 7662 (Token Introspection), RFC 7592 (Dynamic Client Registration Management),
RFC 8417 / 8935 / 8936 (Security Event Tokens, push and poll delivery — the Shared
Signals Framework transmitter), OpenID Connect CIBA Core 1.0

**Test locations:**
- `crates/axiam-api-rest/tests/oauth2_flow_test.rs` — baseline 37-test suite
- `crates/axiam-api-rest/tests/oauth2_conformance.rs` — MUST-gap conformance tests (Phase 7)
- `crates/axiam-api-rest/tests/dynamic_registration_test.rs`, `crates/axiam-oauth2/src/dcr.rs` —
  RFC 7592 (Phase 23, T23.4.1)
- `crates/axiam-oauth2/src/ssf.rs`, `crates/axiam-oauth2/tests/ssf_delivery_test.rs`,
  `crates/axiam-api-rest/tests/ssf_test.rs` — SET issuance, push and poll (Phase 23, G-5)
- `crates/axiam-oauth2/src/ciba.rs`, `crates/axiam-oauth2/src/ciba_signed_request.rs`,
  `crates/axiam-oauth2/tests/ciba_ping_test.rs`, `crates/axiam-api-rest/tests/ciba_test.rs`,
  `ciba_approval_test.rs`, `ciba_ping_flow_test.rs` — CIBA (Phase 23, G-7)

---

## RFC 6749 — The OAuth 2.0 Authorization Framework

| # | MUST | RFC Ref | Status | Evidence |
|---|------|---------|--------|----------|
| 1 | Authorization code grant: successful code issuance | §4.1.2 | Pass | `oauth2_flow_test.rs::full_authorization_code_flow` |
| 2 | Authorization code grant: with PKCE S256 | §4.1 / RFC 7636 | Pass | `oauth2_flow_test.rs::full_authorization_code_flow_with_pkce` |
| 3 | Authorization code MUST be single-use | §4.1.2 | Pass | `oauth2_flow_test.rs::auth_code_is_single_use` |
| 4 | redirect_uri mismatch MUST be rejected (authorize) | §3.1.2.4 | Pass | `oauth2_flow_test.rs::invalid_redirect_uri_rejected_at_authorize` |
| 5 | redirect_uri mismatch MUST be rejected (token) | §4.1.3 | Pass | `oauth2_flow_test.rs::redirect_uri_mismatch_at_token_rejected` |
| 6 | Invalid client secret MUST return 401 invalid_client | §5.2 | Pass | `oauth2_flow_test.rs::invalid_client_secret_rejected` |
| 7 | 401 invalid_client MUST include WWW-Authenticate header | §5.2 | Pass | `oauth2_conformance.rs::invalid_client_returns_www_authenticate_header` (D-04 inline fix) |
| 8 | Unsupported response_type MUST produce error redirect | §4.1.2.1 | Pass | `oauth2_flow_test.rs::unsupported_response_type_rejected` |
| 9 | state parameter MUST be echoed in redirect | §4.1.2 | Pass | `oauth2_flow_test.rs::state_parameter_echoed_in_redirect` |
| 10 | Missing code MUST return invalid_request | §4.1.3 | Pass | `oauth2_flow_test.rs::missing_code_returns_error` |
| 11 | Unsupported grant_type MUST return error | §5.2 | Pass | `oauth2_flow_test.rs::unsupported_grant_type_returns_error` |
| 12 | token_type=Bearer MUST be present in token response | §7.1 | Pass | `oauth2_conformance.rs::token_response_includes_bearer_token_type` |
| 13 | Client credentials grant: success | §4.4 | Pass | `oauth2_flow_test.rs::client_credentials_grant` |
| 14 | Client credentials: wrong secret MUST return 401 | §5.2 | Pass | `oauth2_flow_test.rs::client_credentials_wrong_secret` |
| 15 | Client credentials: unauthorized grant type rejected | §4.4 | Pass | `oauth2_flow_test.rs::client_credentials_unauthorized_grant` |
| 16 | Refresh token grant: success + rotation | §6 | Pass | `oauth2_flow_test.rs::refresh_token_grant` |
| 17 | Old refresh token MUST be invalidated after rotation | §6 | Pass | `oauth2_flow_test.rs::refresh_token_rotation_retires_old_on_a_standard_client`. The predecessor is revoked at rotation and a second presentation is `invalid_grant`, "already consumed". A client registered `profile: fapi2` is the documented exception: FAPI 2.0 §5.3.2.1-9 requires the previous token to stay redeemable for a short period, so it is retired on a 60-second clock instead — and every token on that profile is sender-constrained (T-254). Either way the second presentation is audited as `oauth2.refresh_token_replayed`: `token_service.rs::t254_*` |
| 18 | Refresh token MUST be bound to issuing client | §6 | Pass | `oauth2_conformance.rs::refresh_token_bound_to_original_client` |
| 18a | A refresh token presented after rotation is detectable and recorded | §6, BCP §4.14.2 | Pass | Rotation stamps `rotated_at`, so a later presentation is a *replay* rather than an ordinary stale credential; it increments a per-outcome counter on the session and appends an `oauth2.refresh_token_replayed` audit row naming the client, the profile, the session and the disposition — never the token. `token_service.rs::t254_a_replay_on_a_standard_client_is_refused_and_marked`, `::t254_an_ordinary_stale_refresh_token_is_not_a_replay`, `oauth2_flow_test.rs::a_refused_refresh_replay_is_audited` |

## RFC 7636 — PKCE

| # | MUST | RFC Ref | Status | Evidence |
|---|------|---------|--------|----------|
| 19 | S256 code_challenge_method MUST be supported | §4.2 | Pass | `oauth2_flow_test.rs::full_authorization_code_flow_with_pkce` |
| 20 | plain code_challenge_method MUST be rejected (S256-only policy) | §4.2 | Pass | `oauth2_conformance.rs::pkce_plain_method_rejected` |
| 21 | code_verifier < 43 chars MUST be rejected | §4.1 | Pass | `oauth2_conformance.rs::pkce_verifier_too_short_rejected` |
| 22 | code_verifier > 128 chars MUST be rejected | §4.1 | Pass | `oauth2_conformance.rs::pkce_verifier_too_long_rejected` |
| 23 | Wrong code_verifier MUST return invalid_grant | §4.6 | Pass | `oauth2_flow_test.rs::pkce_verification_failure` |
| 24 | code_verifier MUST be required when challenge was registered | §4.6 | Pass | `oauth2_flow_test.rs::pkce_required_when_challenge_registered` |

## RFC 7009 — Token Revocation

| # | MUST | RFC Ref | Status | Evidence |
|---|------|---------|--------|----------|
| 25 | Revocation MUST invalidate the refresh token | §2 | Pass | `oauth2_flow_test.rs::revoke_refresh_token` |
| 26 | Revocation of unknown token MUST return 200 | §2.2 | Pass | `oauth2_flow_test.rs::revoke_unknown_token_returns_200` |

## RFC 7662 — Token Introspection

| # | MUST | RFC Ref | Status | Evidence |
|---|------|---------|--------|----------|
| 27 | Active token introspection MUST return active=true | §2.2 | Pass | `oauth2_flow_test.rs::introspect_active_access_token` |
| 28 | Unknown token MUST return active=false | §2.2 | Pass | `oauth2_flow_test.rs::introspect_unknown_token_returns_inactive` |
| 29 | Introspection MUST require client authentication | §2.1 | Pass | `oauth2_flow_test.rs::introspect_requires_client_auth` |
| 30 | Revoked token MUST be reported as inactive | §2.2 | Pass | `oauth2_flow_test.rs::introspect_revoked_refresh_token` |
| 30a | A token whose authorization has been withdrawn — its account locked, deactivated, anonymized, deleted or removed — is reported inactive, access and refresh tokens alike (#520) | §2.2 | Pass | `oauth2_flow_test.rs::p23w1_12_userinfo_and_introspection_answer_for_a_suspended_account`; `token_service.rs::p23w1_12_introspection_reports_a_suspended_accounts_tokens_inactive` |


## RFC 7592 — Dynamic Client Registration Management Protocol

The client configuration endpoint, `GET` / `PUT` / `DELETE /oauth2/register/{client_id}`
(contract §28.12; threat T-289). Only a client registered through `POST /oauth2/register`
holds a registration access token.

| # | MUST | RFC Ref | Status | Evidence |
|---|------|---------|--------|----------|
| 31 | The registration response carries `registration_client_uri` and `registration_access_token` | §3 | Pass | `dynamic_registration_test.rs::rfc7592_register_read_update_delete_round_trip` (both taken from the `201`); `dcr.rs::the_registration_client_uri_follows_the_issuer_the_request_used`, `::a_registration_access_token_is_32_random_bytes_base64url_and_stored_as_a_digest` |
| 32 | The registration access token is presented as an RFC 6750 bearer in the `Authorization` header. No token is `401` with the bare `Bearer` challenge; a token in the query string is refused `400 invalid_request`, even beside a good header | §2; RFC 6750 §2.1, §3.1 | Pass | `dynamic_registration_test.rs::rfc7592_only_this_clients_management_token_is_accepted`, `::p23w1_02_the_bearer_scheme_is_matched_case_insensitively` |
| 33 | A read returns the client's current registration — never the token and never a client secret | §2.1, §3 | Pass | `dynamic_registration_test.rs::rfc7592_register_read_update_delete_round_trip`; `dcr.rs::the_client_information_response_carries_each_secret_only_where_it_should` |
| 34 | An invalid token, or a client that does not exist, is `401` and does not reveal whether the client exists: another client's token, a user's access token, a client secret, HTTP Basic, another tenant's token, a client never issued a token and a deleted client are all `401 invalid_token`; `404` is never used | §2.1 | Pass | `dynamic_registration_test.rs::rfc7592_only_this_clients_management_token_is_accepted`, `::rfc7592_a_token_is_refused_under_another_tenant`, `::rfc7592_clients_without_a_management_token_are_refused`, `::rfc7592_register_read_update_delete_round_trip` (after the `DELETE`) |
| 35 | An update is a full replacement naming the client's own `client_id`; `registration_access_token`, `registration_client_uri`, `client_secret_expires_at` and `client_id_issued_at` in the body are refused `400 invalid_request` | §2.2 | Pass | `dcr.rs::an_update_naming_a_server_stated_member_is_refused` (all four), `::an_update_must_name_its_own_client_id`; `dynamic_registration_test.rs::rfc7592_an_update_cannot_widen_beyond_the_tenants_policy` (over HTTP: the token in the body, a foreign `client_id`) |
| 36 | Updated metadata is validated as a registration is, refused with the RFC 7591 error codes, and a refusal changes nothing (no rotation, no write) | §2.2; RFC 7591 §3.2.2 | Pass | `dynamic_registration_test.rs::rfc7592_an_update_cannot_widen_beyond_the_tenants_policy` (`invalid_client_metadata`, `invalid_redirect_uri`), `::rfc7592_an_update_cannot_change_what_a_registration_cannot_set`; `dcr.rs::an_update_cannot_widen_scopes_grants_hosts_or_the_auth_method` |
| 37 | A rotated registration access token is returned in the update response, and the one it replaces stops working for every operation; of racing updates on one token exactly one wins | §2.2 | Pass | `dynamic_registration_test.rs::rfc7592_an_update_rotates_the_token_and_the_old_one_dies`, `::rfc7592_racing_updates_on_one_token_have_one_winner` |
| 38 | A delete is `204` and invalidates the registration access token and the client: a second `DELETE` and a read are `401`, and the client's refresh tokens are revoked | §2.3 | Pass | `dynamic_registration_test.rs::rfc7592_register_read_update_delete_round_trip`, `::rfc7592_deletion_revokes_an_issued_refresh_token`. Access tokens already issued to the deleted client live out their remaining lifetime, as for any deleted client (T-289's stated residual) |

## RFC 8417 / 8935 / 8936 — Security Event Tokens, push and poll (SSF transmitter)

AXIAM is the **transmitter** (contract §32; threats T-385 … T-406). The rows track what
the transmitter owes. The receiver's obligations — above all de-duplicating `jti`, which
is what T-388 closed — are the receiver's: the §32.7 helper in the SDK repositories carries
them, and they are not rows here, because their tests are not in this repository.

| # | MUST | Spec Ref | Status | Evidence |
|---|------|----------|--------|----------|
| 39 | A SET carries `iss`, `iat`, `jti` and `events` (exactly one event), and `aud` is the stream's audience | RFC 8417 §2.2 | Pass | `ssf.rs::a_set_verifies_against_the_published_jwks_with_the_pinned_header_and_claims` |
| 40 | `jti` is unique per SET (128 bits from the OS CSPRNG); a retried push and a repeated poll carry the byte-identical SET, so one event is one `jti` | RFC 8417 §2.2 | Pass | `ssf.rs::every_jti_is_unique`, `::signing_the_same_pending_event_twice_gives_the_same_set`; `ssf_delivery_test.rs::a_retried_push_carries_the_identical_set`; `ssf_test.rs::a_poll_returns_held_events_as_signed_sets_and_an_unacknowledged_one_comes_back` |
| 41 | Explicit typing, `typ: secevent+jwt`, and a SET cannot be taken for an ID token or an access token: no `exp`, a receiver audience, refused by every verifier AXIAM runs | RFC 8417 §2.3, §4.5–§4.7; SSF §4.1.1 | Pass | `ssf.rs::a_set_verifies_against_the_published_jwks_with_the_pinned_header_and_claims`, `::a_set_is_never_accepted_as_an_axiam_access_token`, `::a_set_is_refused_by_every_verifier_axiam_runs` |
| 42 | The SET is signed under the deployment key published at the tenant's `jwks_uri`; `iss` is the tenant's issuer and the SET does not verify for another audience, issuer or tenant | SSF §4.1.6, §4.1.8 | Pass | `ssf.rs::a_set_does_not_verify_for_another_audience_or_issuer`, `::the_issuer_follows_the_tenant_issuer_mode`, `::with_tenant_issuers_a_set_of_one_tenant_does_not_verify_as_anothers` |
| 43 | No `sub` and no `exp` claim; the subject is the top-level `sub_id`, in an RFC 9493 format | SSF §3, §4.1.2, §4.1.7 | Pass | `ssf.rs::a_set_verifies_against_the_published_jwks_with_the_pinned_header_and_claims`, `::both_subject_formats_are_rfc_9493_and_the_session_is_named`; `ssf_delivery_test.rs::a_push_is_a_signed_set_with_the_stored_credential` |
| 44 | Transmitter metadata is published at `/.well-known/ssf-configuration`, in both issuer forms; a tenant with nothing to publish answers one indistinguishable `404` | SSF §7.1, §7.2 | Pass | `ssf_test.rs::discovery_on_the_root_issuer_lists_the_endpoints_and_events`, `::discovery_on_a_tenant_path_issuer_names_the_tenant_issuer`, `::discovery_answers_one_empty_404_for_every_way_of_having_nothing_to_say`; `ssf.rs::discovery_lists_the_endpoints_methods_and_events_for_both_issuer_modes` |
| 45 | Push is an HTTP `POST` of the compact SET with `Content-Type: application/secevent+jwt`, carrying the stored `Authorization` header when there is one | RFC 8935 §2 | Pass | `ssf_delivery_test.rs::a_push_is_a_signed_set_with_the_stored_credential`, `::no_authorization_header_is_sent_when_none_is_stored` |
| 46 | A `2xx` (RFC 8935: `202`) is delivery; a `400` carrying an RFC 8935 `err` code is a refusal that is not retried, its code — and never the receiver's description — audited | RFC 8935 §2, §2.4 | Pass | `ssf_delivery_test.rs::every_2xx_is_delivered`, `::a_400_with_an_rfc_8935_error_is_dead_lettered_with_the_code`, `::a_400_without_a_known_code_is_dead_lettered_with_its_status` |
| 47 | Push travels over TLS only, to an `https` endpoint that is globally routable at the moment of delivery; a redirect is never followed | contract §32.6 (AXIAM's rule) | Pass | `ssf.rs::the_push_endpoint_policy_is_the_webhook_one`; `ssf_delivery_test.rs::the_address_guard_refuses_an_internal_endpoint_at_delivery`, `::a_3xx_is_retried_and_never_followed`, `::a_redirect_is_not_followed` |
| 48 | A poll request carries `maxEvents`, `returnImmediately`, `ack` and `setErrs`, each optional; the answer is `sets`, keyed by `jti`, and `moreAvailable` | RFC 8936 §2.2, §2.3 | Pass | `ssf_test.rs::a_poll_returns_held_events_as_signed_sets_and_an_unacknowledged_one_comes_back`, `::max_events_is_clamped_and_the_oldest_come_first`, `::the_poll_body_is_optional_and_bounded` |
| 49 | A SET not yet acknowledged is returned again; an acknowledged one is not, and `ack` removes exactly the named SETs of that stream | RFC 8936 §2.2 | Pass | `ssf_test.rs::a_poll_returns_held_events_as_signed_sets_and_an_unacknowledged_one_comes_back`, `::an_acknowledgement_drains_exactly_the_named_rows_of_that_stream`, `::a_poll_receiver_drains_the_buffer_by_acknowledging` |
| 50 | A `setErrs` entry is accepted: the SET is not offered again and the error code is audited | RFC 8936 §2.4 | Pass | `ssf_test.rs::a_set_error_deletes_the_row_and_writes_an_audit_row_with_the_code` |
| 51 | Without `returnImmediately` the request long-polls: it is answered when an event arrives or at a bound (30 seconds) | RFC 8936 §2.2 | Pass | `ssf_test.rs::an_empty_poll_returns_at_once_or_waits_for_an_event`, `::a_second_long_poll_on_a_stream_answers_at_once_while_one_is_waiting` |
| 52 | The poll endpoint and the stream API serve only the stream's receiver: a client-credentials token carrying `ssf.manage`, issued to the client the stream is bound to | contract §32.6 (AXIAM's rule) | Pass | `ssf_test.rs::the_poll_endpoint_is_the_receivers_alone`, `::the_receiver_api_needs_a_client_token_with_the_scope`, `::another_receivers_or_another_tenants_stream_is_not_found` |

## OpenID Connect CIBA Core 1.0 — Client-Initiated Backchannel Authentication

Poll and ping modes; push and `user_code` are not offered (D-64, D-65). Contract §33;
threats T-421 … T-447. The `fapi2` client's FAPI-CIBA rules are recorded in
[`../admin/fapi2-profile.md`](../admin/fapi2-profile.md) and T-434, not as rows here.

| # | MUST | Spec Ref | Status | Evidence |
|---|------|----------|--------|----------|
| 53 | Discovery publishes `backchannel_authentication_endpoint`, `backchannel_token_delivery_modes_supported` (`poll`, `ping`), `backchannel_user_code_parameter_supported` (`false`), the request-signing algorithms and the CIBA grant type, in both issuer forms | CIBA Core §4 | Pass | `ciba_test.rs::discovery_lists_exactly_what_is_implemented_in_both_issuer_forms` |
| 54 | A client registers its token delivery mode; ping needs a client notification endpoint (AXIAM: a public `https` one); an unknown or missing mode, and push, are refused | CIBA Core §4 | Pass | `ciba.rs::push_and_unknown_modes_and_missing_modes_are_refused`, `::a_poll_registration_resolves_to_poll`, `::a_ping_registration_needs_a_public_https_endpoint`; `ciba_test.rs::admin_registration_accepts_and_validates_the_ciba_metadata` |
| 55 | The client authenticates at the backchannel authentication endpoint as at the token endpoint: a wrong credential is `401 invalid_client`, a client without the grant `unauthorized_client`, and a public client never holds the grant | CIBA Core §7.1, §13 | Pass | `ciba_test.rs::bc_authorize_refuses_each_malformed_request_with_its_section_13_code`, `::a_row_edited_to_public_or_fapi2_is_refused_at_bc_authorize`; `ciba.rs::stray_metadata_public_clients_and_unimplemented_members_are_refused` |
| 56 | `scope` includes `openid` (otherwise `invalid_request`); a scope the client is not registered for is `invalid_scope` | CIBA Core §7.1, §13 | Pass | `ciba.rs::scope_must_carry_openid_and_stay_registered`; `ciba_test.rs::bc_authorize_refuses_each_malformed_request_with_its_section_13_code` |
| 57 | Exactly one hint — `login_hint_token`, `id_token_hint` or `login_hint` — or `invalid_request`. AXIAM refuses `login_hint_token` as unsupported, and accepts an `id_token_hint` only when this server issued it to this client | CIBA Core §7.1 | Pass | `ciba.rs::exactly_one_hint_is_required`; `ciba_test.rs::bc_authorize_refuses_each_malformed_request_with_its_section_13_code`, `::an_id_token_hint_must_be_one_this_server_issued_to_this_client` |
| 58 | A `binding_message` the server will not display (empty, too long, multi-line, or carrying a direction override) is `invalid_binding_message` | CIBA Core §7.1, §13 | Pass | `ciba.rs::binding_messages_are_bounded_and_printable`; `ciba_test.rs::bc_authorize_refuses_each_malformed_request_with_its_section_13_code` |
| 59 | In ping mode the request carries a `client_notification_token` | CIBA Core §7.1 | **Partial** | Enforced in `CibaService::initiate` (`crates/axiam-oauth2/src/ciba.rs`: "client_notification_token is required in ping mode"), but no test sends a ping-mode request without one. `ciba_test.rs::a_fapi2_ping_client_needs_a_notification_token_of_128_bits` pins only the `fapi2` length floor |
| 60 | A signed authentication request is verified under the algorithm and keys the client registered; `aud`, `iss`, `exp`, `iat`, `nbf` and `jti` are required; parameters outside the JWT are refused; every failure is `invalid_request` and stores nothing | CIBA Core §7.1.1 | Pass | `ciba_signed_request.rs::every_claim_section_7_1_1_requires_is_required`, `::a_signature_by_an_unregistered_key_is_refused`, `::only_the_registered_algorithm_is_accepted`, `::iss_and_a_client_id_claim_must_be_this_client`, `::both_issuer_forms_are_an_audience_as_a_string_or_in_an_array`; `ciba.rs::unsupported_parameters_are_refused_before_anything_else`; `ciba_test.rs::signed_request_refusals_are_invalid_request_and_store_nothing`, `::a_signed_request_is_verified_and_its_claims_are_the_request` |
| 61 | A successful request is answered with `auth_req_id`, `expires_in` and `interval`; the `auth_req_id` carries at least 128 bits of entropy (AXIAM: 256) and only its digest is stored | CIBA Core §7.3 | Pass | `ciba_test.rs::bc_authorize_validates_stores_and_notifies`; `ciba.rs::auth_req_ids_are_high_entropy_and_hashed` |
| 62 | The token request uses `grant_type=urn:openid:params:grant-type:ciba` with the `auth_req_id` and client authentication; an undecided request is `authorization_pending`, and polling faster than `interval` is `slow_down` and lengthens it | CIBA Core §10.1, §11 | Pass | `ciba_test.rs::pending_then_slow_down_then_tokens_with_the_approvals_evidence`; `ciba.rs::polling_inside_the_interval_slows_down_and_the_interval_grows_to_a_cap` |
| 63 | A denied request is `access_denied`, an expired one `expired_token`; an `auth_req_id` of another client or tenant, or one already redeemed, is `invalid_grant`, and of concurrent redemptions exactly one succeeds | CIBA Core §11 | Pass | `ciba_test.rs::denied_is_access_denied_and_expired_is_expired_token`, `::another_clients_or_tenants_auth_req_id_is_invalid_grant`, `::pending_then_slow_down_then_tokens_with_the_approvals_evidence` (the second redemption), `::concurrent_redemptions_yield_exactly_one_token_set` |
| 64 | A successful token response carries an ID token, with `token_type` `Bearer`; the ID token's `sub`, `aud`, `acr`, `amr` and `auth_time` are the approval's | CIBA Core §10.1.1 | Pass | `ciba_test.rs::pending_then_slow_down_then_tokens_with_the_approvals_evidence`; `ciba_approval_test.rs::the_signed_in_user_approves_and_the_clients_poll_gets_tokens` |
| 65 | Ping: a `POST` to the client notification endpoint with `Authorization: Bearer <client_notification_token>` and the JSON body `{"auth_req_id": …}` and nothing else; the client then redeems at the token endpoint | CIBA Core §10.2 | Pass | `ciba_ping_test.rs::the_ping_after_an_approval_carries_the_bearer_token_and_the_auth_req_id`, `::the_ping_after_a_denial_is_the_same_ping`; `ciba_ping_flow_test.rs::an_approval_pings_the_client_which_then_redeems_once`, `::a_refusal_sends_the_same_ping_and_the_client_is_told_access_denied` |

**`unknown_user_id` is never sent — a deliberate deviation, not a row.** CIBA Core §13 lists
the code for a hint the server cannot resolve. AXIAM answers an unknown, locked or ineligible
user exactly like a real one — a stored request that nobody is notified of and nothing can
approve, which polls `authorization_pending` until `expired_token` — because answering
`unknown_user_id` would let any CIBA client enumerate the tenant's users (D-63, T-422;
`ciba_test.rs::bc_authorize_is_not_a_user_oracle`). A client written to expect the code
never sees it.

---

## Inline Fixes Applied (D-04)

| Finding | RFC Ref | Fix | Commit |
|---------|---------|-----|--------|
| WWW-Authenticate header absent on 401 responses | RFC 6749 §5.2 | Added `WWW-Authenticate: Bearer realm="axiam"` in `build_oauth2_error_response` | Phase 7 Plan 02 |

---

*Generated: Phase 7, Plan 02 — 2026-06-07*
*Rows 31–65 added: Phase 23 close-out (RFC 7592, the SSF transmitter, CIBA) — 2026-10-09*
