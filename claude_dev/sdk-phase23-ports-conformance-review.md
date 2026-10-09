# CONTRACT 1.53 – 1.58 ports — cross-SDK conformance review (contract 1.59)

**Date:** 2026-10-09
**Scope:** the eleven Phase 23 ports — §28.12 (RFC 7592, contract 1.53), §30 (directory, 1.54),
§29 (SAML service providers, 1.55), §32 and the §32.7 receiver helper (SSF, 1.56), §31
(outbound SCIM targets, 1.57), §33 and the §33.2 signed form (CIBA, 1.58), and the §21.3.1
vector A amendment (seven `mtls_endpoint_aliases` keys) — read from each SDK repository at
its `claude/contract-1.58-sync` merge of 2026-10-09. This is the review that §28.10's rule and
§29.10 … §33.10 name: the posture tables are filled by reading the merged ports, never from
the ports' reports of themselves.

**Outcome:** the contract is amended to **1.59**, clarifications with no wire change, written as
twelve rules P1 … P12 in `CONTRACT.md` §34.2. Forty-two divergences are recorded in §34.3. Every
row is either **contract fixed** in 1.59, **forced by the language, recorded**, or an **SDK fix**
named as one of eleven follow-ups, **F-59-01 … F-59-11**, one per repository and each tracked by
an issue — the shape §28.11 (contract 1.49) used for its F-28 follow-ups. No row is open
without a named follow-up. T-388 is not affected: every helper refuses a replay; the defect
the review found on every `poll` (§34.3 R-1) is the opposite failure, a refusal of an event that
was never delivered.

## 1. Method

One reviewer per repository answered the same checklist: for each section, whether the
operations are present under the §NN.6 names, whether every §NN.5 member is `Sensitive<T>` on
every sink, whether each §NN.8 required test exists and asserts what the contract says, the
call-site documentation, the retry guarantee, and the README conformance statement; then ten
cross-SDK questions (Q1 replay store, Q2 `verify_set` order, Q3 `poll`, Q4 `ciba_await`, Q5
`ciba_handle_ping`, Q6 the signed form, Q7 kept-secret-on-update, Q8 the §21.3.1 pin, Q9
§28.12, Q10 anything else). Every cell carries a `path:line` on the commit below. Where a README
and the code disagreed, the code won.

Test suites were run where the sandbox had the toolchain, and small probes were run to confirm
the main defects at run time. Where a suite could not be built, the review is by reading only,
and the report says so.

| Repo | Commit read | Port merged | Suite run |
|---|---|---|---|
| `axiam-rust-sdk` | `53aa9ff` | [#123](https://github.com/ilpanich/axiam-rust-sdk/pull/123) | yes — 83/83 in the Phase 23 test files |
| `axiam-typescript-sdk` | `ab1c5ee` | [#131](https://github.com/ilpanich/axiam-typescript-sdk/pull/131) | yes — 113/113 (needs `NO_PROXY='*'` in this sandbox) |
| `axiam-python-sdk` | `db9fbd6` | [#93](https://github.com/ilpanich/axiam-python-sdk/pull/93) | yes — 1 922 passed |
| `axiam-java-sdk` | `2b34d08` | [#108](https://github.com/ilpanich/axiam-java-sdk/pull/108) | yes — 1 393 tests, 0 failures |
| `axiam-csharp-sdk` | `3b33515` | [#101](https://github.com/ilpanich/axiam-csharp-sdk/pull/101) | no — no `dotnet` in the sandbox |
| `axiam-php-sdk` | `cec1594` | [#78](https://github.com/ilpanich/axiam-php-sdk/pull/78) | no — `composer install` blocked; one dependency-free probe |
| `axiam-go-sdk` | `ea9eb07` | [#93](https://github.com/ilpanich/axiam-go-sdk/pull/93) | yes — `go test` root, `middleware`, `webhook` |
| `axiam-kotlin-sdk` | `611554d` | [#72](https://github.com/ilpanich/axiam-kotlin-sdk/pull/72) | no — Maven Central answered `429` |
| `axiam-swift-sdk` | `e92364c` | [#70](https://github.com/ilpanich/axiam-swift-sdk/pull/70) | no — no Swift toolchain |
| `axiam-c-sdk` | `265f5b4` | [#69](https://github.com/ilpanich/axiam-c-sdk/pull/69) | yes — 72/72 |
| `axiam-cplusplus-sdk` | `3b949ab` | [#71](https://github.com/ilpanich/axiam-cplusplus-sdk/pull/71) | yes — 1 488 test cases, 0 failed |

Every repository vendors `CONTRACT.md` and `openapi.json` byte-identical to this repository's
`sdks/` at 1.58.

## 2. What the suites did not catch

Every suite that ran was green, and every repository carries the §NN.8 tests by name. The
defects in §34.3 sit where a required test asserts less than the rule it discharges:

- §32.8 helper test 8 polls one SET, so no suite sees a batch aborted after its first SET was
  recorded (R-1, all eleven).
- §33.8 test 8 does not say the `500` carries a body; five suites use a bodiless `500`, which
  hides the server's real `500 {"error":"server_error"}` (R-11). Contract 1.59 now says it.
- The no-retry tests of §29.8 / §30.8 / §31.8 / §32.8 use a `503`; an HTTP library's
  transparent re-send after a dropped connection is invisible to them (R-16).
- The redaction tests use a `400`; TypeScript's leak is on `5xx` and transport errors (R-17).

## 3. Per-SDK reports

The eleven reports follow verbatim. Each has the posture table, the answers to A – F per
section, Q1 … Q10, and its findings table; the ids in the findings tables (`F-1`, `F-P2`,
`CS-01`, `SW-2`, …) are the ones §34.3's rows cite.

---

### Report — rust — commit 53aa9ff (merge #123)
Toolchain run: yes — `cargo test --no-default-features --features rest --test ciba_test --test ssf_receiver_test --test ssf_management_test --test scim_targets_test --test directory_test --test saml_test --test client_registration_test --test mtls_endpoint_aliases_test` on a `git archive HEAD` copy (the repo has no `Cargo.lock`; building in place would have written one). Result: 83 passed, 0 failed (ciba 16, client_registration 8, directory 8, mtls_endpoint_aliases 19, saml 8, scim_targets 7, ssf_management 7, ssf_receiver 10). Vendored `CONTRACT.md` is byte-identical to this repository's `sdks/CONTRACT.md`.

All paths below are relative to the `axiam-rust-sdk` repository root.

#### Posture per section
| Section | Status | Notes |
|---|---|---|
| §28.12 | implemented | three methods on `AxiamClient`; session-free transport; writes unretried |
| §29 | implemented | generated `saml()` namespace, call-site notes, local exactly-one check |
| §30 | implemented | `bind_secret` `Sensitive`, `Option<Option<_>>` explicit null on `update` |
| §31 | implemented | `credential` `Sensitive`, omitted when `None` |
| §32 | implemented | `authorization_header` `Sensitive`, `From<&SsfStream>` RMW form |
| §32.7 | implemented | `SsfReceiver::{verify_set, poll}`; one data-loss defect on poll (F-1) |
| §33 | implemented | four operations; `ciba_await` over-classifies transient errors (F-2); mTLS alias preference untested (F-3) |
| §33.2 signed | implemented | `CibaRequestSigner` PS256/ES256/EdDSA, caller's key + alg, no default |

#### A–F per section

### §28.12
A. `read_client_registration` → `src/oidc/registration.rs:263`; `update_client_registration` → `:334`; `delete_client_registration` → `:365`; type `ClientRegistration` → `:60`. All present, names match §28.12.5.
B. `ClientRegistration.client_secret: Option<Sensitive<String>>` (`:90`), `.registration_access_token: Option<Sensitive<String>>` (`:94`); argument of all three ops is `&Sensitive<String>` (`:266`, `:337`, `:368`). Type derives only `Debug, Clone, Default` (`:59`) — no `Serialize`/`Display`, so no serializer reaches the values. Nothing else wrapped. Errors: transport errors format the reqwest error (URL only, token is header-only); rule-1 refusal names no URI part (`:206-225`).
C. Tests `tests/client_registration_test.rs`: (1) `a_uri_at_another_origin_is_refused_locally_and_nothing_is_sent` `:158` (other host = `localhost` vs `127.0.0.1`, other port, `http` vs `https` base; all three ops; zero requests). (2) `read_and_delete_send_the_bearer_only_and_keep_the_query_verbatim` `:208` (bearer, no cookie, not the session access token, empty body, query == `tenant_id=…`). (3) `update_drops_the_five_server_stated_members_and_returns_the_rotated_token` `:263` + `an_update_answered_503_is_not_retried` `:327` (+ delete 503 once, read retried `:345`). (4) `a_401_invalid_token_is_an_oauth_protocol_error_and_refreshes_nothing` `:369` (counts `/api/v1/auth/refresh` = 0), `a_400_invalid_client_metadata_is_an_oauth_protocol_error` `:391`; 204 on delete in test 2. (5) `neither_the_token_nor_the_secret_reaches_any_rendering` `:428` (Debug, pretty Debug, error Display+Debug, 8-char window). "Serializing-for-logs" discharged structurally (no `Serialize`).
D. Update doc `:316-333`: "`metadata` is the **whole** registration: a member it omits is a member the server deletes. Start from `read_client_registration`'s result…"; "**Persist the returned `registration_access_token` before doing anything else.**" Delete `:363`: "**Never retried**".
E. Read goes through `RetryRunner` (`:274-311`); update `:346-357` and delete `:376-384` are a single `.send()` with no runner. No `management_raw`, so no §9 path.
F. README `README.md:59-61` "conforms to **contract 1.58** … §28, §28.12, §29, §30, §31, §32 and §33, with §32.7 and §33.2 signed"; table `:81-92`. Matches code.

### §29
A. `src/management/ops/saml.rs`: `get_idp` `:66`, `list_service_providers` `:81` (+ `list_service_providers_all` `:110`), `create_service_provider` `:126`, `get_service_provider` `:146`, `update_service_provider` `:180`, `delete_service_provider` `:206`, `parse_sp_metadata` `:229`, `list_idp_credentials` `:248` (returns `Vec`, not `Page`), `issue_idp_credential` `:270`, `promote_idp_credential` `:295`, `retire_idp_credential` `:323`. Accessor `client.saml()`. All eleven present.
B. Nothing wrapped (correct per §29.5). `SamlIdpCredential` (`src/management/models.rs:4114`) declares no key member; serde's default ignore drops `private_key_pem`.
C. `tests/saml_test.rs`: (1) `update_service_provider_puts_the_whole_registration` `:103` — asserts 11 of the 15 members present (the 4 nullable ones are `None` → omitted; see F-12). (2) `sign_assertions_does_not_exist_and_unknown_values_decode` `:150`. (3) `parse_sp_metadata_sends_exactly_one_member_and_the_draft_creates` `:198` (both/neither → local ValidationError, no request). (4) `a_credential_has_no_key_member_and_promotion_may_retire_nothing` `:278` (Debug, pretty, `serde_json::to_string`). (5) `service_providers_page_with_search_and_credentials_are_a_plain_list` `:331`. (6) `none_of_the_seven_writes_is_retried_on_503` `:395` (retry-enabled client). (7) `statuses_map_per_section_2` `:441`. (8) `get_idp_is_never_cached_and_keeps_null_apart_from_absent` `:506`.
D. `update_service_provider` `saml.rs:162-179` repeats the default-on-omit warning and `entity_id` immutability; ECDSA "verifies HTTP-POST requests only — HTTP-Redirect is RSA-only" at `:113-115` and `:176-177`; retire `:308-315` "**Retiring the `active` credential with no successor stops SAML sign-on for the whole tenant at once**"; delete `:200-203` ends no session. RMW form: `impl From<&SamlServiceProvider> for SamlServiceProviderInput` `src/management/checks.rs:54`.
E. `src/management/request.rs:57` `is_read_only` = `Get` only; writes take `management_attempt(…, 0)` once (`:166-170`). Only §9 refresh-then-retry-once on 401 (`:184-189`).
F. Named in README `:60`, `:86`. Matches.

### §30
A. `src/management/ops/directory.rs`: `get` `:63`, `set` `:95`, `update` `:126` (PATCH), `delete` `:156`, `link_account` `:181`, `get_sync_status` `:200`.
B. `SetDirectoryConfig.bind_secret: Option<Sensitive<String>>` `models.rs:4848`; `UpdateDirectoryConfig.bind_secret` `models.rs:5837`. Both public types derive only `Debug, Clone[, Default]` — no `Serialize`. Serialization goes through `pub(crate)` wire twins (`SetDirectoryConfigWire` `:4881`, `UpdateDirectoryConfigWire` `:5878`) built at send time via `expose_for_wire`. `DirectoryConfig` (`:1789`) has no secret member. Nothing else wrapped.
C. `tests/directory_test.rs`: (1) `the_bind_secret_reaches_the_wire_and_no_rendering` `:99`; (2) `a_bind_secret_in_a_response_is_dropped` `:139`; (3) `update_sends_exactly_the_members_it_was_given` `:165` (exact `{"enabled":false}`, key set `[bind_secret,url]`, `{"group_filter":null}`); (4) `set_sends_every_required_member_and_decodes_201_and_200` `:213`; (5) `no_write_is_retried_on_503` `:253`; (6) `errors_map_per_section_2_and_link_account_sends_only_the_user_id` `:290`.
D. `set` `directory.rs:78-94` and `update` `:115-125` both carry "**Moving the connection requires the secret again** (§30.3 rule 2)… The SDK holds no copy of the secret"; `set` repeats reset-to-default; `delete` `:146-155` "no fallback to a local hash … There is no unlink"; `link_account` `:171-180` "**Signs the account's owner out everywhere**".
E. As §29 (verb gate `request.rs:57`).
F. README `:60`, `:87`. Matches.

### §31
A. `src/management/ops/scim_targets.rs`: `list` `:55` (+`list_all` `:77`), `create` `:90`, `get` `:110`, `update` `:140`, `delete` `:168`, `reconcile` `:189`.
B. `ScimTargetInput.credential: Option<Sensitive<String>>` `models.rs:4473`; input derives `Debug, Clone` only; wire twin `:4492`. `ScimTargetResponse` `:4532` and `ScimTargetAuth` `:4403` declare no credential member.
C. `tests/scim_targets_test.rs`: (1) `the_credential_is_on_the_wire_and_in_no_rendering` `:95`; (2) `a_credential_in_a_response_is_dropped` `:118`; (3) `update_without_a_credential_sends_no_key_and_the_variants_keep_their_shape` `:145`; (4) `unknown_values_decode_and_the_pager_carries_search` `:211`; (5) `no_write_is_retried_on_503` `:283`; (6) `statuses_map_and_reconcile_is_a_bodyless_202` `:327`.
D. `update` `:124-139`: "**The credential is bound to its URL** (§31.3 rule 2) … The SDK holds no credential to re-send"; `create` `:84-87` names the credential; `delete` `:160-165` "**Deprovisions nothing downstream**". Rule 2 is documented on `update`; on `create` only "required here" (create has no move case, acceptable).
E. As §29.
F. README `:60`, `:88`. Matches.

### §32 (management)
A. `src/management/ops/ssf.rs`: `list_streams` `:64` (+`list_streams_all` `:87`), `create_stream` `:97`, `get_stream` `:118`, `update_stream` `:147`, `delete_stream` `:171`.
B. `SsfStreamInput.authorization_header: Option<Sensitive<String>>` `models.rs:5348`; wire twin `:5377`; `SsfStream` `:5282` has only `authorization_header_set`.
C. `tests/ssf_management_test.rs`: (1) `update_stream_puts_every_member_it_models` `:95`; (2) `the_push_header_is_sent_and_never_rendered_or_decoded` `:141`; (3) `unknown_values_and_both_transmitter_states_decode` `:170`; (4) `list_streams_pages_and_the_walk_carries_search` `:212`; (5) `none_of_the_three_writes_is_retried_on_503` `:259`; (6) `statuses_map_per_section_2` `:297`.
D. `update_stream` `:133-146`: "An omitted optional member takes its default (§32.2) -- **except `authorization_header`, which absent keeps the stored one** -- unless the update moves `endpoint_url` …"; 409-overtaken noted.
E. As §29.
F. README `:60`, `:89`. Matches.

### §32.7 (helper)
A. `SsfReceiver::verify_set` `src/ssf.rs:399`; `SsfReceiver::poll` `src/ssf.rs:518`; config `SsfReceiverConfig` `:129` (`issuer`, `audience`, `keys: SsfKeySource::{JwksUri, DiscoveryUrl}`, `access_token_provider`, `replay_window`, `replay_store`). Event-type constants `:45-69`.
B. Poll bearer is `Sensitive<String>` (`AccessTokenFuture` `:86`). Nothing else in §32.7 needs wrapping. `SsfReceiver`/`SsfReceiverConfig` Debug hide the provider (`:140-153`, `:271-280`).
C. `tests/ssf_receiver_test.rs`: (1) `a_set_signed_by_the_jwks_key_verifies_into_its_claims` `:142`; (2) `a_wrong_typ_or_alg_is_refused_in_that_order` `:172`; (3) `another_key_or_a_tampered_payload_is_invalid_key` `:211`; (4) `another_issuer_or_audience_is_refused` `:236`; (5) `exp_sub_two_events_or_no_jti_is_invalid_request` `:255`; (6) `a_replay_is_refused_and_a_short_window_is_refused_at_configuration` `:283`; (7) `an_unknown_kid_costs_one_refetch_and_a_second_one_none` `:304`; (8) `poll_passes_ack_and_set_errs_through_and_sorts_the_answer` `:330` + `poll_is_not_retried_on_400` `:403`. Keys generated at run time. No test covers a JWKS failure mid-poll (F-1).
D. `poll` doc `:505-517`: "**Nothing is acknowledged on your behalf** … Retried per §16 on a transport failure or `5xx`, never on a `4xx`." (but see Q3: 429 is retried).
E. `src/ssf.rs:566-582`: non-success → `if !status_is_retryable(status) { return Ok(Err(err)) }`; `status_is_retryable` (`src/retry.rs:122`) = `>=500 || 408 || 429`.
F. README `:60` "with §32.7", table `:90`. Matches.

### §33
A. `ciba_initiate` `src/oidc/ciba.rs:388`; `ciba_poll` `:482`; `ciba_await` `:576`; `ciba_handle_ping` `:642` (sync `fn`). All on `AxiamClient`.
B. `CibaInitiateResponse.auth_req_id: Sensitive<String>` `:235`; `CibaPollParams.auth_req_id` `:258`; `ciba_handle_ping` returns `Sensitive<String>` and takes `expected_token: &Sensitive<String>` `:646-647`; `CibaDelivery::Ping { client_notification_token: Sensitive<String> }` `:90`; signer key `Sensitive<EncodingKey>` `:125`, PEM input `&Sensitive<Vec<u8>>` `:148`; signed `request` returned as `Sensitive<String>` `:780`. The form is built as `Vec<(&str, Sensitive<String>)>` `:425` and exposed only into the reqwest body. `binding_message`/`login_hint` not wrapped (correct). `CibaInitiateParams` derives `Debug` (shows `binding_message`/`login_hint`; not a log line).
C. `tests/ciba_test.rs`: 1 `t01_…` `:219`; 2 `t02_…` `:252`; 3 `t03_…` `:316`; 4 `t04_…` `:381` (503, 429-with-body, accept-and-hang-up listener: one connection); 5 `t05_…` `:435` (sleeps `[5,10,15,15]`); 6 `t06_…` `:512` (injected `TestClock`); 7 `t07_…` `:548`; 8 `t08_…` `:582`; 9 `t09_…` `:617`; 10 `t10_…` `:650`; 11 `t11_…` `:671` (constant-time asserted structurally by `include_str!` grep for `token.ct_eq(expected)`); 12 `t12_…` `:705`; 13 `t13_…` `:737` (`server.received_requests()` empty — not a failing transport, but equivalent); 14 `t14_…` `:783`; 15 `t15_…` `:867` (structural: signer requires alg+key, signed form has no channel for a form member); 16 `t16_…` `:890`. Weak spots: t08's `500` is absorbed by §16 inside `ciba_poll` with a real `TokioSleeper`, not by the loop; no test of a 400-without-`error` or a post-200 failure inside the loop (F-2); no test of the mTLS alias (F-3).
D. `ciba_initiate` `:367-387`: "**Never retried** — not on a transport error, a `5xx` or a `429` … A success proves nothing about the user"; `ciba_poll` `:469-481`: "**Store the returned tokens before anything else**"; `ciba_await` `:557-575`; `ciba_handle_ping` `:621-641` "answer `204` as soon as this returns, **then** `ciba_poll`".
E. `ciba_initiate` performs exactly one `.send()` (`:443-451`) with no `RetryRunner`; error → `oauth2_error_or_fallback`. `ciba_poll` uses `RetryRunner` and returns protocol answers unretried (`:540-545`).
F. README `:59-61` "§32 and §33, with §32.7 and §33.2 signed"; `:91-92`; `:77-79` claims the seventh alias "decoded and honoured on an mTLS CIBA call" — true in code (`ciba.rs:409-415`), untested (F-3).

#### Q1 … Q10

### Q1 Replay store
- Interface `src/ssf.rs:96-101`: `pub trait ReplayStore: Send + Sync { fn check_and_record(&self, jti: &str, window: Duration) -> bool; }` — **synchronous**, **atomic check-and-insert** (doc: "two concurrent calls with one `jti` must not both see `true`").
- Default `MemoryReplayStore` `:104-119`: `Mutex<HashMap<String, Instant>>` storing the expiry instant; TTL by `seen.retain(|_, expires| *expires > now)` on **every** call (O(n) sweep). **Unbounded** apart from expiry (no cap, no LRU). Poisoned mutex is recovered (`unwrap_or_else(|p| p.into_inner())`).
- Store errors: **not representable** — the method returns `bool` and cannot fail; a custom distributed store must decide fail-open/closed internally (F-8).
- Recorded only after 1–8: yes — `check_and_record` at `:490`, after step 8 and after the poll-key check `:485`.
- Window floor: `SsfReceiver::new` refuses `replay_window < MIN_REPLAY_WINDOW` (7 days, `:39`) at `:303-309` with `local_refusal("ssf.receiver","replay_window",…)` → `AxiamError::Network` whose `validation()` is `Some` (ValidationError). Constructor refusal, no clamp.

### Q2 verify_set order and codes
Steps follow 1–9 in order with the contract's codes (`src/ssf.rs:409-502`). Details: step 1 also requires the signature part to base64url-decode (`:411`); `typ` compared with `eq_ignore_ascii_case` against both spellings, absent `typ` → `invalid_type` (`:418-423`); `alg` exactly `"EdDSA"` (`:425`); missing `kid` → `invalid_key` (`:429-431`); kid-miss → `JwksVerifier::key_for_kid` (`src/token/jwks.rs:799-809`) forces **one** refetch rate-limited by `FORCED_REFETCH_MIN_INTERVAL = 60 s` (`jwks.rs:43`, `:1194-1225`); signature via `jsonwebtoken::decode` with exp/nbf/aud validation off (`:437-446`); `iss` exact (`:448`); `aud` string or array (`:454-458`); step 8 additionally requires `iat` numeric and `sub_id` an object, `jti` non-empty (`:463-484`). Extra: in `poll`, the map key must equal the SET's `jti`, else `invalid_request` (`:485`, F-7). A JWKS / discovery fetch failure is an `AxiamError::Network` with no reason code (`:432`), not `invalid_key` (F-5). Push codes: `push_error_code` maps `malformed`, `invalid_type`, `replayed` → `invalid_request` (`src/error.rs:714-721`, F-6).

### Q3 poll
Never acknowledges by itself: body is `PollBody` built only from the caller's options, absent members omitted (`src/ssf.rs:237-246`, `:537-542`); test 8 asserts `{}` on a default poll. `ack`/`set_errs` passed through verbatim. Refused returned as `RefusedSet { jti, reason: SetFailureReason }` (`:193-199`). 4xx not retried **except 408 and 429**, which `status_is_retryable` treats as retryable (`:579`, `src/retry.rs:122-124`) — the contract says "not retried on a `4xx`" (F-9). Token source: `access_token_provider` called once per `poll`, before the retry loop (`:543`); request goes over the session-free `http_bare()` (`:556`). A non-verdict error during verification (JWKS fetch) aborts the whole poll after earlier SETs were already recorded (F-1).

### Q4 ciba_await
- Clock: injectable `CibaClock { now(), sleep() }` (`src/oidc/ciba.rs:266-272`), passed in `CibaAwaitParams.clock`; default `SystemCibaClock`. The §16 retry inside each `ciba_poll` uses the real `TokioSleeper`, not this clock (`:507-513`).
- Initial interval: response `interval`, 0 or absent → 5 s (`:461-464`, `:590-594`); no faster floor.
- `slow_down`: `interval += 5` cumulative, never reset (`:616`). **No cap at 60** (allowed).
- Deadline: `received_at + expires_in` where `received_at = Instant::now()` taken after the response is parsed (`:465`, `:589`); stops when `now + wait >= deadline` and raises `oauth_protocol_error("expired_token", …)` locally (`:597-602`).
- 5xx/transport: retried by §16 inside `ciba_poll`; if exhausted, `classify` → `Transient` → wait one interval and continue (`:330-341`, `:614-618`). 429 with `rate_limit_exceeded` body → `Transient` (`:336`); bodiless 429 retried by §16 first.
- **`classify` treats every `AxiamError::Network` as transient** (`:338`), which includes a 400/404 without an `error` member (`oauth2_error_or_fallback` → `from_http_status` → `Network`, `src/oidc/exchange.rs:342-354`, `src/error.rs:261`) and a post-`200` failure in `to_token_set` (ID-token JWKS fetch, `exchange.rs:651-652`) — F-2.
- Cancellation: dropping the future (Rust idiom); no explicit token.
- `auth_req_id`: borrowed from the caller's `&CibaInitiateResponse`, cloned per poll into `CibaPollParams` and dropped after it (`:605-611`).

### Q5 ciba_handle_ping
Constant-time: `subtle::ConstantTimeEq` on byte slices (`src/oidc/ciba.rs:670`; length mismatch returns early, normal for `subtle`). Returns `Sensitive<String>` (`:677`). Refusals: missing, duplicated (`:655-661`), no space / non-Bearer / empty token (`:662-668`), wrong or empty expected (`:669-671`) → `AxiamError::Auth` with a fixed message naming no value (`:649-654`); body not JSON / no non-empty string `auth_req_id` → `local_refusal` ValidationError (`:673-682`). Synchronous `fn`, but a method on `&AxiamClient` (needs a client instance; uses none of it).

### Q6 Signed request
Offered: `CibaRequestSigner::from_pem(alg, &Sensitive<Vec<u8>>, kid)` (`:146-171`); algs `Ps256`, `Es256`, `EdDsa` (`:96-104`); a probe signature proves the key fits the alg (`:165`). Claims (`:735-787`): every plain member inside the JWT (`requested_expiry` as a number), plus `iss` = client_id, `aud` = discovery `issuer` (string), `iat` = `nbf` = now, `exp` = now + 300 s (`SIGNED_REQUEST_LIFETIME_SECS`, `:64`), `jti` = UUIDv4 simple. Form sent: `client_id`, `client_secret` (if any), `request` only (`:425-437`). Key held as `Sensitive<EncodingKey>`; `request` as `Sensitive<String>`. No default alg or key (type requires both). Client authentication for CIBA is `client_secret_post` or mTLS only — the SDK has no `private_key_jwt` client authentication at all (grep finds none), consistent with its §21.8 posture.

### Q7 Kept-secret-on-update
All three: `Option<Sensitive<String>>`; `None` → the wire twin's `#[serde(skip_serializing_if = "Option::is_none")]` **omits** the key.
- `directory.update`: `UpdateDirectoryConfigWire.bind_secret` `src/management/models.rs:5883-5884`.
- `ssf.update_stream`: `SsfStreamInputWire.authorization_header` `:5379-5380` (plus separate `clear_authorization_header: Option<bool>` for "remove").
- `scim_targets.update`: `ScimTargetInputWire.credential` `:4495-4496`.
"Keep" (`None`) vs "replace" (`Some(Sensitive::new(v))`) are distinct; the RMW `From` conversions leave the secret `None` (`src/management/checks.rs:90-145`). Tests assert absence of the key (`directory_test.rs:239-242`, `scim_targets_test.rs:174-178`, `ssf_management_test.rs:130-133`).

### Q8 §21.3.1 pin
No literal vector-A test. The fixture `tests/oidc_support/mod.rs:276-286` carries seven keys incl. `"backchannel_authentication_endpoint": format!("{mtls_base_url}/oauth2/bc-authorize")`, and `tests/mtls_endpoint_aliases_test.rs:174-177` asserts `assert_eq!(round_tripped["mtls_endpoint_aliases"], mtls_endpoint_aliases(&mtls.uri()))` — an exact seven-key equality through the closed `MtlsEndpointAliases` struct (`src/oidc/discovery.rs:58-88`; unknown keys are dropped, never fatal). `ciba_initiate` prefers the alias: `mtls_preferred_opt(&configuration, |a| a.backchannel_authentication_endpoint.as_deref(), …)` (`src/oidc/ciba.rs:409-415`), which reads the member only when a client certificate is configured (`exchange.rs:519-524`) and applies the vector-C check (`:532`). **No test exercises it** (F-3).

### Q9 §28.12 details
URI: `check_registration_uri` (`src/oidc/registration.rs:212-245`) parses with `url::Url::parse` and sends the parsed `Url` — no rebuild, no host swap; `url` normalisation (host case, default port) applies (F-15). Origin compare scheme/host/port, `http` only against an `http` loopback base. Update body: `extra` minus `SERVER_STATED_MEMBERS` (the five, `:39-45`), `client_id` forced (`:169-193`). Token only via `.bearer_auth(...)` on `http_bare()` (no cookie jar, no SDK token) (`:285-287`, `:347-349`, `:377-379`). 401 → `oauth2_error_or_fallback` → `AxiamError::Auth` with OAuth code; no §9 path (these ops never enter `management_raw`). Test 4 asserts zero refreshes.

### Q10 Other divergences / decisions the contract left open
- F-1, F-2, F-3 (defects) below.
- `update_client_registration` always sends `redirect_uris`, `grant_types`, `response_types` (as `[]` when the read lacked them), and `take_list` silently drops a non-array or non-string value instead of preserving it in `extra` the way `take_str` does (`registration.rs:129-136`, `:181-183`) — F-4.
- Deadline anchored at response receipt, not request send (F-10). Interval `0` → 5 s (F-10).
- §16 retries inside `ciba_poll` called from `ciba_await` are on the real clock with an uncapped `Retry-After` floor, so a retry can be sent after `expires_in` (F-11).
- Generated boilerplate "Every field of the body is required" on `scim_targets.update` (`ops/scim_targets.rs:125-128`) and `ssf.update_stream` (`ops/ssf.rs:134-137`) contradicts the optional members and the kept-secret rule documented three lines later; `ParseSamlSpMetadata` doc calls it a "sparse body: what you leave `None` is left unchanged" (`models.rs:3474-3478`) — F-13.
- `MtlsEndpointAliases` doc still says "all six" (`src/oidc/discovery.rs:46-50`) — F-14.
- Wire twins holding plaintext secrets derive `Debug` (`models.rs:4492`, `:4881`, `:5377`, `:5878`); `pub(crate)` and never formatted, but one `{:?}` away from a leak — F-16.
- A polled SET that verified is recorded; if the caller neither acks nor refuses it, its re-offer reads `replayed` and the README advises sending that in `setErrs`, which deletes an event the caller may never have processed (`ssf.rs:505-517`) — contract-level interplay of step 9 and RFC 8936 ack (F-8).

#### Findings
| id | Severity (defect / doc / clarification) | Clause | What | Evidence (path:line) | Suggested disposition (SDK fix / contract clarification / forced by language) |
|---|---|---|---|---|---|
| F-1 | defect | §32.7 step 9, `poll` | `poll` verifies SETs in a loop; a non-verdict error (JWKS refetch/network failure on a later SET) returns `Err` for the whole poll after earlier SETs were already recorded in the replay store. Those events are never returned, are re-offered by the transmitter, and then refuse as `replayed` — silent event loss. | `src/ssf.rs:598-616` (`None => return Err(e)` at `:612`), `:489-492`, `src/token/jwks.rs:807` | SDK fix: either refuse-and-continue the remaining SETs with no record, or pre-fetch keys before recording anything; add a test. Contract clarification: a non-verdict failure inside `poll` must not consume `jti`s already verified. |
| F-2 | defect | §33.4, §33.7 rules 5 and 7 | `ciba_await`'s `classify` treats every `AxiamError::Network` as transient. That includes a 400/404 without an `error` member (terminal per §33.4/§2), local precondition errors, and a failure **after** a `200` in `to_token_set` (ID-token JWKS fetch). The loop then re-polls a redeemed request, gets `invalid_grant`, and the approved tokens are lost. | `src/oidc/ciba.rs:338`, `:614-618`; `src/oidc/exchange.rs:342-354`, `:649-652`; `src/error.rs:261` | SDK fix: classify only transport errors and 5xx/408/429 as transient (carry the status), and never re-poll after a 200 was received. |
| F-3 | defect | §21.3.1 assertions table; §21.10 "prefers" | No test asserts that an mTLS client's `ciba_initiate` goes to the `backchannel_authentication_endpoint` alias host (a required §21.3.1 row since 1.58). The code does it; the README claims it. | `src/oidc/ciba.rs:409-415`; absent from `tests/ciba_test.rs` and `tests/mtls_endpoint_aliases_test.rs` | SDK fix: add the vector-A CIBA row (and the no-certificate counterpart). |
| F-4 | defect (low) | §28.12.2 rule 4 (full replacement) | `update_body` sends `redirect_uris`/`grant_types`/`response_types` as `[]` when the read did not carry them, and `take_list` drops a non-array/non-string value rather than keeping it in `extra`, so a round-trip can change or delete a member. | `src/oidc/registration.rs:129-136`, `:181-183` | SDK fix: omit an absent list, preserve unexpected shapes in `extra` (as `take_str` already does). |
| F-5 | clarification | §32.7 step 4 | A JWKS or discovery fetch failure is raised as `NetworkError` with no reason code, not `invalid_key`. The contract lists only reason codes. | `src/ssf.rs:330-341`, `:432` | Contract clarification: a key-fetch failure is not a verdict; say what it raises. |
| F-6 | clarification | §32.7 "reason codes match RFC 8935" | `malformed` and `invalid_type` are not RFC 8935 codes; `push_error_code` maps both (and `replayed`) to `invalid_request`. | `src/error.rs:714-721` | Contract clarification: state the mapping for `malformed`/`invalid_type`. |
| F-7 | clarification | §32.7 `poll` | Extra check: the poll response's map key must equal the SET's `jti`, else `invalid_request`. | `src/ssf.rs:485-487` | Contract clarification (adopt or forbid across SDKs). |
| F-8 | clarification | §32.7 step 9 + poll ack | (a) `ReplayStore::check_and_record` is infallible (`bool`), so fail-open vs fail-closed for a store error is undefined; the default store is unbounded (expiry-swept). (b) A verified, unacked SET re-offered on the next poll is `replayed`; the documented advice is to `setErr` it, which deletes it server-side. | `src/ssf.rs:96-119`, `:505-517` | Contract clarification: the store's error semantics (fail closed) and whether a `jti` is recorded at verify time or only when the caller acknowledges. |
| F-9 | clarification | §32.7 "not retried on a 4xx" vs §16.3 | `poll` retries 408 and 429 (§16 says yes; §32.7 says no 4xx). | `src/ssf.rs:579`, `src/retry.rs:122-124` | Contract clarification: say whether 408/429 count as "4xx" for `poll`. |
| F-10 | clarification | §33.7 rules 2 and 4 | Deadline anchored at response receipt (`received_at`), not request send; `interval: 0` treated as absent (5 s). | `src/oidc/ciba.rs:461-465`, `:589-594` | Contract clarification: define "initiate time" and the zero case. |
| F-11 | clarification | §33.7 rules 4 vs 5 | §16 retries inside `ciba_poll` (called by `ciba_await`) use the real sleeper and an uncapped `Retry-After` floor, so a retry can land after `expires_in` and is invisible to the injected clock. | `src/oidc/ciba.rs:507-513`, `src/retry.rs:97-115` | Contract clarification: does rule 4's "MUST NOT poll past it" bound the per-attempt §16 retries? |
| F-12 | clarification | §29.8 test 1, §29.2 | Replacement body omits nullable members that are `None` (server default null) instead of sending `null`; the test checks 11 of 15 members. | `src/management/models.rs:4314-4366`, `tests/saml_test.rs:121-135` | Contract clarification: "every member" may omit a member whose omission equals its default. |
| F-13 | doc | §27.4 rule 5, §29.2, §31.2, §32.2 | Generated "Every field of the body is required" on `scim_targets.update` and `ssf.update_stream` contradicts their optional members and kept-secret rule; `ParseSamlSpMetadata` doc calls an exactly-one body "sparse … left unchanged". | `src/management/ops/scim_targets.rs:125-128`, `src/management/ops/ssf.rs:134-137`, `src/management/models.rs:3474-3478` | SDK fix (generator template). |
| F-14 | doc | §21.3.1 (seven aliases) | `MtlsEndpointAliases` doc still says the schema has "all six". | `src/oidc/discovery.rs:46-50` | SDK fix. |
| F-15 | clarification | §28.12.2 rule 1 "verbatim" | URI is parsed and re-serialized by `url::Url` (normalises host case and default port); not a rebuild, but not byte-verbatim. | `src/oidc/registration.rs:226`, `:285` | Contract clarification: parse-and-reserialize is acceptable. |
| F-16 | clarification | §7 rule 4 | `pub(crate)` wire twins carrying plaintext secrets derive `Debug`. | `src/management/models.rs:4492`, `:4881`, `:5377`, `:5878` | SDK fix (hardening): give the twins a redacting `Debug` or none. |

---

### Report — typescript — commit ab1c5ee (merge #131)
Toolchain run: yes. On a `git archive HEAD` copy: `npm ci --ignore-scripts`, then `NO_PROXY='*' npx vitest run test/node/ciba.test.ts test/node/ssfReceiver.test.ts test/node/mtlsEndpointAliases.test.ts test/node/clientRegistration.test.ts test/management/saml.test.ts test/management/ssf.test.ts test/management/directory.test.ts test/management/scimTargets.test.ts`. Result: 8 files, 113 tests, all passed. A first run without `NO_PROXY` failed 81 of them: axios sent the mock hosts to the sandbox egress proxy, which answered 403. That is an environment artefact, not an SDK defect. Two extra probe tests in the copy (not in the repo) confirmed F-1 empirically (see Findings). Vendored `CONTRACT.md` is byte-identical to this repository's `sdks/CONTRACT.md`.

All paths below are relative to the `axiam-typescript-sdk` repository root.

#### Posture per section
| Section | Status | Notes |
|---|---|---|
| §28.12 | implemented | on `AxiamClient`; bare transport (no jar, no interceptors, no redirects); token argument also accepts a plain `string` (F-4) |
| §29 | implemented | `client.saml`; key member dropped by denylist only (F-6) |
| §30 | implemented | `bind_secret` `Sensitive`, but leaked through `NetworkError.cause` on a 5xx or transport failure (F-1) |
| §31 | implemented | `credential` `Sensitive`; same F-1 leak |
| §32 | implemented | `authorization_header` `Sensitive`; same F-1 leak |
| §32.7 | implemented | `SsfReceiver` (Node-only); event loss when a poll aborts partway (F-2) |
| §33 | implemented | on Node-only `OidcClient`; transient classification correct |
| §33.2 signed | implemented | `CibaRequestSigner.create(alg, key, kid)` PS256/ES256/EdDSA via `jose` |

#### A–F per section

### §28.12
A. `AxiamClient.readClientRegistration` `src/rest/client.ts:575`, `updateClientRegistration` `:605`, `deleteClientRegistration` `:626` (implementations `src/rest/clientRegistration.ts:290`, `:325`, `:354`); type `ClientRegistration` `src/rest/clientRegistration.ts:54`; decoder `clientRegistrationFromJson` `:114`.
B. `client_secret?: Sensitive<string>` `:80` and `registration_access_token?: Sensitive<string>` `:86`, wrapped at decode (`:176-179`). `Sensitive` redacts `toString`, `toJSON` and `util.inspect` (`src/core/sensitive.ts:54-66`). The operation argument is typed `Sensitive<string> | string` (`src/rest/client.ts:577`, `:607`, `:628`), so a caller can pass the bearer unwrapped (F-4). Errors: `bareRequest` keeps no axios `cause` (`src/rest/bareTransport.ts:59-67`); `mapRegistrationError` passes no ctx (`clientRegistration.ts:271-275`); the rule-1 refusal names no URI part (`:226-260`).
C. `test/node/clientRegistration.test.ts`:
   1. `:156` (another host, port, `http` vs `https`; no request).
   2. `:213` (no SDK token, no cookie, no CSRF, no body, query verbatim; control `:206`).
   3. `:244`; 503 not retried on update `:280`, on delete `:290`; bodiless 400 on read not retried `:304`.
   4. `:339` (401 `invalid_token`, §9 not entered), `:362` (400 `invalid_client_metadata`), `:374` (204).
   5. `:397`.
D. `src/rest/client.ts:587-603`: "`metadata` is the **whole** registration: a member it omits is a member the server deletes … **Persist the returned `registration_access_token` before doing anything else.** … **Never retried**". Delete `:620-624`.
E. Read: `withRetry` with a decisive-4xx escape (`clientRegistration.ts:302-321`). Update `:337-350` and delete `:366-372` each make a single `bareRequest`, with no runner.
F. `README.md:28-30` states "conforms to **contract 1.58** … §28, §28.12, §29, §30, §31, §32 and §33, with §32.7 and §33.2 signed"; table `:35-46`. Matches.

### §29
A. `src/management/ops/saml.ts` (`SamlApi` `:40`):
   - `getIdp` `:60`;
   - `listServiceProviders` `:72` and `listServiceProvidersAll` `:92`;
   - `createServiceProvider` `:108`, `getServiceProvider` `:121`, `updateServiceProvider` `:152`, `deleteServiceProvider` `:173`;
   - `parseSpMetadata` `:196`;
   - `listIdpCredentials` `:210` (an array);
   - `issueIdpCredential` `:230`, `promoteIdpCredential` `:253`, `retireIdpCredential` `:277`.

   All present on `client.saml`.
B. Nothing is wrapped (correct). `SamlIdpCredential` (`src/management/models.ts:3845`) declares no key. Responses pass through `scrubSamlIdpCredential` (`models.ts:6132-6135`, called at `saml.ts:218`, `:239`, `:285`) and `scrubSamlIdpCredentialPromotion` (`:261`), which drop **only** `private_key_pem` (F-6).
C. `test/management/saml.test.ts`, required tests (1)–(8) in order: `:86`, `:128`, `:155`, `:196`, `:227`, `:257`, `:287`, `:315`.
D. ECDSA is HTTP-POST only and HTTP-Redirect is RSA-only (`saml.ts:101`, `:142`). The update keeps the default-on-omit list and says `entity_id` is immutable (`:135-150`). Delete ends no session (`:167`). Retire says "**Retiring the `active` credential with no successor stops SAML sign-on for the whole tenant at once**" (`:268-269`). Issue says the call "takes seconds" (`:224`). The read-modify-write form is `samlServiceProviderInputFrom` (`src/management/checks.ts:68`).
E. `src/management/request.ts:92-95`: `withRetry(attempt, { …, idempotent: call.method === 'GET' })`. Writes get one attempt.
F. `README.md:29`, `:41`. Matches.

### §30
A. `src/management/ops/directory.ts`: `get` `:51`, `set` `:84`, `update` `:110` (PATCH), `delete` `:135`, `linkAccount` `:158`, `getSyncStatus` `:171`.
B. Fields:
   - `SetDirectoryConfig.bind_secret?: Sensitive<string>` `models.ts:4579`;
   - `UpdateDirectoryConfig.bind_secret?: Sensitive<string>` `models.ts:5435`;
   - each is unwrapped only in `setDirectoryConfigToWire` `:4643-4648` and `updateDirectoryConfigToWire` `:5509-5514`;
   - `scrubDirectoryConfig` drops `bind_secret` from responses (`:6122`).

   **Defect F-1:** on a 5xx or a transport failure the thrown `NetworkError.cause` is the axios error, shallow-copied by `sanitizeAxiosError` (`src/core/errorMapper.ts:207-213`, which redacts response headers only). Its `config.data` is the serialized wire body, which holds the plaintext `bind_secret` (`src/management/request.ts:129`, `:151`). Probe: a `503` on `directory.set` or `directory.update` → `util.inspect(err)` contains the secret, at default depth too.
C. `test/management/directory.test.ts`:
   1. `:79`. Covers a **400** only, so it misses F-1.
   2. `:105`.
   3. `:123`.
   4. `:146`.
   5. `:170`. Asserts one request on 503, but no rendering check.
   6. `:200`.

   There is also `:238` (sync status) and a read-modify-write test at `:254`.
D. `set` `directory.ts:62-83` and `update` `:96-109` both carry "**Moving the connection requires the secret again** (§30.3 rule 2) … The SDK holds no copy". Delete `:122-134` says there is no unlink. Link `:145-157` says "**Signs the account's owner out everywhere**".
E. As §29.
F. `README.md:29`, `:40`. The claim of §30.5 wrapping is contradicted by F-1.

### §31
A. `src/management/ops/scim_targets.ts`: `list` `:43`, `listAll` `:61`, `create` `:74`, `get` `:88`, `update` `:118`, `delete` `:142`, `reconcile` `:161`. Unknown `auth`/`scope` tags are refused before sending (`:119-120`).
B. `ScimTargetInput.credential?: Sensitive<string>` `models.ts:4201`; wire `scimTargetInputToWire` `:4247-4252`; responses go through `scrubScimTargetResponse` (`:6155`). The same F-1 leak applies (probe: a `503` on `scimTargets.create` puts the credential in `inspect(err)`).
C. `test/management/scimTargets.test.ts`:
   1. `:77` (400 only).
   2. `:94`.
   3. `:111`.
   4. `:148`.
   5. `:199`.
   6. `:223`.

   The open-union guards are tested at `:265-283`.
D. `update` `:98-117` says "**The credential is bound to its URL** (§31.3 rule 2)". `create` `:66-73` says the credential is required. Delete `:132-141` says "**Deprovisions nothing downstream**".
E. As §29.
F. `README.md:29`, `:44`. Contradicted by F-1.

### §32 (management)
A. `src/management/ops/ssf.ts`: `listStreams` `:55`, `listStreamsAll` `:74`, `createStream` `:84`, `getStream` `:97`, `updateStream` `:127`, `deleteStream` `:145`.
B. `SsfStreamInput.authorization_header?: Sensitive<string>` `models.ts:4996`; wire `ssfStreamInputToWire` `:5059-5064`; responses go through `scrubSsfStream`. The same F-1 leak applies (probe: a `503` on `ssf.createStream`).
C. `test/management/ssf.test.ts`, required tests (1)–(6) in order: `:68`, `:109`, `:128`, `:165`, `:188`, `:210`.
D. `updateStream` `:107-126`: absent `authorization_header` keeps the stored header, unless the endpoint moves origin.
E. As §29.
F. `README.md:29`, `:42`. Contradicted by F-1.

### §32.7 (helper)
A. `SsfReceiver` `src/node/ssf.ts:317`: `verifySet` `:381`, `poll` `:407`. Config is `{ issuer, audience, jwksUri | discoveryUrl, accessTokenProvider, replayWindowMs, replayStore }` (`:179-198`), with exactly one key source enforced (`:347-349`). Event constants are at `:47-64`. The helper is exported from `axiam-sdk/node` only.
B. The poll bearer comes from `AccessTokenProvider: () => Promise<Sensitive<string> | string>` (`:173`). It is sent on `bareRequest`, which keeps no `cause`.
C. `test/node/ssfReceiver.test.ts`:
   1. `:113`.
   2. `:139`.
   3. `:161`.
   4. `:175`.
   5. `:187`.
   6. `:208` and `:217`.
   7. `:237`. Also `:253`: a JWKS failure is a `NetworkError`.
   8. `:263`. Also `:325`: not retried on 400, a 503 is. Also `:348`: a JWKS failure aborts the poll. That test uses a single SET, so it cannot see F-2.
D. The `poll` doc (`:385-406`) says: "**Nothing is acknowledged on your behalf** … Retried per §16 on a transport failure, `408`, `429` or `5xx`; never on another `4xx`". The README says "not retried on a `4xx`" (`README.md:2243`), which contradicts the code (F-9).
E. `:444-447`: `if (statusIsRetryable(response.status)) throw retryableNetworkError(...)`, otherwise `return { error }`. `statusIsRetryable` is 408, 429 or 5xx (`src/rest/bareTransport.ts:91-93`).
F. `README.md:29` "with §32.7", plus the table at `:43`. Matches.

### §33
A. All four are on `OidcClient` (`axiam-sdk/node`):
   - `cibaInitiate` `src/node/oidc.ts:2186`;
   - `cibaPoll` `:2267`;
   - `cibaAwait` `:2336`;
   - `cibaHandlePing` `:2394`, synchronous.

   The names match §33.6.
B. Wrapped values:
   - `CibaInitiateResponse.authReqId: Sensitive<string>` `src/node/oidcTypes.ts:1230`;
   - `CibaPollParams.authReqId` `:1242`;
   - `CibaDelivery` ping `clientNotificationToken: Sensitive<string>` `:1181`;
   - `cibaHandlePing` takes `expectedToken: Sensitive<string>` and refuses a non-`Sensitive` one (`oidc.ts:2409-2410`); it returns `Sensitive<string>`;
   - the signer key is `#key: Sensitive<KeyObject | CryptoKey>` (`:683`), and the PEM input is `Sensitive<string>` (`:666`);
   - the signer renders as `{alg, kid}` only (`:748-762`);
   - the signed `request` comes back as `Sensitive<string>` (`:740-746`).

   `#postCibaForm` turns a transport failure into a `NetworkError` with no axios cause, because the form holds the client secret (`:2448-2467`). `cibaError` passes no ctx (`:790-795`).
C. `test/node/ciba.test.ts`:
   1. `:149`.
   2. `:174`. The alias row is `:204`, and the no-endpoint case `:217`.
   3. `:228`.
   4. `:294` (503 and 429) and `:307` (dropped connection).
   5. `:323`. A bodiless 400 is terminal: `:364`.
   6. `:378`.
   7. `:401`.
   8. `:416`. §16 inside one poll: `:439`.
   9. `:455`.
   10. `:476`.
   11. `:501`. Constant time is asserted structurally: the test reads the source for `timingSafeEqual`.
   12. `:539`.
   13. `:565`.
   14. `:595`.
   15. `:649`.
   16. `:675`.

   There is also `:693`, and `:704` (a transport failure is not terminal for `cibaAwait`).
D. Call-site docs:
   - `cibaInitiate` `:2158-2185`: "**Never retried** — not on a transport error, a `5xx` or a `429` … **A success proves nothing about the user**".
   - `cibaPoll` `:2249-2266`: "**Store the returned tokens before anything else**".
   - `cibaAwait` `:2312-2335`, including the ping-mode fallback.
   - `cibaHandlePing` `:2371-2393`: "prefer Node's `req.rawHeaders`, which keeps a duplicated `Authorization` that `req.headers` drops".
E. `cibaInitiate` makes a single `#postCibaForm` call (`:2234-2236`) and is not wrapped in `withRetry`. In `cibaPoll`, protocol answers are `return { error }` (`:2291-2292`), and only 408, 429 and 5xx without an `error` body are thrown as transient (`:2293-2295`).
F. `README.md:29-30` "§33, with … §33.2 signed", plus `:45` and `:47-53`. The README says plainly that there is no `private_key_jwt` client authentication (`README.md:51-54`). Matches.

#### Q1 … Q10

### Q1 Replay store
- **Interface** (`src/node/ssf.ts:141-148`): `interface ReplayStore { checkAndRecord(jti: string, windowMs: number): boolean | Promise<boolean>; }`. It may be **sync or async**, and it is an **atomic check-and-insert**: the contract text says "two concurrent calls with one `jti` must not both see `true`".
- **Default** `MemoryReplayStore` (`:151-169`): a `Map<string, number>` of expiry times in epoch ms. Every call sweeps out all expired entries, an O(n) pass. The store is **unbounded** apart from expiry, with no cap and no LRU. Its clock is injectable.
- **Store errors**: a throw or rejection propagates out of `#verify` as itself, not as a `SetRefusedError`. The SET is therefore not accepted (**fail closed**). In `poll` the error aborts the whole poll (`:470-473`), which is F-2 again.
- **Recorded only after 1–8**: yes. The store is called at `:558-561`, after step 8 and after the poll-key check at `:554`.
- **Window floor**: the constructor refuses with `if (!(window >= MIN_REPLAY_WINDOW_MS))` (`:341-344`), which also rejects `NaN`. It throws a local `ValidationError` (`refuseConfig`, `:253-257`) on field `replayWindowMs`. This is a refusal, not a clamp.

### Q2 verifySet order and codes
The code follows steps 1–9 in order, with the contract's codes (`src/node/ssf.ts:478-572`).

- **Step 1**: a regex check on the signature part, then a JSON-object header and payload (`:480-488`).
- **Step 2**: `typ` is lower-cased and compared with both spellings. An absent `typ` gives `invalid_type` (`:490-493`).
- **Step 3**: `alg === 'EdDSA'` exactly (`:495`).
- **Step 4**: a missing or empty `kid` gives `invalid_key` (`:499-501`). `#keyFor` (`:575-587`) fetches once; on a miss it forces one refetch if 60 s have passed since the last forced one (`JWKS_REFETCH_INTERVAL_MS`, `:40`, `:580`), using an injectable `now`.
- **Step 5**: `node:crypto` Ed25519 verify, and the key type must be `ed25519` (`:507-522`).
- **Step 6**: `iss` must match exactly.
- **Step 7**: `aud` may be a string or an array (`:529-535`).
- **Step 8**: as the contract says, but `iat` must also be a finite number, `sub_id` must be an object and `jti` must be non-empty (`:537-553`).

There is one extra check: in `poll`, the map key must equal the SET's `jti` (`:554-556`, F-7).

A JWKS or discovery failure surfaces as `NetworkError`, or as whatever `mapHttpStatusToError` returns for that status. It is never a reason code (F-5).

`pushErrorCode` maps `malformed`, `invalid_type` and `replayed` to `invalid_request` (`:98-102`, F-6b).

### Q3 poll
- **Never acknowledges by itself.** The body is built only from the members the caller set (`:423-427`), and a bare poll sends `{}`, which test `:263` asserts. `ack` and `setErrs` are passed through verbatim.
- **Refusals** come back as `RefusedSet { jti, reason }`.
- **Retries.** A 4xx is not retried except 408 and 429 (`:445`; F-9).
- **Token.** The token source is `accessTokenProvider`, called once per poll, before the retry loop (`:428-429`). A missing provider is a local `AuthError` (`:410-414`).
- **Transport.** Requests go on `bareRequest`: no jar, no interceptors, no redirects.
- **Abort.** A non-verdict error during verification aborts the poll. SETs that verified earlier in the same poll have already been recorded by then (F-2).

### Q4 cibaAwait
- **Clock.** The clock is injectable: `CibaClock { now(): number; sleep(ms): Promise<void> }` (`oidcTypes.ts:1253-1258`), defaulting to `SYSTEM_CIBA_CLOCK` (`oidc.ts:632`). The §16 retries inside `cibaPoll` use the real `setTimeout`, because no `sleepFn` is passed (`:2297-2302`; F-11).
- **Initial interval.** The response `interval` is used when it is greater than 0; otherwise 5 s (`:2244`, `:2340`). There is no faster floor.
- **`slow_down`.** Each one adds 5 s, cumulatively, and the interval is never reset (`:2359-2362`). There is no cap at 60 s, which the contract allows.
- **Deadline.** The deadline is `receivedAt + expiresIn*1000`, where `receivedAt = Date.now()` is taken after the response arrives (`:2245`, `:2339`; F-10). When `now + wait >= deadline`, the loop raises a local `OAuthProtocolError('expired_token', …)` (`:2343-2348`).
- **Transient errors.** `authorization_pending` and `rate_limit_exceeded` continue (`:2358`). A `NetworkError` continues only if it is tagged in `TRANSIENT_POLL_FAILURES` (`:624-629`, `:2365`). Two paths tag it: a transport failure (`:2465`) and a 408, 429 or 5xx that §16 exhausted (`:2294`). A bodiless 400, a post-200 parse failure and an ID-token failure are therefore terminal, and the loop **never re-polls a redeemed request**.
- **Lost tokens.** If `#toTokenSet` fails after a 200 (for example, the ID-token JWKS fetch fails), the approved tokens are lost and the loop ends with that error (F-12).
- **Cancellation.** There is no `AbortSignal`. A caller can only stop the loop through the injected clock.
- **`authReqId`.** It is read from the caller's `CibaInitiateResponse` on each poll. The loop keeps no copy of it.

### Q5 cibaHandlePing
- **Constant time.** `constantTimeEqual` (`src/node/oidc.ts:2834-2842`) uses `crypto.timingSafeEqual`. On a length mismatch it runs a dummy self-compare and returns false.
- **Return value.** `Sensitive<string>` (`:2428`).
- **Bearer refusals** are an `AuthError` with a fixed message (`:2399-2400`). Each of these is refused:
  - zero or more than one `Authorization` value (`:2401-2402`);
  - no space after the scheme;
  - a non-`Bearer` scheme or an empty token (`:2403-2408`);
  - an `expectedToken` that is not a `Sensitive` or is empty;
  - a token that does not match.
- **Body refusals** are a local `ValidationError` (`:2413-2427`).
- **Header shapes.** It accepts rawHeaders, `[name,value]` iterables and header records (`:798-821`). A duplicated header is only detectable from rawHeaders or iterables, because Node's `req.headers` drops the duplicate. This is documented (`oidcTypes.ts:1270-1279`).
- **Synchronous.** It is a method on `OidcClient`, and it does no I/O.

### Q6 Signed request
- **Construction.** `CibaRequestSigner.create(alg, key, kid?)` is async (`:702-728`). It accepts `PS256`, `ES256` or `EdDSA` (`:616`), anything else is refused, and a probe signature confirms the key signs under that algorithm.
- **Claims** (`:2217-2229`):
  - every plain member, with `requested_expiry` as a number;
  - `iss` = `clientId`;
  - `aud` = discovery `issuer`, as a string;
  - `iat` = `nbf` = now;
  - `exp` = now + 300 s;
  - `jti` = 16 random bytes in hex.
- **Form.** Only `client_id`, `client_secret` if one is set, and `request`.
- **Key.** Held as `Sensitive<KeyObject | CryptoKey>`. `jose` is loaded with a dynamic import.
- **Client authentication.** There is no `private_key_jwt` client authentication. The README states this (`README.md:51-54`).

### Q7 Kept-secret-on-update
All three wire converters use `{ ...v, secret: v.secret === undefined ? undefined : v.secret.expose() }`, and `JSON.stringify` then **omits** the `undefined` member:
- `directory.update` → `updateDirectoryConfigToWire` `src/management/models.ts:5509-5514`;
- `ssf.updateStream` → `ssfStreamInputToWire` `:5059-5064` (plus `clear_authorization_header?: boolean` `:5001`);
- `scimTargets.update` → `scimTargetInputToWire` `:4247-4252`.

"Keep" is `undefined` and "replace" is a `Sensitive`, so the two are distinct. The read-modify-write helpers leave the secret absent (`src/management/checks.ts:94-153`).

An explicit `null`, which the types do not allow, would throw a `TypeError` in `.expose()` before any request.

### Q8 §21.3.1 pin
The pin is in `test/node/mtlsEndpointAliases.test.ts:113-121`: `expect(Object.keys(configuration.mtls_endpoint_aliases ?? {}).sort()).toEqual(['backchannel_authentication_endpoint','device_authorization_endpoint','introspection_endpoint','pushed_authorization_request_endpoint','revocation_endpoint','token_endpoint','userinfo_endpoint'])`. That is **seven** keys, from the SDK's own fixture (`test/node/oidcTestKit.ts:57-67`), not from the literal vector-A JSON.

`cibaInitiate` prefers the alias through `#optionalEndpoint(configuration, 'backchannel_authentication_endpoint')` (`src/node/oidc.ts:2205`, `:2580-2588`). It reads aliases only when a client certificate is presented (`:2553-2557`).

The preference is tested at `test/node/ciba.test.ts:204-215`: an mTLS client hits `MTLS_BC_AUTHORIZE_ENDPOINT` with `tenant_id`, and a non-mTLS client hits the top-level endpoint.

### Q9 §28.12 details
- **URI verbatim.** The string is sent byte-for-byte as given; `URL` is used only to check it (`src/rest/clientRegistration.ts:297-299`, `:333-335`, `:361-363`).
- **Update body.** `extra` minus the five server-stated members, with `client_id` forced (`:190-206`).
- **Token.** Sent only as `Authorization: Bearer`, on `bareRequest`: no jar, no session token, no CSRF header (`src/rest/bareTransport.ts:42-68`).
- **401.** It becomes an `OAuthProtocolError` through `oauth2ErrorFromBody`. Because `validateStatus: () => true` and no interceptors are attached, it does not trigger §9; test `:339` asserts this.

### Q10 Other divergences, and decisions the contract left open
- F-1, F-2 and F-3 are defects; see Findings.
- `clientRegistrationUpdateBody` always sends `redirect_uris`, `grant_types` and `response_types` (`[]` when absent). That `[]` overwrites a mistyped value that the decoder had kept in `extra` (`clientRegistration.ts:137-145`, `:198-200`; F-5b).
- The generator boilerplate "Every field of the body is required" on `scimTargets.update` (`ops/scim_targets.ts:110-111`) and `ssf.updateStream` (`ops/ssf.ts:119-120`) is wrong for those two operations. The `ParseSamlSpMetadata` doc calls it a "sparse body … left unchanged" (`models.ts:3247-3252`). This is F-13 and matches the Rust SDK.
- A mTLS test title still says "names only some of the **six**" (`test/node/mtlsEndpointAliases.test.ts`, test "falls back per endpoint…"; F-14).
- `SsfReceiver` and the CIBA helpers are Node-only. They are documented as such and are not a §33.10 problem.

#### Findings
| id | Severity (defect / doc / clarification) | Clause | What | Evidence (path:line) | Suggested disposition (SDK fix / contract clarification / forced by language) |
|---|---|---|---|---|---|
| F-1 | defect | §30.5, §31.5, §32.5 ("an error raised by set/update/create MUST NOT include it"); §7 rule 1 | Every management write that fails with a 5xx or a transport error throws a `NetworkError` whose `cause` is a shallow copy of the axios error. `sanitizeAxiosError` redacts only response headers, so `config.data`, the serialized body holding the plaintext `bind_secret`, `credential` or `authorization_header`, survives. `console.log(err)` / `util.inspect(err)` prints it. Confirmed by probe on `directory.set` and `directory.update`, `scimTargets.create` and `ssf.createStream` with a `503`. It also affects the §27.5 request secrets (`users.create` password, `webhooks` secret, `federation` client_secret, `ca_certificates.import_ca` key). The required redaction tests use only a 400, which takes the `ValidationError` path with no cause, so they pass. | `src/management/request.ts:129`, `:151`; `src/core/errorMapper.ts:207-213`, `:267`; `test/management/directory.test.ts:90-95`; `test/management/scimTargets.test.ts:84-88` | SDK fix: drop the axios `cause` on the management path, or deep-scrub `config.data`/`config.headers`/`request`, as `bareTransport.ts` and `#postCibaForm` already do. Add a 5xx and a transport-failure rendering test per secret-bearing write. Contract clarification: the §30.8/§31.8/§32.8 redaction tests should name a 5xx and a transport error, not only a 400. |
| F-2 | defect | §32.7 step 9, `poll` | `poll` verifies SETs one after another. A non-verdict error (a forced JWKS refetch failing on a later SET, or a replay-store error) rethrows (`else throw err`) after earlier SETs have been recorded. Those events are never returned; when the transmitter re-offers them they are refused as `replayed`. The test at `:348` uses one SET and cannot see this. | `src/node/ssf.ts:463-474`, `:558-561`, `:580-584` | SDK fix: refuse the remaining SETs without recording them, or fetch the keys before recording anything. Contract clarification (shared with Rust F-1). |
| F-3 | defect | §29.5 ("a member named `private_key_pem` (or any other member the type does not declare) … MUST drop it"); §30.2 (`bind_secret_set`, a hash or prefix) | The response scrubbers drop one named key each (`private_key_pem`, `bind_secret`, `credential`, `authorization_header`). Any other undeclared member (`private_key`, `bind_secret_set`, `credential_hash`) reaches the caller's object and every rendering of it. | `src/management/models.ts:6110-6168` (`dropMembers` denylist) | SDK fix: decode these four response types by allow-list. Contract clarification: confirm that the allow-list reading of §29.5 also applies to §30–§32. |
| F-4 | defect (low) | §28.12.4 ("MUST be `Sensitive<T>` … as the argument of all three operations") | `registrationAccessToken` is typed `Sensitive<string> \| string`, so a bare bearer is accepted. | `src/rest/client.ts:577`, `:607`, `:628`; `src/rest/clientRegistration.ts:262-264` | SDK fix (narrow the type), or record it as forced-by-language with a reason. |
| F-5b | defect (low) | §28.12.2 rule 4 (full replacement) | The update sends `redirect_uris`/`grant_types`/`response_types` as `[]` when the read lacked them, overriding a mistyped value kept in `extra`. | `src/rest/clientRegistration.ts:137-145`, `:198-200` | SDK fix: omit an absent list and keep what `extra` holds. |
| F-5 | clarification | §32.7 step 4 | A JWKS or discovery fetch failure is a `NetworkError` (or the §2 type for its status), never a reason code. | `src/node/ssf.ts:589-614`, `:616-643` | Contract clarification (shared with Rust F-5). |
| F-6b | clarification | §32.7 RFC 8935 codes | `malformed`/`invalid_type`/`replayed` → `invalid_request`. | `src/node/ssf.ts:86-102` | Contract clarification (shared with Rust F-6). |
| F-7 | clarification | §32.7 `poll` | An extra check: a poll map key different from the SET's `jti` is refused as `invalid_request`. | `src/node/ssf.ts:554-556` | Contract clarification (shared). |
| F-8 | clarification | §32.7 step 9 + ack | (a) The default store is unbounded. (b) A verified but unacked SET is `replayed` on re-offer, and the README advises `setErrs` for it, which deletes it on the server. Store errors fail closed. | `src/node/ssf.ts:151-169`, `:390-395`; `README.md:2240-2242` | Contract clarification (shared with Rust F-8). |
| F-9 | doc | §32.7 "not retried on a 4xx" vs §16 | The code retries 408/429 (and says so in TSDoc); the README says "not retried on a `4xx`". | `README.md:2243`; `src/node/ssf.ts:398-401`, `:445` | SDK fix (README); contract clarification on 408/429 (shared with Rust F-9). |
| F-10 | clarification | §33.7 rules 2, 4 | The deadline is anchored at response receipt, and `interval: 0` is treated as absent. | `src/node/oidc.ts:2244-2245`, `:2339-2340` | Contract clarification (shared). |
| F-11 | clarification | §33.7 rules 4 vs 5 | §16 retries inside `cibaPoll` use the real timer and an uncapped `Retry-After` floor, so they can cross the deadline and are not seen by the injected clock. | `src/node/oidc.ts:2297-2302`; `src/rest/retry.ts:84-87` | Contract clarification (shared). |
| F-12 | clarification | §33.7 rule 7 vs §12.4 rule 7 | After a 200, an ID-token validation failure (including a transient JWKS fetch) discards the token set and ends the loop, and the redeemed tokens are lost. Rule 7 says to store the 200 first; §12.4 says to discard on a bad ID token. The two conflict. | `src/node/oidc.ts:2304-2306`, `:2486-2500` | Contract clarification: may the SDK return the tokens with the ID-token error, or retry only the JWKS fetch? |
| F-13 | doc | §27.4 rule 5, §29.2, §31.2, §32.2 | The generated "Every field of the body is required" on `scimTargets.update`/`ssf.updateStream`, and "sparse … left unchanged" on `ParseSamlSpMetadata`, are wrong. | `src/management/ops/scim_targets.ts:110-111`; `src/management/ops/ssf.ts:119-120`; `src/management/models.ts:3247-3252` | SDK fix (generator template). |
| F-14 | doc | §21.3.1 (seven aliases) | A test title still says "only some of the six". | `test/node/mtlsEndpointAliases.test.ts` ("falls back per endpoint when the alias object names only some of the six") | SDK fix. |
| F-15 | clarification | §33.1 ping rule 1 (a second `Authorization` is refused) | Node's `req.headers` silently drops a duplicate `Authorization`, so the refusal holds only when the caller passes `req.rawHeaders` or an iterable. This is documented. | `src/node/oidcTypes.ts:1270-1279`; `src/node/oidc.ts:798-821` | Forced by the platform, recorded. |

---

### Report — python — commit db9fbd6 (merge #93)
Toolchain run: yes — scratch venv (deps from pyproject + pytest/pytest-asyncio/respx), `PYTHONPATH=src pytest -p no:cacheprovider tests` → **1922 passed** (95 s); the eight §28.12–§33 files alone → 108 passed. Plus two scratch probes (outside the repo) confirming F-P1, F-P2, F-P4. Repo left clean (`git status` empty). CONTRACT.md byte-identical to axiam `sdks/CONTRACT.md` (1.58).

Paths below are relative to the `axiam-python-sdk` repository root; `src/` = `src/axiam_sdk/`.

#### Posture per section
| Section | Status | Notes |
|---|---|---|
| §28.12 | implemented | sync + async, session-free transport, rule 1 origin check, no write retry; token args also accept bare `str` (F-P8) |
| §29 | implemented | 11 ops, `client.saml`; exactly-one precheck; generic "every field required" doc text is wrong (F-P6) |
| §30 | implemented | 6 ops, `client.directory`; `bind_secret` `SecretStr`; sparse PATCH exact keys |
| §31 | implemented | 6 ops, `client.scim_targets`; unknown arm refuses to serialize even for logs (F-P5); create call site omits rule 2 (F-P7) |
| §32 | implemented | 5 ops, `client.ssf`; header `SecretStr`; event URIs are strings + named constants |
| §32.7 | implemented (defect) | `SsfReceiver`/`AsyncSsfReceiver`; poll loses recorded events when a later SET raises a non-verdict error (F-P2) |
| §33 | implemented (defect) | 4 ops on both clients; a 5xx carrying an `error` member is terminal in `ciba_await` (F-P1) |
| §33.2 signed | implemented | `CibaRequestSigner` PS256/ES256/EdDSA, caller key+alg, 300 s lifetime |

#### A–F per section

### §28.12
A. `read_client_registration` → `src/_client.py:2216` (async `src/_async_client.py:973`); `update_client_registration` → `src/_client.py:2271` (async :1008); `delete_client_registration` → `src/_client.py:2319` (async :1033); `ClientRegistration` → `src/_registration.py:72`. Unknown members kept in `extra` (`src/_registration.py:141-183`).
B. `registration_access_token`, `client_secret` are `SecretStr` on the type (`src/_registration.py:129,133`); mistyped secrets are dropped, not parked in `extra` (`:174-179`). Operation args typed `SecretStr | str` (`src/_client.py:2218-2219`) — bare str accepted (F-P8). Errors: refusal names no URI part (`src/_registration.py:224-237`); transport error not chained (`src/_errors.py:335-346`).
C. 1 origin refusal → `tests/test_client_registration.py::test_a_uri_at_another_origin_is_refused_locally_and_nothing_is_sent` (+ `test_http_is_accepted_only_against_an_http_loopback_base`); 2 header only → `test_read_and_delete_send_the_bearer_only_and_keep_the_query_verbatim` (logged-in session present; asserts exact bearer, no cookie/CSRF/X-Tenant-ID, empty body, query verbatim); 3 update body → `test_update_drops_the_five_server_stated_members_and_returns_the_rotated_token` + `test_an_update_answered_503_is_not_retried`; 4 errors → `test_a_401_invalid_token_is_an_oauth_protocol_error_and_refreshes_nothing` (refresh route count 0), `test_a_400_invalid_client_metadata_is_an_oauth_protocol_error_and_204_is_ok`; 5 redaction → `test_neither_the_token_nor_the_secret_reaches_any_rendering`. All five present.
D. update: "`metadata` is the **whole** registration … Start from `read_client_registration`'s result" and "**Persist the returned `registration_access_token` before doing anything else.**" (`src/_client.py:2280-2297`). Present.
E. update/delete: one `bare_sync_client.send`, no `retry_sync` (`src/_client.py:2310-2317`, `:2338-2343`); bare transport has `follow_redirects=False`, refusing cookie jar, no transport retries (`src/_session.py:346-370`). Read via `retry_sync` with decisive 4xx lifted out (`src/_client.py:2250-2268`).
F. README `README.md:26-28`: "conforms to **contract 1.58** … §27, §28, §28.12, §29, §30, §31, §32 and §33, with §32.7 and §33.2 signed". Matches code.

### §29
A. `client.saml` (`src/management/ops/__init__.py:251`): `get_idp` :292, `list_service_providers` :300 (+`_all` :311), `create_service_provider` :324, `get_service_provider` :346, `update_service_provider` :354, `delete_service_provider` :386, `parse_sp_metadata` :401, `list_idp_credentials` :421 (plain list), `issue_idp_credential` :429, `promote_idp_credential` :444, `retire_idp_credential` :461 — all in `src/management/ops/saml.py`; async twins :508–:683. Read-modify-write `saml_service_provider_input` `src/management/conversions.py:54`.
B. Nothing wrapped (correct). `SamlIdpCredential` declares no key (`src/management/models.py:4472-4527`); `ManagementModel` ignores unknown members (pydantic default) so `private_key_pem` is dropped.
C. 1→`tests/management/test_saml.py::test_update_service_provider_puts_the_whole_registration`; 2→`::test_sign_assertions_does_not_exist_and_unknown_values_decode`; 3→`::test_parse_sp_metadata_sends_exactly_one_member_and_the_draft_creates` (+ async `::test_the_async_handle_refuses_both_or_neither_too`); 4→`::test_a_credential_has_no_key_member_and_promotion_may_retire_nothing`; 5→`::test_service_providers_page_with_search_and_credentials_are_a_plain_list`; 6→`::test_none_of_the_seven_writes_is_retried_on_503`; 7→`::test_statuses_map_per_section_2`; 8→`::test_get_idp_is_never_cached_and_keeps_null_apart_from_absent`. All eight.
D. update: §27.4 rule 5 warning + defaults listed + entity_id immutable + ECDSA HTTP-POST only (`saml.py:357-375`); create: ECDSA/RSA-only note (:328-333); retire: "stops SAML sign-on for the whole tenant at once" (:465-469); delete: ends no session (:390-391); parse: stores nothing, 503 without SAML (:403-410). Present. Text "Every field of the body is required" (:372-373) contradicts the model (F-P6).
E. `send_management` routes only `GET` through `retry_sync` (`src/management/_request.py:131-138`); writes `attempt(1)`. httpx transport has no retries.
F. as §28.12.

### §30
A. `client.directory`: `get` :171, `set` :179, `update` :207 (PATCH), `delete` :228, `link_account` :246, `get_sync_status` :265 (`src/management/ops/directory.py`); async from :274. `set_directory_config` `src/management/conversions.py:27`.
B. `SetDirectoryConfig.bind_secret` / `UpdateDirectoryConfig.bind_secret` are `SecretStr | None` (`src/management/models.py:5417,6415`); unwrapped only in `to_wire` (`src/management/_wire.py:69-90`); `DirectoryConfig` has no secret member; `_SECRET_MEMBER_NAMES` (`_wire.py:123-125`) also strips them from open-union catch-alls. Nothing else wrapped.
C. 1→`tests/management/test_directory.py::test_the_bind_secret_reaches_the_wire_and_no_rendering`; 2→`::test_a_bind_secret_in_a_response_is_dropped`; 3→`::test_update_sends_exactly_the_members_it_was_given` (exact `{"enabled":false}`, two keys, `{"group_filter":null}`); 4→`::test_set_needs_its_seven_members_sends_them_and_decodes_201_and_200`; 5→`::test_no_write_is_retried_on_503`; 6→`::test_errors_map_per_section_2_and_link_account_sends_only_the_user_id`. All six.
D. set + update: "**Moving the connection requires the secret again** (§30.3 rule 2) … The SDK holds no copy" (`directory.py:182-188`, `:210-215`); delete: "stops the directory, and only that … no unlink" (:231-236); link_account: "**Signs the account's owner out everywhere**" (:249-254). Present.
E. as §29 (`_request.py:131-138`).
F. as §28.12.

### §31
A. `client.scim_targets`: `list` :175 (+`list_all` :183), `create` :195, `get` :210, `update` :218, `delete` :246, `reconcile` :262 (`src/management/ops/scim_targets.py`); `scim_target_input` `conversions.py:84`.
B. `ScimTargetInput.credential: SecretStr | None` (`models.py:4948`); response type has none; unknown `auth` arm drops `credential` (`_wire.py:179-187`). Nothing else wrapped.
C. 1→`tests/management/test_scim_targets.py::test_the_credential_is_on_the_wire_and_in_no_rendering`; 2→`::test_a_credential_in_a_response_is_dropped` (asserts `repr`/`str` only — JSON dump of that value raises, F-P5); 3→`::test_update_without_a_credential_sends_no_key_and_the_variants_keep_their_shape`; 4→`::test_unknown_values_decode_and_the_pager_carries_search`; 5→`::test_no_write_is_retried_on_503`; 6→`::test_statuses_map_and_reconcile_is_a_bodyless_202`. All six.
D. update: "**The credential is bound to its URL** (§31.3 rule 2) …" (`scim_targets.py:221-230`); delete: "**Deprovisions nothing downstream**" (:249-253); create says only "`credential` is required here (§31.3 rule 2)" (:198-199) — the URL-binding rule is not repeated (F-P7).
E. as §29.
F. as §28.12.

### §32 (management)
A. `client.ssf`: `list_streams` :171 (+`_all` :179), `create_stream` :188, `get_stream` :200, `update_stream` :208, `delete_stream` :235 (`src/management/ops/ssf.py`); `ssf_stream_input` `conversions.py:106`.
B. `SsfStreamInput.authorization_header: SecretStr | None` (`models.py:5968`); `SsfStream` has only `authorization_header_set`. Event URIs: strings, named constants in `src/ssf/_receiver.py:63-87` (also `axiam_sdk.ssf`); unknown URI decodes, refused on send (`_wire.py:128`).
C. 1→`tests/management/test_ssf.py::test_update_stream_puts_every_member_it_models`; 2→`::test_the_push_header_is_sent_and_never_rendered`; 3→`::test_unknown_values_and_an_inactive_transmitter_decode`; 4→`::test_list_streams_pages_with_search_on_every_request`; 5→`::test_no_write_is_retried_on_503`; 6→`::test_statuses_map_per_section_2`. All six.
D. update_stream: header exception + §32.3 rule 5 + 409 overtaken (`ssf.py:211-219`). Present.
E. as §29.
F. as §28.12.

### §32.7 (receiver helper)
A. `SsfReceiver.verify_set` `src/ssf/_receiver.py:729`, `SsfReceiver.poll` :759; `AsyncSsfReceiver.verify_set` :909 / `.poll` :918. Config `{issuer, audience, jwks_uri|discovery_url, access_token_provider}` (:656-690).
B. Poll bearer from provider, `SecretStr | str` (:274-281), only in the `Authorization` header (`_bearer` :634-637); `repr` hides provider (:388-395, :692-694). Nothing else secret.
C. 1→`tests/test_ssf_receiver.py::test_a_set_signed_by_the_jwks_key_verifies_into_its_claims`; 2→`::test_a_wrong_typ_or_alg_is_refused_in_that_order`; 3→`::test_another_key_or_a_tampered_payload_is_invalid_key`; 4→`::test_another_issuer_or_audience_is_refused`; 5→`::test_exp_sub_two_events_or_missing_members_are_invalid_request`; 6→`::test_a_replay_is_refused_and_a_short_window_is_refused_at_configuration`; 7→`::test_an_unknown_kid_costs_one_refetch_and_a_second_one_none` (cache primed first, so the cold-start double fetch F-P4 is not exercised); 8→`::test_poll_passes_ack_and_set_errs_through_and_sorts_the_answer` + `::test_poll_is_not_retried_on_400_and_is_on_503`. All eight. Keys generated at run time.
D. `poll` docstring: "**Nothing is acknowledged on your behalf** … A SET you neither acknowledge nor refuse is re-offered -- and … reads as `replayed`" (:768-776). Present.
E. `poll`: `retry_sync`, `status_is_retryable` gate → 4xx except 408/429 returned, not raised (:795-812; async :944-960).
F. "with §32.7 … " (`README.md:28`). Matches.

### §33
A. `ciba_initiate` `src/_client.py:2027` / async `src/_async_client.py:853`; `ciba_poll` :2100 / :895; `ciba_await` :2158 / :937; `ciba_handle_ping` `src/_oidc.py:1712` (shared mixin, sync on both). `CibaInitiateResponse` `src/_ciba.py:160`.
B. `CibaInitiateResponse.auth_req_id: SecretStr` (`_ciba.py:165`); `ciba_handle_ping` returns `SecretStr` (`_ciba.py:529`); `client_notification_token`, `auth_req_id` input and `expected_token` typed `SecretStr | str` (`_client.py:2038`, :2102; `_oidc.py:1716`) — bare str accepted (F-P8). Error messages name no value (`_ciba.py:499-501`, `:350-374`).
C. 1→`tests/test_ciba.py::test_t01_the_three_values_are_on_the_wire_and_in_no_rendering`; 2→`::test_t02_…`; 3→`::test_t03_exactly_the_members_set_are_sent`; 4→`::test_t04_initiate_is_sent_once_on_503_429_and_a_dropped_connection` + `::test_t04_a_dropped_connection_is_one_attempt_and_a_network_error` (raw socket, accepts==1); 5→`::test_t05_…` (+ `…unknown_answer_without_an_error_member…`); 6→`::test_t06_…` (injected clock); 7→`::test_t07_…`; 8→`::test_t08_a_500_and_a_429_mid_loop_are_survived` (+ transport variant); 9→`::test_t09_…` (+ unreadable 200 one request); 10–13→`::test_t10…t13`; 14–16→`::test_t14…t16`. All sixteen. Gap: no test of a 5xx **with** an `error` body mid-loop (F-P1).
D. initiate: "**Never retried** …", "**A success proves nothing about the user**", personal-data note (`_client.py:2057-2072`); poll: "**Store the returned tokens before anything else**" (:2122-2124); await: ping-mode guidance (:2182-2186); handle_ping: answer 204 then poll (`_oidc.py:1733-1738`). Present.
E. initiate: single `_rest_send_sync`, `TransportError`→`NetworkError`, no `retry_sync` (`_client.py:2093-2098`); `_send_sync` has no 401 interceptor (`src/_session.py:430-454`); httpx client has no transport retries.
F. "§33, with … §33.2 signed" (`README.md:27-28`). Matches.

#### Q1 … Q10

### Q1 Replay store
- Interface: `ReplayStore` Protocol, `check_and_record(jti: str, window_seconds: float) -> bool`, **sync** (also for `AsyncSsfReceiver`) — `src/ssf/_receiver.py:239-250`. Atomic check-and-insert ("MUST be atomic").
- Default `MemoryReplayStore` (:253-271): dict `jti → expiry`, `threading.Lock`, every call rebuilds the dict dropping expired entries (O(n) per call); **no cap** (unbounded within 7 days); own clock `time.monotonic`, not the receiver's injected clock (:256, :382).
- Expiry: per-entry `now + window`.
- Store error: not caught — `finish()` (:559) propagates the store's raw exception from `verify_set`; no event returned (fail closed), not classified as `SetVerificationError`/`NetworkError`; in `poll` it aborts the whole poll (F-P2).
- Recorded only after steps 1–8 (and the poll-key check): store call is last (`:554-560`).
- Window floor: constructor refusal, `local_refusal("ssf.receiver","replay_window",…)` = management `ValidationError` (`:359-365`); default = floor = 7 d (`MIN_REPLAY_WINDOW_SECONDS` :89).

### Q2 verify_set order and codes
Order follows 1–9 (`_receiver.py:400-439` parse, `:505-570` finish): 1 split/sig-b64/header+payload JSON objects → `malformed`; 2 `typ` case-insensitive, `secevent+jwt`|`application/secevent+jwt` → `invalid_type`; 3 `alg` exactly `"EdDSA"` → `invalid_key`; 4 missing `kid` → `invalid_key` before any fetch, then lookup with one forced refetch; 5 Ed25519-only key, OKP verify → `invalid_key`; 6 `iss` exact → `invalid_issuer`; 7 `aud` string or array containing → `invalid_audience`; 8 `exp`/`sub` present, `jti` non-empty str, `iat` int|float (not bool), `sub_id` object, `events` exactly one → `invalid_request`; extra in poll only: map key ≠ `jti` → `invalid_request` (:554-557); 9 → `replayed`. Codes exact. Kid-miss refetch: one, rate-limited by a global `last_forced` ≥60 s (:446-451, :713-727); a cold cache costs fill + forced refetch = 2 fetches (F-P4, probe). JWKS lifespan 300 s. JWKS/discovery fetch over the session-free transport, https or loopback-http only (:308-322).

### Q3 poll
Never acknowledges (body built only from caller args, `:580-597`); `ack`/`set_errs` passed as given (`SetErr.to_wire`); refused returned as `RefusedSet(jti, reason: SetFailureReason)` (:214-222); not retried on 4xx other than 408/429 (:805-807); token from `access_token_provider` (called once per poll, before the retry loop, :793); missing provider → local `AuthError` (:640-645, :789). URL `{base_url}/ssf/v1/poll/{quoted id}` (:575-577).

### Q4 ciba_await
- Injectable `clock` with `now()`/`sleep()` (`CibaClock`/`AsyncCibaClock`, `_ciba.py:181-203`); default monotonic.
- Initial interval = response `interval` if >0 else 5 (`_ciba.py:429-437`, `_client.py:2195`); no faster floor; sleeps before first poll (:2199).
- `slow_down` `+= 5`, cumulative, never reset (:2207-2208); **no 60 s cap**.
- Deadline `received_at + expires_in`; stops when `now + interval >= deadline` and raises `CibaExpiredTokenError` locally (:2194-2198) — up to one interval early. `received_at` defaults to `time.monotonic()` at model construction (`_ciba.py:176`), independent of the injected clock.
- 5xx/transport: retried per §16 inside `ciba_poll` (:2139-2143), then `poll_step`→"transient", loop continues; 429 `rate_limit_exceeded` (body) → transient (`_ciba.py:152-153`); bodiless 429 → retried then transient. **A 5xx carrying an `error` member is terminal** (F-P1).
- Cancellation: sync none; async via task cancellation (`await clock.sleep`).
- `auth_req_id` held only in the caller's `CibaInitiateResponse` and the loop; never cached.

### Q5 ciba_handle_ping
`hmac.compare_digest` on UTF-8 bytes (`_ciba.py:514-517`); returns `SecretStr` (:529); missing / duplicated (multi-items aware) / non-`Bearer` / empty / wrong / double-space → one `AuthError` naming no value (:499-517); bad body → `ValidationError` (:518-528); synchronous on both clients (`_oidc.py:1712`); no network (test t13).

### Q6 Signed request
Offered: `CibaRequestSigner(alg, private_key, kid=None)` `_ciba.py:239`; algs PS256/ES256/EdDSA, no defaults, probe-sign at construction (:273-289). Claims: every member + `iss`=client_id, `aud`=discovery `issuer` (string), `iat`=`nbf`=now, `exp`=now+300, `jti`=128-bit hex (:307-325); `requested_expiry` a JSON number inside. Form carries only client auth + `request` (:395-409). Key held as a prepared key object, `repr` redacted (:301-305); the `request` string is a transient plain `str` in the form dict. No private_key_jwt anywhere in the SDK (F-P12).

### Q7 Kept-secret-on-update
All three omit when unset: `to_wire` = `model_dump(exclude_unset=True)` (`_wire.py:84-90`); read→body converters leave the secret unset (`conversions.py:27-51, 84-103, 106-128`). Keep = leave unset; replace = set a `SecretStr`; SSF clear = `clear_authorization_header=True`. An explicitly assigned `None` is sent as JSON `null` (`_wire.py:72-75`) — a third, server-refused state (F-P9). Tests: `test_set_needs_its_seven_members…` asserts `"bind_secret" not in body`; scim test 3 asserts no `credential` key; ssf test 1 asserts no `authorization_header`.

### Q8 §21.3.1 pin
`tests/test_ciba.py:824-847`: `assert set(vector["mtls_endpoint_aliases"]) == set(MtlsEndpointAliases.model_fields)` and `assert len(vector["mtls_endpoint_aliases"]) == 7` (vector read from the vendored CONTRACT.md); `tests/test_mtls_endpoint_aliases.py:288-303` pins the seven field names. `ciba_initiate` prefers the alias on an mTLS client (`_oidc.py:1691-1710` via `_preferred_optional_endpoint`), asserted `mtls.call_count == 1 and front.call_count == 0`, tenant_id displaced not duplicated; no-cert client uses top-level. `MtlsEndpointAliases` is a closed model that ignores extra keys (`src/_models.py:233-288`).

### Q9 §28.12 details
URI verbatim (`httpx.URL(uri)` returned unchanged, `_registration.py:239-256`); body strips the five and sets `client_id` (`:185-208`, set `SERVER_STATED_MEMBERS` :49-55); only `Authorization: Bearer` on a bare `httpx.Request` (`:259-274`) over the cookie-refusing, non-redirecting transport; 401 → `OAuthProtocolError`, no refresh (structurally: bare transport, and test asserts refresh count 0).

### Q10 Other divergences / contract-silent decisions
1. 5xx + `error` body on `ciba_poll` → terminal (F-P1). Contract ambiguity: "an unknown `error` falls back to §2" vs. "body with an `error` member is OAuthProtocolError at any status".
2. Poll partial-failure loses recorded events (F-P2); contract silent on poll atomicity vs. step 9.
3. Poll-mode `client_notification_token` refused locally; caller must declare `delivery` (`_ciba.py:360-376`).
4. `ciba_poll` validates the ID token before returning; a JWKS/ID-token failure after a `200` discards a redeemed token set (`_oidc.py:1155-1166`) — tension with §33.7 rule 7.
5. Unknown open-union arm makes the whole response un-serializable (F-P5).
6. `iat` accepted as float (Java requires integer).
7. `ClientRegistration.update_body` sends list members only when non-empty or present on read (`_registration.py:202-205`) — Java always sends them.
8. Replay-window refusal type is the management `ValidationError` (a `NetworkError` subtype).
9. Default replay store unbounded and not on the injected clock.
10. `AsyncSsfReceiver` uses a sync store protocol.

#### Findings
| id | Severity | Clause | What | Evidence (path:line) | Suggested disposition |
|---|---|---|---|---|---|
| F-P1 | defect | §33.7 r5, §33.4 | A `5xx` whose body carries an `error` member (e.g. `503 {"error":"temporarily_unavailable"}`) becomes `OAuthProtocolError`, is not §16-retried and ends `ciba_await` as terminal after one poll (probe confirmed). | `src/_errors.py:329-331`; `src/_client.py:2139-2144`; `src/_ciba.py:143-157` | SDK fix (treat status ≥500/429 as transient whatever the body, except the named CIBA codes) + contract clarification of "unknown error falls back to §2" |
| F-P2 | defect | §32.7 step 9, poll | A non-verdict exception on the k-th SET of a poll (replay-store error, JWKS `NetworkError` on a forced refetch) aborts `poll` after SETs 1..k-1 were verified **and recorded**; they are never returned, and when re-offered read `replayed` — silently lost (probe confirmed). | `src/ssf/_receiver.py:559`, `:819-828` (async `:968-977`) | SDK fix (return partial result / record after the batch / un-record) + contract clarification (store failure fails closed for that SET only) |
| F-P3 | clarification | §32.7 step 9 | Store failure propagates the store's raw exception (fail closed, unclassified). | `src/ssf/_receiver.py:559` | contract clarification (name the error) |
| F-P4 | clarification | §32.7 step 4 | Unknown `kid` on a cold cache costs two JWKS fetches (fill + forced); test 7 primes first so it is not seen. | `src/ssf/_receiver.py:713-727` | contract clarification ("one refetch" after the initial fill?) |
| F-P5 | clarification | §31.2/§31.8 t4, §7 | A decoded `ScimTargetResponse` with an unknown `auth`/`scope` arm raises `PydanticSerializationError` on `model_dump`/`model_dump_json` — logging it as JSON fails; test 2 asserts `repr`/`str` only. | `src/management/_wire.py:189-196`; `tests/management/test_scim_targets.py:118-139` | SDK fix (serialize the arm for logs, refuse only in `to_wire`) / contract clarification |
| F-P6 | doc | §27.4 r5, §29.2/§30.2/§31.2/§32.2 | Generated replace-op docstrings say "Every field of the body is required" while only 3/7/4/4 members are. | `src/management/ops/saml.py:372-373`; `directory.py:193`; `scim_targets.py:232`; `ssf.py:221` (and async twins) | SDK fix (generator text) |
| F-P7 | doc | §31.3 r2 | `scim_targets.create` does not repeat the credential-bound-to-URL rule ("both call sites"). | `src/management/ops/scim_targets.py:198-199` | SDK fix / contract clarification of "both call sites" |
| F-P8 | clarification | §28.12.4, §33.5, §7 | Sensitive inputs typed `SecretStr | str`: registration token args, `auth_req_id`, `client_notification_token`, `expected_token`, signer key. | `src/_client.py:2218-2219,2038,2102`; `src/_oidc.py:1716`; `src/_ciba.py:250` | contract clarification (is a bare-str overload acceptable) — forced by Python idiom only partly |
| F-P9 | clarification | §30.2, §31.3 r2, §32.2 | An explicitly assigned `None` secret is sent as JSON `null` (third state beside keep/replace). | `src/management/_wire.py:72-75`; `README.md:53` | contract clarification / SDK may refuse `None` on secrets |
| F-P10 | clarification | §33.2 | Poll-mode request carrying a `client_notification_token` refused locally; contract silent. | `src/_ciba.py:368-374` | contract clarification |
| F-P11 | clarification | §33.7 r7 | ID-token validation runs before tokens are handed back; a JWKS failure after redemption loses the token set. | `src/_oidc.py:1155-1166`; `src/_client.py:2149` | contract clarification |
| F-P12 | clarification | §33.1, §21.8, §33.3 r10 | CIBA client auth is `client_secret_post` or `tls_client_auth` only; no `private_key_jwt` in the SDK. | `src/_oidc.py:1669-1689` | contract clarification (record per-SDK) |
| F-P13 | clarification | §33.7 r2–4 | `received_at` uses `time.monotonic()` independent of the injected clock; loop stops up to one interval before the deadline; no 60 s cap. | `src/_ciba.py:176`; `src/_client.py:2194-2208` | contract clarification |
| F-P14 | clarification | §32.7 | Replay store protocol is sync even for `AsyncSsfReceiver`; default store unbounded, own clock. | `src/ssf/_receiver.py:239-271,382` | SDK fix (optional) |
| F-P15 | doc | — | `ManagementMethod` docstring says PATCH arrived with contract 1.58 (it was 1.54). | `src/management/_request.py:34` | SDK fix |

Counts: defect 2, doc 3, clarification 10.

---

### Report — java — commit 2b34d08 (merge #108)
Toolchain run: yes — on a `git archive` copy in scratch (the repo itself untouched): `mvn -q -B test -Djacoco.skip=true` → **1393 tests, 0 failures, 0 errors** (107 classes); the eight §28.12–§33 classes alone (`CibaTest, ClientRegistrationTest, AxiamClientMtlsEndpointAliasesTest, DirectoryTest, SamlTest, ScimTargetsTest, SsfManagementTest, SsfReceiverTest`) → 87 pass. Plus three scratch probes against the built classes, confirming F-J1 (silent re-send of a write), F-J5 (tenant-path 401 → refresh + re-sent initiate) and F-J6 (unknown enum sent as `""`). CONTRACT.md byte-identical to axiam `sdks/CONTRACT.md` (1.58).

Paths are relative to the `axiam-java-sdk` repository root; `M/` = `src/main/java/io/axiam/sdk/`, `T/` = `src/test/java/io/axiam/sdk/`.

#### Posture per section
| Section | Status | Notes |
|---|---|---|
| §28.12 | implemented | session-free, no-retry OkHttp client; `Sensitive` args; `*Async` twins |
| §29 | implemented (defect) | 11 ops `saml()`; writes can be silently re-sent by OkHttp (F-J1); unknown enum re-sent as `""` (F-J6) |
| §30 | implemented (defect) | 6 ops `directory()`; F-J1 applies |
| §31 | implemented (defect) | 6 ops `scimTargets()`; F-J1, F-J6 apply |
| §32 | implemented (defect) | 5 ops `ssf()`; F-J1, F-J6 apply (event types are an enum: unknown URI lost and re-sent as `""`) |
| §32.7 | implemented (defect) | `SsfReceiver` sync + `pollAsync`; poll loses recorded events on a non-verdict error (F-J7) |
| §33 | implemented (defect) | 4 ops + `*Async` for the I/O three; tenant-path 401 enters §9 and re-sends initiate (F-J5); 5xx+`error` terminal (F-J2); decisive `NetworkError`s loop (F-J3) |
| §33.2 signed | implemented | `CibaRequestSigner` PS256/ES256/EdDSA, caller key+alg, 300 s lifetime |

#### A–F per section

### §28.12
A. `readClientRegistration` `M/AxiamClient.java:4183` (+`Async` :4221); `updateClientRegistration` :4263 (+`Async` :4298); `deleteClientRegistration` :4321 (+`Async` :4343); `ClientRegistration` record `M/oidc/ClientRegistration.java` (unknown members in `extra`, `fromJson` :160-193).
B. Args are `Sensitive` (no `String` overload); record members `clientSecret`, `registrationAccessToken` are `Sensitive` (`ClientRegistration.java` record header; `fromJson` :186-191) — `toString` `[SENSITIVE]`, Jackson via `Sensitive.Redactor` (`M/Sensitive.java`). Gap: a **non-string** `registration_access_token`/`client_secret` stays in `extra` and is rendered (`takeString` :239-249 leaves mistyped nodes) (F-J14). Errors: refusal names no URI part (`:4356-4389`).
C. 1 → `T/ClientRegistrationTest.java::aUriAtAnotherOriginIsRefusedLocallyAndNothingIsSent`; 2 → `::readAndDeleteSendTheBearerOnlyAndKeepTheQueryVerbatim` (logged-in client; exact bearer, no Cookie/CSRF, SDK access token absent, empty body, query verbatim; delete 204); 3 → `::updateDropsTheFiveServerStatedMembersAndReturnsTheRotatedToken` + `::anUpdateOrDeleteAnswered503IsNotRetriedAndAReadIs`; 4 → `::a401InvalidTokenIsAnOAuthProtocolErrorAndRefreshesNothing` (refresh calls 0), `::a400InvalidClientMetadataIsAnOAuthProtocolError`; 5 → `::neitherTheTokenNorTheSecretReachesAnyRendering`. All five.
D. update Javadoc: "`metadata` is the **whole** registration … Start from readClientRegistration's result" and "**Persist the returned registrationAccessToken() before doing anything else.**" (`:4232-4245`). Present.
E. update/delete: one `sessionlessHttpClient.newCall` (:4278, :4327); `Sessionless.of` = no interceptors, `NO_COOKIES`, `Authenticator.NONE`, `followRedirects(false)`, **`retryOnConnectionFailure(false)`** (`M/internal/Sessionless.java:37-48`). Read via `StatusRetry.run`, only `Transient` retried (:4186-4212; `M/internal/StatusRetry.java`).
F. `README.md:27-29`: "conforms to **contract 1.58**: … §27, §28, §28.12, §29, §30, §31, §32 and §33, with §32.7 and §33.2 signed". Names match; the claim "None of the writes is retried" (`README.md` §29–§32 section) is not true at the transport (F-J1).

### §29
A. `client.saml()` `M/AxiamClient.java:1410` → `M/management/SamlApi.java`: `getIdp` :61, `listServiceProviders` :82 (+`All` :101), `createServiceProvider` :126, `getServiceProvider` :147, `updateServiceProvider` :184, `deleteServiceProvider` :210, `parseSpMetadata` :239 (`ManagementChecks.parseSpMetadataExactlyOne` :241), `listIdpCredentials` :260 (`List`), `issueIdpCredential` :287, `promoteIdpCredential` :315, `retireIdpCredential` :344. No management `*Async` (consistent across §27). `ReplacementBodies.from(SamlServiceProvider)` `M/management/ReplacementBodies.java:36`.
B. Nothing wrapped; `SamlIdpCredential` `@JsonIgnoreProperties(ignoreUnknown = true)` and no key component (`M/management/models/SamlIdpCredential.java:34-36`).
C. 1 → `T/management/SamlTest.java::updateServiceProviderPutsTheWholeRegistration` (asserts 11 members present; the "cannot be built without" half rests on the positional constructor, which accepts `null` — F-J10); 2 → `::signAssertionsDoesNotExistAndUnknownValuesDecode` (re-encode test **replaces** the unknown binding before sending, so it never observes F-J6); 3 → `::parseSpMetadataSendsExactlyOneMemberAndTheDraftCreates`; 4 → `::aCredentialHasNoKeyMemberAndPromotionMayRetireNothing`; 5 → `::serviceProvidersPageWithSearchAndCredentialsAreAPlainList`; 6 → `::noneOfTheSevenWritesIsRetriedOn503` (status only); 7 → `::statusesMapPerSection2`; 8 → `::getIdpIsNeverCachedAndKeepsNullApartFromAbsent`. All eight.
D. update: defaults + entity_id immutable + ECDSA HTTP-POST only + §27.4 r5 warning (`SamlApi.java:157-172`); create: RSA/ECDSA note (:109); delete: ends no session (:196); parse: stores nothing (:221); retire: "stops SAML sign-on for the whole tenant" (:327). Present; "Every field of the body is required" (:167) is wrong for this type (F-J11).
E. `ManagementTransport.send`: non-GET → single `attempt` (`M/internal/ManagementTransport.java:204-206`), but over `httpClient` (`M/AxiamClient.java:1043-1045`), whose OkHttp default `retryOnConnectionFailure=true` silently re-sends a write after a pooled-connection failure (probe: server received the PUT twice) — F-J1.
F. as §28.12.

### §30
A. `client.directory()` `M/AxiamClient.java:1393` → `M/management/DirectoryApi.java`: `get` :61, `set` :98, `update` :130 (PATCH), `delete` :158, `linkAccount` :187, `getSyncStatus` :207. `ReplacementBodies.from(DirectoryConfig)` :109.
B. `SetDirectoryConfig.bindSecret`, `UpdateDirectoryConfig.bindSecret` are `@Nullable Sensitive` (`models/SetDirectoryConfig.java:52`, `models/UpdateDirectoryConfig.java:52`); unwrapped only by `ManagementTransport.WIRE`'s mixin (`ManagementTransport.java:72-87`); `DirectoryConfig` ignores unknown members and has no secret component.
C. 1 → `T/management/DirectoryTest.java::theBindSecretReachesTheWireAndNoRendering`; 2 → `::aBindSecretInAResponseIsDropped`; 3 → `::updateSendsExactlyTheMembersItWasGiven` (exact bodies incl. `{"group_filter":null}`); 4 → `::setSendsEveryRequiredMemberAndDecodes201And200` (its comment "does not compile" is not true for `null` — F-J10); 5 → `::noWriteIsRetriedOn503`; 6 → `::errorsMapPerSection2AndLinkAccountSendsOnlyTheUserId`. All six.
D. set/update: "**Moving the connection requires the secret again** (§30.3 rule 2)" (`DirectoryApi.java:73`, `:110`); delete: "**Deleting stops the directory, and only that**" (:142); linkAccount: "**Signs the account's owner out everywhere**" (:169). Present.
E. as §29 (F-J1).
F. as §28.12.

### §31
A. `client.scimTargets()` `M/AxiamClient.java:1441` → `M/management/ScimTargetsApi.java`: `list` :51 (+`listAll` :69), `create` :91, `get` :111, `update` :147, `delete` :173, `reconcile` :199. `ReplacementBodies.from(ScimTargetResponse)` :88.
B. `ScimTargetInput.credential` `@Nullable Sensitive` (`models/ScimTargetInput.java:44`); response ignores unknown members; `ScimTargetAuthUnknown` keeps only `type` and refuses to serialize (`models/ScimTargetAuthUnknown.java`).
C. 1 → `T/management/ScimTargetsTest.java::theCredentialIsOnTheWireAndInNoRendering`; 2 → `::aCredentialInAResponseIsDropped`; 3 → `::updateWithoutACredentialSendsNoKeyAndTheVariantsKeepTheirShape`; 4 → `::unknownValuesDecodeAndThePagerCarriesSearch` (asserts unknown **arm** refused; unknown **enums** decode to `UNKNOWN` — never checked on send, F-J6); 5 → `::noWriteIsRetriedOn503`; 6 → `::statusesMapAndReconcileIsABodiless202`. All six.
D. update: "**The credential is bound to its URL** (§31.3 rule 2)" (`ScimTargetsApi.java:122`); delete: "**Deprovisions nothing downstream**" (:158); create only "`credential` is required here (§31.3 rule 2)" (:76) — URL binding not repeated (F-J12).
E. as §29 (F-J1).
F. as §28.12.

### §32 (management)
A. `client.ssf()` `M/AxiamClient.java:1426` → `M/management/SsfApi.java`: `listStreams` :61 (+`All` :80), `createStream` :99, `getStream` :120, `updateStream` :156, `deleteStream` :179. `ReplacementBodies.from(SsfStream)` :64.
B. `SsfStreamInput.authorizationHeader` `@Nullable Sensitive` (`models/SsfStreamInput.java:45`); `SsfStream` has only `authorizationHeaderSet`. Event types modelled as enum `SsfEventType` with `UNKNOWN("")` (`models/SsfEventType.java:47`) — contract SHOULD (strings + constants) not followed; unknown URIs are lost on decode and re-sent as `""` (F-J6). Constants also in `M/ssf/SsfEventTypes.java`.
C. 1 → `T/management/SsfManagementTest.java::updateStreamPutsEveryMemberItModels`; 2 → `::thePushHeaderIsSentAndNeverRenderedOrDecoded`; 3 → `::unknownValuesAndBothTransmitterStatesDecode`; 4 → `::listStreamsPagesAndTheWalkCarriesSearch`; 5 → `::noneOfTheThreeWritesIsRetriedOn503`; 6 → `::statusesMapPerSection2`. All six.
D. updateStream: header exception + §32.3 r5 + 409 overtaken (`SsfApi.java:132-137`). Present.
E. as §29 (F-J1).
F. as §28.12.

### §32.7 (receiver helper)
A. `SsfReceiver.verifySet` `M/ssf/SsfReceiver.java:146`, `.poll` :382, `.pollAsync` :465 (no `verifySetAsync`; contract permits sync). Config `SsfReceiverConfig.builder(issuer, audience, SsfKeySource)` + `accessTokenProvider` (`M/ssf/SsfReceiverConfig.java`).
B. Poll bearer `Sensitive` from the provider (:409), only in the header; `toString` shows config only.
C. 1 → `T/ssf/SsfReceiverTest.java::aSetSignedByTheJwksKeyVerifiesIntoItsClaims`; 2 → `::aWrongTypOrAlgIsRefusedInThatOrder`; 3 → `::anotherKeyOrATamperedPayloadIsInvalidKey`; 4 → `::anotherIssuerOrAudienceIsRefused`; 5 → `::expSubTwoEventsOrNoJtiIsInvalidRequest`; 6 → `::aReplayIsRefusedAndAShortWindowIsRefusedAtConfiguration` (+ `::theMemoryStoreForgetsAfterTheWindow`); 7 → `::anUnknownKidCostsOneRefetchAndASecondOneNone`; 8 → `::pollPassesAckAndSetErrsThroughAndSortsTheAnswer` + `::pollIsNotRetriedOn400ButIsOn503`. All eight; keys generated at run time.
D. poll Javadoc: "**Nothing is acknowledged on your behalf** … A SET you neither acknowledge nor refuse is re-offered, and … then reads as replayed" (:362-368). Present.
E. poll: `StatusRetry.run`, `Transient` only for `retryableStatus` (408/429/5xx) and IOException (:411-436); transport `Sessionless.of(client.okHttpClient())` (:100) — retry-on-connection-failure off.
F. "with §32.7 …" (`README.md:28-29`), README section `README.md:2131`. Matches.

### §33
A. `cibaInitiate` `M/AxiamClient.java:4454` (+`Async` :4506); `cibaPoll` :4536 / short form :4581 (+`Async` :4592); `cibaAwait` :4635 / short :4677 (+`Async` :4686, only for the short form); `cibaHandlePing` :4719 (pairs) / :4766 (multimap), synchronous. Request builder `M/oidc/CibaInitiateRequest.java`, sealed hint `M/oidc/CibaUserHint.java`.
B. `CibaInitiateResponse.authReqId` `Sensitive` (record, `M/oidc/CibaInitiateResponse.java`); poll input `Sensitive` only; ping returns `Sensitive`; `expectedToken` `Sensitive`; notification token `Sensitive` in the builder; `CibaUserHint.toString` hides the hint. Leak path: public `CibaInitiateRequest.members()` returns the raw notification token in a plain `Map` (`CibaInitiateRequest.java:127-146`) (F-J4).
C. 1 → `T/CibaTest.java::t01TheValuesAreOnTheWireAndInNoRendering`; 2 → `::t02NoCredentialIsRefusedLocallyAndOneIsSentWithTenantInTheQuery`; 3 → `::t03ExactlyTheMembersSetAreSent`; 4 → `::t04InitiateIsSentOnceOn503429AndADroppedConnection` (fresh-connection drop: OkHttp would not retry that case anyway, so the test cannot see a retry-on-connection-failure regression); 5 → `::t05…`; 6 → `::t06…` (injected `CibaClock`); 7 → `::t07…`; 8 → `::t08A500AndA429MidLoopAreSurvived`; 9 → `::t09ASecondRedemptionIsInvalidGrantAndNotRetried`; 10–13 → `::t10…t13`; 14–16 → `::t14…t16`. All sixteen. Gaps: no 5xx-with-`error` (F-J2), no bodiless 4xx / unreadable 200 inside `cibaAwait` (F-J3), no tenant-path endpoint (F-J5).
D. initiate: "**Never retried** …", "**A success proves nothing about the user**" (`:4435-4443`); poll: "**Store the returned tokens before anything else**" (`:4524-4526`); await: ping-mode guidance (:4620-4624); ping: answer 204 then poll (:4705-4710). Present.
E. initiate over `sendOnceHttpClient` = `httpClient.newBuilder().retryOnConnectionFailure(false)` (`:722`, `:4481`) — but it **inherits** the `AuthAuthenticator` and `followRedirects(true)`; the authenticator's 401 exclusion is an exact-path set (`M/internal/SessionState.java:70-74`, `M/rest/AuthAuthenticator.java:67-72`), so `/t/{tid}/oauth2/bc-authorize` → refresh + re-send (probe: 2 initiate requests, 1 refresh) — F-J5.
F. "§33, with … §33.2 signed … for all three algorithms" (`README.md:27-29, 45-48`). Matches the code's surface.

#### Q1 … Q10

### Q1 Replay store
`ReplayStore` `@FunctionalInterface boolean checkAndRecord(String jti, Duration window)`, **sync**, atomic check-and-insert (`M/ssf/ReplayStore.java:24`). Default `MemoryReplayStore`: `HashMap<String, Long>` expiry in `System.nanoTime`, `synchronized`, `removeIf` sweep of expired entries on every call, **no cap**, no injectable clock (`M/ssf/MemoryReplayStore.java:21-34`). Store error: not caught (`SsfReceiver.java:250`) — the raw exception leaves `verifySet` (fail closed, unclassified) and aborts `poll` (F-J7). Recorded only after 1–8 and the poll-key check (store call is last, :245-252). Floor: `SsfReceiverConfig.Builder.build()` refuses `< MIN_REPLAY_WINDOW` (7 days, :22, :150) with `LocalRefusal` → `ValidationError` (operation `ssf.receiver`, field `replay_window`); default = floor.

### Q2 verifySet order and codes
`SsfReceiver.java:163-256`: 1 three parts, sig part base64url, header+payload JSON objects → `malformed`; 2 `typ` `equalsIgnoreCase` either form → `invalid_type` (:181); 3 `alg` exactly `"EdDSA"` → `invalid_key` (:185); 4 non-textual `kid` → `invalid_key`, then `keyFor` (:189-195); 5 nimbus `Ed25519Verifier` on the JWKS OKP (Ed25519 curve only, :291-307) → `invalid_key`; 6 `iss` exact → `invalid_issuer`; 7 `aud` string or array → `invalid_audience`; 8 `exp`/`sub` present, `jti` non-empty, **`iat` integral only** (:233; Python also accepts a float), `sub_id` object, exactly one event → `invalid_request`; poll-only map key ≠ `jti` → `invalid_request` (:245); 9 → `replayed`. Codes exact. Refetch: cold or expired (300 s) cache = one fetch and **no** forced refetch in that call (:272-279); otherwise one forced refetch, globally rate-limited 60 s (:280-286). JWKS/discovery over `https` or loopback `http` only (:338-349); a non-2xx fetch → `NetworkError`.

### Q3 poll
Never acknowledges; body only from `SsfPollOptions` members set (`none()` → `{}`) (:392-406); `setErrs` serialized from `SetErr`; refused as `RefusedSet(jti, SetFailureReason)` (:443-453); 4xx other than 408/429 not retried, mapped 400→`ValidationError`, 401→`AuthError`, 403→`AuthzError`, 404→`NotFoundError`, 409→`ConflictError` (:425-432, `mapFailure`); bearer from `accessTokenProvider` (`Supplier<Sensitive>`, called once before the loop, :409); missing provider → local `AuthError`. Retries emit no telemetry to the client's hook (`new TelemetryDispatcher(null)`, :82) — F-J9.

### Q4 cibaAwait
- Clock: injectable `CibaClock { Instant now(); void sleep(Duration) }` (`M/oidc/CibaClock.java`), default wall clock `Instant.now()`/`Thread.sleep`.
- Initial interval = response `interval` if >0 else 5 (`:4489-4493`, `:4639`); sleeps before the first poll.
- `slow_down` `interval += 5`, never reset, **no 60 s cap** (:4662).
- Deadline `receivedAt + expiresIn`, `receivedAt` = `Instant.now()` at initiate (:4494); stops when `now + interval` is not before the deadline and throws `OAuthProtocolError("expired_token")` locally (:4643-4648). A missing `expires_in` decodes as 0 → immediate local expiry (F-J16).
- 5xx/transport: retried per §16 inside `cibaPoll`, then `catch (NetworkError e)` continues the loop (:4665) — **every** `NetworkError`, including a bodiless 400/404 and an unreadable `200` (F-J3). 429 with `rate_limit_exceeded` body → continue (:4660); 5xx **with** an `error` body → `default -> throw` (F-J2).
- Cancellation: thread interrupt → `NetworkError("CIBA polling was interrupted")` (:4650-4653); `cibaAwaitAsync` runs on the common pool and `CompletableFuture.cancel` does not interrupt.
- `authReqId` held only in the caller's record and the loop.

### Q5 cibaHandlePing
`java.security.MessageDigest.isEqual` on UTF-8 bytes (:4740); returns `Sensitive`; header name case-insensitive, count ≠ 1 / scheme ≠ `bearer` / empty / wrong / double space → one `AuthError` naming no value (:4720-4742); body not JSON / no non-empty string `auth_req_id` → `ValidationError` (:4743-4752); synchronous; no I/O (t13).

### Q6 Signed request
`CibaRequestSigner.fromPem(alg, Sensitive pem, kid)` / `.of(alg, PrivateKey, kid)` (`M/oidc/CibaRequestSigner.java:86`, `:123`); algs `CibaSigningAlg` PS256/ES256/EdDSA, no defaults (null → NPE), probe-sign (:145). Claims: members + `iss`=client_id, `aud`=discovery issuer, `iat`=`nbf`=now, `exp`=now+300 (:55), `jti` 256-bit hex (:193-215); returns `Sensitive` (:216). Form carries only client auth + `request` (`AxiamClient.java:4474-4479`). Key held as a nimbus `JWSSigner`, no accessor, `toString` alg+kid only. No `private_key_jwt` client auth in the SDK (F-J19).

### Q7 Kept-secret-on-update
All records are `@JsonInclude(NON_NULL)`: a `null` `bindSecret`/`credential`/`authorizationHeader` is **omitted** (keep); a `Sensitive` replaces; SSF clear = `clearAuthorizationHeader(true)`. Explicit JSON `null` for a secret is not expressible (good). `ReplacementBodies.from(...)` leaves the secret `null` (`ReplacementBodies.java:36-130`). Nullable sparse members use `JsonNullable` (`M/management/JsonNullable.java`, `UpdateDirectoryConfig.java:54-55`). Tests: `DirectoryTest::setSendsEveryRequiredMember…` asserts no `bind_secret`; `ScimTargetsTest::updateWithoutACredential…`; `SsfManagementTest::aReadConvertsIntoTheReplacementBodyWithoutTheHeader`.

### Q8 §21.3.1 pin
`T/AxiamClientMtlsEndpointAliasesTest.java:409-431` decodes vector A verbatim (`VECTOR_A` :383-407) and asserts the **seven** alias values in order, ending `m + "bc-authorize" + q`; `:361-380` pins the record's seven component names. mTLS preference: `:221-236` asserts `/oauth2/bc-authorize` hits the mTLS host and nothing reaches the conventional host. `cibaInitiate` uses `preferredEndpointOrNull(config, MtlsEndpointAliases::backchannel_authentication_endpoint, …)` (`AxiamClient.java:4466-4469`).

### Q9 §28.12 details
URI verbatim (`HttpUrl.parse(uri)` after the origin check, `:4356-4389`); `updateBody()` copies `extra`, removes the five, sets `client_id` (`ClientRegistration.java:205-231`); only `Authorization: Bearer` on the session-free client; a 401 → `OAuthProtocolError`, no §9 (no authenticator on that client; test asserts refresh count 0).

### Q10 Other divergences / contract-silent decisions
1. Management writes ride OkHttp's connection-failure retry (F-J1) — the contract's "no retry on transport error" needs a transport-level clause.
2. Open enums decode to `UNKNOWN` (raw value lost) and serialize as `""` (F-J6); Python keeps the string and refuses locally.
3. Tenant-path endpoints escape the exact-path 401 exclusion (F-J5); `sendOnceHttpClient` also follows redirects.
4. `cibaAwait` treats every `NetworkError` as transient (F-J3) — Python marks decisive ones terminal.
5. 5xx + `error` member terminal (F-J2) — same as Python; contract ambiguity.
6. `iat` must be integral; Python accepts float.
7. `ClientRegistration.updateBody()` always sends the three list members, `[]` when absent on read (`:215-217`); Python sends them only when present/non-empty.
8. Required members of replacement inputs are positional record components with no runtime null check (F-J10).
9. `StatusRetry.retryAfterMillis` caps `Retry-After` at 5 s (`M/internal/StatusRetry.java`) — §16.1 says floor, no cap (pre-existing, out of 1.53–1.58 scope).
10. CIBA client auth: `client_secret_post` or `tls_client_auth`; no `private_key_jwt` (F-J19); a client holding both a secret and a certificate sends the secret.

#### Findings
| id | Severity | Clause | What | Evidence (path:line) | Suggested disposition |
|---|---|---|---|---|---|
| F-J1 | defect | §27.4 r8, §29.7, §30.7, §31.7, §32.8 t5 | Every §27 write (incl. the 7+4+4+3 new ones) goes through `httpClient`, whose OkHttp default `retryOnConnectionFailure(true)` silently re-sends a write when a pooled connection fails after the server read it — probe: server received the `PUT` **twice**; with retry off, once. Javadoc/README "issued exactly once" is therefore false. (`cibaPoll` uses the same client: silent re-sends outside the §16 3-attempt count.) | `M/AxiamClient.java:1043-1045`, `:722` (fix applied only to initiate), `:4551`; `M/internal/ManagementTransport.java:204-206,277-283` | SDK fix (send non-GET management calls on a `retryOnConnectionFailure(false)` client) + contract clarification (transport-library silent retries count) |
| F-J2 | defect | §33.7 r5, §33.4 | A 5xx whose body carries an `error` member → `OAuthProtocolError`, not §16-retried, and `cibaAwait`'s `default -> throw e` ends the loop. | `M/AxiamClient.java:4557-4565`, `:4656-4664`; `M/errors/ErrorMapper.java:164-171` | SDK fix + contract clarification |
| F-J3 | defect | §33.7 r7, §33.4, §16.3 | `cibaAwait` swallows **every** `NetworkError` (:4665): a bodiless 400/404 (decisive per §2/§16.3) loops to the deadline, and an unreadable `200` (`readJson` → `NetworkError`) is re-polled — re-issuing the redemption "to be safe", which then reads `invalid_grant`. | `M/AxiamClient.java:4665-4667`, `:4566-4569`, `:4031-4040` | SDK fix (only `retryableStatus`/IO failures are transient) |
| F-J4 | defect | §33.5, §7 r2 | Public `CibaInitiateRequest.members()` returns the raw `client_notification_token` in a plain `Map` whose `toString` prints it — an implicit reachability path beside `Sensitive.expose()`. | `M/oidc/CibaInitiateRequest.java:127-146` | SDK fix (package-private, or keep the token `Sensitive` in the map) |
| F-J5 | defect | §33.7 r1, §33.4, §12.3 r3, §28.12.2 r3 analogue | The 401→§9 exclusion is an exact-path set (`/oauth2/token`, `/introspect`, `/revoke`, `/bc-authorize`). Under a tenant-path issuer (`/t/{tid}/oauth2/bc-authorize`, named by §33.1) a 401 on `cibaInitiate` for a client holding a session enters `AuthAuthenticator`, refreshes and **re-sends the initiate** — probe: 2 initiate requests, 1 refresh. Same for `/t/{tid}/oauth2/token` (`cibaPoll`). `sendOnceHttpClient` also inherits `followRedirects(true)`. | `M/internal/SessionState.java:70-74`; `M/rest/AuthAuthenticator.java:67-72`; `M/AxiamClient.java:722,4481` | SDK fix (match by `/oauth2/` suffix; build the initiate client with `Authenticator.NONE`, no redirects) |
| F-J6 | defect | §29.2, §31.2, §32.2 ("MUST NOT send one it does not know"), README claim | Open enums decode an unknown value to `UNKNOWN("")`; re-sending it serializes `""` instead of refusing locally (probe: `{"binding":""}`, `{"d":""}`); the raw value is lost, so `SsfStream.eventsAllowed` cannot show an unknown event URI. README says unknown values "are never sent". | `M/management/models/SamlBinding.java:39,60,83`; `DeprovisionPolicy.java:37,58,81`; `SsfEventType.java:47,68,91`; `M/internal/ManagementTransport.java:72-75` | SDK fix (refuse `UNKNOWN` in `encodeBody`; keep the raw string) |
| F-J7 | defect | §32.7 step 9, poll | A non-verdict exception on the k-th SET (replay-store error, JWKS fetch `NetworkError` on a forced refetch) aborts `poll` after SETs 1..k-1 were verified and **recorded** — they are lost and read `replayed` when re-offered (same defect as Python F-P2; by code reading). | `M/ssf/SsfReceiver.java:250`, `:443-453` | SDK fix + contract clarification |
| F-J8 | clarification | §32.7 step 9 | Store failure propagates raw (fail closed, unclassified). | `M/ssf/SsfReceiver.java:250` | contract clarification |
| F-J9 | clarification | §16.5 | `SsfReceiver` builds its own `TelemetryDispatcher(null)`: poll retries never reach the client's hook. | `M/ssf/SsfReceiver.java:82` | SDK fix |
| F-J10 | clarification | §29.8 t1, §30.8 t4, §31.8 t3, §32.8 t1 | Required members are positional record components with no runtime null check; `null` compiles, is dropped by `NON_NULL`, and the server answers 400. Tests claim "does not compile". | `M/management/models/SamlServiceProviderInput.java:51-69`; `SetDirectoryConfig.java:49-66`; `T/management/DirectoryTest.java:150-152` | SDK fix (compact-constructor `requireNonNull`) / contract clarification of "cannot be built" in Java |
| F-J11 | doc | §27.4 r5 | Generated replace-op Javadoc "Every field of the body is required" contradicts the types. | `SamlApi.java:167`; `DirectoryApi.java:82`; `ScimTargetsApi.java:130`; `SsfApi.java:139` | SDK fix (generator) |
| F-J12 | doc | §31.3 r2 | `scimTargets().create` does not repeat the credential-bound-to-URL rule. | `M/management/ScimTargetsApi.java:76` | SDK fix / contract clarification |
| F-J13 | clarification | §32.7 step 8 | `iat` must be an integral number; a fractional NumericDate is `invalid_request` (Python accepts). | `M/ssf/SsfReceiver.java:233` | contract clarification |
| F-J14 | clarification | §28.12.4 | A non-string `registration_access_token`/`client_secret` stays in `extra` and is rendered (Python drops it). | `M/oidc/ClientRegistration.java:186-191,239-249` | SDK fix (drop mistyped secrets) |
| F-J15 | clarification | §28.12.2 r4 | `updateBody()` always sends `redirect_uris`/`grant_types`/`response_types`, as `[]` when the read had none. | `M/oidc/ClientRegistration.java:215-217` | contract clarification |
| F-J16 | clarification | §33.2, §33.7 r4 | A missing `expires_in` decodes as 0 (immediate local `expired_token`); Python refuses the response. | `M/AxiamClient.java:4492` | SDK fix (refuse) |
| F-J17 | clarification | §33.7 r2–4 | Deadline on the wall clock (`Instant.now()` at initiate); no 60 s cap; stops up to one interval early. | `M/AxiamClient.java:4494`, `:4643-4648`, `:4662` | contract clarification |
| F-J18 | clarification | §33.6 | `cibaAwaitAsync` exists only for the one-argument form; `CompletableFuture.cancel` does not stop the loop. | `M/AxiamClient.java:4686` | contract clarification (cancellation) |
| F-J19 | clarification | §33.1, §21.8, §33.3 r10 | No `private_key_jwt` client authentication; a `fapi2` CIBA client must use mTLS. | `M/AxiamClient.java:4412-4421` | contract clarification (record per SDK) |

Counts: defect 7, doc 2, clarification 10.

---

### Report — csharp — commit 3b33515 (merge #101)
Toolchain run: no — `dotnet` is not installed in this sandbox (`which dotnet` empty). Review is by reading only.
Vendored `CONTRACT.md` and `openapi.json` are byte-identical to this repository's `sdks/` (cmp).

All paths below are relative to the `axiam-csharp-sdk` repository root. Abbreviations:
`CR` = `Axiam.Sdk/AxiamClient.ClientRegistration.cs`, `CRT` = `Axiam.Sdk/Auth/Oidc/ClientRegistration.cs`,
`CIBA` = `Axiam.Sdk/AxiamClient.Ciba.cs`, `CIBAT` = `Axiam.Sdk/Auth/Oidc/CibaTypes.cs`,
`RCV` = `Axiam.Sdk/Ssf/SsfReceiver.cs`, `RCVT` = `Axiam.Sdk/Ssf/SsfTypes.cs`, `M/` = `Axiam.Sdk/Management/`,
`T/` = `tests/Axiam.Sdk.Tests/`.

#### Posture per section
| Section | Status | Notes |
|---|---|---|
| §28.12 | implemented | Three `*Async` methods on `AxiamClient`, session-free transport, token `Sensitive` in and out. |
| §29 | implemented | Generated `SamlApi` (11 ops) + hand-written `ParseSpMetadataExactlyOne` precheck and `ToInput` RMW. |
| §30 | implemented | Generated `DirectoryApi` (6 ops), `bind_secret` `Sensitive<string>?`, `JsonNullable<T>` for explicit null. |
| §31 | implemented | Generated `ScimTargetsApi` (6 ops), `credential` `Sensitive<string>?`, open tagged unions. |
| §32 | implemented | Generated `SsfApi` (5 ops), `authorization_header` `Sensitive<string>?`, `clear_authorization_header`. |
| §32.7 | implemented | `Axiam.Sdk.Ssf.SsfReceiver` — `VerifySetAsync`, `PollAsync`, pluggable `IReplayStore`. |
| §33 | implemented | `CibaInitiateAsync`, `CibaPollAsync`, `CibaAwaitAsync`, synchronous `CibaHandlePing` on `AxiamClient`. |
| §33.2 signed | implemented | `CibaRequestSigner.FromPem(alg, Sensitive<string> pem, kid?)`, PS256 / ES256 / EdDSA. |

#### A–F per section

### §28.12
**A.** `read_client_registration` → `AxiamClient.ReadClientRegistrationAsync` `CR:114`; `update_client_registration` →
`UpdateClientRegistrationAsync` `CR:173`; `delete_client_registration` → `DeleteClientRegistrationAsync` `CR:203`;
type `ClientRegistration` `CRT:29` (unknown members kept in `Extra`, `CRT:105`, `CRT:136-142`). All present, names match §28.12.5.

**B.** Argument `Sensitive<string> registrationAccessToken` on all three (`CR:116`, `CR:175`, `CR:205`).
`ClientRegistration.RegistrationAccessToken` and `.ClientSecret` are `Sensitive<string>?` (`CRT:96`, `CRT:102`).
`Sensitive<T>` is a struct with `ToString() => "[SENSITIVE]"` and a JSON converter that writes `"[SENSITIVE]"`
(`Axiam.Sdk/Core/Sensitive.cs:88`, `:149`); record printing therefore redacts. Errors: rule-1 refusal names no part of
the URI (`CR:227-229`); OAuth error carries only the server's `error`/`error_description` (`CR:349-351`). Nothing else
wrapped.

**C.** §28.12.6:
1. Origin refusal → `T/ClientRegistrationTests.cs` `AUriAtAnotherOriginIsRefusedLocallyAndNothingIsSent` (other host,
   other port, http-vs-https, ftp, relative, garbage; all three ops; `Assert.Empty(handler.Requests)`), plus
   `HttpIsAcceptedOnlyAgainstAnHttpLoopbackBase`.
2. Header only → `ReadAndDeleteSendTheBearerOnlyAndKeepTheQueryVerbatim` (bearer, no body, no cookie, no CSRF, query
   verbatim, session token absent).
3. Update body → `UpdateDropsTheFiveServerStatedMembersAndReturnsTheRotatedToken` (five absent, `client_id` present,
   rotated token returned) and `NeitherWriteIsRetriedOnA503ButTheReadIs` (503 once on PUT and DELETE → one request each;
   retry enabled by default, `Axiam.Sdk/Options/AxiamClientOptions.cs:170`).
4. Errors → `A401InvalidTokenIsAnOAuthProtocolErrorAndRefreshesNothing` (asserts no request to `/api/v1/auth/refresh`)
   and `A400InvalidClientMetadataIsAnOAuthProtocolErrorAndA204DeleteSucceeds`.
5. Redaction → `NeitherTheTokenNorTheSecretReachesAnyRendering` (ToString, record printer, `JsonSerializer`, interpolation,
   three exception renderings; 8-char substring check `T/Fixtures/CapturingHandler.cs:133-142`).

**D.** Update: "`metadata` is the **whole** registration: a member it omits is a member the server deletes" and
"**Persist the returned `RegistrationAccessToken` before doing anything else.**" (`CR:145-157`); "**Never retried**"
(`CR:159-163`). Delete: "**Never retried**: a retry after a lost `204` would read `401`…" (`CR:193-195`).

**E.** Update and delete call `SendRegistrationAsync` once, outside any retry wrapper (`CR:182-186`, `CR:210-217`).
Read is wrapped in `RetryPolicy.ExecuteAsync(..., retryable: RetryPolicy.IsTransient)` (`CR:121-135`).

**F.** README: "…§28 MCP resource-server helpers, contract 1.48), §28.12, §29, §30, §31, §32 and §33, with §32.7 and
§33.2 signed (the RFC 7592 client configuration operations, contract 1.53; …)" (`README.md:36-40`). Matches code.

### §29
**A.** `saml.get_idp` → `Saml.GetIdpAsync` `M/SamlApi.cs:60`; `list_service_providers` → `ListServiceProvidersAsync`
`:88` (+ `ListServiceProvidersAllAsync` `:118`); `create_service_provider` `:141`; `get_service_provider` `:163`;
`update_service_provider` `:205`; `delete_service_provider` `:242`; `parse_sp_metadata` `:287`;
`list_idp_credentials` `:309` (returns `IReadOnlyList<SamlIdpCredential>`, not a page); `issue_idp_credential` `:344`;
`promote_idp_credential` `:383`; `retire_idp_credential` `:423`. All eleven present.

**B.** Nothing wrapped (correct per §29.5): `grep Sensitive M/Models/Saml*.cs` empty. `SamlIdpCredential` declares no key
member (`M/Models/SamlIdpCredential.cs:19-87`); no `[JsonExtensionData]` anywhere in `M/Models` (grep empty), so a stray
`private_key_pem` is dropped by `System.Text.Json`.

**C.** §29.8 (all in `T/Management/SamlTests.cs`):
1. `UpdateServiceProviderPutsTheWholeRegistration` — asserts 11 members present and `RequiredMemberAttribute` on the three
   required members. **Asserts less than the text:** "every `SamlServiceProviderInput` member" — the nullable ones
   (`slo_url`, `slo_binding`, both certs) are omitted when null (see Q10 / finding CS-07).
2. `SignAssertionsDoesNotExistAndUnknownValuesDecode`.
3. `ParseSpMetadataSendsExactlyOneMemberAndTheDraftCreates`.
4. `ACredentialHasNoKeyMemberAndPromotionMayRetireNothing`.
5. `ServiceProvidersPageWithSearchAndCredentialsAreAPlainList`.
6. `NoneOfTheSevenWritesIsRetriedOn503` (all seven, `r.Calls == 1`).
7. `StatusesMapPerSection2`.
8. `GetIdpIsNeverCachedAndKeepsNullApartFromAbsent` (two calls → two requests; configured tenant in path;
   `JsonNullable<Guid>?` keeps null apart from absent).

**D.** `update_service_provider`: "An omitted member takes its **default**, not its stored value … Start from
`GetServiceProviderAsync` (`ManagementReplacements.ToInput` …)… `entity_id` is immutable" (`M/SamlApi.cs:187-198`).
ECDSA/HTTP-Redirect RSA-only note on create and update (`:128-131`, `:197-198`). Retire active stops sign-on:
"**Retiring the `active` credential with no successor stops SAML sign-on for the whole tenant at once**" (`:410-413`).
`parse_sp_metadata` exactly-one + stores nothing (`:272-279`). RMW helper `ManagementReplacements.ToInput`
(`M/ManagementChecks.cs:55-73`).

**E.** `ManagementTransport.SendAsync`: `if (method != HttpMethod.Get) return await AttemptAsync(... 1 ...)` — writes are one
attempt by construction (`M/ManagementTransport.cs:85-92`); GETs retried (`:94-103`).

**F.** Same README sentence (`README.md:36-38`) names §29. Matches.

### §30
**A.** `directory.get` → `Directory.GetAsync` `M/DirectoryApi.cs:54`; `set` → `SetAsync` `:102`; `update` → `UpdateAsync`
`:144` (PATCH); `delete` → `DeleteAsync` `:184`; `link_account` → `LinkAccountAsync` `:225`; `get_sync_status` →
`GetSyncStatusAsync` `:246`. All six.

**B.** `SetDirectoryConfig.BindSecret` `Sensitive<string>?` (`M/Models/SetDirectoryConfig.cs:52`);
`UpdateDirectoryConfig.BindSecret` `Sensitive<string>?` (`M/Models/UpdateDirectoryConfig.cs:50`). Only `ManagementJson.Wire`
writes it in clear (`M/ManagementJson.cs:53-64`, `:90`); `Reader` and the default converter write `"[SENSITIVE]"`.
`DirectoryConfig` has no secret member (`M/Models/DirectoryConfig.cs`), no extension data. Nothing else wrapped.

**C.** §30.8 (`T/Management/DirectoryTests.cs`): 1 `TheBindSecretReachesTheWireAndNoRendering` (Set and Update
ToString/Json/interpolation, error rendering, secret on wire); 2 `ABindSecretInAResponseIsDropped`;
3 `UpdateSendsExactlyTheMembersItWasGiven` (exact `{"enabled":false}`, keys `bind_secret,url`, exact
`{"group_filter":null}`); 4 `SetSendsEveryRequiredMemberAndDecodes201And200`; 5 `NoWriteIsRetriedOn503` (four writes,
`Calls == 1`); 6 `ErrorsMapPerSection2AndLinkAccountSendsOnlyTheUserId`. All present.

**D.** Rule 2 at both call sites: set "**Moving the connection requires the secret again** (§30.3 rule 2) … The SDK holds no
copy of the secret" (`M/DirectoryApi.cs:84-87`), update same (`:127-130`). Replacement warning on set (`:80-81`, `:88-90`).
Delete rule 5 (`:171-175`). Link signs owner out (`:211-215`).

**E.** As §29 (`M/ManagementTransport.cs:85-92`; PATCH is not GET).

**F.** README names §30 (`README.md:36`). Matches.

### §31
**A.** `scim_targets.list` → `ScimTargets.ListAsync` `M/ScimTargetsApi.cs:49` (+ `ListAllAsync` `:77`); `create` `:97`;
`get` `:118`; `update` `:162`; `delete` `:199`; `reconcile` `:232` (POST, no body). All six.

**B.** `ScimTargetInput.Credential` `Sensitive<string>?` (`M/Models/ScimTargetInput.cs:52`). `ScimTargetResponse` and both
`ScimTargetAuth` arms declare no credential (`M/Models/ScimTargetAuth.cs`). Nothing else wrapped.

**C.** §31.8 (`T/Management/ScimTargetsTests.cs`): 1 `TheCredentialIsOnTheWireAndInNoRendering`; 2
`ACredentialInAResponseIsDropped`; 3 `UpdateWithoutACredentialSendsNoKeyAndTheVariantsKeepTheirShape` (no `credential`
key; exact keys of both arms of both unions; required members); 4 `UnknownValuesDecodeAndThePagerCarriesSearch`;
5 `NoWriteIsRetriedOn503`; 6 `StatusesMapAndReconcileIsABodilessPost202` (400/409 update/404/401/202/409 reconcile,
empty body). All present. Extra: `AnUnknownArmIsRefusedLocally`.

**D.** Rule 2 at update: "**The credential is bound to its URL** (§31.3 rule 2) … The SDK holds no credential to re-send"
(`M/ScimTargetsApi.cs:145-151`); at create only "`credential` is required here (§31.3 rule 2)" (`:86-88`) — the URL
binding itself is not restated at create (acceptable: on create the credential is mandatory anyway). Rule 8 at delete:
"**Deprovisions nothing downstream**" (`:186-190`). 409 overtaken update (`:150-151`).

**E.** As §29.

**F.** README names §31 (`README.md:36`). Matches.

### §32 (management)
**A.** `ssf.list_streams` → `Ssf.ListStreamsAsync` `M/SsfApi.cs:62` (+ `ListStreamsAllAsync` `:91`); `create_stream` `:107`;
`get_stream` `:129`; `update_stream` `:169`; `delete_stream` `:197`. All five.

**B.** `SsfStreamInput.AuthorizationHeader` `Sensitive<string>?` (`M/Models/SsfStreamInput.cs:41`); `SsfStream` has only
`AuthorizationHeaderSet` (`M/Models/SsfStream.cs:30`) and the two transmitter members (`:128`, `:134`).

**C.** §32.8 management (`T/Management/SsfManagementTests.cs`): 1 `UpdateStreamPutsEveryMemberItModels`; 2
`ThePushHeaderIsSentAndNeverRenderedOrDecoded`; 3 `UnknownValuesAndBothTransmitterStatesDecode`; 4
`ListStreamsPagesAndTheWalkCarriesSearch`; 5 `NoneOfTheThreeWritesIsRetriedOn503`; 6 `StatusesMapPerSection2`. All present.

**D.** `update_stream`: "An omitted optional member takes its default (§32.2) — **except `authorization_header`, which
absent keeps the stored one** — unless the update moves `endpoint_url` … else `400` (§32.3 rule 5)" (`M/SsfApi.cs:153-158`).
Create/delete carry only the "Not retried" paragraph (contract asks the warning at `update_stream` only).

**E.** As §29.

**F.** README names §32 (`README.md:36`). Matches.

### §32.7 (receiver helper)
**A.** `ssf.verify_set` → `SsfReceiver.VerifySetAsync` `RCV:98`; `ssf.poll` → `SsfReceiver.PollAsync` `RCV:230`. Config
`SsfReceiverOptions { Issuer, Audience, Keys (FromJwksUri | FromDiscoveryUrl), AccessTokenProvider, ReplayWindow,
ReplayStore, TimeProvider }` (`RCVT:203-232`). Result `SecurityEvent(Jti, Iat, Iss, Aud, Txn, EventType, Event, SubId)`
(`RCVT:243-244`). Names match §32.7 table. No synchronous pre-fetched-JWKS variant (MAY).

**B.** `AccessTokenProvider` returns `Sensitive<string>` (`RCVT:222`); revealed only into the header (`RCV:290`). SET
refusals carry fixed text naming no claim value (`RCV:110-199`).

**C.** §32.8 helper (`T/SsfReceiverTests.cs`): 1 `AValidSetVerifiesWithEveryField`; 2 `TypeAndAlgorithmAreChecked`;
3 `ASignatureByAnotherKeyOrATamperedPayloadIsInvalidKey`; 4 `IssuerAndAudienceAreChecked`; 5
`TheSetClaimRulesAreInvalidRequest`; 6 `ASecondSightingIsReplayedAndAShortWindowIsRefused`; 7
`AnUnknownKidCostsOneRefetchAtMostOnceAMinute` (counts JWKS requests 1 → 2 → 2, then after 61 s → 3); 8
`PollPassesAckAndSetErrsThroughAndSortsTheSets` + `PollIsNotRetriedOnA4xxButIsOnA503`. Ed25519 key generated at run time
(`SigningKey`, `:393`). All present.

**D.** `VerifySetAsync` doc lists the nine steps and "**A SET that verifies has been recorded**" (`RCV:79-91`); `PollAsync`
"**Nothing is acknowledged on your behalf** … A SET you neither acknowledge nor refuse is re-offered — and … then reads as
`replayed`" (`RCV:211-217`).

**E.** Poll: `RetryPolicy.ExecuteAsync(..., retryable: RetryPolicy.IsTransient)` (`RCV:279-325`); `IsTransient` =
`HttpStatus is null or 408 or 429 or >= 500` (`Axiam.Sdk/Core/RetryPolicy.cs:194-196`), so 400/401/403/404 are one shot.

**F.** "…with §32.7 and §33.2 signed (… the SSF receiver helper, contract 1.56; …)" (`README.md:36-39`). Named correctly.

### §33
**A.** `ciba_initiate` → `CibaInitiateAsync` `CIBA:72`; `ciba_poll` → `CibaPollAsync` `CIBA:168`; `ciba_await` →
`CibaAwaitAsync` `CIBA:255`; `ciba_handle_ping` → synchronous `CibaHandlePing(headers, string body, Sensitive<string>)`
`CIBA:319` (+ `byte[]` overload `:375`). Names match §33.6 (no `Async` on the ping helper).

**B.** `CibaInitiateResponse.AuthReqId` `Sensitive<string>` (`CIBAT:280`); `CibaPollParams.AuthReqId` (`CIBAT:286`); await
takes the response; ping returns `Sensitive<string>` (`CIBA:360`). `client_notification_token`: `CibaDelivery.Ping(Sensitive<string>)`
(`CIBAT:62`, held `:65`), `expectedToken` `Sensitive<string>` (`CIBA:320`). Signing key: `CibaRequestSigner` holds
`RSA`/`ECDsa`/`Ed25519PrivateKeyParameters` privately, `ToString` redacts (`CIBAT:95-108`, `:225`), constructed from
`Sensitive<string>` PEM (`CIBAT:128`). Errors: fixed texts (`CIBA:79-98`, `:328-351`); OAuth errors carry server's
`error`/`error_description` only. `binding_message`/`login_hint` are never logged (no log sink touches them).

**C.** §33.8 (`T/CibaTests.cs`): t01 `:152`, t02 `:190`, t03 `:227`, t04 `:268` (503, 429 with and without body, dropped
connection; one request each), t05 `:291` (sleeps `5,10,15,15`; four terminal answers incl. unknown), t06 `:321` (injected
`ManualCibaClock`, zero requests before first sleep; 7 / absent / 0), t07 `:343` (polls at 5, 10 only with `expires_in` 12),
t08 `:362` (500, OAuth 429, bare 429 survived), t09 `:382`, t10 `:399`, t11 `:421` (incl. double space, last char, structural
`FixedTimeEquals` assertion), t12 `:458`, t13 `:475` (tripwire transport), t14 `:531` (all three algs, two distinct jtis,
exactly `client_id, client_secret, request`), t15 `:596`, t16 `:618`. All sixteen present. Plus
`OnMtlsTheBackchannelEndpointIsTheAlias` `:671`.

**D.** Initiate: "**Never retried** — not on a transport error, a `5xx` or a `429` (§33.7 rule 1)" (`CIBA:61-63`); class
remarks "**A successful `CibaInitiateAsync` proves nothing about the user**" (`CIBA:28-31`). Poll: "**Store the returned
tokens before anything else**" (`CIBA:159-161`). Await: ping-mode guidance (`CIBA:243-249`). Ping: "answer `204` as soon as
this returns, **then** call `CibaPollAsync`" (`CIBA:309-312`).

**E.** Initiate: one `PostOAuth2FormAsync` call, no retry wrapper (`CIBA:122-131`). See finding CS-01 for the one path where
the session handler can re-send it.

**F.** "…§32 and §33, with §32.7 and §33.2 signed (… CIBA with the signed request form in PS256, ES256 and EdDSA, and
§21.3.1's seventh `mtls_endpoint_aliases` member, contract 1.58)" (`README.md:36-40`). Matches; contract version 1.58 is
current.

#### Q1 … Q10

### Q1 Replay store
- Interface `IReplayStore { bool CheckAndRecord(string jti, TimeSpan window); }` (`RCVT:120-131`) — **synchronous**,
  **atomic check-and-insert** (doc: "MUST be atomic").
- Expiry: the window is passed per call; `MemoryReplayStore` stores `now + window` and sweeps every expired entry on every
  call, under one lock (`RCVT:154-170`), clock = `TimeProvider`.
- Default `MemoryReplayStore`: `ConcurrentDictionary` — **unbounded, no cap, no LRU**; the sweep is O(n) per call.
- Store error: not caught — the exception propagates out of `VerifySetAsync` (and aborts `PollAsync`, which catches only
  `SetVerificationError`, `RCV:347`). **Fail closed** (nothing is returned as verified), but the error is the store's own
  type, not `replayed`/`AuthError`.
- Recorded only after 1–8: `_replay.CheckAndRecord` is the last check (`RCV:196-200`), after the extra poll-key check.
- Seven-day floor: **constructor refusal** — `if (options.ReplayWindow < MinReplayWindow) throw Refuse(...)` →
  `ValidationError` naming `ReplayWindow` (`RCV:57-60`); `MinReplayWindow = 7 days` (`RCVT:206`). Default = floor.

### Q2 `verify_set` order and codes
Steps in order: 1 split/base64url/JSON-object [`Malformed`] `RCV:106-111` (signature part decoded first, then header,
payload); 2 `typ` case-insensitive against both spellings [`InvalidType`] `:114-119` (absent → ""); 3 `alg != "EdDSA"`
(ordinal, exact) [`InvalidKey`] `:122-125`; 4 missing `kid` or no key [`InvalidKey`] `:128-135`; 5 Ed25519 verify (+ key
length 32) [`InvalidKey`] `:138-141`; 6 `iss` ordinal-equal [`InvalidIssuer`] `:144-148`; 7 `aud` string or array of strings
[`InvalidAudience`] `:151-161`; 8 `exp`/`sub` present, `jti` empty, `iat` not an integer, `sub_id` not an object, `events` not
exactly one member [`InvalidRequest`] `:164-187`; **extra**: in poll, poll key ≠ `jti` → `InvalidRequest` `:189-192`;
9 replay [`Replayed`] `:197-200`. Codes are `malformed, invalid_type, invalid_key, invalid_issuer, invalid_audience,
invalid_request, replayed` (`RCVT:41-50`); `PushErrorCode` maps malformed/invalid_type/replayed → `invalid_request`
(`RCVT:60-66`). Kid miss: one forced refetch, forced refetches globally limited to once per 60 s (`RCV:375-382`); a TTL-expiry
refetch is separate and not counted. JWKS/discovery fetch failure → `NetworkError`, not a reason code (`RCV:446-449`).
Keys only from configured `jwks_uri` or discovery whose `issuer` equals the configured issuer (`RCV:414-426`); `jwk`/`x5c`
never read.

### Q3 `poll`
Never acknowledges (body built only from caller's options, `RCV:241-274`; t8 asserts only the two caller polls went out).
`ack`/`setErrs` passed through exactly (t8 deep-equals the body). Refused returned as `RefusedSet(string Jti,
SetFailureReason Reason)` (`RCVT:249`) — reason is the enum, code via `.Code()`. Not retried on 400/401/403/404; **is**
retried on 408 and 429 (§16, see CS-03). Token from `AccessTokenProvider`, fetched once per poll before the retry loop
(`RCV:277`); none configured → local `AuthError`, no request (`RCV:234-238`). Session-free transport (`CR:35-68`).

### Q4 `ciba_await` clock and loop
- Injectable: `ICibaClock { UtcNow; SleepAsync }` via `CibaAwaitParams.Clock` (`CIBAT:292-302`, `:321`). **But** the deadline
  anchor `CibaInitiateResponse.ReceivedAt` is stamped with the real `DateTimeOffset.UtcNow` in `CibaInitiateAsync`
  (`CIBA:124`) — the initiate side is not on the injected clock (tests build the response by hand). See CS-05.
- Initial interval: response `interval` if > 0, else 5 (`CIBA:141`, again `:263`). No faster floor.
- `slow_down`: `interval += 5`, never reset (`CIBA:284-287`); **no 60 s cap** (allowed).
- Deadline: `ReceivedAt + expires_in` (`CIBA:262`); before each sleep, `if (clock.UtcNow + wait >= deadline) throw new
  OAuthProtocolError("expired_token", …)` (`CIBA:268-273`) — so it gives up when the *next* poll would land at/after the
  deadline, i.e. up to one interval early, with no request.
- 5xx/transport: retried per §16 inside `CibaPollAsync` (`CIBA:187-207`), then swallowed by the loop if
  `RetryPolicy.IsTransient` (`CIBA:288-291`). 429 with `rate_limit_exceeded` body: caught, same interval (`CIBA:281`); bare
  429: §16 retry then loop.
- Cancellation: `CancellationToken` through sleep and poll.
- `auth_req_id`: held in the caller's `CibaInitiateResponse` and per-call form dictionary only; not stored on the client.
- Ping-mode fallback (rule 6) is documented (`CIBA:244-248`), not a helper.

### Q5 `ciba_handle_ping`
Constant-time: `CryptographicOperations.FixedTimeEquals(presented, expected)` (`CIBA:344`; length mismatch returns early,
which is the BCL behaviour). Returns `Sensitive<string>` (`CIBA:360`). Header: exactly one `Authorization` (name
case-insensitive, `Take(2)` detects duplicates), scheme `Bearer` case-insensitive, exactly one space; missing, duplicate,
empty, non-Bearer, double space, wrong, empty expected → `AuthError` with fixed message
"ciba ping refused: the Authorization header is not the expected bearer" (`CIBA:328-347`). Body not JSON object / no
non-empty string `auth_req_id` / invalid UTF-8 → `ValidationError` (`CIBA:349-367`, `:379-386`). Synchronous, no I/O
(instance method on `AxiamClient` but touches no transport; t13).

### Q6 Signed request
Offered. Algs `PS256` (RSA ≥ 2048, PSS), `ES256` (P-256 only, P1363 encoding), `EdDSA` (Ed25519 via BouncyCastle)
(`CIBAT:72-82`, `:128-175`, `:204-221`); key proven by a probe signature at construction. Header `{"alg", "typ":"JWT",
"kid"?}` (`CIBA:460-464`). Claims: `iss` = client id, `aud` = discovery `issuer` (string), `iat` = `nbf` = now, `exp` = now +
300 s, `jti` = 128-bit lower-hex, plus every set member with `requested_expiry` as a number (`CIBA:443-469`). Form then
carries only `client_id`, `client_secret` (if any) and `request` (`CIBA:102-118`). Key material: PEM taken as
`Sensitive<string>`, held in private fields, no accessor, redacted `ToString`; the `request` string lives only in the local
form dictionary (not wrapped). No defaults for alg or key (`FromPem(alg, pem)` both required; t15 asserts no default).

### Q7 Kept-secret-on-update
All three use the same mechanism: the secret property is `Sensitive<string>?` and the wire serializer is
`DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull` (`M/ManagementJson.cs:96`), so **unset → member omitted →
server keeps**; `Sensitive<string>.Wrap(v)` → sent → replace. Distinct, by construction.
- `directory.update`: `public Sensitive<string>? BindSecret { get; init; }` (`M/Models/UpdateDirectoryConfig.cs:50`); test
  `UpdateSendsExactlyTheMembersItWasGiven` asserts `{"enabled":false}` exactly.
- `ssf.update_stream`: `AuthorizationHeader` `Sensitive<string>?` (`M/Models/SsfStreamInput.cs:41`) + a third state
  `ClearAuthorizationHeader = true` (`:47`).
- `scim_targets.update`: `Credential` `Sensitive<string>?` (`M/Models/ScimTargetInput.cs:52`); test asserts no `credential` key.
`ManagementReplacements.ToInput` for SSF/SCIM leaves the secret unset (`M/ManagementChecks.cs:84-123`).

### Q8 §21.3.1 pin
`VectorA_CarriesSevenAliases` reads vector A from the vendored `CONTRACT.md` and asserts
`Assert.Equal(7, raw.RootElement.GetProperty("mtls_endpoint_aliases").EnumerateObject().Count());`
(`T/MtlsEndpointAliasesTests.cs:467`), then that all seven decode onto the mTLS host. `AliasRecord_CarriesOnlyTheSevenAliasableEndpoints`
pins the record's seven property names (`:270-293`) — the decoder is a closed record (an eighth alias would be ignored, not
fail). CIBA prefers the alias: `PreferredEndpoint(configuration, a => a.BackchannelAuthenticationEndpoint, …)`
(`CIBA:92-93`); poll uses the token alias (`CIBA:175`); test `OnMtlsTheBackchannelEndpointIsTheAlias` (`T/CibaTests.cs:671`).

### Q9 §28.12 details
- Verbatim: the string is parsed once to `System.Uri` and sent as that `Uri` (`CR:232`, `:281`); no rebuild or host swap.
  (`System.Uri` canonicalises — dot-segments, some percent-escapes — which is not "verbatim" in the strictest sense; harmless
  for AXIAM's URIs. Test asserts the query is kept.)
- Body strips the five: `ServerStatedMembers` removed from `Extra` copy, then typed members re-added; the five are not typed
  members of the body writer (`CRT:36-43`, `:228-283`).
- Bearer only: `request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token.Reveal())` on
  `SessionlessHttpClient` — no cookie jar (`UseCookies = false`), no `AxiamHttpMessageHandler` (`CR:35-68`, `:282-291`).
- 401 → `OAuthProtocolError` via `MapOAuth2ErrorAnyStatusAsync`; the session-free transport has no §9 handler, so no refresh
  (`CR:303-310`; test asserts no refresh request).

### Q10 Other divergences / silent-contract decisions
- **Tenant-path `/oauth2/*` not exempt from §9** (CS-01).
- **Poll aborts after recording** (CS-02): a `NetworkError` from a JWKS fetch inside `PollAsync` propagates after earlier SETs
  of the same response were recorded in the replay store; they are never returned, and on re-offer read `replayed`.
- Contract silent: what verify_set does when the JWKS cannot be fetched (C# → `NetworkError`); whether 408/429 count as the
  "4xx" poll must not retry; whether a re-offered un-acked SET is a replay (C# says yes and documents it); default store bound.
- Extra verify check (poll key must equal `jti`) under `invalid_request`.
- `ciba_await` gives up up to one interval before the deadline; deadline anchored on response-receipt time, real clock.
- Signed request: lifetime 300 s, header `typ: "JWT"`, `aud` as a string, `jti` 32 hex — contract leaves all four open.
- Management writes omit null optional members of a *replacement* body (§29.8 test 1 asks for "every member").
- `CibaInitiateAsync` requires discovery (`backchannel_authentication_endpoint` absent → `AuthError`, `CIBA:94-99`); it never
  builds the path itself (contract allows either).
- `private_key_jwt` client auth is not implemented anywhere in this SDK, so CIBA supports `client_secret_post` and
  `tls_client_auth` only (`CIBA:392-404`) — consistent with "same code path as `/oauth2/token`".
- Generated doc boilerplate contradicts the types (CS-06).
- A decoded `ScimTargetResponse` with an unknown `auth`/`scope` arm cannot be JSON-serialized for a log line (CS-10); the
  unknown arm keeps only its `type` (no raw members), which is the safe half of §31.2.

#### Findings
| id | Severity | Clause | What | Evidence (path:line) | Suggested disposition |
|---|---|---|---|---|---|
| CS-01 | defect | §33.4, §33.7 rule 1, §12.3 rule 3 | The §9 reactive-refresh exemption matches the request path **exactly** (`/oauth2/bc-authorize`, `/oauth2/token`, …). Under a tenant-path issuer the endpoints are `/t/{tenant}/oauth2/…`, which are not exempt: a `401 invalid_client` from `bc-authorize` with a live session enters §9 and the handler **re-sends** the initiate after refreshing — two wire calls for one `CibaInitiateAsync`, and a 401 on the CIBA grant enters the refresh guard. Untested (all CIBA tests use the query-form path). | `Axiam.Sdk/Rest/AxiamHttpMessageHandler.cs:77-82`, `:209-211`, `:229`; `AxiamClient.Ciba.cs:122` | SDK fix (match on the `/oauth2/` suffix or flag OAuth2 requests explicitly; add a tenant-path test) |
| CS-02 | defect | §32.7 (`poll`), step 9 | `PollAsync` verifies SETs one by one, recording each in the replay store; a `NetworkError` (JWKS fetch) or a store exception on a later SET aborts the poll, so earlier SETs are recorded but never returned. Un-acked, they are re-offered and then refused `replayed` — silent event loss. | `Axiam.Sdk/Ssf/SsfReceiver.cs:335-351`, `:197` | SDK fix (verify steps 1–8 for all SETs before recording any, or fetch keys up front); contract clarification on partial poll failure |
| CS-03 | clarification | §32.7 vs §16.3 | §32.7 says `poll` "is not retried on a `4xx`; §16 applies to transport errors and `5xx`"; §16.3 retries 408 and 429. C# retries 408/429 on poll. | `Axiam.Sdk/Core/RetryPolicy.cs:194-196`; `SsfReceiver.cs:325` | contract clarification (say whether 408/429 are in or out) |
| CS-04 | clarification | §32.7 steps 4, 9 | Contract names no outcome for a JWKS that cannot be fetched (C#: `NetworkError`, not `invalid_key`) nor for a replay-store failure (C#: store exception propagates, fail closed). Also whether a re-offered un-acked SET is a replay (C#: yes, documented). | `SsfReceiver.cs:428-449`, `:197`, `:215-216` | contract clarification |
| CS-05 | clarification | §33.7 rule 4, §33.8 t6/t7 | `CibaAwaitAsync` raises `expired_token` as soon as `now + interval >= deadline`, i.e. up to one interval before the deadline; the deadline anchor `ReceivedAt` is stamped with the real clock in `CibaInitiateAsync`, while waits use the injected `ICibaClock`. | `AxiamClient.Ciba.cs:124`, `:262`, `:268-273` | contract clarification (may the loop stop early? which instant anchors the deadline?); optional SDK fix (take the clock on initiate too) |
| CS-06 | doc | §29.2, §27.4 rule 5 | Generated XML docs contradict the types: `SamlServiceProviderInput` "Every property is required" (only three are); `ParseSamlSpMetadata` "a SPARSE body: what you leave unset is left unchanged" (it is a parse request); replacement methods say "every field of the body is written" though null members are omitted; README's SAML RMW comment mentions "the secret absent" for a type with no secret. | `Axiam.Sdk/Management/Models/SamlServiceProviderInput.cs:23-25`; `.../ParseSamlSpMetadata.cs:17-24`; `Axiam.Sdk/Management/SamlApi.cs:183-184`; `README.md:2068-2069` | SDK fix (generator doc templates) |
| CS-07 | clarification | §29.8 test 1, §27.4 rule 5 | Replacement bodies omit null-valued optional members (`WhenWritingNull`) — `slo_url`, `slo_binding`, both certs absent rather than `null`. Equivalent on the server (default is null), but the required test's "every member" is asserted only for the 11 non-null ones. | `Axiam.Sdk/Management/ManagementJson.cs:96`; `tests/Axiam.Sdk.Tests/Management/SamlTests.cs:76-83` | contract clarification (may a replacement omit members whose default is null?) |
| CS-08 | clarification | §32.7 step 9 | Default `MemoryReplayStore` is unbounded with an O(n) sweep under a global lock per verification; the floor is enforced by a constructor `ValidationError`. Contract states neither a bound nor the refusal's error type. | `Axiam.Sdk/Ssf/SsfTypes.cs:134-170`; `SsfReceiver.cs:57-60` | contract clarification (cross-SDK comparison) |
| CS-09 | clarification | §33.2 signed | Contract leaves open: request lifetime (C# 300 s), header `typ` (C# `"JWT"`), `aud` form (C# string), `jti` format (C# 32 hex); and C# adds an extra verify_set check (poll key ≠ `jti` → `invalid_request`). | `AxiamClient.Ciba.cs:443-469`; `SsfReceiver.cs:189-192` | contract clarification (record the choices; none is wrong) |
| CS-10 | defect | §31.2 (open `ScimTargetAuth`/`ScimTargetScope`), §7 rule 1 (JSON-for-logs sink) | The generated converters refuse to *write* an unknown arm (`throw new ValidationError(...)`), and they are the type's `[JsonConverter]`, so serializing a decoded `ScimTargetResponse` whose `auth` or `scope` is an unknown arm for a log line (`JsonSerializer.Serialize(target)`) throws instead of rendering. Sending must refuse; logging should not. The §31.8 test 4 only decodes. | `Axiam.Sdk/Management/Models/ScimTargetAuth.cs:27`, `:72-80`; same shape in `ScimTargetScope.cs:27`, `:72-80` | SDK fix (refuse in the request encoder, not in the type's converter) |

---

### Report — php — commit cec1594 (merge #78)
Toolchain run: no — `php` 8.3 and `composer` are installed, but `composer install` (in a scratch copy, not the repo) failed: GitHub dist downloads timed out at the proxy and source clones were refused ("Could not authenticate against github.com"), so PHPUnit and every runtime dependency are absent; `phar.phpunit.de` answers 403. One targeted probe ran without dependencies (SDK classes only, autoloaded from `src/`): it confirmed PHP-03.
Vendored `CONTRACT.md` and `openapi.json` are byte-identical to this repository's `sdks/` (cmp).

All paths below are relative to the `axiam-php-sdk` repository root. Abbreviations:
`AC` = `src/AxiamClient.php`, `CRC` = `src/Oidc/ClientRegistrationClient.php`, `CR` = `src/Oidc/ClientRegistration.php`,
`OC` = `src/Oidc/OidcClient.php`, `RCV` = `src/Ssf/SsfReceiver.php`, `M/` = `src/Management/`, `T/` = `tests/Contract158/`.

#### Posture per section
| Section | Status | Notes |
|---|---|---|
| §28.12 | implemented | Three methods on `AxiamClient` over a bare Guzzle client (no cookies, no auth/refresh middleware, no redirects). |
| §29 | implemented | Generated `SamlApi` (11 ops) + `ManagementChecks::parseSpMetadataExactlyOne`, `ReadModifyWrite::samlServiceProvider`. |
| §30 | implemented | Generated `DirectoryApi` (6 ops), `bindSecret` `?Sensitive`, `JsonNull::Null` for explicit null. |
| §31 | implemented | Generated `ScimTargetsApi` (6 ops; the list op is `listItems`, not `list`), `credential` `?Sensitive`. |
| §32 | implemented | Generated `SsfApi` (5 ops), `authorizationHeader` `?Sensitive`, `clearAuthorizationHeader`. |
| §32.7 | implemented | `Axiam\Sdk\Ssf\SsfReceiver` via `$client->ssfReceiver(...)`: `verifySet`, `poll`, pluggable `ReplayStore`. |
| §33 | implemented | `cibaInitiate`, `cibaPoll`, `cibaAwait`, `cibaHandlePing` on `AxiamClient` (engine in `OidcClient`). |
| §33.2 signed | partial | `CibaRequestSigner::fromPem` signs `EdDSA` and `ES256`; **`PS256` refused locally** (documented carve-out). |

#### A–F per section

### §28.12
**A.** `read_client_registration` → `AxiamClient::readClientRegistration` `AC:1773`; `update_client_registration` →
`updateClientRegistration` `AC:1807`; `delete_client_registration` → `deleteClientRegistration` `AC:1827`; type
`Axiam\Sdk\Oidc\ClientRegistration` `CR:28` (unknown members kept in `$extra`, `CR:106-111`). Engine `CRC:75`, `:102`, `:111`.
Names match §28.12.5.

**B.** Argument `Sensitive $registrationAccessToken` on all three (`AC:1775`, `:1809`, `:1829`). `ClientRegistration::$clientSecret`
and `$registrationAccessToken` are `?Sensitive` (`CR:81-82`). `Sensitive` keeps the value in a static `WeakMap`, so
`var_dump`/`print_r`/`var_export`/`serialize` see no property, and `__toString`/`jsonSerialize` return `[SENSITIVE]`
(`src/Core/Sensitive.php:20-49`). `ClientRegistration::jsonSerialize` keeps both wrapped (`CR:214-232`). Rule-1 refusal names
no part of the URI (`CRC:129-133`). Nothing else wrapped.

**C.** §28.12.6 (`T/ClientRegistrationTest.php`):
1. `testAUriAtAnotherOriginIsRefusedLocallyAndNothingIsSent` (+ `testHttpIsAllowedOnlyAgainstAnHttpLoopbackBase`,
   `testTheSameOriginIsAcceptedWithTheDefaultPortSpelledOrNot`).
2. `testReadAndDeleteSendTheBearerOnlyAndKeepTheQueryVerbatim` (+ `testARedirectIsNotFollowed`).
3. `testUpdateDropsTheFiveServerStatedMembersAndReturnsTheRotatedToken` and `testAnUpdateAnswered503IsNotRetried`
   (`retry: true`, exactly one request); delete no-retry is tested with a dropped connection, not a 503
   (`testADeleteIsNeverRetriedAndAReadIsRetriedOnlyOnTransientFailures`).
4. `testA401InvalidTokenIsAnOAuthProtocolErrorAndRefreshesNothing` (asserts no `/api/v1/auth/refresh`),
   `testA400InvalidClientMetadataIsAnOAuthProtocolErrorAndAMissingDescriptionIsTolerated`,
   `testA204OnDeleteReturnsNormallyAndAnErrorOnDeleteIsMapped`.
5. `testNeitherTheTokenNorTheSecretReachesAnyRendering` (print_r, var_export, var_dump, json_encode, serialize; errors;
   8-char fragments, `tests/Fixtures/RedactionAssertions.php:27-60`).

**D.** Update: "`$metadata` is the **whole** registration: a member it omits is a member the server deletes" and "**Persist
the returned `registrationAccessToken` before doing anything else.**" and "**Never retried**" (`AC:1786-1801`). Delete:
"**Never retried**: a retry after a lost `204` would read `401`…" (`AC:1821-1822`).

**E.** `update`/`delete` call `send()` once (`CRC:102-119`); `read` wraps it in `RetryPolicy::execute` with the predicate
`status === null || >= 500 || 408 || 429` (`CRC:79-96`, `:221-226`).

**F.** "§28, §28.12, §29, §30, §31, §32 and §33, with §32.7 and §33.2 signed …" (`README.md:194-197`) and the table row
"§28.12 RFC 7592 client configuration | `readClientRegistration`, …" (`README.md:241`). Matches.

### §29
**A.** `saml.get_idp` → `saml()->getIdp` `M/SamlApi.php:40`; `listServiceProviders` `:64`; `createServiceProvider` `:89`;
`getServiceProvider` `:111`; `updateServiceProvider` `:143`; `deleteServiceProvider` `:173`; `parseSpMetadata` `:199`;
`listIdpCredentials` `:225` (returns `array`, not a `Page`); `issueIdpCredential` `:256`; `promoteIdpCredential` `:282`;
`retireIdpCredential` `:309`. All eleven; auto-pager is the generic `ManagementTransport::walk` (`M/ManagementTransport.php:167`).

**B.** Nothing wrapped (correct). `SamlIdpCredential` declares no key member (`M/Models/SamlIdpCredential.php`); typed
`fromArray` reads only declared members, so a stray `private_key_pem` is dropped.

**C.** §29.8 (`T/SamlTest.php`): 1 `testUpdateServiceProviderPutsTheWholeRegistration` (11 members asserted;
`ArgumentCountError` without the three required — same "every member" gap as C#, nulls omitted); 2
`testSignAssertionsDoesNotExistAndUnknownValuesDecode`; 3 `testParseSpMetadataSendsExactlyOneMemberAndTheDraftCreates`; 4
`testACredentialHasNoKeyMemberAndPromotionMayRetireNothing`; 5 `testServiceProvidersPageWithSearchAndCredentialsAreAPlainList`;
6 `testNoneOfTheSevenWritesIsRetriedOn503` (`retry: true`); 7 `testStatusesMapPerSection2`; 8
`testGetIdpIsNeverCachedAndKeepsNullApartFromAbsent`. All present.

**D.** Update: replacement / defaults / `entity_id` immutable / ECDSA-POST-only (`M/SamlApi.php:125-141`); create ECDSA note
(`:84`); delete ends no session (`:168-170`); parse stores nothing, exactly-one (`:191-196`); retire active stops sign-on
(`:302-304`). RMW form `ReadModifyWrite::samlServiceProvider` (`M/ReadModifyWrite.php:47`).

**E.** `M/ManagementTransport.php:94-95`: `$retryable = static fn (NetworkError $e): bool => $method === 'GET' && !$e instanceof
ValidationError;` — no write is ever retried.

**F.** Named in the README sentence and table (`README.md:195`, `:242`). Matches.

### §30
**A.** `directory()->get` `M/DirectoryApi.php:37`; `set` `:67`; `update` `:96`; `delete` `:127`; `linkAccount` `:153`;
`getSyncStatus` `:174`. All six.

**B.** `SetDirectoryConfig::$bindSecret` and `UpdateDirectoryConfig::$bindSecret` are `?Sensitive`
(`M/Models/SetDirectoryConfig.php:56`, `M/Models/UpdateDirectoryConfig.php:58`); `toArray()`/`jsonSerialize()` keep the
`Sensitive` object (renders `[SENSITIVE]`), the transport is the one place it is revealed (`UpdateDirectoryConfig.php:170-181`).
`DirectoryConfig` has no secret member. Nothing else wrapped.

**C.** §30.8 (`T/DirectoryTest.php`): 1 `testTheBindSecretReachesTheWireAndNoRendering`; 2 `testABindSecretInAResponseIsDropped`;
3 `testUpdateSendsExactlyTheMembersItWasGiven` (exact `{"enabled":false}`, keys `bind_secret,url`, exact `{"group_filter":null}`);
4 `testSetSendsEveryRequiredMemberAndDecodes201And200`; 5 `testNoWriteIsRetriedOn503` (`retry: true`); 6
`testErrorsMapPerSection2AndLinkAccountSendsOnlyTheUserId`. All present.

**D.** Rule 2 at `set` (`M/DirectoryApi.php:56-60`) and `update` (`:87-…`); replacement reset warning on `set` (`:60-61`);
delete rule 5 (`:121-…`); link signs owner out (`:145-…`).

**E.** As §29.

**F.** Named (`README.md:195`, `:243`). Matches.

### §31
**A.** `scim_targets.list` → `scimTargets()->listItems` `M/ScimTargetsApi.php:37` (**not** `list`, see PHP-05); `create` `:60`;
`get` `:82`; `update` `:113`; `delete` `:144`; `reconcile` `:169`.

**B.** `ScimTargetInput::$credential` `?Sensitive` (`M/Models/ScimTargetInput.php:47`), emitted only when set (`:89-91`).
`ScimTargetResponse` has no credential member. **But** an unknown `auth`/`scope` arm keeps its raw members minus a fixed
denylist (`credential, client_secret, authorization_header, bind_secret, private_key_pem`) in a public `$raw`
(`M/Models/ScimTargetAuthUnknown.php` `fromArray`), so a credential-bearing member under any other name is surfaced
unwrapped — verified: an unknown arm `{"type":"mtls","cert":"…"}` shows the value in `print_r` (see PHP-03).

**C.** §31.8 (`T/ScimTargetsTest.php`): 1 `testTheCredentialIsOnTheWireAndInNoRendering`; 2 `testACredentialInAResponseIsDropped`;
3 `testUpdateWithoutACredentialSendsNoKeyAndTheVariantsKeepTheirShape`; 4 `testUnknownValuesDecodeAndThePagerCarriesSearch`;
5 `testNoWriteIsRetriedOn503` (`retry: true`); 6 `testStatusesMapAndReconcileIsABodilessTwoHundredTwo`. All present.

**D.** Update: "**The credential is bound to its URL** (§31.3 rule 2)…" (`M/ScimTargetsApi.php:102-108`); create: "`credential`
is required here (§31.3 rule 2)" (`:55`); delete: "**Deprovisions nothing downstream** (§31.3 rule 8)" (`:139-…`).

**E.** As §29.

**F.** Named (`README.md:195`, `:244`). Matches.

### §32 (management)
**A.** `ssf()->listStreams` `M/SsfApi.php:37`; `createStream` `:57`; `getStream` `:79`; `updateStream` `:110`; `deleteStream` `:138`.

**B.** `SsfStreamInput::$authorizationHeader` `?Sensitive` (`M/Models/SsfStreamInput.php:46`); `SsfStream` only
`authorizationHeaderSet` (`M/Models/SsfStream.php:79`).

**C.** §32.8 management (`T/SsfManagementTest.php`): 1 `testUpdateStreamPutsEveryMemberItModels`; 2
`testThePushHeaderIsSentAndNeverRenderedOrDecoded`; 3 `testUnknownValuesAndBothTransmitterStatesDecode`; 4
`testListStreamsPagesAndTheWalkCarriesSearch`; 5 `testNoneOfTheThreeWritesIsRetriedOn503`; 6 `testStatusesMapPerSection2`.

**D.** `updateStream`: "an omitted optional member takes its default, except the header, which absent keeps … unless the
update moves `endpoint_url` … `400` (§32.3 rule 5)" (`M/SsfApi.php:96-104`).

**E.** As §29.

**F.** Named (`README.md:195`, `:245`). Matches.

### §32.7 (receiver helper)
**A.** `ssf.verify_set` → `SsfReceiver->verifySet` `RCV:188`; `ssf.poll` → `SsfReceiver->poll` `RCV:212`; factory
`$client->ssfReceiver(issuer, audience, jwksUri|discoveryUrl, accessTokenProvider, replayWindowSeconds, replayStore)` `AC:1940`.
Result `SecurityEvent{jti, iat, iss, aud, txn, eventType, event, subId}` (`src/Ssf/SecurityEvent.php`). Names match.

**B.** Provider returns `Sensitive|string` (`RCV:220-221`); `__debugInfo` hides the provider and store (`RCV:153-163`).
Refusals carry fixed text.

**C.** §32.8 helper (`T/SsfReceiverTest.php`): 1 `testASetSignedByTheJwksKeyVerifiesIntoItsClaims`; 2
`testAWrongTypOrAlgIsRefusedInThatOrder`; 3 `testAnotherKeyOrATamperedPayloadIsInvalidKey`; 4 `testAnotherIssuerOrAudienceIsRefused`;
5 `testExpSubTwoEventsOrNoJtiIsInvalidRequest`; 6 `testAReplayIsRefusedAndAShortWindowIsRefusedAtConfiguration`; 7
`testAnUnknownKidCostsOneRefetchAndASecondOneNone` (1 → 2 → 2 at +59 s → 3 at +60 s); 8
`testPollPassesAckAndSetErrsThroughAndSortsTheAnswer` + `testPollIsNotRetriedOn400ButIsOn503`. Keys generated at run time
with sodium. All present.

**D.** `verifySet` doc lists the nine steps and "**A SET that verifies has been recorded**" (`RCV:165-187`); `poll`
"**Nothing is acknowledged on your behalf**" (`RCV:197-201`); README adds the PHP-FPM shared-store warning (`README.md:2038-2041`).

**E.** `poll` → `RetryPolicy::execute(..., $retryable)` with `status === null || >= 500 || 408 || 429` (`RCV:225-257`, `:548-553`).

**F.** "with §32.7 …" (`README.md:196`), table row (`README.md:246`). Matches.

### §33
**A.** `ciba_initiate` → `cibaInitiate` `AC:1851` / `OC:1809`; `ciba_poll` → `cibaPoll` `AC:1868` / `OC:1878`; `ciba_await` →
`cibaAwait` `AC:1885` / `OC:1915`; `ciba_handle_ping` → `cibaHandlePing` `AC:1905` (static engine `OC:1984`). Names match §33.6.

**B.** `CibaInitiateResponse::$authReqId` `Sensitive` (`src/Oidc/CibaInitiateResponse.php`); `cibaPoll(Sensitive $authReqId)`;
ping returns `Sensitive` (`OC:2033`). `CibaInitiateRequest::$clientNotificationToken` `?Sensitive`
(`src/Oidc/CibaInitiateRequest.php:54`); `expectedToken` `Sensitive`. Signer key held as `private readonly Sensitive $key`
(`src/Oidc/CibaRequestSigner.php:31-35`), `jsonSerialize` shows alg/kid only (`:92-95`); the signed `request` is returned as
`Sensitive` and revealed only into the form (`OC:1834`, `:2122-2140`). `loginHint`/`bindingMessage` are public readonly
plain strings (not secrets; never logged by the SDK).

**C.** §33.8 (`T/CibaTest.php`): t01 `:173`; t02 `:194` + `:220` (mTLS client_id only); t03 `:249`; t04 `:301` (503, OAuth 429,
dropped connection; `retry: true`; one request each — no bodiless-429 case); t05 `:321` (sleeps `[5,10,15,15]`, four terminal
codes incl. unknown); t06 `:353` (injected clock, first poll at `1000+interval`; 7 / absent / 0); t07 `:379` (polls at 1005, 1010
for `expires_in` 12); t08 `:391` (+ `:405` bodiless 400 terminal); t09 `:421`; t10 `:434`; t11 `:450`; t12 `:482`; t13 `:494`;
t14 `:530` (EdDSA and ES256 only); t15 `:585` (incl. PS256 refused); t16 `:612`. All sixteen present.

**D.** `cibaInitiate`: "**Never retried** … **A success proves nothing about the user**" (`OC:1796-1806`, `AC:1842-1843`);
`cibaPoll`: "**Store the returned tokens before anything else**" (`OC:1871-1874`); `cibaAwait` ping-mode guidance
(`OC:1905-1910`); ping: "answer `204` as soon as this returns, **then** call `cibaPoll()`" (`OC:1972-1976`).

**E.** Initiate: one `postForm()` on `plainHttp`, which carries `AuthMiddleware` but **no** `RefreshMiddleware`
(`AC:428-433`, `:461`), so neither a retry nor a §9 re-send is possible (`OC:1840-1841`, `:2467-2479`).

**F.** "…§32 and §33, with §32.7 and §33.2 signed (the signed form for `EdDSA` and `ES256`; **`PS256` is not shipped** …)"
(`README.md:194-197`), table row and carve-out (`README.md:247-257`). Honest; the claim "§33.2 signed" is partial (PHP-02).

#### Q1 … Q10

### Q1 Replay store
- Interface `ReplayStore::checkAndRecord(string $jti, int $windowSeconds): bool` (`src/Ssf/ReplayStore.php:20`) —
  **synchronous**, **atomic check-and-insert** by contract of the doc ("MUST be atomic … e.g. Redis `SET NX EX`").
- Default `InMemoryReplayStore`: PHP array `jti => expiry`, swept with `array_filter` on every call (O(n)); **unbounded, no cap**;
  clock injectable callable (`src/Ssf/InMemoryReplayStore.php:31-56`). Per **process** — under PHP-FPM effectively per
  request; README tells FPM users to pass a shared store (`README.md:2038-2041`).
- Store error: not caught; propagates out of `verifySet` and aborts `poll` (which catches only `SetVerificationError`,
  `RCV:273-277`). Fail closed, error type = the store's.
- Recorded only after 1–8 (and the poll-key check): `RCV:373-376`.
- Floor: constructor refusal, `ValidationError` field `replay_window` (`RCV:130-135`); default = floor = 604 800 s (`RCV:58`).

### Q2 `verify_set` order and codes
1 three parts, strict base64url (empty segment allowed by the regex but then fails later), JSON objects [`Malformed`]
`RCV:288-302`; 2 `typ` string, lower-cased, in `{secevent+jwt, application/secevent+jwt}` [`InvalidType`] `:305-308`; 3
`alg !== 'EdDSA'` [`InvalidKey`] `:311-313`; 4 `kid` missing/empty or not in JWKS [`InvalidKey`] `:316-323`; 5 signature length
64 + `sodium_crypto_sign_verify_detached` [`InvalidKey`] `:326-329`; 6 `iss !==` [`InvalidIssuer`] `:332-335`; 7 `aud` string or
array (`in_array` strict) [`InvalidAudience`] `:338-344`; 8 `exp`/`sub` present, `jti` empty, `iat` not int **or float**,
`sub_id` not object, `events` not exactly one member [`InvalidRequest`] `:347-366`; extra poll-key ≠ `jti` [`InvalidRequest`]
`:367-369`; 9 replay [`Replayed`] `:374-376`. Codes are the enum's backing values (`src/Ssf/SetFailureReason.php`);
`pushErrorCode()` maps malformed/invalid_type/replayed → `invalid_request`. Kid miss: one forced refetch, at most every 60 s
(`RCV:404-408`); JWKS TTL 300 s refetch separate (`:401-403`). JWKS failure: transport/5xx → `NetworkError`, but a 401/403 on the
JWKS maps through `ErrorMapper::fromResponse` to `AuthError`/`AuthzError` (`RCV:476-478`). Keys only from configured `jwks_uri`
or discovery with matching `issuer` (`RCV:442-461`).

### Q3 `poll`
Never acknowledges (body = caller's options only, `{}` when none, `RCV:223`; `setErrs` always an object,
`src/Ssf/SsfPollOptions.php`). `ack`/`setErrs` exactly as given (test asserts the exact JSON). Refused as `RefusedSet(string
$jti, SetFailureReason $reason)`. Not retried on 400/401/403/404; retried on 408/429/5xx/transport. Token from
`accessTokenProvider`, once per poll before the retry loop (`RCV:220-221`); none → local `AuthError`, no request (`RCV:214-219`).
Session-free, no redirects (`RCV:234-243`).

### Q4 `ciba_await` clock and loop
- Injectable: `CibaClock { now(): float; sleep(int) }` (`src/Oidc/CibaClock.php`), passed to **both** `cibaInitiate` (stamps
  `receivedAt`, `OC:1855`) and `cibaAwait` (`OC:1919`). Consistent.
- Initial interval: response `interval` if int > 0, else 5 (`OC:1854`, `:1927`). No faster floor.
- `slow_down`: `+= 5`, never reset (`OC:1946-1948`); **no 60 s cap**.
- Deadline `receivedAt + expiresIn` (`OC:1926`); `if ($clock->now() + $interval >= $deadline) throw new
  OAuthProtocolError('expired_token', …)` before each sleep (`OC:1930-1936`) — gives up up to one interval early, no request.
- 5xx/408/429/transport: §16 inside `cibaPollTracked` (`OC:2056-2080`), then the loop continues (`OC:1951-1957`); OAuth
  `rate_limit_exceeded` continues at the same interval (`OC:1943`). Bodiless other 4xx is terminal.
- Cancellation: none (synchronous PHP; `sleep()`).
- `auth_req_id`: held by the caller's `CibaInitiateResponse`; revealed into the per-call form only.

### Q5 `ciba_handle_ping`
`hash_equals($expected, $presented)` (`OC:2011`), constant-time for equal lengths. Returns `Sensitive` (`OC:2033`). Accepts
PSR-7 (`name => list`) or `getallheaders()` maps; collects every `Authorization` value case-insensitively; not exactly one,
no space, non-`Bearer` scheme, empty presented/expected, mismatch (incl. double space) → `AuthError` "ciba ping refused: the
Authorization header is not the expected bearer" (`OC:1987-2013`). Body not a JSON object / no non-empty string
`auth_req_id` → `ValidationError` (`OC:2015-2030`). Static, synchronous, no I/O (t13).

### Q6 Signed request
Offered for `EdDSA` (PKCS#8 Ed25519 → sodium secret key) and `ES256` (P-256 PEM, curve checked); `PS256` → local
`ValidationError` (`src/Oidc/CibaRequestSigner.php:54-75`); key proven by a probe signature. Signing via `firebase/php-jwt`
`JWT::encode($claims, $key, $alg, $kid)` (header `typ: "JWT"`, `alg`, optional `kid`) (`:82-85`). Claims: `iss` = client id,
`aud` = discovery `issuer` (string), `iat` = `nbf` = `time()`, `exp` = +300 s, `jti` = `bin2hex(random_bytes(16))`, plus every set
member (`requested_expiry` an int) (`OC:2122-2140`). Form carries only `client_id`, `client_secret` (if any) and `request`
(`OC:1832-1835`). Key material wrapped (`Sensitive`); `request` returned `Sensitive`. No default alg or key (`fromPem` requires both).

### Q7 Kept-secret-on-update
Same mechanism for all three: the property is `?Sensitive`, and `toArray()` emits it only when non-null — **omit = keep**,
`new Sensitive($v)` = replace.
- `directory.update`: `if ($this->bindSecret !== null) { $out['bind_secret'] = $this->bindSecret; }`
  (`M/Models/UpdateDirectoryConfig.php:120-122`).
- `ssf.update_stream`: `authorizationHeader` likewise, plus `clearAuthorizationHeader: true` as the third state
  (`M/Models/SsfStreamInput.php:46`, `toArray` `:87-…`).
- `scim_targets.update`: `if ($this->credential !== null) { $out['credential'] = $this->credential; }`
  (`M/Models/ScimTargetInput.php:89-91`).
`ReadModifyWrite::*` leaves the secret absent (`M/ReadModifyWrite.php:26-33`).

### Q8 §21.3.1 pin
**No test reads vector A from the vendored `CONTRACT.md` or asserts a key count against it.** The pin is structural:
`testTheAliasTypeCarriesOnlyTheSevenAliasableEndpoints` asserts the `MtlsEndpointAliases` property set is exactly the seven names,
`backchannel_authentication_endpoint` included (`tests/MtlsEndpointAliasesTest.php:378-399`), and a hand-written seven-alias
fixture (`:51-63`) drives `testEveryAliasableEndpointGoesToTheAliasHost`, which calls `cibaInitiate` and asserts
`/oauth2/bc-authorize` went to the mTLS host (`:273-290`). The fixture carries no `tenant_id` query, so vector A's "query
component intact" row is not exercised here. `cibaInitiate` prefers the alias: `preferredEndpoint($configuration, fn ($a) =>
$a->backchannel_authentication_endpoint, …)` (`OC:1817-1821`); `cibaPoll` likewise for the token endpoint (`OC:2047-2051`).

### Q9 §28.12 details
- Verbatim: the string is passed to Guzzle as is (`CRC:196`); no rebuild, no host swap; redirects off.
- Body: `$extra` minus the five, plus typed members (`CR:179-206`). **Always** sends `redirect_uris`, `grant_types` and
  `response_types`, as `[]` when the read had none (`CR:189-191`) — RFC 7591 gives omitted `grant_types`/`response_types`
  defaults, so `[]` is not the same request (PHP-07). A non-string item in those lists is dropped on decode, not kept
  (`CR:134-138`), unlike other mistyped members.
- Bearer only, on `bareHttp` (`'cookies' => false`, no middleware, `allow_redirects => false`) (`AC:441-445`, `CRC:183-190`).
- 401 → `OAuthProtocolError` via `ErrorMapper::fromOAuth2Response` (any status with `error`) (`CRC:206-208`,
  `src/Core/ErrorMapper.php:88-98`); no refresh middleware on that client.

### Q10 Other divergences / silent-contract decisions
- `scim_targets.list` is `listItems()` (SDK-wide for every §27 `list`), not §31.6's `scimTargets()->list` (PHP-05).
- `PS256` refused for the signed request; contract has no notion of a partial "§33.2 signed" (PHP-02).
- Poll partial-failure loss: same as C# — SETs recorded before a later JWKS/store failure aborts `poll` are lost to
  `replayed` on re-offer (PHP-01).
- Unknown `ScimTargetAuth`/`ScimTargetScope` arm: keeps a denylist-scrubbed `$raw` (surfaces any other-named secret), and
  `json_encode()` of a response carrying one throws (PHP-03).
- `SsfReceiver` calls sodium without the `extension_loaded('sodium')` guard `JwksVerifier` has, and `composer.json` does not
  require `ext-sodium` (PHP-04).
- `iat` accepted as float (C#: integer only); JWKS 401/403 surfaces as `AuthError`/`AuthzError`, the parent of
  `SetVerificationError`, so a push handler catching `AuthError` would answer it as a SET refusal.
- `ciba_await` stops up to one interval before the deadline (same as C#; clock is consistent here).
- Signed request: 300 s lifetime, `typ: "JWT"`, string `aud`, 32-hex `jti` — contract silent.
- Replacement bodies omit null optional members (§29.8 t1 "every member" asserted for 11).
- Generated doc boilerplate: `ParseSamlSpMetadata` "a SPARSE body: what you leave unset is left unchanged"; SAML input "every
  field is required"; doubled "`POST …`" lines in `SamlApi` method docs (PHP-06).

#### Findings
| id | Severity | Clause | What | Evidence (path:line) | Suggested disposition |
|---|---|---|---|---|---|
| PHP-01 | defect | §32.7 (`poll`), step 9 | `poll()` verifies and records SETs one by one; a `NetworkError` (JWKS) or store exception on a later SET aborts the poll after earlier SETs were recorded, so they are never returned and read `replayed` when re-offered — silent event loss (`testAJwksFailureAbortsThePoll` pins the abort, not the loss). | `src/Ssf/SsfReceiver.php:266-279`, `:374` | SDK fix (verify 1–8 for all before recording, or prefetch keys); contract clarification on partial poll failure |
| PHP-02 | clarification | §33.2, §33.10, Conformance Statement | "§33.2 signed" is claimed with `PS256` declined (README carve-out, local `ValidationError`, tested). The contract defines declining the signed form as a whole (§21.7.3), not per algorithm; a `PS256`-registered `fapi2` CIBA client cannot use this SDK. | `src/Oidc/CibaRequestSigner.php:60-63`; `README.md:196-197`, `:251-257`; `tests/Contract158/CibaTest.php:585` | contract clarification (record per-alg posture in §33.10; say whether the claim may be partial) |
| PHP-03 | defect | §31.2, §7 rule 1 | Unknown `auth`/`scope` arm keeps its raw members in a public `$raw`, scrubbed only by a name denylist — a secret under any other name is surfaced unwrapped (verified: `print_r` shows an unknown arm's `cert` value). And `toArray()`/`jsonSerialize()` of an unknown arm throw, so `json_encode($scimTargetResponse)` for a log line throws `AxiamException` (verified). | `src/Management/Models/ScimTargetAuthUnknown.php` (`fromArray`, `toArray`, `jsonSerialize`); `ScimTargetScopeUnknown.php:15-67`; `ScimTargetResponse.php:86`, `:94`, `:114` | SDK fix (keep only `type` as C# does; refuse unknown arms in the request encoder, not in `jsonSerialize`) |
| PHP-04 | defect | §32.7, packaging | `SsfReceiver` uses `SODIUM_CRYPTO_SIGN_BYTES`/`sodium_crypto_sign_verify_detached` with no `extension_loaded('sodium')` guard (unlike `JwksVerifier`), and `composer.json` does not declare `ext-sodium`; without it `verifySet` dies with an `Error`, not a typed SDK error. | `src/Ssf/SsfReceiver.php:326-327`, `:433`; `src/Auth/JwksVerifier.php:226-232`; `composer.json` `require` | SDK fix (guard + `ext-sodium` in `require` or `suggest`) |
| PHP-05 | doc | §31.6, §27.3 | The `list` operation is `listItems()` (`scimTargets()->listItems`, and every §27 namespace), not the naming map's `list`; `list` is a legal PHP method name since 7.0 (checked with `php -r`). The divergence is not recorded in the contract. | `src/Management/ScimTargetsApi.php:37`; `src/Management/UsersApi.php:39`; `README.md:1527` | contract clarification (record PHP's `listItems` in §27.3/§31.6) or SDK alias |
| PHP-06 | doc | §29.2, §27.4 rule 5 | Generated docblocks contradict the types: `ParseSamlSpMetadata` "SPARSE body: what you leave unset is left unchanged"; `SamlServiceProviderInput` "every field is required" (three are); `SamlApi` method docs repeat the request line twice. | `src/Management/Models/ParseSamlSpMetadata.php:11-16`; `SamlServiceProviderInput.php:17-18`; `src/Management/SamlApi.php:186-190` | SDK fix (generator templates) |
| PHP-07 | defect | §28.12.2 rule 4, RFC 7591 §2 | `updateBody()` always sends `redirect_uris`, `grant_types`, `response_types`, as `[]` when the read carried none; RFC 7591 defaults omitted `grant_types`/`response_types`, so an empty array is a different request than the registration read. Non-string list items are dropped on decode instead of kept. | `src/Oidc/ClientRegistration.php:134-138`, `:189-191` | SDK fix (omit when absent, as C# does) |
| PHP-08 | clarification | §21.3.1 | Vector A is not read from the vendored `CONTRACT.md`; it is reproduced by a hand fixture without the `tenant_id` queries, and the seven-key pin is on the alias type's property names. Contract says "MUST pin all three" without saying verbatim. | `tests/MtlsEndpointAliasesTest.php:51-63`, `:378-399` | contract clarification (verbatim vs equivalent); optional SDK test reading the vector |
| PHP-09 | clarification | §32.7 vs §16.3; §32.7 steps 4/9; §33.7 rule 4 | Same open points as C#: `poll` retries 408/429 although §32.7 says "not retried on a 4xx"; no reason code for an unfetchable JWKS (PHP: `NetworkError`, or `AuthError` for a 401 JWKS); default store unbounded, floor enforced by constructor `ValidationError`; `cibaAwait` gives up up to one interval early; signed-request lifetime/`typ`/`aud`/`jti` choices. | `src/Ssf/SsfReceiver.php:548-553`, `:476-478`, `:130-135`; `src/Ssf/InMemoryReplayStore.php:46-56`; `src/Oidc/OidcClient.php:1930`, `:2122-2140` | contract clarification |

---

### Report — go — commit ea9eb07 (merge #93)
Toolchain run: yes — `go test -count=1 . ./middleware/... ./webhook/...` (go1.24.7) → `ok` for all three packages (root 27.1 s), exit 0. Run against the clone in place; only Go's build/test cache (outside the repo) was written.

Vendored `CONTRACT.md`, `openapi.json`, `management-registry.json` are byte-identical to this repository's `sdks/` (cmp).

#### Posture per section
| Section | Status | Notes |
|---|---|---|
| §28.12 | implemented | Methods on `*Client`; own bare transport (no jar, no redirects); origin check before I/O; PUT/DELETE single-shot. |
| §29 | implemented | Generated `client.SAML()`; 11 ops; `ParseSAMLSpMetadata` exactly-one check is local; no key member on `SAMLIdpCredential`. |
| §30 | implemented | Generated `client.Directory()`; `BindSecret *Sensitive` on both request types; `Nullable[T]` for explicit null. Sparse `Update` cannot send an empty list (F-GO-03). |
| §31 | implemented | Generated `client.SCIMTargets()`; `Credential *Sensitive`; unknown `auth`/`scope` union decodes but refuses to encode. |
| §32 | implemented | Generated `client.Ssf()`; `AuthorizationHeader *Sensitive`; `ClearAuthorizationHeader` modelled. |
| §32.7 | implemented | `NewSsfReceiver` / `VerifySet` / `Poll`. A poll aborted by a JWKS failure loses SETs it already recorded (F-GO-02). |
| §33 | implemented | `CibaInitiate` / `CibaPoll` / `CibaAwait` / `CibaHandlePing` on `*Client`. AXIAM's real `500 {"error":"server_error"}` ends `CibaAwait` (F-GO-01). |
| §33.2 signed | implemented | `CibaRequestSigner` (PS256/ES256/EdDSA, the caller's key and alg, no defaults). |

#### A–F per section

### §28.12
- **A.** `read_client_registration` → `(*Client).ReadClientRegistration` oidc_registration.go:412; `update_client_registration` → `UpdateClientRegistration` :466; `delete_client_registration` → `DeleteClientRegistration` :489; type `ClientRegistration` :66. Names match §28.12.5. Unknown members kept in `Extra` (:59-65, :141-143).
- **B.** Token argument `Sensitive` (all three signatures). `ClientRegistration.ClientSecret` and `.RegistrationAccessToken` are `Sensitive` (:97, :100). `MarshalJSON` writes `[SENSITIVE]` for both (:152-164). `%v/%+v/%#v` go through `Sensitive`'s Format/GoString (sensitive.go:34-56). Errors: the transport failure is generic, `operation+": request failed"` (:525). The origin refusal names no part of the URI (:327-328). Test 5 checks the 401 error and the origin-refusal error for 8-character fragments (oidc_registration_test.go:372-396). No §19 event is emitted on this path.
- **C.**
  1. Origin refusal: `TestClientRegistration_AnotherOriginIsRefusedLocallyAndNothingIsSent` (oidc_registration_test.go:58). Covers another host, another port, http vs https, http on a non-loopback http base; asserts 0 requests.
  2. Header only: `…ReadAndDeleteSendTheBearerOnlyAndKeepTheQuery` (:131). Checks no cookie, no session token, no CSRF, no body, and a verbatim query.
  3. Update body: `…UpdateDropsTheFiveServerStatedMembersAndReturnsTheRotatedToken` (:196). The "503 not retried" half is in `…WritesAreNotRetriedAndTheReadIs` (:241): a permanent 503 gives exactly 1 PUT, 1 DELETE, and `MaxAttempts` GETs.
  4. Errors: `…A401InvalidTokenIsAnOAuthProtocolErrorAndRefreshesNothing` (:287, asserts 0 refresh calls), `…A400InvalidClientMetadata…` (:309), 204 handled in :150. The 400 case does not assert "no §9", but no path could reach §9.
  5. Redaction: `…NeitherTheTokenNorTheSecretReachesAnyRendering` (:372).
- **D.** Update doc (:446-465): "metadata is the WHOLE registration … PERSIST THE RETURNED RegistrationAccessToken BEFORE DOING ANYTHING ELSE … NEVER RETRIED". Delete doc (:487): "NEVER RETRIED". Read doc (:404-408): §16, and that a 401 never refreshes.
- **E.** Update and delete call `sendRegistration` once, outside any retry runner (:479, :498). Read uses `retryReadOnly` (:425), which stops on non-retryable statuses (:431-433). `retryReadOnly` retries only `*NetworkError` (retry.go:96).
- **F.** README:23-24 lists "§28, §28.12". This matches the code.

### §29
- **A.** All eleven ops are on `SAMLAPI` (management_saml.go), reached through `client.SAML()` (management_api.go:168):

  | Operation | Method | Line |
  |---|---|---|
  | `get_idp` | `GetIdp` | :68 |
  | `list_service_providers` | `ListServiceProviders` (+`ListServiceProvidersAll`) | :96 (:111) |
  | `create_service_provider` | `CreateServiceProvider` | :143 |
  | `get_service_provider` | `GetServiceProvider` | :168 |
  | `update_service_provider` | `UpdateServiceProvider` | :211 |
  | `delete_service_provider` | `DeleteServiceProvider` | :243 |
  | `parse_sp_metadata` | `ParseSpMetadata` | :282 |
  | `list_idp_credentials` | `ListIdpCredentials` (`[]SAMLIdpCredential`) | :307 |
  | `issue_idp_credential` | `IssueIdpCredential` | :339 |
  | `promote_idp_credential` | `PromoteIdpCredential` | :372 |
  | `retire_idp_credential` | `RetireIdpCredential` | :406 |

  §29.6's Go row is `Saml()`, and the SDK uses `SAML()` (Go initialism style) — F-GO-12.
- **B.** Nothing is wrapped, which is correct. `SAMLIdpCredential` (management_models.go:2991-3016) has no key member. `encoding/json` drops unknown members. Test 4 checks this with reflect and renderings.
- **C.** Tests 1–8 are `TestSAML_*` at management_saml_test.go:71, :111, :149, :205, :236, :275, :311, :351.
  - Test 1 asserts 11 of the members. The four null ones (`slo_url`, `slo_binding` and the two certificates) are omitted by `omitempty`. "Cannot be built without the three required members" rests on `NewSAMLServiceProviderInput` (management_models.go:3194), which takes them as arguments but does not refuse empty strings, and a struct literal bypasses it. This is forced by the language (F-GO-10).
  - Test 6 uses a permanent 503 with exactly-one assertions.
- **D.** Notes at the call sites:
  - `UpdateServiceProvider` (:193-210): the §27.4 rule 5 replacement warning, the defaults list, `ToInput()`, `entity_id` immutable, and ECDSA is POST-only.
  - `CreateServiceProvider` (:135-139): the ECDSA/RSA note.
  - `DeleteServiceProvider` (:238-239): "Ends no session".
  - `RetireIdpCredential` (:399-402): "RETIRING THE ACTIVE CREDENTIAL WITH NO SUCCESSOR STOPS SAML SIGN-ON FOR THE WHOLE TENANT".
  - `ParseSpMetadata` (:272-278): "PARSES AND STORES NOTHING". The type's own doc, however, calls it a "SPARSE body … left unchanged" (management_models.go:2465-2470), which is wrong (F-GO-08).
- **E.** `sendManagement` / `sendManagementNoContent` call a non-GET once, never through `retryReadOnly` (management_request.go:89-94, :113-115).
- **F.** README:24 lists "§29", and its 1.53–1.58 table row (README:45) matches the code.

### §30
- **A.** All six ops are on `DirectoryAPI` (management_directory.go), reached through `client.Directory()` (management_api.go:155):

  | Operation | Method | Line |
  |---|---|---|
  | `get` | `Get` | :61 |
  | `set` | `Set` | :105 |
  | `update` | `Update` | :143 |
  | `delete` | `Delete` | :178 |
  | `link_account` | `LinkAccount` | :213 |
  | `get_sync_status` | `GetSyncStatus` | :238 |
- **B.** `SetDirectoryConfig.BindSecret *Sensitive` (management_models.go:3607) and `UpdateDirectoryConfig.BindSecret *Sensitive` (:4417). The secret is unwrapped only in `toWire()` (:3683ff, :4487ff; `exposeOptional` management_wire.go:22). `DirectoryConfig` has no secret member, and nothing else is wrapped.
- **C.** Tests 1–6 are management_directory_test.go:51, :74, :93, :136, :161, :189.
  - Test 3 asserts exact bodies `{"enabled":false}`, keys `[bind_secret url]`, and `{"group_filter":null}`.
  - Test 4's "cannot be built without" rests on `NewSetDirectoryConfig` (:3650), as for §29.
- **D.**
  - `Set` (:93-101) and `Update` (:132-139): "MOVING THE CONNECTION REQUIRES THE SECRET AGAIN … The SDK holds no copy of the secret". `Set` also carries the default-reset warning.
  - `Delete` (:169-174): "DELETING STOPS THE DIRECTORY, AND ONLY THAT … no fallback … There is no unlink".
  - `LinkAccount` (:204-209): "SIGNS THE ACCOUNT'S OWNER OUT EVERYWHERE".
  - `Set`'s doc opens with the generic "Every field of the body is required" (:88-91). It is contradicted two lines later (F-GO-08).
- **E.** Same path as §29. Test 5 checks one request each.
- **F.** README:24 lists "§30". This matches the code.

### §31
- **A.** All six ops are on `SCIMTargetsAPI`, reached through `client.SCIMTargets()` (management_api.go:189):

  | Operation | Method | Line in management_scim_targets.go |
  |---|---|---|
  | `list` | `List` (+`ListAll`) | :54 (:64) |
  | `create` | `Create` | :89 |
  | `get` | `Get` | :106 |
  | `update` | `Update` | :142 |
  | `delete` | `Delete` | :167 |
  | `reconcile` | `Reconcile` | :191 |
- **B.** `SCIMTargetInput.Credential *Sensitive` (management_models.go:3291), unwrapped only in `toWire` (:3344). `SCIMTargetResponse` (:3361) and `SCIMTargetAuth` (:3231) have no credential member.
- **C.** Tests 1–6 are management_scim_targets_test.go:51, :70, :91, :131, :202, :232.
  - Test 3's oauth2 shape is asserted only with `scope` set. A nil `Scope` is omitted, not sent as `null` (F-GO-06).
  - Test 4 additionally asserts that an unknown union is refused locally with 0 requests.
- **D.**
  - `Update` (:130-138): "THE CREDENTIAL IS BOUND TO ITS URL (§31.3 rule 2) … The SDK holds no credential to re-send", plus the 409 note.
  - `Create` (:84-85): "Credential is required here (§31.3 rule 2)".
  - `Delete` (:160-163): "DEPROVISIONS NOTHING DOWNSTREAM".
  - `Reconcile` (:185-187): 202/409.
- **E.** Same path as §29. Test 5 checks this.
- **F.** README:24 lists "§31". This matches the code.

### §32 (management)
- **A.** All five ops are on `SsfAPI` (management_ssf.go), reached through `client.Ssf()` (management_api.go:179):

  | Operation | Method | Line |
  |---|---|---|
  | `list_streams` | `ListStreams` (+`ListStreamsAll`) | :67 (:81) |
  | `create_stream` | `CreateStream` | :107 |
  | `get_stream` | `GetStream` | :132 |
  | `update_stream` | `UpdateStream` | :174 |
  | `delete_stream` | `DeleteStream` | :202 |

  Event types are an open `SsfEventType` string with named constants (management_models.go:3960ff). The receiver file adds the two SSF stream event types (ssf_receiver.go:48-51).
- **B.** `SsfStreamInput.AuthorizationHeader *Sensitive` (management_models.go:4047). `SsfStream` (:3991) has only `AuthorizationHeaderSet`.
- **C.** Tests 1–6 are management_ssf_test.go:54, :90, :115, :138, :169, :196. All discharged. Test 1's "cannot be built without" is again constructor-based.
- **D.** `UpdateStream` (:164-170): "An omitted optional member takes its default (§32.2) — EXCEPT AuthorizationHeader, WHICH ABSENT KEEPS THE STORED ONE — unless the update moves EndpointURL … else 400 (§32.3 rule 5)", plus the 409 note.
- **E.** Same path as §29. Test 5 checks this.
- **F.** README:24 lists "§32". This matches the code.

### §32.7 (helper)
- **A.** `SsfReceiver.VerifySet` ssf_receiver.go:498 and `SsfReceiver.Poll` :640, matching §32.7's Go row. The constructor is `NewSsfReceiver(client, SsfReceiverConfig)` :287. The config carries `Issuer`, `Audience`, `JWKSURI` | `DiscoveryURL`, `AccessTokenProvider`, `ReplayWindow` and `ReplayStore` (:179-199). The result `SecurityEvent` (:202-220) has jti, iat, iss, aud (raw), txn, event_type, event and sub_id.
- **B.** The token provider returns `Sensitive` (:175), and the bearer is exposed only at the header (:687). `SsfReceiver.String()` omits the provider (:347-349). There is no other secret on this surface.
- **C.** Tests are in ssf_receiver_test.go. All eight are discharged.

  | # | Test | Line | Notes |
  |---|---|---|---|
  | 1 | `…ASetSignedByTheJWKSKeyVerifiesIntoItsClaims` | :166 | |
  | 2 | `…AWrongTypOrAlgIsRefusedInThatOrder` | :198 | |
  | 3 | `…AnotherKeyOrATamperedPayloadIsInvalidKey` | :235 | |
  | 4 | `…AnotherIssuerOrAudienceIsRefused` | :253 | |
  | 5 | `…ExpSubTwoEventsOrNoJtiIsInvalidRequest` | :269 | |
  | 6 | `…AReplayIsRefusedAndAShortWindowIsRefusedAtConfiguration` | :296 | |
  | 7 | `…AnUnknownKidCostsOneRefetchAndASecondOneNone` | :324 | |
  | 8 | `…PollPassesAckAndSetErrsThroughAndSortsTheAnswer` | :366 | + `…PollIsNotRetriedOn400ButIsOn503` :432 |

  The keys are generated with `ed25519.GenerateKey`, so the test holds no key literal.
- **D.** The `VerifySet` doc lists the nine steps and the codes (:476-497). The `Poll` doc (:629-639) says "NOTHING IS ACKNOWLEDGED ON YOUR BEHALF". It also warns that a verified SET is recorded and that a re-offered one then reads `replayed`.
- **E.** `Poll` runs `retryReadOnly`. A non-retryable status sets `decisive` and stops the loop (:701-704). Only 408, 429 and 5xx (`statusIsRetryable`, oidc_registration.go:364) and transport errors are retried.
- **F.** README:24-25 says "with §32.7". This matches the code.

### §33
- **A.** All four ops are on `*Client`:

  | Operation | Method | Line in oidc_ciba.go |
  |---|---|---|
  | `ciba_initiate` | `CibaInitiate` | :461 |
  | `ciba_poll` | `CibaPoll` | :563 |
  | `ciba_await` | `CibaAwait` | :659 |
  | `ciba_handle_ping` | `CibaHandlePing` | :728 (synchronous) |

  The types are `CibaInitiateParams` :237, `CibaInitiateResponse` :275, `CibaPollParams` :297, `CibaAwaitParams` :331 and `CibaClock` :308. `CibaInitiateParams` has no `user_code`, `login_hint_token`, `request_uri` or extra-parameter member (asserted in oidc_ciba_test.go:360-365).
- **B.**
  - `CibaInitiateResponse.AuthReqID Sensitive` (:278), `CibaPollParams.AuthReqID Sensitive` (:299), and the ping result is `Sensitive` (:755).
  - `ClientNotificationToken Sensitive` (:263); `CibaHandlePing`'s `expectedToken Sensitive` (:728).
  - `CibaRequestSigner` has unexported fields and redacts in `String`/`Format`/`GoString`/`MarshalJSON` (:187-204). The PEM input is `Sensitive` (:162). The signed `request` is `Sensitive` (:442) and exposed only into the form (:496).
  - The errors carry the server's `error`/`error_description` only. The transport error is generic (:544).
- **C.** Tests are `TestCiba_T01…T16` in oidc_ciba_test.go. All sixteen are present.

  | # | Line | Notes |
  |---|---|---|
  | T01 | :231 | Asserts no notification-token fragment in the error; does not separately check the `auth_req_id` in an error, which the error cannot carry. |
  | T02 | :268 | |
  | T03 | :330 | |
  | T04 | :394 | 503, 429 with body, and a dropped connection, each exactly one. |
  | T05 | :451 | |
  | T06 | :510 | Injected clock. |
  | T07 | :543 | |
  | T08 | :565 | Uses **bodiless** 500/503 replies. AXIAM's real 500 carries `{"error":"server_error"}` and would fail this loop (F-GO-01). |
  | T09 | :601 | |
  | T10 | :629 | |
  | T11 | :651 | Constant-time asserted structurally: source grep for `subtle.ConstantTimeCompare`. |
  | T12 | :694 | |
  | T13 | :711 | |
  | T14 | :751 | Verifies with lestrrat jws for EdDSA, ES256 and PS256. |
  | T15 | :845 | |
  | T16 | :901 | |
- **D.** Package doc (:16-25) and `CibaInitiate` doc (:454-460): "NEVER RETRIED … A success proves nothing about the user". `CibaPoll` (:560-562): "STORE THE RETURNED TOKENS BEFORE ANYTHING ELSE". `CibaAwait` (:655-658) gives the ping-mode guidance, and `CibaHandlePing` (:725-727) says "Answer 204 … THEN call CibaPoll".
- **E.** `CibaInitiate` makes one `postCibaForm` with no retry runner (:508). `doRequest` has no retry and no §9 (client.go:863-891). `CibaPoll` uses `retryReadOnly` but treats any `OAuthProtocolError` as decisive (:609-611), including one at 5xx.
- **F.** README:23-25 says "… §32 and §33, with §32.7 and §33.2 signed". The "contract 1.58" version is current. This matches the code.

#### Q1 … Q10

### Q1 Replay store
- **Interface.** `SsfReplayStore { CheckAndRecord(jti string, window time.Duration) bool }` (ssf_receiver.go:134-139). It is synchronous and does an atomic check-and-insert ("MUST be atomic", :135-137).
- **Default and expiry.** The default is `MemorySsfReplayStore` (:143-170): a mutex plus `map[jti]expiry`. Every call sweeps all expired entries (O(n) per call). There is no count cap, so it is bounded only by the window. `now` is test-injectable only (unexported).
- **Store errors.** The interface has **no error channel**. A store that fails, such as a shared cache, must itself return true (fail open) or false (fail closed). Nothing documents which it should return (F-GO-09).
- **Order.** The jti is recorded only after steps 1–8 and the poll-key check (:577-588).
- **Seven-day window.** Enforced by refusal at construction: `NewSsfReceiver` returns a local `*ValidationError` with field `replay_window` and "must be at least seven days" (:299-302). Zero means seven days (:296-298). A longer window is accepted.

### Q2 `verify_set` order and reason codes
The steps run in contract order 1–9 with the contract's codes (:502-588). Details:
- **Step 1.** The signature segment is base64-checked before the header and payload are decoded; all three failures are `malformed`.
- **`typ`.** Compared case-insensitively against `secevent+jwt` or `application/secevent+jwt` (:518-521).
- **`alg`.** Must be exactly `EdDSA` (:523).
- **Missing `kid`.** Gives `invalid_key` with no refetch (:527-530).
- **`kid` miss refetch.** One forced refetch, gated by a **global** `lastForced` at 60 s (:444-449). If the 300 s cache is also stale, a single call can fetch twice: the ordinary refresh, then the forced one (:436-449) (F-GO-11).
- **Non-Ed25519 JWK.** A JWK for the `kid` that is not Ed25519 gives `invalid_key` (:538-540).
- **`aud`.** Accepted as a string or an array containing the audience (:608-622).
- **Step 8 extras.** Step 8 also requires `iat` numeric and `sub_id` an object (:565-572). In `Poll` it adds a check that the poll map key equals the SET's `jti` (`invalid_request`, :577-579). Both are additive.
- **JWKS fetch failure.** A failed fetch is a `*NetworkError`, not `invalid_key` (:531-534). The contract is silent on this (F-GO-13).

### Q3 `poll`
- **Acknowledgements.** `Poll` never acknowledges on its own. `ack` and `setErrs` are sent exactly as given, and only when non-nil (:648-660; test :366 asserts the exact body and `{}`).
- **Refusals.** Returned as `RefusedSet{Jti, Reason}` (:222-229), sorted by jti.
- **Retry.** Not retried on 4xx other than 408 and 429 (:701-704). 400 maps to `*ValidationError` via `managementError`.
- **Token source.** The bearer comes from `AccessTokenProvider`, called once per poll outside the retry loop (:665). With no provider, `Poll` returns a local `*AuthError` (:645-647).
- **Defect.** If the JWKS fetch fails while verifying the n-th SET, `Poll` returns the error and **discards the events already verified**. Those were already recorded in the replay store (:739-747). When re-offered they read `replayed`, the documented advice is to `setErrs` them, and the events are lost (F-GO-02).

### Q4 `ciba_await` clock and loop
- **Injectable time.** `CibaClock{Now, Sleep(ctx,d)}` (:308-313), set through `CibaAwaitParams.Clock`.
- **Initial interval.** The response's `interval`, or 5 s when it is ≤0 or absent (:520-523, :669-672). There is no faster floor.
- **`slow_down`.** Adds 5 s each time, cumulatively, and nothing resets it (:699-700). There is **no cap at 60 s** (allowed).
- **Deadline.** `ReceivedAt + ExpiresIn`. The loop stops when `now+interval ≥ deadline`, before sleeping, and raises a local `OAuthProtocolError{ErrorCode:"expired_token"}` (:668, :674-680). `ReceivedAt` is stamped with `time.Now()`, not the injectable clock (:528). Tests overwrite it (F-GO-14).
- **5xx and transport errors.** A bodiless 5xx or a transport failure is §16-retried inside the poll (:600-623), then treated as transient and the loop continues (:704). A 5xx **with an `error` body** is an `OAuthProtocolError` and therefore terminal (:609-611, :706-707) (F-GO-01).
- **429.** A bodiless 429 goes through §16, then is transient. A `429 {"error":"rate_limit_exceeded"}` waits one interval (:701-703).
- **Cancellation.** Through `ctx` (`Sleep` returns `ctx.Err()`, :319-328; test :950).
- **`auth_req_id`.** Held only in the caller's `CibaInitiateResponse` value and the per-call form. Nothing is cached.

### Q5 `ciba_handle_ping`
- **Comparison.** Constant-time, `subtle.ConstantTimeCompare([]byte(token), []byte(expected))` (:744). Header names are matched case-insensitively across the map, and exactly one value is required (:730-738). The scheme `Bearer` is matched case-insensitively, then one space via `strings.Cut`.
- **Result.** Returns `Sensitive` (:755).
- **Refusals.** A missing, empty, duplicated, non-Bearer or wrong token, or an empty expected token, all give an `*AuthError` with a fixed message that names no value (:729). A body that is not an object, or has a missing, empty or non-string `auth_req_id`, gives a `*ValidationError`, and extra members are ignored (:747-754).
- **Synchronous.** Yes, and it performs no I/O (test T13).

### Q6 Signed request
- **Offered.** `CibaRequestSigner` via `NewCibaRequestSigner(alg, crypto.Signer, kid)` (:125) or `…FromPEM(alg, Sensitive, kid)` (:162). A key that does not fit the algorithm is refused: Ed25519 for EdDSA, P-256 for ES256, RSA ≥2048 for PS256, plus a probe signature (:129-155).
- **Algorithms.** PS256, ES256 (DER converted to raw R‖S) and EdDSA (:208-230).
- **Claims.** Every set member, plus `iss`=client_id, `aud`=discovery `issuer` as a string, `iat`=`nbf`=now, `exp`=now+300 s, and a 128-bit random base64url `jti` (:415-443).
- **Form.** Client authentication plus `request` only (:491-496).
- **Key material.** Held as unexported `crypto.Signer` and redacted. `requested_expiry` is a JSON number inside the JWT but a string on the form (F-GO-15).

### Q7 Kept-secret-on-update
All three let the caller express "keep" and "replace" distinctly.
- `directory.update`: `BindSecret *Sensitive` with `json:"bind_secret,omitempty"` (management_models.go:4417). A nil pointer is **omitted** (keep) and a set one is sent (replace).
- `directory.set`: the same (:3607).
- `ssf.update_stream`: `AuthorizationHeader *Sensitive` with `omitempty` (:4047). nil is omitted (keep). Clearing is a separate `ClearAuthorizationHeader *bool` (:4050), so keep, replace and clear are all expressible.
- `scim_targets.update`: `Credential *Sensitive` with `omitempty` (:3291). nil is omitted (keep).
- `ToInput()` on each read type leaves the secret nil (management_checks.go:76-129). Tests: directory :148-151, ssf :82-84, scim :103-105.

### Q8 §21.3.1 pin
- **The pin.** `TestMtlsAliases_VectorACarriesSevenAliasesIncludingCIBAs` (mtls_endpoint_aliases_test.go:642) parses vector A **out of the vendored CONTRACT.md** (:622-640). It checks all seven named fields against the mTLS host, then `if len(raw.Aliases) != 7 { t.Fatalf("vector A has %d aliases, want seven", …) }` (:671-672).
- **Decoding.** The decoder is a struct with seven named fields (oidc_types.go:168-174), so an eighth alias would be ignored rather than fail.
- **Prefers.** `CibaInitiate` calls `preferredEndpoint(..., a.BackchannelAuthenticationEndpoint, ...)` (oidc_ciba.go:477-479). `TestMtlsAliases_CibaInitiateUsesTheSeventhAlias` (:681) asserts the mTLS host with a certificate and the conventional host without one.

### Q9 §28.12 details
- **URI verbatim.** `url.Parse` is followed by `target.String()` with nothing rebuilt or swapped (oidc_registration.go:330, :510). The test asserts the query is kept verbatim.
- **Update body.** Strips the five members via `serverStatedRegistrationMembers` (:44-50, :189-196) and re-sets `client_id`.
- **Token.** Sent only as `Authorization: Bearer` (:514), on `bareHTTPClient` (no jar, no redirect; :354-361). `decorateRequest` is not called, so no session or CSRF is attached.
- **401.** Becomes an `OAuthProtocolError`, with no §9 path (test :287 asserts 0 refreshes).

### Q10 Other divergences and contract-silent decisions
- `CibaAwait` and `CibaPoll` end on a 5xx that carries an `error` body, which is AXIAM's real `500 server_error` (F-GO-01). §33.4 ("`error` member at any status → `OAuthProtocolError`") and §33.7 rule 5 ("5xx not terminal") collide here, and Go chose §33.4.
- Sparse `UpdateDirectoryConfig` cannot send `trust_anchors_pem: []` or `group_mappings: []`, because `omitempty` drops an empty slice (management_models.go:4435, :4449; wire twin likewise) (F-GO-03).
- `SCIMTargetAuth.MarshalJSON` and `SCIMTargetScope.MarshalJSON` refuse unknown types (:3246, :3408). JSON-logging a *response* that carries an unknown `auth.type` therefore fails rather than rendering (F-GO-07).
- CIBA needs a `Delivery` (poll|ping) parameter the contract has no member for. The SDK also **refuses a notification token in poll mode** locally (oidc_ciba.go:396-409) (F-GO-16).
- With no `backchannel_authentication_endpoint` in discovery, `CibaInitiate` raises `AuthError` and builds no path (:483-485). The SDK always resolves discovery, so the "builds the path as §14.1" branch never applies.
- `PushErrorCode` maps `malformed`, `invalid_type` and `replayed` to `invalid_request` (ssf_receiver.go:92-98). The contract names only `replayed` (F-GO-13).
- §29.6 names the accessor `Saml()`; Go ships `SAML()` (F-GO-12).

#### Findings
| id | Severity | Clause | What | Evidence | Suggested disposition |
|---|---|---|---|---|---|
| F-GO-01 | defect | §33.7 rule 5 vs §33.4 | AXIAM's token endpoint answers `500 {"error":"server_error"}`. Go maps it to `OAuthProtocolError`, which is not §16-retried, and `CibaAwait` treats it as terminal. Test T08 passes only because it uses bodiless 500/503. | oidc_ciba.go:609-611, :706-707; oidc_ciba_test.go:570; server crates/axiam-oauth2/src/error.rs:226 | SDK fix (treat a 5xx as transient whatever its body) + contract clarification (state that rule 5 outranks §33.4 for 5xx) |
| F-GO-02 | defect | §32.7 poll / step 9 | A JWKS fetch failure mid-batch aborts `Poll` and discards SETs already verified and recorded in the replay store. When re-offered they are `replayed`, so the events are lost. | ssf_receiver.go:739-747, :586 | SDK fix (return partial results, or verify everything before recording) + contract clarification (when the jti is recorded relative to delivery to the caller) |
| F-GO-03 | defect | §30.2 / §27.4 rule 5 | A sparse `Update` cannot clear `trust_anchors_pem` or `group_mappings` to `[]`, because `omitempty` drops an empty slice. | management_models.go:4435, :4449 (+ wire twin) | SDK fix (`Nullable`/present-flag for lists) |
| F-GO-04 | doc | §29.8 t1 / §30.8 t4 / §31.8 t3 / §32.8 t1 | "Cannot be built without the required members" rests on `New…Input` constructors that do not refuse empty values, and a struct literal bypasses them. | management_models.go:3194, :3650, :3319, :4086 | forced by language (record) |
| F-GO-05 | clarification | §33.8 t08 | The contract test does not say whether the 500/429 carry an OAuth body, so a bodiless mock hides F-GO-01. | oidc_ciba_test.go:565-597 | contract clarification (specify `{"error":"server_error"}`) |
| F-GO-06 | clarification | §31.2 / §31.8 t3 | An oauth2 `ScimTargetAuth` with no scope omits `scope` rather than sending `null`. §31.2 types it `string \| null`, and "exact keys" is ambiguous. | management_models.go:3235-3239 | contract clarification |
| F-GO-07 | clarification | §27.13 open enums | An unknown `auth`/`scope` union decodes but cannot be re-encoded at all, so JSON-logging such a response errors. | management_models.go:3246-3255, :3408-3417; test :186-191 | contract clarification (whether "MUST NOT send" may block rendering) |
| F-GO-08 | doc | §29.2 / §27.4 rule 5 | Generated docs are wrong: `ParseSAMLSpMetadata` is called a "SPARSE body … left unchanged", and replacement ops open with "Every field of the body is required" despite optional members. | management_models.go:2465-2470; management_directory.go:88, management_saml.go:195, management_scim_targets.go:125, management_ssf.go:159 | SDK fix (generator) |
| F-GO-09 | clarification | §32.7 step 9 | The replay-store interface has no error result, so fail-open or fail-closed on a store failure is left to each implementer, undocumented. | ssf_receiver.go:134-139 | contract clarification (store failure MUST refuse) + SDK doc |
| F-GO-10 | clarification | §32.7 / §33.7 | The default replay store is unbounded in count (time-bounded only), with an O(n) sweep on every call. | ssf_receiver.go:150-170 | record |
| F-GO-11 | clarification | §32.7 step 4 | With a stale cache (>300 s), an unknown `kid` costs two fetches in one call: the refresh plus the forced refetch. The forced-refetch limiter is global, not per kid. | ssf_receiver.go:436-449 | contract clarification ("one refetch" counting) |
| F-GO-12 | clarification | §29.6 | The accessor is `SAML()` where §29.6 names `Saml()`, and the types are `SAML…` (Go initialism). | management_api.go:168 | contract fixed (§29.6 Go row) or record |
| F-GO-13 | clarification | §32.7 | A JWKS fetch failure is `*NetworkError`, not a reason code. `malformed` and `invalid_type` map to `invalid_request` for RFC 8935, though §32.7 says only `replayed` does. | ssf_receiver.go:92-98, :531-534 | contract clarification |
| F-GO-14 | clarification | §33.7 rule 4 / §33.8 t6 | `ReceivedAt` (the deadline anchor) comes from the wall clock, not the injected `CibaClock`. | oidc_ciba.go:528, :668 | SDK fix (minor) |
| F-GO-15 | clarification | §33.2 signed | `requested_expiry` is a JSON number inside the `request` JWT (string on the form). The contract is silent. | oidc_ciba.go:375-377; test :799 | contract clarification |
| F-GO-16 | clarification | §33.2 / §33.8 t3 | A `Delivery` mode parameter exists that the contract has no member for. A token in poll mode is refused locally. | oidc_ciba.go:257-259, :396-409 | contract clarification (mode is SDK input) |

---

### Report — kotlin — commit 611554d (merge #72)
Toolchain run: no. `gradle test` was attempted three times on a scratch copy, so the repository stayed untouched. Every attempt failed while resolving dependencies, because Maven Central answered `429 Too Many Requests` (for example `kotlin-build-tools-impl:2.1.0`, `dokka-core:1.9.20` and `kover-features-jvm:0.9.9`). No test compiled. Every finding below comes from reading the code.

Vendored `CONTRACT.md`, `openapi.json` and `management-registry.json` are byte-identical to this repository's `sdks/` (cmp). Kotlin is REST-only: §32.7 and §33 are MAY for it. It ships both, and they are reviewed below like any other section.

Paths below are relative to `src/main/kotlin/io/axiam/sdk/` (main) and `src/test/kotlin/io/axiam/sdk/` (test).

#### Posture per section
| Section | Status | Notes |
|---|---|---|
| §28.12 | implemented | Three `suspend` methods on `AxiamClient`. They run on the `Sessionless` transport: no interceptors, no jar, no redirects, and OkHttp retry off. |
| §29 | implemented | `client.saml`, 11 ops. Required members are non-null constructor parameters, so the compiler enforces them. |
| §30 | implemented | `client.directory`. `bindSecret` is `Sensitive`. `JsonNullable` carries explicit null, and an empty list is sendable. |
| §31 | implemented | `client.scimTargets`. `credential` is `Sensitive`. Sealed unions plus an `Unknown` arm. |
| §32 | implemented | `client.ssf`. `authorizationHeader` is `Sensitive`. Event types are a closed enum with `UNKNOWN` (F-KT-05). |
| §32.7 | implemented (MAY) | `io.axiam.sdk.ssf.SsfReceiver`. If a JWKS fetch fails partway through a poll, the SETs already recorded are lost (F-KT-02). |
| §33 | implemented (MAY) | `cibaInitiate` / `cibaPoll` / `cibaAwait` / `cibaHandlePing`. AXIAM's real `500 server_error` ends `cibaAwait` (F-KT-01). |
| §33.2 signed | implemented | `CibaRequestSigner`: PS256, ES256 or EdDSA, with no defaults. |

#### A–F per section

### §28.12
- **A.** The three operations are on `AxiamClient`:

  | Operation | Kotlin | Location |
  |---|---|---|
  | `read_client_registration` | `suspend fun readClientRegistration` | AxiamClient.kt:1630 |
  | `update_client_registration` | `updateClientRegistration` | AxiamClient.kt:1668 |
  | `delete_client_registration` | `deleteClientRegistration` | AxiamClient.kt:1689 |
  | type `ClientRegistration` | data class | oidc/ClientRegistration.kt:54 |

  The engine is oidc/ClientRegistrationSupport.kt. Unknown members are kept in `extra` (:69, :159).
- **B.**
  - The argument is `Sensitive<String>`. `clientSecret` and `registrationAccessToken` are `Sensitive<String>?` (ClientRegistration.kt:67-68).
  - `toString` is synthesized from the data class, and it calls `Sensitive.toString()`, which returns `[SENSITIVE]` (Sensitive.kt:23).
  - The type has no kotlinx serializer, so it has no JSON sink. The test asserts `serializerOrNull == null` (oidc/ClientRegistrationTest.kt:302).
  - `Sensitive` does not override `equals`, so data-class equality compares by identity, not by raw value.
  - Errors carry only the operation and the exception class name (ClientRegistrationSupport.kt:140). The origin refusal names no part of the URI (:131-132).
- **C.** All five tests are in oidc/ClientRegistrationTest.kt:
  1. `a URI at another origin is refused locally and nothing is sent` (:123) covers another host, another port, `ftp`, a relative URI, and http against an https base, and asserts that 0 requests were sent. An http URI on a non-loopback http base cannot be built at all (SEC-073).
  2. `read and delete send the bearer only, no session and the query verbatim` (:159).
  3. `update drops the five server-stated members and returns the rotated token` (:191). The 503 half is in `neither write is retried on a 503, and the read is` (:227).
  4. `a 401 invalid_token is an OAuthProtocolError and never refreshes` (:257) logs in first and then asserts `refreshes == 0`.
  5. `the token and secret appear in no rendering and no error` (:285) also checks the stack trace.
- **D.**
  - `updateClientRegistration` (AxiamClient.kt:1638-1662): "**Persist the returned `registrationAccessToken` before doing anything else** … **Never retried**", and that `metadata` is the whole registration.
  - `deleteClientRegistration` (:1680-1681): "**Never retried**".
- **E.** `update` and `delete` call `execute` exactly once (ClientRegistrationSupport.kt:87-107). `read` runs under `Retry.withRetry`, retrying only on a transport failure, 408, 429 or 5xx (:65-84).
  - The `Sessionless` transport sets `retryOnConnectionFailure(false)` (internal/Sessionless.kt:49), so OkHttp cannot resend these requests either.
- **F.** README.md:30 claims "§28.12", and :37-39 point to the section. This matches the code.

### §29
- **A.** The `SamlApi` handle is reached through `client.saml` (AxiamClient.kt:717); `forTenant` is at SamlApi.kt:39.

  | Operation | Kotlin | SamlApi.kt |
  |---|---|---|
  | `get_idp` | `getIdp` | :47 |
  | `list_service_providers` | `listServiceProviders` (`listServiceProvidersAll` :90) | :68 |
  | `create_service_provider` | `createServiceProvider` | :107 |
  | `get_service_provider` | `getServiceProvider` | :126 |
  | `update_service_provider` | `updateServiceProvider` | :158 |
  | `delete_service_provider` | `deleteServiceProvider` | :185 |
  | `parse_sp_metadata` | `parseSpMetadata` | :220 |
  | `list_idp_credentials` | `listIdpCredentials` (returns `List`) | :239 |
  | `issue_idp_credential` | `issueIdpCredential` | :266 |
  | `promote_idp_credential` | `promoteIdpCredential` | :295 |
  | `retire_idp_credential` | `retireIdpCredential` | :326 |

  The names match §29.6.
- **B.** Nothing is wrapped. `SamlIdpCredential` (management/models/SamlIdpCredential.kt) has no key member. `READER` sets `ignoreUnknownKeys`, so an unknown member is dropped (internal/ManagementTransport.kt:291-298).
- **C.** All eight tests are in management/SamlTest.kt:

  | # | Test | Line | Note |
  |---|---|---|---|
  | 1 | `update_service_provider puts the whole registration` | :67 | Asserts 11 members. The null ones are omitted because `explicitNulls = false`. The required members are enforced by the compiler. |
  | 2 | `sign_assertions does not exist…` | :91 | |
  | 3 | `parse_sp_metadata sends exactly one member…` | :115 | |
  | 4 | `a credential has no key member…` | :152 | |
  | 5 | pagination | :180 | |
  | 6 | `none of the seven writes is retried on 503` | :201 | Uses 503 only. No transport-drop case (see F-KT-03). |
  | 7 | statuses | :228 | |
  | 8 | `get_idp is never cached…` | :254 | |
- **D.** The call-site documentation is present:
  - `createServiceProvider`: "**ECDSA certificate verifies HTTP-POST requests only**" (SamlApi.kt:95-106).
  - `updateServiceProvider`: replacement, defaults list, `toInput()`, immutable `entity_id` (:141-157).
  - `deleteServiceProvider`: "Ends no session" (:172-184).
  - `parseSpMetadata`: "**Parses and stores nothing**" plus the local check (:211-218). The check itself is `ManagementChecks.parseSpMetadataExactlyOne` (management/ManagementChecks.kt:23), called at SamlApi.kt:223.
  - `retireIdpCredential`: "**Retiring the `active` credential with no successor stops SAML sign-on for the whole tenant at once**" (:318-321).
- **E.** A non-GET call makes a single `attempt` (internal/ManagementTransport.kt:88-90). It goes out on the shared `httpClient`, where OkHttp's own `retryOnConnectionFailure` is still on (AxiamClient.kt:268-283). See F-KT-03.
- **F.** README.md:30 claims "§29". This matches the code.

### §30
- **A.** The `DirectoryApi` handle is reached through `client.directory` (AxiamClient.kt:708).

  | Operation | Kotlin | DirectoryApi.kt |
  |---|---|---|
  | `get` | `get` | :42 |
  | `set` | `set` | :79 |
  | `update` | `update` | :111 |
  | `delete` | `delete` | :141 |
  | `link_account` | `linkAccount` | :174 |
  | `get_sync_status` | `getSyncStatus` | :192 |
- **B.** `SetDirectoryConfig.bindSecret` and `UpdateDirectoryConfig.bindSecret` are `@Contextual Sensitive<String>?` (models/SetDirectoryConfig.kt:49; UpdateDirectoryConfig).
  - The secret is exposed only by `ManagementTransport.WIRE`'s `SensitiveExposingSerializer` (management/SensitiveSerializers.kt:49-55). `READER` redacts it.
  - `WIRE` is a **public** companion `val` on a public class (internal/ManagementTransport.kt:42, :311). That makes it a second public path to the raw value besides `expose()` (F-KT-04).
  - `DirectoryConfig` declares no secret.
- **C.** All six tests are in management/DirectoryTest.kt: :62, :85, :106, :133, :152, :170. Test 1 also checks `READER.encodeToString`.
  - Empty lists are sent: the defaults are `null` and `encodeDefaults = false`, so an explicit `[]` is encoded. Clearing `trust_anchors_pem` or `group_mappings` with `[]` is therefore possible, unlike Go.
- **D.** The call-site documentation is present:
  - `set`: "**Moving the connection requires the secret again** … The SDK holds no copy" (DirectoryApi.kt:51-77).
  - `update`: the same rule (:96-109).
  - `delete`: "**Deleting stops the directory, and only that** … There is no unlink" (:124-140).
  - `linkAccount`: "**the owner is signed out everywhere**" (:153-172).
- **E.** As §29: the SDK makes a single attempt, but OkHttp can resend on a transport error (F-KT-03).
- **F.** README.md:30 claims "§30". This matches the code.

### §31
- **A.** The `ScimTargetsApi` handle is reached through `client.scimTargets` (AxiamClient.kt:735).

  | Operation | Kotlin | ScimTargetsApi.kt |
  |---|---|---|
  | `list` | `list` (`listAll` :53) | :32 |
  | `create` | `create` | :68 |
  | `get` | `get` | :86 |
  | `update` | `update` | :121 |
  | `delete` | `delete` | :148 |
  | `reconcile` | `reconcile` | :173 |
- **B.** `ScimTargetInput.credential` is `@Contextual Sensitive<String>?` (models/ScimTargetInput.kt). The response types and the `ScimTargetAuth*` variants have no credential member.
- **C.** All six tests are in management/ScimTargetsTest.kt: :74, :92, :110, :135, :173, :192. Test 3's OAuth2 shape is asserted only with `scope` set (F-KT-08).
- **D.** The call-site documentation is present:
  - `create`: "`credential` is required here (§31.3 rule 2)" (:61-62).
  - `update`: "**The credential is bound to its URL** (§31.3 rule 2)" (:96-119).
  - `delete`: "**Deprovisions nothing downstream**" (:140-146).
- **E.** As §29 (F-KT-03).
- **F.** README.md:30 claims "§31". This matches the code.

### §32 (management)
- **A.** The `SsfApi` handle is reached through `client.ssf` (AxiamClient.kt:726).

  | Operation | Kotlin | SsfApi.kt |
  |---|---|---|
  | `list_streams` | `listStreams` (`listStreamsAll` :64) | :42 |
  | `create_stream` | `createStream` | :76 |
  | `get_stream` | `getStream` | :95 |
  | `update_stream` | `updateStream` | :127 |
  | `delete_stream` | `deleteStream` | :148 |

  Event types in the management models are an enum, `SsfEventType`, with an `UNKNOWN("")` arm (models/SsfEventType.kt:28-62). §32.2 says SHOULD be strings (F-KT-05).
- **B.** `SsfStreamInput.authorizationHeader` is `@Contextual Sensitive<String>?`. `SsfStream` has only `authorizationHeaderSet` (models/SsfStream.kt:45).
- **C.** All six tests are in management/SsfManagementTest.kt: :76, :104, :129, :161, :176, :193.
- **D.** `updateStream`: "An omitted optional member takes its default (§32.2) — **except `authorization_header`, which absent keeps the stored one** — unless the update moves `endpoint_url` to another origin…" (SsfApi.kt:115-120).
- **E.** As §29 (F-KT-03).
- **F.** README.md:30 claims "§32". This matches the code.

### §32.7 (helper)
- **A.** `SsfReceiver(client, SsfReceiverConfig)` (ssf/SsfReceiver.kt:74) provides:
  - `suspend fun verifySet` (:135) and `suspend fun poll` (:161).
  - The config is `{issuer, audience, keys: SsfKeySource.JwksUri | DiscoveryUrl, accessTokenProvider, replayWindow, replayStore}` (ssf/SsfTypes.kt:264-271).
  - The result type is `SecurityEvent` (SsfTypes.kt:140).
  - The receiver's event types are plain strings, with constants in `SsfEventTypes` (SsfTypes.kt:19-44).
- **B.** `accessTokenProvider` returns `Sensitive<String>` (SsfTypes.kt:268), and the value is exposed only into the header. There are no other secrets.
- **C.** All eight tests are in ssf/SsfReceiverTest.kt. Keys are generated with `OctetKeyPairGenerator`.

  | # | Test | Line |
  |---|---|---|
  | 1 | `a SET signed by the JWKS key verifies…` | :157 |
  | 2 | wrong typ or alg | :179 |
  | 3 | another key or a tampered payload | :201 |
  | 4 | issuer and audience | :215 |
  | 5 | step-8 claims | :232 |
  | 6 | replay, and a short window | :255 |
  | 7 | `an unknown kid costs one refetch…` | :280 |
  | 8 | `poll passes ack and set_errs through…` | :295; also `poll is not retried on 400…` :349 |
- **D.** The KDoc gives the nine-step order. The README states that `poll` "acknowledges nothing itself" and that an unacknowledged SET "comes back as `replayed`" (README.md:2120-2130).
- **E.** `poll` runs under `Retry.withRetry` with `retryable = lastStatus == null || 408/429/5xx` (SsfReceiver.kt:181). The `Sessionless` transport turns OkHttp's own retry off.
- **F.** README.md:31 says "with §32.7". This matches the code.

### §33
- **A.** The operations are on `AxiamClient`:

  | Operation | Kotlin | Location |
  |---|---|---|
  | `ciba_initiate` | `suspend fun cibaInitiate` | AxiamClient.kt:1729 |
  | `ciba_poll` | `cibaPoll` | :1753 |
  | `ciba_await` | `cibaAwait` | :1788 |
  | `ciba_handle_ping` | `cibaHandlePing`, synchronous, two overloads | :1819 (`Iterable<Pair>`), :1835 (`Map<String, List<String>>`) |

  The engines are oidc/OidcSupport.kt:1149, :1228, :1283 and oidc/CibaPing.kt:27. The types are in oidc/CibaTypes.kt:
  - `CibaUserHint` (sealed; makes exactly one hint impossible to get wrong) :38
  - `CibaDelivery` (`Poll` / `Ping(token)`) :60
  - `CibaRequestSigner` :102
  - `CibaInitiateParams` :257 — no `user_code`, `login_hint_token` or `request_uri` members
  - `CibaInitiateResponse` :282
  - `CibaPollParams` :296
  - `CibaClock` :306
  - `CibaAwaitParams` :335
- **B.** Every secret is wrapped:
  - `authReqId` is `Sensitive` in the response (:283) and in the poll parameters (:297). The ping returns `Sensitive.of(id)` (CibaPing.kt:59).
  - `Ping.clientNotificationToken` is `Sensitive` (:72), and so is `expectedToken`.
  - The signer keeps the key inside a private `JWSSigner`, and its `toString` is redacted (:139). `fromPem` takes a `Sensitive` PEM. `sign` returns `Sensitive<String>` (:135).
  - `IdTokenHint.toString` is redacted (:55).
  - Errors carry only the class name (OidcSupport.kt:1189).
- **C.** All sixteen tests are in oidc/CibaTest.kt:

  | # | Line | # | Line | # | Line | # | Line |
  |---|---|---|---|---|---|---|---|
  | t01 | :171 | t05 | :303 | t09 | :384 | t13 | :465 |
  | t02 | :193 | t06 | :336 | t10 | :400 | t14 | :502 |
  | t03 | :223 | t07 | :353 | t11 | :418 | t15 | :547 |
  | t04 | :264 | t08 | :365 | t12 | :447 | t16 | :565 |

  - t04 includes an accept-and-hang-up listener and asserts one connection.
  - t08 uses a **bodiless** `500` (:370), the same gap as Go (F-KT-01).
  - t11 checks constant time structurally: the source must contain `MessageDigest.isEqual(`.
- **D.** The call-site documentation is present:
  - `cibaInitiate`: "**Never retried** … **A success proves nothing about the user**" (AxiamClient.kt:1711-1717).
  - `cibaPoll`: "**Store the returned tokens before anything else**" (:1747-1749).
  - `cibaAwait`: ping-mode guidance (:1777-1781).
  - `cibaHandlePing`: "answer `204` as soon as this returns, **then** call [cibaPoll]" (:1808-1812).
- **E.** `cibaInitiate` makes one `newCall` on `noRetryHttpClient`, which is the shared client with `retryOnConnectionFailure(false)` (OidcSupport.kt:1125-1127, :1187).
  - `cibaPoll` uses `Retry.withRetry` on the shared client (:1251-1270).
  - An `OAuthProtocolError` is not a `NetworkError`, so it is never retried, even at 5xx.
- **F.** README.md:30-31 says "§32 and §33, with §32.7 and §33.2 signed", and :44-45 says "a MAY for this SDK; shipped in full". This matches the code.

#### Q1 … Q10

### Q1 Replay store
- **Interface.** `fun interface ReplayStore { fun checkAndRecord(jti: String, window: Duration): Boolean }` (ssf/SsfTypes.kt:216-229). It is synchronous (not `suspend`) and documents an atomic check-and-insert: "MUST be atomic".
- **Default.** `MemoryReplayStore(clock: Clock = systemUTC())` (:237-247) is `synchronized` over a `ConcurrentHashMap<jti, expiry>`.
  - It sweeps expired entries on every call, an O(n) sweep.
  - There is no count cap, so the store is bounded only by time.
  - The clock is injectable through the public constructor.
- **Store failure.** The interface has no error result. A store that throws propagates its exception out of `verifySet`, which fails closed for a push. `poll` aborts on such an exception, because it catches only `SetVerificationError` (SsfReceiver.kt:208). This is undocumented (F-KT-09).
- **Recording order.** The `jti` is recorded only after steps 1–8 and the check that the poll key matches (:276-283).
- **Seven-day window.** It is enforced by refusing in the constructor (`init`): `ValidationError("ssf.receiver: replay_window must be at least seven days…")` (:90-95). The default is seven days (SsfTypes.kt:269).

### Q2 `verify_set` order and reason codes
- **Order and codes.** The steps run 1→9 with the contract's codes (SsfReceiver.kt:213-283).
  - Step 1 decodes the signature segment first.
  - `typ`: an absent value, or anything other than `secevent+jwt` / `application/secevent+jwt` (compared ignoring case), is `invalid_type` (:228-233).
  - `alg` must be exactly `"EdDSA"` (:235).
  - A missing `kid` is `invalid_key` with no refetch.
- **Unknown `kid`.** One forced refetch, gated by a global `lastForcedRefetchNanos` at 60 s (:303-312).
  - The JWKS cache **never expires otherwise**: `jwks ?: fetchJwks()` (:304). Rotation is picked up only through the kid-miss path (F-KT-10).
  - A JWK whose `kid` matches but which is not Ed25519 counts as a miss.
- **`aud`.** A string or an array is accepted (:255-262).
- **Step 8 extras.** Step 8 adds a numeric `iat` (a double is truncated), a `sub_id` that is an object, and `jti` equal to the poll key.
- **JWKS fetch failure.** It raises `NetworkError` rather than `invalid_key` (:325-333).
- **`pushErrorCode`.** It maps `malformed`, `invalid_type` and `replayed` to `invalid_request` (SsfTypes.kt:85-88).

### Q3 `poll`
- **No self-acknowledgement.** `poll` never acknowledges on its own. `pollBody` sends only the members that are set (SsfReceiver.kt:376-393). The test asserts the exact body and `{}`.
- **Refusals.** They come back as `RefusedSet(jti, reason)` in the transmitter's order, not sorted, although the test is named "sorts".
- **Retry.** `poll` is not retried on a 4xx other than 408 or 429 (:181). A 400 becomes `ValidationError`.
- **Token.** It comes from `accessTokenProvider`, called once per poll, outside the retry loop (:171). A missing provider gives a local `AuthError`.
- **Defect.** A `NetworkError` from a JWKS fetch on the n-th SET escapes the loop, which catches only `SetVerificationError` (:206-210). The SETs already verified are lost, and they are already recorded as replayed (F-KT-02).

### Q4 `ciba_await` clock and loop
- **Clock.** `CibaClock{now(); suspend sleep(Duration)}` is injectable through `CibaAwaitParams.clock` (CibaTypes.kt:306-339).
- **Initial interval.** The response's `interval`, or 5 when it is absent or ≤0 (OidcSupport.kt:1205, :1287).
- **`slow_down`.** Adds 5 s cumulatively and is never reset (:1311). There is **no cap at 60 s**.
- **Deadline.** `receivedAt + expiresIn`, checked before each sleep. Past it, the loop raises a local `OAuthProtocolError("expired_token")` (:1286, :1293-1298).
  - `receivedAt` is `Instant.now()`, not the injected clock (:1207) (F-KT-11).
  - `expires_in` must be present in the initiate response, or it is a `NetworkError`.
- **Transient failures.** A transport failure or a bodiless 5xx/408/429 is retried under §16 inside the poll. The loop then continues on a `NetworkError` whose last status is null or retryable (:1317-1321).
  - A **5xx carrying an `error` body** is an `OAuthProtocolError`, which ends the loop as terminal (:1315) (F-KT-01).
  - `429 rate_limit_exceeded` costs one interval (:1313).
- **Cancellation.** Coroutine cancellation interrupts `delay`.
- **`auth_req_id` lifetime.** The SDK keeps it only in the caller's value and the per-call form; nothing is cached.

### Q5 `ciba_handle_ping`
- **Comparison.** `MessageDigest.isEqual` on the UTF-8 bytes, which is constant-time (CibaPing.kt:42).
- **Header.** Names are matched ignoring case, and exactly one `Authorization` entry is accepted (:33). A map whose `Authorization` key holds two values is refused like two header lines. The scheme is split at the first space and compared ignoring case.
- **Result.** It returns `Sensitive` (:59).
- **Refusals.** A missing, duplicate, empty, `Basic` or wrong token, or an empty expected token, is an `AuthError` with a fixed message that names no value. A malformed body, or one with no non-empty string `auth_req_id`, is a `ValidationError`; extra members are ignored.
- **Synchronous.** Yes, a non-`suspend` function.

### Q6 Signed request (§33.2)
- **API.** `CibaRequestSigner.of(alg, PrivateKey, kid)` and `fromPem(alg, Sensitive<String>, kid)`. `fromPem` accepts **PKCS#8 only** (CibaTypes.kt:161-209). A probe signature runs at construction.
- **Algorithms.** PS256, ES256 and EdDSA (via Nimbus JOSE). The Ed25519 public key is derived with Tink.
- **Claims.** Every member that is set, plus:
  - `iss` = the client id;
  - `aud` = the discovery `issuer`, as a string;
  - `iat` = `nbf` = now;
  - `exp` = now + 5 minutes;
  - a 256-bit random `jti`.

  `requested_expiry` is a number inside the JWT and a string on the form (OidcSupport.kt:1177) (F-KT-12).
- **Form.** The form carries client authentication plus `request` only (:1172-1179).
- **Key material.** The key is held in a private `JWSSigner` and redacted from `toString`.

### Q7 Kept-secret-on-update
Each request model below declares the secret nullable and defaulting to `null`. The `WIRE` `Json` sets `explicitNulls = false`, so a `null` secret is **omitted** and the server keeps the stored one (internal/ManagementTransport.kt:311-319).

| Operation | Declaration | Model file |
|---|---|---|
| `directory.update` (`set` too) | `@SerialName("bind_secret") val bindSecret: @Contextual Sensitive<String>? = null` | models/UpdateDirectoryConfig.kt; SetDirectoryConfig.kt:49 |
| `ssf.update_stream` | `authorizationHeader: @Contextual Sensitive<String>? = null` | models/SsfStreamInput.kt |
| `scim_targets.update` | `credential: @Contextual Sensitive<String>? = null` | models/ScimTargetInput.kt |

- For `ssf.update_stream`, clearing the header is a separate flag, `clearAuthorizationHeader: Boolean?`.
- Keep and replace are therefore distinct. The `toInput()` helpers leave the secret `null` (management/ReplacementBodies.kt:34, :61, :88, :113).

### Q8 §21.3.1 pin
- **The seven-alias pin.** `vector A parses to its seven aliases` (oidc/MtlsEndpointAliasesTest.kt:486) reads vector A from the vendored CONTRACT.md and asserts:
  - `assertEquals(7, published.size, "vector A publishes seven aliases")`;
  - that the seven decoded keys equal the published keys.
- **The alias type.** `the alias type carries only the seven aliasable endpoints` (:335) pins the seven property names of `MtlsEndpointAliases`.
- **Preference on an mTLS client.** `cibaInitiate` calls `preferredEndpoint(configuration, { it.backchannel_authentication_endpoint }, …)` (OidcSupport.kt:1158-1162). `every aliasable endpoint goes to the alias host` (:187) includes `bc-authorize` (:206-225).

### Q9 §28.12 details
- **URI.** `uri.toHttpUrlOrNull()` is compared with the base URL's scheme, host and port (ClientRegistrationSupport.kt:115-129). The parsed `HttpUrl` is used without rebuilding or swapping the host, although OkHttp canonicalizes its encoding (F-KT-13).
- **Update body.** `updateBody()` removes the five members and sets `client_id` (ClientRegistration.kt:77-104).
- **Token.** It is sent only as `Authorization: Bearer` (:77, :91, :100) over the `Sessionless` transport. That transport has no interceptors, so no SDK token, CSRF header or `X-Tenant-ID` rides along. It also has no jar, no authenticator, no redirects and no OkHttp retry.
- **401.** A 401 maps straight to `OAuthProtocolError`. The test asserts zero refreshes after a real login.

### Q10 Other divergences and contract-silent decisions
- **OkHttp retries management writes.** The §27, §29, §30, §31 and §32 writes go out on the shared OkHttp client with `retryOnConnectionFailure` at its default of `true` (AxiamClient.kt:268-283; ManagementTransport.kt:179). OkHttp can then silently resend a POST, PUT, PATCH or DELETE after a dropped connection. The SDK's own comment describes exactly this hazard and fixes it for `cibaInitiate` only (OidcSupport.kt:1117-1127). Go has no equivalent: `net/http` replays only idempotent methods (F-KT-03).
- **Open enums sent as `""`.** Open enums decode to `UNKNOWN("")`, which loses the original value, and **serialize as `""`**. A `toInput()` round trip of an unknown `binding` or event type therefore sends `""` to the server instead of refusing locally. Unknown unions, by contrast, throw on encode (models/SamlBinding.kt:29-55; ScimTargetAuth.kt) (F-KT-06).
- **Public clear-text writer.** `ManagementTransport.WIRE` is public, so it is a supported-looking path that writes `Sensitive` values in the clear (F-KT-04).
- **README example scope.** The receiver snippet calls `client.loginClientCredentials()` with default parameters and only a comment naming `ssf.manage` (README.md:2096). It works only if the client's registered scopes are granted by default. This is a note, not a finding.
- **CIBA mode modelling.** Kotlin models the mode as `CibaDelivery.Poll` / `Ping(token)`. A token in poll mode therefore cannot be written at all; Go refuses it at run time instead. The contract has no mode member (shared clarification with Go).
- **Shared clarifications with Go.** Two decisions match Go and are recorded there: a missing `backchannel_authentication_endpoint` raises `AuthError`, and an empty `client_notification_token` is refused.

#### Findings
| id | Severity | Clause | What | Evidence | Suggested disposition |
|---|---|---|---|---|---|
| F-KT-01 | defect | §33.7 rule 5 vs §33.4 | A `5xx` carrying `{"error":"server_error"}` (AXIAM's real 500) is an `OAuthProtocolError`: `cibaPoll` does not retry it, and `cibaAwait` treats it as terminal. t08 uses a bodiless 500. | oidc/OidcSupport.kt:1251-1270, :1315; oidc/CibaTest.kt:370 | SDK fix + contract clarification (as F-GO-01) |
| F-KT-02 | defect | §32.7 poll / step 9 | A JWKS `NetworkError` partway through a batch escapes `poll`. It discards SETs already verified and recorded, which then read `replayed` and are lost. | ssf/SsfReceiver.kt:206-210, :281 | SDK fix + contract clarification (as F-GO-02) |
| F-KT-03 | defect | §27.4 rule 8, §29.7, §30.7, §31.7, §32.8 t5 | OkHttp's `retryOnConnectionFailure` is still on for every management write, which can be silently resent after a dropped connection. The tests assert "no retry" only on a 503. | AxiamClient.kt:268-283 (no `retryOnConnectionFailure(false)`); internal/ManagementTransport.kt:88-90, :179; contrast OidcSupport.kt:1125-1127 | SDK fix (management writes on a no-retry client) + test with a hang-up listener |
| F-KT-04 | clarification | §7 rules 2–3 | The public `ManagementTransport.WIRE` serializes every `Sensitive` in the clear: a second public path to raw values besides `expose()`. Documented as "internal plumbing … not supported API". | internal/ManagementTransport.kt:38-42, :311-319 | SDK fix (make `WIRE` internal) or record |
| F-KT-05 | doc | §32.2 ("SHOULD model event types as strings") | Management event types are a closed enum with `UNKNOWN("")`, so an unknown URI loses its value. The receiver uses strings. | models/SsfEventType.kt:28-62 | SDK fix (value class/string) or record the divergence |
| F-KT-06 | clarification | §29.2 / §32.2 "MUST NOT send one it does not know" | `UNKNOWN` open-enum values serialize as `""` and reach the server, which refuses them. The SDK does not refuse locally (`toInput()` docs say "refused by the server"). | models/SamlBinding.kt:29-55; management/ReplacementBodies.kt:55-60 | contract clarification (local refusal vs server refusal) |
| F-KT-08 | clarification | §31.2 / §31.8 t3 | An OAuth2 auth with no `scope` omits the key rather than sending `null` (as Go). | models/ScimTargetAuthOauth2ClientCredentials.kt | contract clarification |
| F-KT-09 | clarification | §32.7 step 9 | The replay store has no error contract: a throwing store fails closed for push, but aborts `poll`. The default store is unbounded in count. | ssf/SsfTypes.kt:216-247 | contract clarification |
| F-KT-10 | clarification | §32.7 step 4 | The JWKS cache never expires: there is no max-age, only the kid-miss refetch. The forced-refetch limiter is global. | ssf/SsfReceiver.kt:303-312 | contract clarification (cache lifetime) |
| F-KT-11 | clarification | §33.7 rule 4 / §33.8 t6 | `receivedAt` comes from the wall clock, not the injectable `CibaClock` (as Go). | oidc/OidcSupport.kt:1207, :1286 | SDK fix (minor) |
| F-KT-12 | clarification | §33.2 signed | `requested_expiry` is a JSON number inside the JWT. The contract is silent (as Go). | oidc/OidcSupport.kt:1175-1178 | contract clarification |
| F-KT-13 | clarification | §28.12.2 rule 1 "verbatim" | The URI is re-serialized through OkHttp's canonicalizing `HttpUrl`. The query is kept, but its encoding may be normalized. | oidc/ClientRegistrationSupport.kt:116, :128 | contract clarification (verbatim = no rebuild; canonical re-encoding acceptable?) |

---

### Report — swift — commit e92364c (merge #70)

Toolchain run: **no** — no `swift` toolchain in the sandbox (`which swift` empty). Review is by reading only. Vendored `CONTRACT.md` is byte-identical to this repository's `sdks/CONTRACT.md` (1.58) (`cmp` clean).

All paths below are relative to the `axiam-swift-sdk` repository root. `NS` = `Sources/AxiamSDK/Management/Generated/ManagementNamespaces.swift`, `MM` = `Sources/AxiamSDK/Management/Generated/ManagementModels.swift`.

#### Posture per section
| Section | Status | Notes |
|---|---|---|
| §28.12 | implemented | three `async` methods on `AxiamClient`, bare path, origin-pinned; writes `.never` |
| §29 | implemented | `client.saml` (11 ops), generated; no auto-pager (SDK-wide §27 gap) |
| §30 | implemented | `client.directory` (6 ops), `bindSecret` Sensitive both types |
| §31 | implemented | `client.scimTargets` (6 ops), `credential` Sensitive; `ScimTargetAuth` keeps `raw` |
| §32 | implemented | `client.ssf` (5 ops), `authorizationHeader` Sensitive; event types modelled as enum+`.unknown` |
| §32.7 | implemented (MAY) | `SsfReceiver` actor, `verifySet`/`poll`; pluggable non-throwing replay store |
| §33 | implemented (MAY) | `cibaInitiate`/`cibaPoll`/`cibaAwait`/`cibaHandlePing`, injectable `CibaClock` |
| §33.2 signed | implemented | `CibaRequestSigner` PS256/ES256/EdDSA; PS256 only refusal-tested (README admits) |

#### A–F per section

### §28.12
**A.** `read_client_registration` → `AxiamClient.readClientRegistration(registrationClientURI:registrationAccessToken:)` `Sources/AxiamSDK/Oidc/ClientRegistration.swift:254`; `update_client_registration` → `updateClientRegistration(…metadata:)` `:293`; `delete_client_registration` → `deleteClientRegistration` `:327`; type `ClientRegistration` `:36`. All `async`. Unknown members kept in `extra` `:69,:123-195`.
**B.** Args: `Sensitive<String>` `:256,:295,:329`. `ClientRegistration.clientSecret`/`.registrationAccessToken` `Sensitive<String>?` `:64,:67`; type is not `Encodable` `:26-28`; custom `description`/`debugDescription` render `[SENSITIVE]` `:219-229`. Rule-1 refusal message names no URI part `:352-358`; OAuth error message is server text only (`OidcInternals.swift:393-402`). Gap: `Sensitive` has no `CustomReflectable`, so `dump()`/`Mirror` print the wrapped value (`Sources/AxiamSDK/Sensitive.swift:12-39`) — finding SW-1.
**C.** `Tests/AxiamSDKTests/ClientRegistrationTests.swift`: (1) origin refusal `testAURIAtAnotherOriginIsRefusedLocallyAndNothingIsSent` :81 (+:121 loopback/query); (2) header only `testReadAndDeleteSendTheBearerOnlyAndKeepTheQueryVerbatim` :137 (signed-in client, asserts no Cookie/CSRF, no body, query verbatim); (3) update body `testUpdateDropsTheFiveServerStatedMembersAndReturnsTheRotatedToken` :172 + `testAnUpdateAnswered503IsNotRetried` :212 (retry ENABLED client, count==1) + delete/read :229; (4) errors `testA401InvalidTokenIsAnOAuthProtocolErrorAndRefreshesNothing` :260 (refresh route mounted, asserts no call), `testA400InvalidClientMetadata…AndA204DeletesNormally` :281; (5) redaction `testNeitherTheTokenNorTheSecretReachesAnyRendering` :323 — covers describing/reflecting/interpolation/error; no `dump`, no serialization (type not Encodable, so N/A).
**D.** Update doc: "`metadata` is the **whole** registration…" and "**Persist the returned … before doing anything else**" `:277-287`; "**Never retried**" `:289-292`, delete `:325-326`.
**E.** `bareSend(... retry: .never)` for PUT `:318` and DELETE `:340`; read `.section16` `:270`. `.never` → budget 1 (`Sources/AxiamSDK/HTTP/BareRequest.swift:52-56,112-113`). Bare path has no §9 refresh.
**F.** README.md:15-17 "conforms to contract 1.58 … §28, §28.12, §29, §30, §31, §32 and §33, with §32.7 and §33.2 signed"; table row README.md:90. Matches code.

### §29
**A.** `client.saml` `NS:5054`; `SamlApi` `NS:3435`: `getIdp` 3461, `listServiceProviders(page:)` 3484, `createServiceProvider` 3510, `getServiceProvider` 3531, `updateServiceProvider` 3562, `deleteServiceProvider` 3587, `parseSpMetadata` 3614 (local exactly-one check `ManagementChecks.swift:17-30`, builders `.fromURL/.fromXML` :44-52), `listIdpCredentials` 3633 (plain array), `issueIdpCredential` 3655, `promoteIdpCredential` 3678, `retireIdpCredential` 3704. RMW helper `SamlServiceProviderInput(copying:)` `ManagementChecks.swift:62`. No auto-paging form (finding SW-7).
**B.** Nothing wrapped (correct). `SamlIdpCredential` `MM:8440` has no key member; synthesised-style decoder ignores unknown keys.
**C.** `SamlManagementTests.swift`: (1) :76; (2) :107; (3) :136 (both/neither refused, `transport.count==2`, draft sent unchanged); (4) :195 (leaked `private_key_pem` absent from describing/reflecting/re-encoded); (5) :221 — manual `nextRequest` walk, not an auto-pager; (6) :260 (7×503, counts [1..7], retry enabled); (7) :298; (8) :345 (null vs absent, 2 calls 2 requests, implicit tenant in path).
**D.** update replacement warning `NS:3552-3556` ("An omitted member takes its **default**…"); `entity_id` immutable `NS:3556-3557`; ECDSA/Redirect note on create `NS:3505` and update `NS:3557-3558` (but not on the model field `MM:8928-8929`, SW-15); retire-active warning `NS:3698-3699`.
**E.** `managementSend`: `let retryable = method == .get && config.retryEnabled` `Sources/AxiamSDK/Management/AxiamClient+Management.swift:58`.
**F.** README.md:16 names §29; README.md:91. Matches.

### §30
**A.** `client.directory` `NS:5044`; `DirectoryApi` `NS:3259`: `get` 3285, `set(body:)` 3314, `update(body:)` 3342, `delete` 3365, `linkAccount` 3395, `getSyncStatus` 3412. RMW `SetDirectoryConfig(copying:)` `ManagementChecks.swift:92`.
**B.** `SetDirectoryConfig.bindSecret: Sensitive<String>?` `MM:10124`; `UpdateDirectoryConfig.bindSecret` `MM:11842`; unwrapped only in `encode(to:)` `MM:10255, MM:11989`. `DirectoryConfig` `MM:4000` declares none. Default struct `description` recurses via `Sensitive.description` → `[SENSITIVE]`; `dump()` leaks (SW-1); `JSONEncoder().encode(body)` emits it (SW-8).
**C.** `DirectoryManagementTests.swift`: (1) :64 (describing/reflecting/interp + error; on-wire asserted); (2) :91; (3) :111 exact key sets `["enabled"]`, `["bind_secret","url"]`, `["group_filter"]`=null; (4) :154 (201 and 200; required members non-optional init params); (5) :179 (4×503, retry enabled, one each); (6) :220.
**D.** set: "**Moving the connection requires the secret again** (§30.3 rule 2)…Every other optional member left `nil` is **reset to its default**" `NS:3305-3309`; update `NS:3334-3337`; delete rule 5 `NS:3360-3364`; link signs out `NS:3388-3392`.
**E.** as §29 (`AxiamClient+Management.swift:58`).
**F.** README.md:16; README.md:91. Matches.

### §31
**A.** `client.scimTargets` `NS:5070`; `ScimTargetsApi` `NS:3871`: `list(page:)` 3903, `create` 3925, `get` 3944, `update` 3972, `delete` 3995, `reconcile` 4020; no `{tenant_id}` (`implicitTenant: false`). Builders `ScimTargetAuth.bearer()/oauth2ClientCredentials`, `ScimTargetScope.allUsers()/groups` `ManagementChecks.swift:120-157`; RMW `ScimTargetInput(copying:)` :167.
**B.** `ScimTargetInput.credential: Sensitive<String>?` `MM:9245`, unwrapped at `MM:9322`. `ScimTargetResponse` `MM:9334` has no credential member. `ScimTargetAuth` keeps the whole server object in `raw` `MM:9120,:9143-9145` (SW-9).
**C.** `ScimTargetsManagementTests.swift`: (1) :59; (2) :82; (3) :103 (no `credential` key when nil; exact keys of all four variants); (4) :149 (unknown `auth.type`/enums/`state:null`; manual walk carries `search`); (5) :207 (4×503); (6) :240 (400/409/409/404/202, reconcile no body; 401 → AuthError after §9).
**D.** update rule 2 `NS:3962-3966`, rule 4 `NS:3967-3968`; delete rule 8 `NS:3990-3993`; create: only "`credential` is required here (§31.3 rule 2)" `NS:3921` — URL binding not restated at the second call site (SW-14).
**E.** as §29.
**F.** README.md:16; README.md:91. Matches.

### §32 (management)
**A.** `client.ssf` `NS:5062`; `SsfApi` `NS:3726`: `listStreams` 3758, `createStream` 3777, `getStream` 3796, `updateStream` 3826, `deleteStream` 3848. RMW `SsfStreamInput(copying:)` `ManagementChecks.swift:190`.
**B.** `SsfStreamInput.authorizationHeader: Sensitive<String>?` `MM:11129`, unwrapped `MM:11230`. `SsfStream` `MM:10941` has only `authorizationHeaderSet`.
**C.** `SsfManagementTests.swift`: (1) :60; (2) :92 (sent; absent from renderings; response `authorization_header` dropped incl. re-encode); (3) :115; (4) :141 (manual walk); (5) :167; (6) :197.
**D.** update_stream: "**except `authorizationHeader`, which absent keeps**…§32.3 rule 5…409" `NS:3817-3822`.
**E.** as §29.
**F.** README.md:16; README.md:91. Matches.

### §32.7 (helper)
**A.** `SsfReceiver` actor `Sources/AxiamSDK/Ssf/SsfReceiver.swift:279`; `verifySet(_:)` :357; `poll(streamID:options:)` :488. Config `SsfReceiverConfiguration {issuer, audience, keySource (.jwksURI|.discoveryURL), accessTokenProvider, replayWindow, replayStore}` :163-193. Event-type constants `SsfEventTypeURI` :25-50.
**B.** Provider returns `Sensitive<String>` :159, revealed only into the header :511. Refusal messages name the step, never a claim value :630-634.
**C.** `SsfReceiverTests.swift`: (1) :130; (2) :160 (typ absent/`JWT`; `none`, real HS256 MAC; asserts no JWKS fetch for steps 1–3); (3) :200; (4) :219; (5) :235; (6) :262 (+expiry :286; window 6 d refused at init); (7) :300 (prime=1, refetch=2, +30 s no refetch, +61 s one more, injected clock); (8) :342 (exact ack/setErrs body, verified/refused apart, empty `{}` second poll) + :393 (400 → one request with retry enabled). Missing assertion: a SET refused at steps 1–8 is not recorded.
**D.** verifySet doc lists the nine steps + "A SET that verifies has been recorded" :336-356; poll "Nothing is acknowledged on your behalf" :477-481.
**E.** poll `retry: .section16` :516 → retries transport/408/429/5xx, never other 4xx (`BareRequest.swift:114-115`; `Retry.shouldRetry`). 408/429 are 4xx — SW-6.
**F.** README.md:17 "with §32.7"; README.md:46-47, :92 ("MAY for Swift"). Matches.

### §33
**A.** `Sources/AxiamSDK/Oidc/Ciba.swift`: `cibaInitiate(_:tenantID:configuration:)` :348, `cibaPoll(authReqID:tenantID:configuration:)` :421, `cibaAwait(_:tenantID:configuration:clock:)` :471, `cibaHandlePing(headers:body:expectedToken:)` :525 (`nonisolated`, sync). Request type `CibaInitiateRequest` :185 (hint is a sum type `CibaUserHint` :39 → both/neither unwritable; no `login_hint_token`/`user_code`/`request_uri`); `CibaDelivery.ping(clientNotificationToken:)` :53.
**B.** `CibaInitiateResponse.authReqID` Sensitive :259; poll input Sensitive :422; ping result Sensitive :529/:558; `client_notification_token` Sensitive in `CibaDelivery` :53 and `expectedToken` :528; signer `keyMaterial: Sensitive<Data>` :90, PEM input Sensitive :103; signed `request` returned `Sensitive` :620/:650. Custom descriptions :55-60, :171-174, :242-250, :276-279. Errors carry server text/codes only.
**C.** `CibaTests.swift`: T1 :106, T2 :147, T3 :195 (+no-endpoint :245), T4 :260 (503 / 429 `rate_limit_exceeded` / dropped: one request each), T5 :289 (sleeps `[5,10,15,15]`; four terminal codes, one request each), T6 :336 (7/absent/0 → 7/5/5; injected clock stamps), T7 :363 (polls at 5,10; none at 15 > 12), T8 :385 (500 and 429 mid-loop survived; 200 has id_token/access_token) + :407, T9 :426, T10 :453, T11 :473 (constant-time asserted structurally by grepping the source for `ConstantTime.equals(...)`), T12 :514, T13 :540, T14 :572 (EdDSA + ES256 verified with caller's public key; PS256 not exercised), T15 :644, T16 :671.
**D.** initiate: "**Never retried** … (§33.7 rule 1)" :335-337, "**A success proves nothing about the user** (§33.3 rule 4)" :339-341; poll "Store the returned tokens before anything else" :419-420; await ping-mode guidance :467-470; handlePing "answer 204 … then cibaPoll" :516-519.
**E.** initiate `retry: .never` :392; poll `.section16UnlessOAuthError` :445 (`BareRequest.swift:28-31,116-119`); await loop classification `cibaStep` :576-591.
**F.** README.md:15-17 "§33, with … §33.2 signed"; README.md:46-51 (PS256 refusal-test-only caveat); README.md:93. Matches.

#### Q1 … Q10

### Q1 Replay store
- Interface: `protocol SsfReplayStore: Sendable { func checkAndRecord(jti: String, window: TimeInterval) async -> Bool }` `SsfReceiver.swift:125-130` — **async, atomic check-and-insert** (doc mandates atomicity :127-128), **non-throwing**.
- Default: `actor InMemorySsfReplayStore` :134-154 — `[String: Date]` expiries, **unbounded**, expired entries filtered on every call (O(n) per call) :148-149; TTL = `now + window` :151; atomic by actor isolation.
- Store error: **no error channel** — a store cannot report failure; fail-open/closed is entirely the implementer's choice (SW-4).
- Recorded only after steps 1–8 (and the poll-key check): :452-459.
- Window floor: default `minimumReplayWindow` = 7 d :282, :183; below → **constructor refusal** in `SsfReceiver.init` :314-319, `NetworkError` with `isValidation` ("replay_window must be at least seven days…"). No clamp.

### Q2 verify_set
Order 1→9 matches, codes match (`SetFailureReason` :55-70): malformed :363-374; typ :377-380 (`lowercased()`, case-insensitive ✓); alg `== "EdDSA"` exact :383; kid (missing kid → `invalid_key`) :388-393; signature + non-OKP/Ed25519 key → `invalid_key` :396-405; iss exact :408-411; aud string or array :414-426; claims :429-451 (numeric `iat` accepts int or float). Extra step for polled SETs: poll key ≠ `jti` → `invalid_request` :452-454 (between 8 and 9). Kid miss: cold cache fetch, then **one** forced refetch per 60 s (`forcedRefetchInterval` :285, :553-567) — first unknown kid on a cold cache costs two fetches. JWKS fetch failure → `NetworkError`, not a verdict :579-586.

### Q3 poll
Never acknowledges itself — body is exactly `options` :248-259, :500. `ack`/`setErrs` passed through (`SetErr(reason:)` maps to RFC 8935 code :100-103). Refused returned as `RefusedSet {jti, reason}` :216-221, :540-543; a non-string SET → `malformed` :533-535. Retry `.section16` :516 — not on 400/401/403/404…, **but yes on 408/429** (SW-6). Token from `accessTokenProvider` (called once per poll :504); none configured → local `AuthError`, no request :492-496. Aborts the whole poll on a JWKS failure mid-batch, after earlier SETs were recorded (SW-2).

### Q4 ciba_await
- Clock injectable: `protocol CibaClock { now(); sleep(seconds:) }` :286-302, parameter `clock:` :475. (§16 sleeps inside a poll use the client's `_sleep` seam, not `CibaClock`.)
- Initial interval = response `interval`, or 5 s when absent/≤0 :396-401, :479; no faster floor.
- `slow_down`: `interval += 5` :497-498, never reset; **no cap** at 60.
- Deadline = `receivedAt + expiresIn` :478 (`receivedAt` = time the initiate *response* arrived :393, not send time — SW-11); stops when `now + interval >= deadline` and raises `AuthError(oauthError: "expired_token")` locally :483-488 (can stop up to one interval before the deadline).
- 5xx/transport: retried per §16 inside `cibaPoll` (`.section16UnlessOAuthError`), then `.transient` keeps the loop :586-588; 429 with `rate_limit_exceeded` → transient :583, bodiless 429 retried by §16 then transient.
- Cancellation: Swift structured cancellation — `Task.sleep` throws `CancellationError`, `bareSend` rethrows it :69-74; the `catch let error as AxiamError` does not swallow it.
- `auth_req_id` held only via the caller's `initiated` value for the loop.
- Defect: a `NetworkError` with no status (e.g. a `200` whose body fails to decode, `oidcDecode` :449) is classified transient :587 → loop re-polls an already-redeemed request (SW-3).

### Q5 ciba_handle_ping
Constant-time: `ConstantTime.equals(Array(token.utf8), Array(expected.utf8))` :544 (`ConstantTime.swift:34-48`, full walk, length folded into accumulator). Returns `Sensitive<String>` :558. Missing / duplicated / non-`Bearer` / empty / wrong token / double space → `AuthError("CIBA ping refused: …")` naming no value :530-547; header name matched case-insensitively :533. Body errors → local `NetworkError(isValidation)` :549-557. Synchronous, `nonisolated`, no I/O :525.

### Q6 Signed request
Offered: `CibaRequestSigner(algorithm:privateKeyPEM:keyID:)` :101 — PS256 (`_RSA`, PSS), ES256 (P-256, raw r||s), EdDSA; probe-signs at construction :131. Claims :614-651: every member (`requested_expiry` as **number** :624-626), `iss`=client_id, `aud`=`document.issuer` (string) :376/:628, `iat`=`nbf`=now, `exp`=now+300 s (`cibaSignedRequestLifetimeSeconds` :325), `jti` 128-bit CSPRNG hex :654-664. Header `alg` + optional `kid` :634-635. Form = client auth + `request` only :372-377. Key wrapped (`Sensitive<Data>` :90).

### Q7 Kept-secret-on-update
All three **omit** the member when not supplied (`encodeIfPresent(x?.expose(), …)`): `UpdateDirectoryConfig` `MM:11989` (also `SetDirectoryConfig` `MM:10255`); `SsfStreamInput` `MM:11230`; `ScimTargetInput` `MM:9322`. Keep = `nil`, replace = `.some(Sensitive(...))`; SSF additionally `clearAuthorizationHeader: Bool?` for "remove". The `init(copying:)` helpers set the secret `nil` (`ManagementChecks.swift:96,171,193-194`). Tests: Directory :111 (exact keys), Scim :103, SSF :60/:235.

### Q8 §21.3.1 pin
`MtlsEndpointAliasesTests.swift:205` decodes vector A (retyped inline, not read from CONTRACT.md) and asserts `XCTAssertEqual(seven.compactMap { $0 }.count, 7, "all seven aliases decode")` :242 plus the top-level `backchannel_authentication_endpoint` :234-235. Decoder is a fixed struct `MtlsEndpointAliases` (`Oidc/OidcTypes.swift:30-55`), so an eighth member is ignored, not fatal. Prefers: `cibaInitiate` uses `preferredEndpoint(document, { $0.backchannelAuthenticationEndpoint }, …)` :362-364 (`OidcInternals.swift:92-103`, vector-C refusal :140); live two-listener test `testEveryAliasableEndpointGoesToTheAliasHost` :252 asserts `bc-authorize` hits the mTLS host :267-273.

### Q9 §28.12
URI verbatim: `checkRegistrationURI` returns `URL(string: uri)` unchanged :352-383 (origin = scheme+host+effective port; `http` only on loopback base). Body strips all five (`serverStatedMembers` :74-80, removed from `extra` too :199-203), sets `client_id` :204. Bearer only, bare path, no cookie/CSRF/device bearer (`BareRequest.swift:3-18`); note the bare path still adds `X-Tenant-ID` on a same-host URL (`AxiamClient.swift:1166-1168`). 401 maps via `oidcMapGrantError` (`OAuthProtocolError` = `AuthError.oauthError`) and never enters §9 (test :260).

### Q10 Other divergences / decisions
- `Sensitive` lacks `CustomReflectable` → `dump()`/`Mirror` leak (SW-1, SDK-wide, pre-existing §7).
- No §27.4 rule 4 auto-paging form anywhere; tests walk with `nextRequest` (SW-7).
- Inputs are `Encodable` and that is the wire codec: `JSONEncoder` output carries the three write-only secrets; contract's "serialized for logs" sink is undefined for such languages (SW-8).
- `ScimTargetAuth`/`Scope` forward `raw` verbatim (SW-9); unknown `type` refused locally before send (`MM:9149-9161`) — stricter than §31.9's "no local validation", consistent with §31.2's "MUST NOT send".
- SSF event types are a closed enum with `.unknown` (`MM:1068`); an unknown URI is lost on decode and `copying:` would send `""` (server refuses) (SW-10).
- CIBA: no `private_key_jwt` client auth exists in this SDK (secret or mTLS only, `Ciba.swift:597-609`) — consistent with its `/oauth2/token`. Poll mode with a ping token cannot be expressed (delivery enum). Missing `backchannel_authentication_endpoint` in discovery → `AuthError`, never a built path (`:361-369`) (SW-13). `requested_expiry` is a number inside the JWT (SW-12). Deadline anchored at response receipt (SW-11).
- Bare-path `X-Tenant-ID` only when URL host equals base host (port ignored) — omitted on an mTLS-alias CIBA call, contrary to §33.1 "X-Tenant-ID still emitted"; C sends it on CIBA always but never on §28.12/§32.7 (SW-16).
- Contract silent: replay-store failure semantics; whether a verified-but-unreturned SET stays recorded; whether 408/429 count as "4xx" for `poll`; `aud` form (string vs array) of the signed request; number vs string `requested_expiry` in JWT.

#### Findings
| id | Severity | Clause | What | Evidence | Suggested disposition |
|---|---|---|---|---|---|
| SW-1 | defect | §7 rule 1 (→ §28.12.4, §30.5, §31.5, §32.5, §33.5) | `Sensitive` is not `CustomReflectable`; `dump(x)` / `Mirror(reflecting:)` print the private `value` of every wrapped secret (and recurse into containing structs such as `SetDirectoryConfig`). Redaction tests cover only `String(describing:/reflecting:)`. | `Sources/AxiamSDK/Sensitive.swift:12-39`; tests e.g. `DirectoryManagementTests.swift:68-73` | SDK fix (`extension Sensitive: CustomReflectable { var customMirror: Mirror { Mirror(self, children: []) } }` + a `dump` test); contract clarification naming `dump`/`Mirror` in §7's Swift row |
| SW-2 | defect | §32.7 step 9 / `poll` | A poll that hits a JWKS fetch failure mid-batch throws; SETs already verified in that batch were recorded in the replay store and are discarded — re-offered next poll they read `replayed`, and the documented advice (put refused in `setErrs`) then deletes them server-side: silent event loss. | `SsfReceiver.swift:456-459, 537-543` | SDK fix (return partial result or record only on hand-back); contract clarification on recording vs hand-back |
| SW-3 | defect | §33.7 rule 7 | `cibaAwait` treats any `NetworkError` without a status as transient, including a `200` whose token body failed to decode — the loop polls again after the redemption and surfaces `invalid_grant` instead of the real failure. | `Ciba.swift:449, 587, 494-496` | SDK fix (terminal on post-2xx failures) |
| SW-4 | clarification | §32.7 step 9 | Replay store protocol is non-throwing `async -> Bool`; a shared store cannot report failure, so fail-open vs fail-closed is undefined. (C: negative return → `NetworkError`, fail closed.) | `SsfReceiver.swift:125-130` | contract clarification (store failure = refuse, not accept); SDK fix (`throws`) |
| SW-5 | clarification | §32.7 step 9 | Default in-memory store unbounded; full O(n) filter on every call. | `SsfReceiver.swift:147-153` | contract clarification on a bound (or document) |
| SW-6 | clarification | §32.7 `poll` | Poll retries 408 and 429 (§16 table) though §32.7 says "not retried on a 4xx". | `BareRequest.swift:114-115`; `SsfReceiver.swift:516` | contract clarification (408/429 excepted?) |
| SW-7 | defect | §27.4 rule 4 (§29.8 #5, §31.8 #4, §32.8 #4) | No auto-paging form; required tests discharge "auto-pager carries search" with a hand-written `nextRequest` loop. Pre-existing §27 gap. | `Management/ManagementCore.swift:50-52,123`; `SamlManagementTests.swift:237-251` | SDK fix (AsyncSequence pager) |
| SW-8 | clarification | §30.8 #1, §31.8 #1, §32.8 #2 ("serialized for logs") | Request types are `Encodable` and that is the wire codec; `JSONEncoder().encode(body)` emits `bind_secret`/`credential`/`authorization_header`. No separate log serializer exists. | `MM:10255, 11989, 9322, 11230` | contract clarification (what "serialize-for-logs" means where the only serializer is the wire one) |
| SW-9 | clarification | §31.2 | `ScimTargetAuth`/`ScimTargetScope` keep the server object in `raw`; a response `auth` carrying an unexpected secret member would be surfaced in `description` and echoed by `ScimTargetInput(copying:)`. | `MM:9114-9161`; `ManagementChecks.swift:167-178` | contract clarification (drop undeclared members inside `auth`?) |
| SW-10 | clarification | §32.2 ("SHOULD model event types as strings") | Event types are an enum with `.unknown`; an unknown URI is not preserved. | `MM:1068` | SDK fix or accepted deviation |
| SW-11 | clarification | §33.7 rule 4 | Deadline = response-receipt time + `expires_in` (not initiate send time); loop stops when the *next* poll would reach it. | `Ciba.swift:393, 478, 483` | contract clarification (anchor) |
| SW-12 | clarification | §33.2 | `requested_expiry` sent as a JSON number inside the signed JWT, string on the form. | `Ciba.swift:624-626` | contract clarification |
| SW-13 | clarification | §33.1 | With no `backchannel_authentication_endpoint` in discovery the SDK refuses (`AuthError`) rather than building the path; it always holds a document. | `Ciba.swift:361-369` | contract clarification (acceptable) |
| SW-14 | doc | §31.3 rule 2 ("both call sites") | `scim_targets.create` doc says only "credential is required here", not the URL-binding rule. (C identical.) | `NS:3921-3922` | SDK fix (generator) |
| SW-15 | doc | §29.3 rule 2 ("where it documents the field") | ECDSA/HTTP-Redirect caveat is on the methods, not on the `spSigningCertPEM` field docs. (C identical.) | `MM:8928-8929`, `MM:8757`; methods `NS:3505, 3557` | SDK fix (generator) |
| SW-16 | clarification | §5 rule 2 / §33.1 / §28.12.2 rule 3 | Bare path adds `X-Tenant-ID` only when URL host == base host (port ignored): sent on §28.12 and SSF poll, omitted on an mTLS-alias CIBA call; C does the opposite on §28.12/§32.7. | `AxiamClient.swift:1166-1168` | contract clarification (is the tenant header "session"?) |
| SW-17 | doc | §33.8 #14 | PS256 signed form only refusal-tested (no RSA keygen in tests); README states this. | `CibaTests.swift:572-642`; README.md:50-51 | SDK fix (test) |

---

### Report — c — commit 265f5b4 (merge #69)

Toolchain run: **yes** — out-of-tree build in the scratchpad: `cmake -S <repo> -B <scratch>/c-build -DAXIAM_BUILD_TESTS=ON -DAXIAM_BUILD_EXAMPLES=OFF && make -j8 && ctest -j8` → configure 0, build 0 (0 warnings in `make.log`), **72/72 tests passed** (incl. `test_client_registration`, `test_saml`, `test_directory`, `test_scim_targets`, `test_ssf_management`, `test_ssf_receiver`, `test_ciba`, `test_contract_158_alloc`, `test_mtls_endpoint_aliases`). Vendored `CONTRACT.md` byte-identical to this repository's `sdks/CONTRACT.md` (1.58).

Paths are relative to the `axiam-c-sdk` repository root. `OPS.h` = `include/axiam/management_ops.h`, `OPS.c` = `src/management_ops.c`, `MM.h` = `include/axiam/management_models.h`, `MM.c` = `src/management_models.c`.

#### Posture per section
| Section | Status | Notes |
|---|---|---|
| §28.12 | implemented | three flat functions, `axiam_client_send_bare` (no cookie jar, no CSRF, no tenant header); writes single attempt |
| §29 | implemented | 11 `axiam_saml_*`; no auto-pager (SDK-wide); management GET retry has no backoff (pre-existing) |
| §30 | implemented | 6 `axiam_directory_*`; `bind_secret` `axiam_sensitive_t*` in both inputs |
| §31 | implemented | 6 `axiam_scim_targets_*`; `credential` Sensitive; `ScimTargetAuth.raw` passthrough |
| §32 | implemented | 5 `axiam_ssf_*_stream(s)`; event types kept as raw JSON strings |
| §32.7 | implemented (MAY) | `axiam_ssf_receiver_new/verify_set/poll`; replay store fn-pointer with failure channel |
| §33 | implemented (MAY) | `axiam_ciba_initiate/poll/await/handle_ping`; injectable `axiam_ciba_clock_t` |
| §33.2 signed | implemented | `axiam_ciba_request_signer_new` PS256/ES256/EdDSA (OpenSSL EVP); all three round-trip-tested |

#### A–F per section

### §28.12
**A.** `axiam_read_client_registration` `include/axiam/registration.h:146` / `src/registration.c:371`; `axiam_update_client_registration` `.h:176` / `.c:388`; `axiam_delete_client_registration` `.h:190` / `.c:422`; type `axiam_client_registration_t` `.h:73-110` (unknown members kept as JSON text in `extra`), parse/free `.h:118,123`.
**B.** Token arg `const axiam_sensitive_t *` on all three; `client_secret` and `registration_access_token` members `axiam_sensitive_t *` `.h:103,106`, removed from `extra` whatever their type `.c:80-92`; scrubbed on free `.c:54-55`. Bearer header buffer zeroed `.c:288-301`. Rule-1 refusal via `axiam_local_refusal` with fixed reasons, no URI text `.c:259-280`.
**C.** `tests/test_client_registration.c`: (1) `test_a_uri_at_another_origin_is_refused_before_any_request` :187 (host/port/http/userinfo/ftp/relative/NULL; `g.calls == 0`) + :228; (2) `test_read_and_delete_send_only_the_bearer` :301 + `test_a_device_bearer_is_never_attached` :342; (3) `test_update_drops_the_server_stated_members_and_returns_the_rotated_token` :379 + `test_writes_are_never_retried_and_the_read_is` :454 (503 and dropped connection: 1 call; read 503→200: 2 calls, 1 sleep; bodiless 400: 1 call); (4) `test_oauth_errors_at_any_status_and_no_refresh` :506 (`g.refresh_calls == 0`); (5) `test_neither_the_token_nor_the_secret_reaches_any_rendering` :566 (`axiam_sensitive_to_string`, `extra` NULL, error messages).
**D.** "`metadata` is the **whole** registration…" `.h:156-162`; "**Persist the returned `registration_access_token` before doing anything else.**" `.h:164-166`; "**Never retried**" `.h:168-171, 187-188`.
**E.** `registration_send(..., retryable=0)` for PUT `.c:416-417` and DELETE `.c:434-435` → `budget = 1` `.c:307`; read `retryable=1` §16 with backoff/jitter/`Retry-After` `.c:316-325`.
**F.** README.md:16 "conforms to CONTRACT.md 1.58 … §28, §28.12, §29, §30, §31, §32 and §33, with §32.7 and §33.2 signed"; README.md:25-33. Matches.

### §29
**A.** `OPS.h`: `axiam_saml_get_idp` 2227, `_list_service_providers` 2244 (page), `_create_service_provider` 2263, `_get_service_provider` 2277, `_update_service_provider` 2301, `_delete_service_provider` 2322, `_parse_sp_metadata` 2343 (exactly-one check `src/management_helpers.c:90`, called `OPS.c:4997`; builders `axiam_mgmt_parse_saml_sp_metadata_from_url/_from_xml` `include/axiam/management_helpers.h:58,61`), `_list_idp_credentials` 2359 (plain list), `_issue_idp_credential` 2376, `_promote_idp_credential` 2394, `_retire_idp_credential` 2413. RMW `axiam_mgmt_saml_service_provider_to_input` `management_helpers.h:38`. No auto-paging form, only `axiam_mgmt_page_next` `include/axiam/management.h:135` (C-3).
**B.** Nothing wrapped (correct); `SamlIdpCredential` declares no key; parser ignores unknown members.
**C.** `tests/test_saml.c`: (1) :64; (2) :122; (3) :156; (4) :211; (5) :251 (manual `axiam_mgmt_page_next` walk, asserts `search=payroll` each request :265-270); (6) :289; (7) :324; (8) :360.
**D.** Same generated text as Swift: replacement warning `OPS.h:2285-2291`; ECDSA/Redirect on create/update `OPS.h:2251-2254, 2290-2291` (not on the field `MM.h:6399-6402`, C-9); retire-active `OPS.h:2401-2404`.
**E.** `src/management.c:289-290` `int retryable = strcmp(method,"GET")==0; int attempts = retryable ? 3 : 1;` — writes single attempt. (GET retry: see C-2.)
**F.** README.md:16, :25-28. Matches.

### §30
**A.** `OPS.h`: `axiam_directory_get` 2102, `_set` 2124, `_update` 2146, `_delete` 2169, `_link_account` 2190, `_get_sync_status` 2203. RMW `axiam_mgmt_directory_config_to_set` `management_helpers.h:52`.
**B.** `bind_secret` `axiam_sensitive_t *` in set `MM.h:7076` and update `MM.h:8139`; revealed only into the wire body `MM.c:9531-9533, 11202-11204`. `DirectoryConfig` declares none. Rendered body freed without scrub (C-5).
**C.** `tests/test_directory.c`: (1) :109; (2) :137; (3) :161 (exact bodies `{"enabled":false}`, keys `bind_secret,url`, `{"group_filter":null}`); (4) :219; (5) :265; (6) :318.
**D.** set/update rule 2 `OPS.h:2109-2115, 2131-2138`; delete rule 5 `OPS.h:2158-2162`; link signs out `OPS.h:2177-2181`.
**E.** as §29.
**F.** README.md:16, :27. Matches.

### §31
**A.** `OPS.h`: `axiam_scim_targets_list` 2533, `_create` 2549, `_get` 2562, `_update` 2583, `_delete` 2604, `_reconcile` 2621 (no scope arg — tenant is the token's). Builders `axiam_mgmt_scim_target_auth_bearer/_client_credentials`, `_scope_all_users/_groups` `management_helpers.h:66-79`; RMW `axiam_mgmt_scim_target_response_to_input` :47. Unknown `auth`/`scope` type refused before send `OPS.c:5485-5494`.
**B.** `credential` `axiam_sensitive_t *` `MM.h:6575`; revealed `MM.c:8729`. Response declares none. `ScimTargetAuth { type; raw }` `MM.h:6482-6492` keeps the server object (C-6).
**C.** `tests/test_scim_targets.c`: (1) :85; (2) :105; (3) :128; (4) :226 (+ :270 unknown arm never sent); (5) :319; (6) :349 (+ :386).
**D.** update rule 2/4 `OPS.h:2569-2574`; delete rule 8 `OPS.h:2595-2597`; create only "`credential` is required here (§31.3 rule 2)" `OPS.h:2540-2541` (C-8).
**E.** as §29.
**F.** README.md:16, :27. Matches.

### §32 (management)
**A.** `OPS.h`: `axiam_ssf_list_streams` 2439, `_create_stream` 2453, `_get_stream` 2467, `_update_stream` 2489, `_delete_stream` 2508. RMW `axiam_mgmt_ssf_stream_to_input` `management_helpers.h:42`.
**B.** `authorization_header` `axiam_sensitive_t *` `MM.h:7655`, revealed `MM.c:10445`; `clear_authorization_header` + `has_` flag `MM.h:7660-7661`. `SsfStream` has `authorization_header_set` only; event-type arrays kept as JSON text `MM.h:7576-7584` (unknown URIs preserved).
**C.** `tests/test_ssf_management.c`: (1) :76; (2) :127; (3) :170; (4) :212; (5) :235; (6) :261 (+ :281).
**D.** update_stream header exception + rule 5 + 409 `OPS.h:2475-2479`.
**E.** as §29.
**F.** README.md:16, :28. Matches.

### §32.7 (helper)
**A.** `include/axiam/ssf.h`: `axiam_ssf_receiver_new` (config `{issuer, audience, jwks_uri | discovery_url, access_token_provider, replay_window_s, replay_store}`), `axiam_ssf_verify_set`, `axiam_ssf_poll`; event-type macros; `axiam_ssf_reason_t` + `axiam_ssf_reason_code`/`axiam_ssf_push_error_code`. Implementation `src/ssf.c` (verify `:429-574`, poll `:706-791`).
**B.** Token provider returns a new `axiam_sensitive_t` freed after the poll; header buffer zeroed `src/ssf.c:642-656`. Refusal messages name the step only `src/ssf.c:415-421`.
**C.** `tests/test_ssf_receiver.c`: (1) :278; (2) :318; (3) :363; (4) :400; (5) :421; (6) :458; (7) :511; (8) :554 + `test_poll_is_not_retried_on_a_4xx_and_is_on_a_5xx` :643 (400 → 1 call, 503 → 2 calls); extras: pluggable store :836, failing token provider :880, configuration refusals :775.
**D.** `ssf.h` verify doc lists the nine steps + "**A SET that verifies has been recorded**"; poll doc "**Nothing is acknowledged on your behalf**".
**E.** poll loop `src/ssf.c:756-772`: `axiam_retry_should_retry(rc != 0, resp.status)` → transport/408/429/5xx only (C-4).
**F.** README.md:16 "with §32.7"; README.md:29. Matches.

### §33
**A.** `include/axiam/ciba.h`: `axiam_ciba_initiate`, `axiam_ciba_poll`, `axiam_ciba_await`, `axiam_ciba_handle_ping` (no client argument), `axiam_error_is_access_denied/_expired_token`. Params struct: one `hint_kind` + one `hint` (both hints unwritable; no `login_hint_token`/`user_code`/`request_uri` members). Implementation `src/oidc_ciba.c`.
**B.** `auth_req_id` `axiam_sensitive_t *` in the response and as poll input; ping result a new Sensitive; response JSON buffer scrubbed after copy `src/oidc_ciba.c:457, 717`; `client_notification_token` `const axiam_sensitive_t *`, `expected_token` Sensitive; signer key held in an opaque `EVP_PKEY` (`struct axiam_ciba_request_signer` :57-61), PEM input Sensitive; signed `request` and every intermediate scrubbed `:314-322, 418-422`.
**C.** `tests/test_ciba.c`: t01 :327, t02 :372, t03 :432, t04 :517, t05 :586, t06 :636, t07 :670, t08 :698, t09 :741, t10 :776, t11 :808 (constant-time asserted structurally by finding `CRYPTO_memcmp(token, expected, expected_len)` in the helper's body), t12 :876, t13 :907, t14 :997 (EdDSA, ES256 **and PS256**, each verified with the public key, `jti` 32 hex, two distinct), t15 :1073, t16 :1125; extras :1161 (no endpoint), :1208 (mTLS alias + vector-C refusal), :1244.
**D.** `ciba.h`: "**Never retried** … (§33.7 rule 1)"; "**A successful axiam_ciba_initiate() proves nothing about the user**"; poll "**Store the returned tokens before anything else**"; ping "answer `204` as soon as this returns, THEN axiam_ciba_poll()".
**E.** initiate `oidc_post(c, url, FORM_CONTENT_TYPE, form.buf, 0, &resp)` once, no loop `src/oidc_ciba.c:423-424`; poll §16 loop skipping any response with an OAuth `error` `:513-527`.
**F.** README.md:16 "§33, with … §33.2 signed"; README.md:30-31, :2218-2291. Matches.

#### Q1 … Q10

### Q1 Replay store
- Interface: `typedef int (*axiam_ssf_replay_check_fn)(void *ctx, const char *jti, long window_s);` (`include/axiam/ssf.h`) — **synchronous**, **atomic check-and-insert** (MUST be atomic per doc); returns 1 recorded / 0 already held / **negative = store failure**.
- Default: in-memory singly linked list under `seen_mtx`, **unbounded**, expired entries pruned on every call (O(n)) `src/ssf.c:338-370`; TTL = `now + window_s` via the client's injectable clock :362.
- Store error: `fresh < 0` → `AXIAM_ERR_NETWORK` "the SSF replay store failed", **SET not accepted (fail closed)**, not a verdict :560-571; in `poll` it aborts the whole poll (C-1).
- Recorded only after steps 1–8 **and** after the result struct is built (OOM cannot leave a recorded-but-unreturned SET) :541-556 → :559.
- Window: `0` = default 7 d; `< AXIAM_SSF_MIN_REPLAY_WINDOW_S` → **refused at `axiam_ssf_receiver_new`** with the local ValidationError (`AXIAM_ERR_NETWORK`, cause 400) :166-172. No clamp.

### Q2 verify_set
Order 1→9, codes exact: malformed `:428-443`; typ `strcasecmp` either form `:453-455`; alg `strcmp(…,"EdDSA")` `:462`; kid must be a string (missing → `invalid_key`) and looked up `:467-479`; signature (64-byte Ed25519 via EVP) `:482-485`; iss exact `:487-492`; aud string or array `:494-504`; exp/sub/jti/iat/sub_id/events `:506-534`; extra poll-only check (key ≠ `jti` → `invalid_request`) `:535-539`; replay `:559-571`. Kid miss: cold cache fetch then one forced refetch, rate-limited to once per 60 s by the client clock (`AXIAM_SSF_JWKS_REFETCH_INTERVAL_S`) `:313-331`; keys mutex held across the fetch (single-flight). Fetch failure → `AXIAM_ERR_NETWORK`, `out_reason` NONE.

### Q3 poll
Never acknowledges — body is exactly the set members, `{}` for NULL options `src/ssf.c:609-638`. `ack`/`set_errs` passed through (`axiam_ssf_set_err_from_reason`). Refused as `{jti, reason}` (`axiam_ssf_refused_set_t`); non-string SET → `malformed` `:675-697`. Retry: transport/408/429/5xx only `:756-772` (C-4). Token source: `access_token_provider` fn pointer, once per poll; none → local `AXIAM_ERR_AUTH`, no request `:717-722`; provider failure stops the poll `:738-748`. Not as the session: `axiam_client_send_bare` (withholds cookie jar, no CSRF, no tenant header) `src/client.c:344-368`.

### Q4 ciba_await
- Clock injectable: `axiam_ciba_clock_t { now, sleep, ctx }` (`ciba.h`), defaulting to the client's `clock_fn`/`sleep_fn` `src/oidc_ciba.c:589-597, 627`. §16 sleeps inside a poll use the client's `sleep_fn`.
- Initial interval = response `interval`, 5 s when absent/≤0 `:459-460, 627`; no faster floor.
- `slow_down`: `interval += 5` `:650-653`, never reset, **no cap**.
- Deadline = `received_at + expires_in` `:629`; `received_at` taken when the response was parsed `:461` (C-7); stops when `now + interval >= deadline`, raising `AXIAM_ERR_AUTH` with `oauth_error` "expired_token", no request `:633-639`.
- 5xx/transport: §16 within the poll, then `transient` keeps the loop `:531-548, 649`; 429 `rate_limit_exceeded` → transient `:545`; bodiless 429 retried by §16 then transient `:547`.
- A `200` whose body fails to parse is terminal (not re-polled) `:538-541` — correct per §33.7 rule 7.
- Cancellation: **none** — blocking loop; the clock's `sleep` returns `void`, so a caller cannot abort except by `expires_in` or closing the client (C-10).
- `auth_req_id`: borrowed from `initiated` for the loop, never copied.

### Q5 ciba_handle_ping
Exactly one `Authorization` (name `strcasecmp`), scheme `strncasecmp(value,"Bearer",6)` with the space at index 6, then `token_len == expected_len && CRYPTO_memcmp(token, expected, expected_len) == 0` `src/oidc_ciba.c:680-704` (length check is non-secret). Missing / duplicated / non-Bearer / empty expected / wrong → `AXIAM_ERR_AUTH` with a fixed message naming no value `:675-677`. Body: `cJSON_ParseWithLength`, non-empty string `auth_req_id`, extras ignored, else local ValidationError `:707-715`. Returns a new `axiam_sensitive_t` (source buffer zeroed) `:716-724`. Synchronous; takes no client, so it cannot do I/O.

### Q6 Signed request
Offered: `axiam_ciba_request_signer_new(alg, private_key_pem, kid, err)` — PS256 (RSA/RSA-PSS ≥ 2048, PSS salt = digest), ES256 (P-256, DER→raw r||s), EdDSA; enum has no zero value, so "no algorithm" is refused; key family checked and probe-signed `src/oidc_ciba.c:122-187` (probe :178). Claims `:258-299`: `iss`=client_id, `aud`=discovery `issuer` (string) :276, `iat`=`nbf`=client clock now, `exp`=now+300 s :279, `jti` 128-bit `RAND_bytes` hex :269-271, every member inside (`requested_expiry` as a number :286-287). Form = `client_id`(+`client_secret`) + `request` only `:398-401`; a failed signing never falls back to an unsigned form `:419-421`. Key material in an opaque `EVP_PKEY`.

### Q7 Kept-secret-on-update
All omit when NULL: `UpdateDirectoryConfig.bind_secret` `MM.c:11202-11204` (and set `:9531-9533`); `SsfStreamInput.authorization_header` `MM.c:~10444-10446` (plus `clear_authorization_header` with `has_` flag for "remove"); `ScimTargetInput.credential` `MM.c:~8728-8730`. Keep = NULL, replace = non-NULL Sensitive. `_to_input`/`_to_set` helpers leave it NULL (`test_directory.c:402-414`). Tests assert exact keys (`test_directory.c:161`; `test_scim_targets.c:128`).

### Q8 §21.3.1 pin
`tests/test_mtls_endpoint_aliases.c:625` reads vector A **verbatim from the vendored CONTRACT.md** (`vector_a()` :599-623) and asserts `TEST_ASSERT_EQUAL_INT_MESSAGE(7, cJSON_GetArraySize(aliases), "vector A names seven aliases");` :630, then that all seven decode to the vector's values and the CIBA call from an mTLS client goes to `https://mtls.iam.example.test/oauth2/bc-authorize?tenant_id=…`. Prefers: `oidc_preferred_endpoint(c, config, config->mtls_endpoint_aliases.backchannel_authentication_endpoint, config->backchannel_authentication_endpoint, …)` `src/oidc_ciba.c:378-380`; also poll uses the token alias `:495-497`; tested `test_ciba.c:1208`.

### Q9 §28.12
URI verbatim: passed unchanged to `axiam_client_send_bare` `src/registration.c:315`; origin check compares lower-cased scheme/host and parsed port, refuses userinfo, `http` only on a loopback base `:259-280` (`src/util.c:88-150`). Body: `extra` minus the five members, named members over it, `client_id` set `:221-253`. Bearer only; `send_bare` withholds the cookie jar (empty `Cookie` signal) and sends no CSRF/tenant/device header `src/client.c:344-368`. 401 → `oidc_map_grant_error` (OAuthProtocolError = `AXIAM_ERR_AUTH` + `oauth_error`), no §9 `:347-358`; tested `g.refresh_calls == 0`.

### Q10 Other divergences / decisions
- Management GET retry (covers every §29–§32 read): fixed 3 attempts, **no backoff/jitter/`Retry-After`**, ignores `retry_enabled`, retries only transport/5xx (not 408/429) `src/management.c:289-290, 318, 344` (C-2, pre-existing §27).
- No auto-paging form (C-3).
- Management request bodies carrying `bind_secret`/`credential`/`authorization_header` are `free`d without scrubbing (`OPS.c:5505-5506` and peers), unlike §28.12/§32.7/§33 which zero their buffers (C-5).
- `ScimTargetAuth.raw` passthrough (C-6).
- §28.12 and §32.7 send **no** `X-Tenant-ID`; CIBA always sends it (`src/oidc.c:414-421`) — opposite of Swift on §28.12/§32.7 (C-11).
- CIBA: a poll-mode request carrying a `client_notification_token` is refused locally (`src/oidc_ciba.c:362-366`) — stricter than §33.2; no `private_key_jwt` client authentication (consistent with this SDK's token endpoint, documented in `ciba.h`); a document without `backchannel_authentication_endpoint` → `AXIAM_ERR_AUTH`, never a built path `:381-387`; a tenant slug without UUID refused (`oidc_require_tenant_uuid`).
- README DPoP decline rationale is now stale: "it ships no JOSE implementation covering PS256/ES256/EdDSA" (README.md:1086-1090) while `src/oidc_ciba.c` now signs all three with the same OpenSSL (C-12).
- Contract silent: replay-store failure semantics (C chose fail closed); recorded-vs-handed-back on poll abort; 408/429 as "4xx" for `poll`; `requested_expiry` type inside the JWT; deadline anchor; cancellation of `ciba_await`.

#### Findings
| id | Severity | Clause | What | Evidence | Suggested disposition |
|---|---|---|---|---|---|
| C-1 | defect | §32.7 step 9 / `poll` | A JWKS-fetch or replay-store failure mid-batch aborts `axiam_ssf_poll` and disposes the result; SETs already verified in that batch stay recorded, are re-offered as `replayed`, and the documented `set_errs` advice then deletes them server-side — silent event loss. | `src/ssf.c:688-692, 787` | SDK fix (return partial result / un-record); contract clarification |
| C-2 | defect | §16.1/§16.3 via §27.4 rule 8 (reads of §29–§32, "MAY be retried per §16") | Management GET retry is immediate (no backoff, jitter or `Retry-After`), ignores the `retry_enabled` switch, and skips 408/429. Pre-existing §27 path. | `src/management.c:289-290, 312-318, 341-344` | SDK fix |
| C-3 | defect | §27.4 rule 4 (§29.8 #5, §31.8 #4, §32.8 #4) | No auto-paging form; tests walk with `axiam_mgmt_page_next`. Pre-existing. | `include/axiam/management.h:135`; `tests/test_saml.c:251-270` | SDK fix |
| C-4 | clarification | §32.7 `poll` | Poll retries 408/429 (§16 table) though §32.7 says "not retried on a 4xx". | `src/ssf.c:766-768` | contract clarification |
| C-5 | defect | §30.5 / §31.5 / §32.5 ("MUST NOT keep it after the request") | Rendered JSON bodies holding the write-only secrets are freed without `axiam_secure_zero`, unlike §28.12/§33 buffers. | `src/management_ops.c:5505-5506` (create; same pattern on directory set/update, scim update, ssf create/update) | SDK fix (scrub in generator) |
| C-6 | clarification | §31.2 | `axiam_mgmt_scim_target_auth_t.raw` keeps the server's whole `auth` object; an undeclared secret member would be surfaced and echoed by `_to_input`. | `include/axiam/management_models.h:6482-6492`; `management_helpers.h:47` | contract clarification |
| C-7 | clarification | §33.7 rule 4 | Deadline anchored at response-parse time, not send time; loop stops when the next poll would reach it. | `src/oidc_ciba.c:461, 629, 633` | contract clarification |
| C-8 | doc | §31.3 rule 2 ("both call sites") | `create` doc does not restate the URL-binding rule. | `include/axiam/management_ops.h:2540-2541` | SDK fix (generator) |
| C-9 | doc | §29.3 rule 2 ("where it documents the field") | ECDSA/Redirect caveat on functions only, not on `sp_signing_cert_pem`. | `include/axiam/management_models.h:6399-6402, 6298-6301` | SDK fix (generator) |
| C-10 | clarification | §33.1 / §33.7 | `axiam_ciba_await` cannot be cancelled (blocking loop; `sleep` hook returns void). | `include/axiam/ciba.h` (`axiam_ciba_clock_t`); `src/oidc_ciba.c:631-660` | contract clarification (is cancellation required?) |
| C-11 | clarification | §5 rule 2 / §28.12.2 rule 3 / §33.1 | §28.12 and §32.7 send no `X-Tenant-ID`; CIBA always does. Swift sends it on same-host bare requests. | `src/client.c:344-368`; `src/oidc.c:414-421` | contract clarification |
| C-12 | doc | §21.9 / README | DPoP-decline rationale "ships no JOSE implementation covering PS256/ES256/EdDSA" is contradicted by the new CIBA signer using the same OpenSSL; the decline may stand, the stated reason no longer does. | `README.md:1086-1090`; `src/oidc_ciba.c:122-187` | SDK fix (README) |
| C-13 | clarification | §32.7 step 9 | Default in-memory store unbounded, O(n) prune per call. | `src/ssf.c:338-370` | contract clarification |
| C-14 | clarification | §33.2 | `requested_expiry` as a JSON number inside the signed JWT, string on the form. | `src/oidc_ciba.c:286-287` | contract clarification |

---

### Report — cplusplus — commit 3b949ab (merge #71)
Toolchain run: yes. `apt-get install libcurl4-openssl-dev` (sandbox only, nothing in the repo), then out-of-tree
`cmake -G Ninja -DAXIAM_BUILD_TESTS=ON` + `ninja` + `ctest` in the scratchpad: build OK, ctest 1/1 passed; the test
binary reports **1488 test cases, 5178 checks, 0 failed**. I also wrote two throw-away probes (scratchpad `cppprobe/`,
linked against the built `libaxiam_cpp.a` and the repo's own test helpers) to confirm F-1 and F-2 below.
`CONTRACT.md` and `openapi.json` are byte-identical to this repository's `sdks/` (cmp).

All paths are relative to the `axiam-cplusplus-sdk` repository root.

#### Posture per section
| Section | Status | Notes |
|---|---|---|
| §28.12 | implemented | `Client::{read,update,delete}_client_registration`. Origin check, a bearer-only sessionless request, the five members stripped, no write retried. The rotated token comes back `Sensitive`, and the only accessor is the documented-internal `detail::reveal` (F-8). |
| §29 | implemented | All 11 ops on `SamlApi`. No key member (static_assert). Both/neither refused locally. The required members of the input are not enforced (F-4). The ECDSA note is on the method docs, not on the field doc (F-7). |
| §30 | implemented | All 6 ops on `DirectoryApi`, with `delete_` for `delete` (C++ keyword). `bind_secret` is `optional<Sensitive>`. The PATCH body is tri-state. |
| §31 | implemented | All 6 ops on `ScimTargetsApi`. Unknown union types decode, and sending one is refused locally. The create doc does not restate the URL binding (F-6). |
| §32 | implemented | All 5 ops on `SsfApi`. Event types are a closed enum (`SsfEventType::Unknown` is written as `""`), not strings plus constants as the SHOULD asks (F-5). |
| §32.7 | implemented (defect) | `ssf::SsfReceiver::{verify_set,poll}`. Nine steps in order. A poll aborted mid-batch leaves the jtis already verified recorded, so those events are lost (F-1, confirmed by probe). |
| §33 | implemented (defect) | `Client::ciba_{initiate,poll,await,handle_ping}`. A 5xx carrying an `error` body (the server's `500 {"error":"server_error"}`) ends `ciba_await` and is not §16-retried by `ciba_poll` (F-2, confirmed by probe). |
| §33.2 signed | implemented | `CibaRequestSigner::from_pem` (PS256, ES256, EdDSA) over OpenSSL. Key and algorithm are both required by construction. iss, aud, iat, nbf, exp (+300 s) and a 128-bit jti. |

#### A–F per section

### §28.12
**A.** `read_client_registration` → `Client::read_client_registration` include/axiam/client.hpp:910, src/oidc.cpp:2150.
`update_client_registration` → client.hpp:933, oidc.cpp:2161. `delete_client_registration` → client.hpp:941, oidc.cpp:2173.
Type `ClientRegistration` → include/axiam/oidc.hpp:791. Unknown members are kept in `extra_json` (oidc.hpp:817; oidc.cpp:2061–2127).
**B.** `registration_access_token` and `client_secret` are `std::optional<Sensitive<std::string>>` (oidc.hpp:812–816). The call
arguments are `const Sensitive<std::string>&` (client.hpp:910–942). The origin-refusal message names no part of the URI
(oidc.cpp:1996–2001). Error messages come from `raise_grant_error` (status/`error` code). The token never reaches the body
or the URL. Caveat: `take_string` leaves a *non-string* `client_secret`/`registration_access_token` in the public
`extra_json` unwrapped (oidc.cpp:2077–2085, 2119–2124). This is an edge case, and `update_body()` erases those keys anyway (oidc.cpp:2134).
**C.** (1) tests/test_client_registration.cpp:98 "§28.12.6 (1)…", which covers host, port, http-vs-https, ftp, relative and
userinfo, with `count()==0`. (2) :144 (bearer only, `sessionless`, no Cookie/CSRF/X-Tenant-ID, no body, URI verbatim with its
`tenant_id`), plus :182 (device credential not attached). (3) :212 (five stripped, `client_id` set, rotated token returned);
the 503-not-retried case is at :250 (the mock always answers 503 and the test asserts exactly 1 request). (4) :298 (401
`invalid_token` → `OAuthProtocolError`, `/auth/refresh` count 0, `refresh_call_count()==0`), :320 (400
`invalid_client_metadata`), delete 204 at :144. (5) :366. It renders the `Sensitive` members, `extra_json`, `update_body()`,
the server-error message and the local-refusal message. C++ has no struct-level stringification, so a per-member check is all there is.
**D.** Rule 4 ("whole registration") and rule 5 ("Persist the returned … before doing anything else", "Never retried")
are on the method doc: client.hpp:915–932, 937–940.
**E.** `registration_request(..., retryable)` with `budget = retryable ? 3 : 1` (oidc.cpp:2026). Update and delete pass
`false` (oidc.cpp:2169, 2178), so a transport error or 5xx throws on attempt 1.
**F.** README.md:15 "…§27, §28, §28.12, §29, §30, §31, §32 and §33 at contract 1.58, with §32.7 and §33.2 signed…"
matches the code. §28.12 is named rather than folded into §28.

### §29
**A.** Every op is on `SamlApi` (include/axiam/management.hpp):
`get_idp` :1903, `list_service_providers` :1913, `create_service_provider` :1925, `get_service_provider` :1932,
`update_service_provider` :1949, `delete_service_provider` :1964, `parse_sp_metadata` :1977, `list_idp_credentials` :1985
(a `std::vector`, not a Page), `issue_idp_credential` :1995, `promote_idp_credential` :2006, `retire_idp_credential` :2018.
Reached as `client.saml()` (client.hpp:1463) or `client.management().saml()` (management.hpp:2727).
The auto-pager is `Page::next_request()` (management.hpp:99), the SDK's existing §27 pattern.
**B.** Nothing is wrapped, which is correct. `SamlIdpCredential` declares no key member (management_models.hpp:3714–3739;
static_assert at tests/test_saml.cpp:88). The decoder reads named fields only, so `private_key_pem` is dropped.
**C.** (1) test_saml.cpp:107 discharges it only partly. It asserts PUT plus every member plus the 200 decode. For "cannot be built
without display_name/entity_id/acs_urls" it documents the decline instead: `SamlServiceProviderInput{}` serializes them
empty (:123–126) and nothing refuses locally (F-4). (2) :130. (3) :155: both and neither raise `std::invalid_argument` with
no request; exactly one member is sent; the draft is created unchanged. (4) :190. (5) :213. (6) :241: seven writes, 7
requests, all `NetworkError`. (7) :263. (8) :288: null vs absent, two calls give two requests, configured tenant in the path.
**D.** The update warning is at management.hpp:1937–1943 ("An omitted member takes its default, not its stored value…").
`entity_id` immutability is at :1942. ECDSA HTTP-POST-only is on create (:1918–1920) and update (:1943), but not on the field doc
`SamlServiceProviderInput::sp_signing_cert_pem` (management_models.hpp:3867) (F-7). Retiring the active credential
"stops SAML sign-on for the whole tenant at once" is at :2011–2015. "Ends no session" on delete is at :1962.
**E.** The management transport retries only `GET` (`retryable = http_method == "GET"; budget = … ? 3 : 1`,
src/management_transport.cpp:162–163). Every POST, PUT and DELETE is single-shot.
**F.** README.md:15 names §29, and README.md:2215–2262 documents it. Matches the code.

### §30
**A.** `DirectoryApi` (management.hpp): `get` :1803, `set` :1819, `update` :1834, `delete_` :1850 (canonical
`directory().delete`, which is a C++ keyword, F-9), `link_account` :1864, `get_sync_status` :1869. Also `client.directory()`
(client.hpp:1458).
**B.** `SetDirectoryConfig::bind_secret` and `UpdateDirectoryConfig::bind_secret` are both
`std::optional<Sensitive<std::string>>` (management_models.hpp:4177, :4599). `DirectoryConfig` has no secret member
(static_assert at tests/test_directory.cpp:71). The secret is serialized only by the internal (non-installed) JSON hook
(src/management_models.cpp:4607–4609). A 400's `ValidationError` carries only the server `message`
(management_transport.cpp:224–236).
**C.** (1) test_directory.cpp:91. It renders the `Sensitive` members and the `set` error, and checks the secret is on the wire. It
does not stringify the whole Set/Update structs, which have no stringification in C++. (2) :112. (3) :130: exactly `{"enabled":false}`, exactly the
url and bind_secret keys, and `{"group_filter":null,…}`. The clear-null case also sets `group_base_dn`, so it is not the bare
`{"group_filter":null}` the contract names, though it is exact-key. (4) :169 discharges it only partly: `SetDirectoryConfig{}`
serializes the required members empty and does not refuse (F-4); 201 and 200 both decode. (5) :205: four writes, 4 requests.
(6) :220 and :236.
**D.** Rule 2 is on `set` (management.hpp:1811–1817) and `update` (:1826–1832). Rule 5 is on `delete_` (:1845–1849). Rule 6
("Signs the account's owner out everywhere") is on `link_account` (:1857–1862). Rule 3's 409 is on set and update.
**E.** As for §29 (management_transport.cpp:162–163).
**F.** README.md:15 names §30. Matches the code.

### §31
**A.** `ScimTargetsApi` (management.hpp): `list` :2137, `create` :2147, `get` :2154, `update` :2170, `delete_` :2186,
`reconcile` :2197. Also `client.scim_targets()` (client.hpp:1473). There is no `{tenant_id}`, so the tenant is the token's.
**B.** `ScimTargetInput::credential` is `std::optional<Sensitive<std::string>>` (management_models.hpp:3957).
`ScimTargetResponse` has no credential member (:3976–4004). The union decoders strip `credential`, `bind_secret`,
`authorization_header` and `private_key_pem` from `raw` (management_models.cpp:4272–4274, :4330–4332).
**C.** (1) test_scim_targets.cpp:79. (2) :96, at the top level and inside `auth`. (3) :113: no `credential` key without one,
the key present with one, and both auth and both scope variants serialize exactly. Building without the required members:
`ScimTargetInput{}` *is* refused, but only because of the empty union tag (`NetworkError`, :136); an empty `name` or
`base_url` is not (F-4). (4) :158. (5) :199: four writes, 4 requests. (6) :215: reconcile sends no body and decodes the 202.
**D.** Rule 2 is on `update` (management.hpp:2159–2166). On `create` there is only "`credential` is required here (§31.3 rule 2)"
(:2143–2144), with no URL-binding text (F-6). Rule 8 ("Deprovisions nothing downstream") is on `delete_` (:2179–2183). Rule 4's
409 is on `update` (:2165). Rule 7 is on `reconcile` (:2192–2194).
**E.** As for §29.
**F.** README.md:15 names §31. Matches the code.

### §32 (management)
**A.** `SsfApi` (management.hpp): `list_streams` :2056, `create_stream` :2063, `get_stream` :2070, `update_stream` :2086,
`delete_stream` :2099. Also `client.ssf()` (client.hpp:1468).
**B.** `SsfStreamInput::authorization_header` is `std::optional<Sensitive<std::string>>` (management_models.hpp:4445).
`SsfStream` has only `authorization_header_set` (:4390), with a static_assert at tests/test_ssf_management.cpp:67.
**C.** (1) test_ssf_management.cpp:83 discharges it only partly (F-4, same decline). (2) :109. (3) :128, which includes an unknown event URI
(→ `SsfEventType::Unknown`) and inactive with and without a reason. (4) :154. (5) :174: 3 writes, 3 requests. (6) :189.
**D.** On `update_stream` (management.hpp:2076–2083): the replacement warning, the header exception, rule 5's endpoint move,
and the 409.
**E.** As for §29.
**F.** README.md:15 names §32. Matches the code.

### §32.7 (receiver helper, MAY for C++)
**A.** `ssf::SsfReceiver::verify_set` include/axiam/ssf.hpp:248 → src/ssf.cpp:196–282. `ssf::SsfReceiver::poll`
ssf.hpp:265 → ssf.cpp:307–383. Config `{issuer, audience, keys (jwks_uri | discovery_url), access_token_provider,
replay_window, replay_store}` at ssf.hpp:156–166. Event-type constants at ssf.hpp:43–60 (all eight URIs).
**B.** The bearer from `access_token_provider` is `Sensitive` (ssf.hpp:153) and revealed only into the header
(ssf.cpp:336). Refusal messages carry fixed text only (ssf.cpp:172–176).
**C.** (1) tests/test_ssf_receiver.cpp:128. (2) :168. (3) :212. (4) :234. (5) :254. (6) :282 (replay, and the <7 d window refused),
plus :299 and :310. (7) :338 (one refetch, then none within the minute). (8) :469 (ack and setErrs exact, verified and refused
apart, nothing acked on its own) plus :528 (not retried on 400 or 404, retried on 503 and on transport). The poll-abort test at
:568 asserts only that the poll throws. It does not check what was recorded before the throw (F-1).
**D.** Steps 1–9 and "A SET that verifies has been recorded" are on the method docs (ssf.hpp:227–247). Not retried on a 4xx
and acknowledging nothing: README.md:2328–2338.
**E.** `poll`: `budget = retry_enabled ? 3 : 1`, and it stops when `!retry_should_retry(status)` (ssf.cpp:341–351), where
`retry_should_retry` is true only for transport, 408, 429 and 5xx (src/retry.hpp:70–81). A 4xx is never retried.
**F.** README.md:15 says "with §32.7". Correct.

### §33 (MAY for C++)
**A.** `ciba_initiate` client.hpp:991 → oidc.cpp:2355. `ciba_poll` :1005 → oidc.cpp:2420. `ciba_await` :1021 →
oidc.cpp:2433. `ciba_handle_ping` :1041 → oidc.cpp:2484. Types `CibaUserHint`, `CibaDelivery`, `CibaSigningAlg`,
`CibaRequestSigner`, `CibaInitiateParams`, `CibaInitiateResponse`, `CibaClock` and `CibaAwaitOptions` are at oidc.hpp:629–778.
No `login_hint_token`, `user_code` or `request_uri` member exists (oidc.hpp:721–745).
**B.** `CibaInitiateResponse::auth_req_id` is `Sensitive` (oidc.hpp:751). `ciba_poll` and `ciba_await` take it as `Sensitive`
(client.hpp:1005, via `CibaInitiateResponse`). `ciba_handle_ping` returns `Sensitive` (oidc.cpp:2517). `client_notification_token`
is `Sensitive` in `CibaDelivery` (oidc.hpp:660–670) and as `expected_token`. The key is held only as an OpenSSL key behind a
`shared_ptr`, with no accessor (oidc.hpp:693–714), and the PEM goes in as `Sensitive`. The signed `request` is returned as
`Sensitive` (oidc.cpp:2272) and revealed only into the form. The ping refusal names no value (oidc.cpp:2487–2491).
**C.** t01 tests/test_ciba.cpp:280; t02 :314; t03 :384 and :415; t04 :441 (503, 429 with body, 429 bodiless, reset: 1 request
each); t05 :483 (sleeps 5, 10, 15, 15) and :499 (access_denied, expired_token, invalid_grant and unknown are terminal and distinct);
t06 :541 (interval 7, and 0→5); t07 :556; t08 :586 discharges it only partly, because every 5xx in it is **bodiless**, so the
server's actual 5xx shape is never exercised (F-2); t09 :609; t10 :641; t11 :658 (constant-time asserted structurally at
:686–694); t12 :702; t13 :717; t14 :737 (all three algorithms, 3 form members, two jtis differ); t15 :784 (a wrong-algorithm or
empty key is refused at `from_pem`; "no algorithm or no key" and "a form parameter beside it" cannot be written in C++);
t16 :817.
**D.** "Proves nothing about the user" is in the section comment at client.hpp:957–962 (a `//` block, not the method's `///`).
"Never retried" is on `ciba_initiate` (client.hpp:980–982). "Store the tokens before anything else" is on `ciba_poll` (:1001–1003).
The ping's "answer 204 first" is at client.hpp:964–967.
**E.** `ciba_initiate` makes one `send_raw` (oidc.cpp:2401). `send_raw` is a single transport call that throws on a transport
error (src/client_impl.hpp:298–306). No loop exists.
**F.** README.md:15 "…§32 and §33 at contract 1.58, with §32.7 and §33.2 signed". Correct.

#### Q1 … Q10

### Q1 Replay store
- Interface: `class ReplayStore { virtual bool check_and_record(const std::string& jti, std::chrono::seconds window) = 0; }`
  (ssf.hpp:114–121). It is synchronous and an **atomic check-and-insert**: it returns true after recording, or false without
  recording (the doc demands atomicity, ssf.hpp:117–119).
- Default: `MemoryReplayStore` (ssf.hpp:125–132; ssf.cpp:57–64), a `std::map<jti, steady_clock deadline>` under a mutex.
  Expiry is per entry (`now + window`), purged by a **full O(n) scan on every insert**. It is **unbounded** (no cap or LRU) and
  bounded only by the window. Only verified SETs reach it, so flooding it requires transmitter signatures.
- Store error: an exception from `check_and_record` is not caught, so it propagates out of `verify_set`. That **fails
  closed** (not accepted). In `poll` it aborts the whole call (see F-1).
- The jti is recorded only after steps 1–8 pass (ssf.cpp:265–268, after :245–263). Tested at test_ssf_receiver.cpp:299.
- Seven-day floor: the **constructor refuses** with `std::invalid_argument` (C++'s local ValidationError mapping) when
  `replay_window < kMinReplayWindow` (ssf.cpp:286–290; ssf.hpp:65). It never clamps.

### Q2 `verify_set` order and codes
The steps run 1→9 in order with exactly §32.7's codes (ssf.cpp:198–268). Details:
- Step 1 also requires the signature segment to decode as base64url (ssf.cpp:208–211).
- `typ` is case-insensitive and accepts `secevent+jwt` or `application/secevent+jwt` (:187–192). An absent `typ` → `invalid_type`.
- `alg` must be exactly `"EdDSA"` (:218).
- An empty or missing `kid` → `invalid_key` before any lookup (:221–222), which merges into step 4.
- A kid miss refetches once, at most once per 60 s **per receiver** (not per kid). The timestamp is set before the fetch, so a
  failed refetch also uses up the minute (:153–165). The *initial* load (`!have_keys`) is not rate-limited: while the JWKS is
  down, every `verify_set` triggers a fetch (:155).
- `aud` may be a string, or an array containing the configured audience (:236–243). `iss` must match exactly (:233).
- Step 8 is stricter than the text in two ways: `iat` must be an integer (`is_number_integer`), and `sub_id` must be an object
  (:253–258).
- One check is added after step 8, in `poll` only: the `sets` map key must equal the SET's `jti`, else `invalid_request`
  (:261–263). It is not in the contract.

### Q3 `poll`
It never acknowledges by itself. The body is built only from `options`, and an unset member is omitted (ssf.cpp:316–328).
`ack` and `set_errs` pass through. `set_errs` is a `std::map`, so the entries are re-ordered by jti; the key set is exact. `refused`
is `{jti, SetFailureReason}`, an enum with `reason_code()` / `push_error_code()` (ssf.hpp:185–188, 79–85), not a string. A
non-string SET value is refused as `malformed` (ssf.cpp:371–374). There is no retry on a 4xx; §16 covers transport, 408, 429 and
5xx, with `Retry-After` honoured (ssf.cpp:341–358). The token comes from `access_token_provider`, called once per `poll()` and
reused across the §16 attempts (:330). A missing provider → local `AuthError` (:310–314). The request is `sessionless` (:339).
The URL is `base_url + "/ssf/v1/poll/" + encode(stream_id)` (:333), i.e. the client's base URL, not discovery.

### Q4 `ciba_await`
- Clock: injectable through `CibaAwaitOptions::clock` (`CibaClock{now, sleep}`, oidc.hpp:764–778). The §16 sleeps inside one poll
  use the client's own `sleeper`, not the injected clock (oidc.cpp:2337–2341).
- Initial interval: the response's `interval`, or 5 when it is absent **or ≤0** (oidc.cpp:2414–2415, 2447–2448). There is no
  faster floor.
- `slow_down`: `interval += 5`, cumulative, never reset and **no cap** (oidc.cpp:2471–2473). Never reducing is allowed.
- Deadline: `received_at + expires_in`, where `received_at` is stamped *after* the response arrives (oidc.cpp:2403, 2445). It is
  checked before each sleep as `now + interval >= deadline`, and it raises `OAuthProtocolError("expired_token")` locally
  (:2451–2456).
- Transient errors: transport, bodiless 5xx, 408 and bodiless 429 are §16-retried inside one poll (oidc.cpp:2320–2342).
  Once §16 is exhausted, the loop `continue`s after one interval (:2464). A 429 with `{"error":"rate_limit_exceeded"}`
  counts as one interval (:2469). **A 5xx that carries an `error` body is treated as a protocol answer: it is not retried and it
  is terminal** (F-2).
- Cancellation: none explicit. The only way out is a throwing `CibaClock::sleep`, which is undocumented.
- `auth_req_id`: read from the caller's `CibaInitiateResponse` on each poll. The SDK makes no copy beyond the form string
  (oidc.cpp:2460).

### Q5 `ciba_handle_ping`
- It is synchronous, `const`, and does no I/O (client.hpp:1041–1043; t13 test_ciba.cpp:717).
- Header check: exactly one `Authorization` header, with the name matched case-insensitively. A duplicate → refused
  (oidc.cpp:2493–2497).
- Scheme: case-insensitive `bearer` and one space. The comparison is `CRYPTO_memcmp`, after a length-equality pre-check
  (oidc.cpp:2348–2351, 2498–2504). An empty `expected_token` never matches.
- A missing, non-Bearer, wrong, empty, duplicated or double-space value → `AuthError` with a fixed message (oidc.cpp:2487–2491).
- Body: a JSON object with a non-empty string `auth_req_id`. Anything else → `std::invalid_argument`; extra members are ignored
  (oidc.cpp:2507–2517).
- It returns `Sensitive<std::string>`.

### Q6 Signed request
It is offered through `CibaInitiateParams::signer` (oidc.hpp:741) and `CibaRequestSigner::from_pem(alg, Sensitive pem, kid?)`
(oidc.cpp:2185–2199).
- Algorithms: PS256 (RSA ≥2048), ES256 (P-256 only) and EdDSA (Ed25519). The key is probe-signed and a mismatch →
  `std::invalid_argument`.
- Header: `{alg[, kid]}`.
- Claims (oidc.cpp:2253–2275): every §33.2 member (`requested_expiry` as a JSON number), plus `iss`=client_id, `aud`=discovery
  `issuer` (a string, never the alias), `iat`=`nbf`=now, `exp`=now+300 s, and `jti`=16 random bytes in hex.
- Form: `client_id`, `client_secret` if configured, and `request` only (oidc.cpp:2380–2385).
- Key material: an OpenSSL key object with no accessor and no stringification. The PEM goes in as `Sensitive`, and the `request`
  is `Sensitive` until it is put in the form.

### Q7 Kept-secret-on-update
`std::optional<Sensitive<std::string>>` throughout. Disengaged means the member is **omitted**, so the server keeps it;
engaged means replace. There is no way to send `null`/`""` for these members. The `to_input()` read-modify-write helpers leave
it disengaged.
- `directory.update`: `if (value.bind_secret) { j["bind_secret"] = detail::reveal(*value.bind_secret); }`
  (management_models.cpp:5343–5345). `set` does the same (:4607–4609).
- `ssf.update_stream`: `if (value.authorization_header) { j["authorization_header"] = …; }` (management_models.cpp:5017–5019).
  `clear_authorization_header` is a separate `std::optional<bool>` (management_models.hpp:4448), so "keep", "replace" and
  "clear" are all distinct.
- `scim_targets.update`: `if (value.credential) { j["credential"] = …; }` (management_models.cpp:4339–4341).
  Tested at test_scim_targets.cpp:113.

### Q8 §21.3.1 pin
The test reads vector A out of the vendored CONTRACT.md (tests/test_mtls_endpoint_aliases.cpp:461–472) and asserts all seven
members by name, including
`AXIAM_CHECK(a.backchannel_authentication_endpoint == mtls + "bc-authorize" + q);` (:500) and the top-level member (:501–502).
The decoder is a fixed seven-field struct, not a count assertion (src/oidc.cpp:613–626), so an eighth member is ignored, not
fatal. `ciba_initiate` prefers the alias: `preferred_endpoint(*p_, config, alias_of::backchannel_authentication, …)`
(oidc.cpp:2368–2370). It is used only when the client presents a certificate (oidc.cpp:156–169) and is asserted at
test_mtls_endpoint_aliases.cpp:505–518 and test_ciba.cpp:344.

### Q9 §28.12 details
- The URI is used verbatim: `req.url = uri` (oidc.cpp:2017). The check compares the (scheme, host, port) origin only, refuses
  userinfo, and allows `http` only when the base is http on loopback (oidc.cpp:1989–2002; src/url_origin.hpp:33–75).
- The update body is built from `extra_json`, erases all five members, and sets `client_id` (oidc.cpp:2129–2148).
- Only `Authorization: Bearer` is sent (oidc.cpp:2019). The request is `sessionless`, goes straight to `impl.transport` (no
  `send_raw`, no `build_request`), and never follows a redirect (oidc.cpp:2005–2022; src/http_curl.cpp:422, 470, 505–506).
- A 401 → `raise_grant_error`, and nothing calls the §9 guard (oidc.cpp:2037–2039). Tested at test_client_registration.cpp:298.

### Q10 Other divergences and ambiguities
1. **The management GET retry differs from §16.3** (pre-existing §27 transport). It retries only transport errors and ≥500,
   not 408 or 429, and ignores `Retry-After` (management_transport.cpp:198–205). This affects every §29/§30/§31/§32 read. It is
   not a MUST violation for those reads (MAY), but it is inconsistent with this SDK's own `retry_should_retry`.
2. **Required members are not enforced.** C++ aggregates default-construct, so `SamlServiceProviderInput{}`,
   `SetDirectoryConfig{}` and `SsfStreamInput{}` serialize empty required strings. `SetDirectoryConfig s;` (default-init, as the
   repo's own test writes it) also leaves `bool enabled/start_tls` indeterminate if the caller forgets one
   (management_models.hpp:4182, 4199). The tests say so openly (test_saml.cpp:121–126, test_directory.cpp:181–188,
   test_ssf_management.cpp:99–104). (F-4)
3. **`SsfEventType` is a closed enum** (management_models.hpp:1003–1011). An unknown URI decodes as `Unknown`, and
   `to_wire(Unknown)` is `""` (management_models.cpp:971). A stream whose `events_allowed` holds a newer URI therefore cannot be
   read-modify-written without the caller editing it. Same for every open enum (README.md:2289). (F-5)
4. **`ClientRegistration::update_body()`** always emits `redirect_uris`, `grant_types` and `response_types`, so a read that lacked
   them sends `[]`. It also overwrites a mistyped value that `from_json` documented as "kept rather than dropped" in
   `extra_json`, and `take_list` silently drops non-string elements (oidc.cpp:2068–2071, 2087–2096, 2138–2140). This is relevant
   for CIBA-only clients, which need no redirect URI (§33.3 rule 11). (F-10)
5. **No `private_key_jwt`** anywhere in the SDK, so a `private_key_jwt` CIBA client (one of §33.3 rule 10's three `fapi2`
   methods) cannot use `ciba_*`. This is consistent with the SDK's §21 client-role posture, and README.md:2342–2344 names the two
   supported methods.
6. **The `ciba_await` deadline is anchored at receipt, not at send** (`received_at`, oidc.cpp:2403). It is later than "initiate
   time" by one round trip. Contract clarification: say which instant.
7. **A contract tension decided here:** §33.4 and §16.3 ("a body with `error` is `OAuthProtocolError` at any status … never
   retried") against §33.7 rule 5 ("a 5xx … on ciba_poll is not terminal"). The SDK followed the former (F-2).
8. **A contract ambiguity decided here:** §32.7 records the jti at verification, while RFC 8936 re-offers every unacked SET.
   A receiver with a persistent store that crashes between `poll()` and processing sees the re-offer as `replayed`. §32.7 then
   tells it to `setErrs` the SET, which deletes it at the transmitter. The contract should say whether a re-offered, never-acked
   jti is a replay, or whether recording should happen at ack.
9. **The `Sensitive` accessor:** README.md:1809 tells callers to use `axiam::detail::reveal()`, but include/axiam/sensitive.hpp:15–19
   calls it "Not part of the public API surface … internal-only", and §7's C++ row names `expose()`. For §28.12 this is the only
   way to persist the rotated token, and the README example (README.md:2190) only re-wraps it in memory. (F-8)
10. The initial JWKS load is not rate-limited during an outage (Q2). The default replay store is unbounded and does an O(n) purge
    per insert (Q1).

#### Findings
| id | Severity | Clause | What | Evidence (path:line) | Suggested disposition |
|---|---|---|---|---|---|
| F-1 | defect | §32.7 step 9 / §32.7 poll | `poll` verifies SETs one by one, and each verify records its jti. A later SET in the same batch that throws a non-verdict error (JWKS refetch failure → `NetworkError`, or a store exception) aborts `poll`. The jtis already recorded are never returned and never acked, so the transmitter re-offers them and they read `replayed`. Following §32.7 the caller then `setErrs` them, and the events are lost. Probe: SET "a" verified, SET "b" (unknown kid, JWKS 503) aborted, re-offered "a" → `replayed`. | src/ssf.cpp:369–380, 265–268; tests/test_ssf_receiver.cpp:568 (asserts only the throw) | SDK fix: catch non-verdict errors per SET (report them separately, or roll back), or record only once the whole batch is returned. Add a test. |
| F-2 | defect | §33.7 rule 5 (vs §33.4/§16.3) | `ciba_poll_once` treats any non-2xx with a non-empty `error` as a protocol answer: `transient = !protocol_answer && …`. The server's real 5xx at the token endpoint is `500 {"error":"server_error"}` (axiam-oauth2/src/error.rs:226), so `ciba_poll` does not §16-retry it and `ciba_await` rethrows it as terminal. Probe: 500 `server_error` → await ends after 1 request. t08 uses only bodiless 5xx. | src/oidc.cpp:2318–2334, 2474–2477; tests/test_ciba.cpp:586–597 | SDK fix: classify ≥500 (and 429) as transient whatever the body. Contract clarification: §33.4 and §16.3 vs §33.7 rule 5 for 5xx with an OAuth error body, and add a bodied 5xx to §33.8 t08. |
| F-3 | clarification | §32.7 / RFC 8936 | Recording at verification makes a never-acked SET re-offered after a crash read `replayed` when the store is persistent. §32.7's "SHOULD pass each refused one in set_errs" then deletes it at the transmitter. | src/ssf.cpp:265; include/axiam/ssf.hpp:243–244 | Contract clarification (record at ack, or exempt an unacked re-offer). |
| F-4 | defect (minor) | §29.8(1), §30.8(4), §31.8(3), §32.8(1) | The input types can be built without their required members, and nothing refuses locally. C++ has constructors, so "no compile-time check" is the SDK's choice, not the language's. `SetDirectoryConfig s;` leaves `bool enabled/start_tls` indeterminate. The tests document the decline instead of the contract's "builder refuses". | include/axiam/management_models.hpp:3830–3866, 4168–4201, 4439–4469; tests/test_saml.cpp:121–126; tests/test_directory.cpp:181–188 | SDK fix (constructors taking the required members, or a local check before send), or a contract clarification for C/C++. |
| F-5 | doc / SHOULD deviation | §32.2 | Event types are a closed `enum class SsfEventType`, not strings plus named constants. An unknown URI becomes `Unknown`, and an update writes it as `""`, so a stream carrying a newer URI cannot round-trip. | include/axiam/management_models.hpp:1003–1018; src/management_models.cpp:961–976 | SDK fix (string type plus the constants already in `axiam::ssf::event_types`), or record the deviation in the README. |
| F-6 | doc | §31.3 rule 2 ("both call sites") | The `create` doc says only "`credential` is required here (§31.3 rule 2)" and does not state the credential/URL binding. | include/axiam/management.hpp:2143–2144 | SDK fix (doc). |
| F-7 | doc | §29.3 rule 2 ("where it documents the field") | The ECDSA HTTP-POST-only / RSA-only-Redirect note is on the create and update method docs but not on `SamlServiceProviderInput::sp_signing_cert_pem` (or `SamlServiceProvider`'s). | include/axiam/management_models.hpp:3866–3867; include/axiam/management.hpp:1918–1920 | SDK fix (doc; the generator's field docs). |
| F-8 | doc | §28.12.2 rule 5, §7 rule 3 | The rotated `registration_access_token` must be persisted, but the only accessor is `axiam::detail::reveal`, which the header calls internal-only, while the README tells callers to use it and §7 names `expose()`. The §28.12 README example only re-wraps the token. | include/axiam/sensitive.hpp:15–19; README.md:1809, 2187–2190 | SDK fix: make one accessor public and named (`expose()` per §7), and show persisting in the §28.12 example. |
| F-9 | clarification | §30.6, §31.6 C++ column | `delete` is a C++ keyword, and the SDK uses `delete_` (as in all its §27 namespaces). The contract tables say `directory().delete` and `scim_targets().delete`. | include/axiam/management.hpp:1850, 2186 | Forced by language. Contract clarification: write `delete_` in the C++ column. |
| F-10 | defect (minor) | §28.12.2 rule 4 / §28.12.1 | `update_body()` always sends `redirect_uris`, `grant_types` and `response_types` (as `[]` when the read had none, overwriting a mistyped kept value). `take_list` drops non-string elements, contrary to the "kept rather than dropped" comment. | src/oidc.cpp:2068–2071, 2087–2096, 2138–2140 | SDK fix (emit a list only when the read had one, and keep mistyped values verbatim). |
| F-11 | clarification | §16.3 vs §27.4 rule 8 (pre-existing) | Management GETs (all §29–§32 reads) retry only transport and ≥500 errors, not 408 or 429, and ignore `Retry-After`. | src/management_transport.cpp:198–205 | SDK fix (use `retry_should_retry` and `Retry-After`). Not a 1.53–1.58 regression. |
| F-12 | clarification | §33.7 rule 4 | The deadline is `received_at + expires_in`, with `received_at` stamped after the response arrives, so it is later than "initiate time" by one round trip. | src/oidc.cpp:2403, 2445 | Contract clarification (which instant). |
| F-13 | clarification | §32.7 step 4 | The unknown-kid refetch is rate-limited (once/min per receiver), but the initial JWKS load is not: during a JWKS outage every `verify_set` fetches. | src/ssf.cpp:153–165 | Contract clarification: does the once-a-minute limit cover a failed first fetch? Optional SDK hardening. |
| F-14 | clarification | §32.7 step 8 | Stricter than the text: `iat` must be an integer and `sub_id` an object. In `poll` it adds "map key == jti" as `invalid_request`. | src/ssf.cpp:253–263 | Contract clarification (types of `iat`/`sub_id`; whether the poll-key/jti mismatch check is expected). |
