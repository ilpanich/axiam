/*
 * AXIAM OPAQUE (RFC 9807) client — C ABI.
 *
 * Hand-written rather than generated, because it is a published interface that
 * eight SDKs bind and its comments are part of the contract. See
 * `sdks/CONTRACT.md` §23.1 for why no SDK implements OPAQUE itself, and the
 * crate's lib.rs for the ownership rules restated below.
 *
 * Everything crosses this boundary as NUL-terminated lowercase hex, which is
 * also the AXIAM wire encoding.
 *
 * Ownership, in three rules:
 *
 *   1. Every non-NULL char* this library returns must be released with
 *      axiam_opaque_string_free(). It was allocated by Rust.
 *   2. Every state handle must be released: either by passing it to its
 *      *_finish() function, which consumes it whether it succeeds or fails, or
 *      by calling the matching *_free(). A handle is single-use.
 *   3. A NULL return means failure. axiam_opaque_last_error() describes it for
 *      the calling thread; that pointer is owned by the library, is valid only
 *      until the next call on this thread, and must NOT be freed.
 *
 * Thread safety: every function may be called from any thread. A state handle
 * must be used by one thread at a time, which is its natural shape since it
 * belongs to one in-flight exchange. The last-error slot is thread-local.
 */

#ifndef AXIAM_OPAQUE_H
#define AXIAM_OPAQUE_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Opaque handles. Their layout is deliberately not exposed. */
typedef struct AxiamOpaqueKsf AxiamOpaqueKsf;
typedef struct AxiamOpaqueRegistration AxiamOpaqueRegistration;
typedef struct AxiamOpaqueLogin AxiamOpaqueLogin;

/* ---- memory and diagnostics ------------------------------------------- */

/* Release a string returned by this library. NULL is a no-op. */
void axiam_opaque_string_free(char *ptr);

/*
 * The most recent failure on this thread, or NULL if the last call succeeded.
 * Deliberately coarse: a caller that could distinguish "the server sent a
 * malformed KE2" from "your password is wrong" would be reporting a fact it
 * cannot establish.
 */
const char *axiam_opaque_last_error(void);

/*
 * Non-zero when this build can perform OPAQUE. Always 1 here; it exists so an
 * SDK's opaqueAvailable() (CONTRACT §23.2) has something to call after a
 * successful dlopen, and so a binding that failed to load can answer the same
 * question with 0 without a special case.
 */
int32_t axiam_opaque_available(void);

/* ---- key-stretching parameters ---------------------------------------- */

/*
 * Build KSF parameters, range-checked per CONTRACT §23.4 rule 4. Return NULL
 * if any value is out of range.
 *
 * The caller MUST pass the values the server named in its register/start or
 * login/start response, not its own defaults: a credential enrolled under one
 * cost keeps working after a tenant raises its policy, so a client that
 * guessed would fail against a record that is perfectly good.
 */
AxiamOpaqueKsf *axiam_opaque_ksf_argon2id(uint32_t memory_kib,
                                          uint32_t iterations,
                                          uint32_t parallelism);
AxiamOpaqueKsf *axiam_opaque_ksf_scrypt(uint8_t log_n, uint32_t r, uint32_t p);
void axiam_opaque_ksf_free(AxiamOpaqueKsf *ptr);

/* ---- registration ------------------------------------------------------ */

/*
 * Begin an enrolment. On success writes the hex RegistrationRequest to
 * *out_request (caller frees) and returns a state handle.
 */
AxiamOpaqueRegistration *axiam_opaque_registration_start(const char *password,
                                                         char **out_request);

/*
 * Complete an enrolment, CONSUMING `state` whether it succeeds or fails.
 * Returns the hex RegistrationRecord to embed in the request body's `opaque`
 * object. `out_export_key` may be NULL.
 */
char *axiam_opaque_registration_finish(AxiamOpaqueRegistration *state,
                                       const char *password,
                                       const char *registration_response,
                                       const AxiamOpaqueKsf *ksf,
                                       char **out_export_key);

/* Release registration state that was never finished. */
void axiam_opaque_registration_free(AxiamOpaqueRegistration *ptr);

/* ---- login ------------------------------------------------------------- */

/* Begin a login. Writes the hex KE1 to *out_ke1 (caller frees). */
AxiamOpaqueLogin *axiam_opaque_login_start(const char *password, char **out_ke1);

/*
 * Complete a login, CONSUMING `state`. Returns the hex KE3.
 *
 * A NULL return is the WHOLE of the client's authentication check, and it
 * covers both halves of the mutual authentication: the envelope only opens
 * under the right password, and KE2's MAC only verifies if the server actually
 * holds the record. Per CONTRACT §23.4 rule 7 the caller MUST NOT send anything
 * to login/finish after a NULL here.
 *
 * `out_session_key` and `out_export_key` may be NULL.
 */
char *axiam_opaque_login_finish(AxiamOpaqueLogin *state,
                                const char *password,
                                const char *ke2,
                                const AxiamOpaqueKsf *ksf,
                                char **out_session_key,
                                char **out_export_key);

/* Release login state that was never finished. */
void axiam_opaque_login_free(AxiamOpaqueLogin *ptr);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* AXIAM_OPAQUE_H */
