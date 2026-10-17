# lib-env.sh — load the harness's configuration (W9). Sourced, not run.
#
# Two files, and the split is the point.
#
#   conformance/suite.env        COMMITTED. The shape: pins, ports, paths, and
#                                every knob with a safe default. Reviewable, and
#                                the thing a reader diffs to see what a run was.
#   conformance/suite.local.env  GITIGNORED. The values a run produces or an
#                                operator supplies: client ids, client secrets,
#                                the test user's password, an admin password.
#                                Sourced second, so it overrides.
#
# Why it was split. `register-clients.sh` rewrites its results back into the
# config file, and until W9 that file was `suite.env` — which is tracked. The
# FAPI lane only wrote client ids, so this stayed survivable; the Basic OP lane
# writes client SECRETS and a user password, and the first `git add -A` after a
# registration would have committed them. .gitignore already promised the
# opposite in as many words ("the plan TEMPLATES and the rendered REPORTS,
# never the credentials in between") — the promise was right and the layout
# did not implement it.
#
# Exports: conf_load (source both files), conf_write_local (upsert keys into
# the local file), conf_require_uint (refuse a non-numeric value before it
# reaches bash arithmetic).

# shellcheck shell=bash

# Callers set HERE to conformance/ before sourcing.
# Precedence, highest first: the environment, then suite.local.env, then
# suite.env.
#
# The environment has to win, and getting this wrong is not a subtle failure.
# suite.env assigns unconditionally — `AXIAM_ADMIN_PASSWORD=` with nothing after
# it is a real assignment to the empty string — so sourcing it CLEARS an
# operator's exported credential. The symptom is a registrar that exits 1 having
# printed nothing, because the empty password makes the login prompt read from a
# stdin that is not a terminal. It looks like a broken script and is a
# precedence bug.
#
# Implemented by snapshotting the environment and restoring anything that was
# already set, rather than by rewriting every line of suite.env into
# `${VAR:-default}` form: the files stay plain assignments that a reader can
# scan, and the rule lives in one place instead of on every line.
conf_load() {
  local base="${HERE:?lib-env.sh: set HERE to the conformance/ directory}"
  local snapshot; snapshot="$(mktemp)"
  export -p > "$snapshot"

  # shellcheck disable=SC1091
  set -a
  . "$base/suite.env"
  [ -f "$base/suite.local.env" ] && . "$base/suite.local.env"
  set +a

  # `export -p` emits `declare -x NAME=...`, and `declare` inside a FUNCTION is
  # local by default — sourcing the snapshot as-is would restore every variable
  # into conf_load's own scope and lose all of it on return, which looks exactly
  # like the restore not happening. `-g` makes the assignments global, which is
  # the scope they came from.
  sed -i 's/^declare -x /declare -gx /' "$snapshot"
  # shellcheck disable=SC1090
  . "$snapshot" 2>/dev/null || true
  rm -f "$snapshot"
}

# conf_write_local KEY=VALUE [KEY=VALUE ...]
#
# Upserts into suite.local.env, creating it 600 on first use. Upsert rather than
# append: a re-registration must replace the previous run's client id, not leave
# two lines whose winner depends on source order.
conf_write_local() {
  local base="${HERE:?lib-env.sh: set HERE to the conformance/ directory}"
  local target="$base/suite.local.env"
  if [ ! -f "$target" ]; then
    cat > "$target" <<'EOF'
# conformance/suite.local.env — written by the harness. GITIGNORED.
#
# Client ids, client secrets and passwords for THIS machine's conformance run.
# Sourced after suite.env, so anything here overrides the committed defaults.
# Safe to delete: re-running the registrars recreates it.
EOF
    chmod 600 "$target"
  fi
  python3 - "$target" "$@" <<'PY'
import re, sys
path, rest = sys.argv[1], sys.argv[2:]
src = open(path).read()
for pair in rest:
    k, _, v = pair.partition("=")
    # SINGLE-QUOTE the value, always.
    #
    # This file is `source`d, so an unquoted value goes through the shell's
    # quote removal and word splitting. Most values here survive that —
    # a client id is `[A-Za-z0-9_]` — but a JWKS does not:
    #
    #     written:  CLIENT_..._JWKS={"keys":[{"kty":"EC", ...}]}
    #     sourced:  {keys:[{kty:EC, ...}]}
    #
    # Every double quote gone, and what reaches the plan template is a string
    # that is no longer JSON. The private_key_jwt plan then fails to render with
    # "Expecting property name enclosed in double quotes", which reads as a
    # broken template and is a quoting bug two files away.
    #
    # Single quotes because the values are JSON and secrets: JSON strings never
    # contain a raw single quote, and the `'"'"'` dance below handles one
    # anyway rather than trusting that.
    quoted = "'" + v.replace("'", "'\"'\"'") + "'"
    line = f"{k}={quoted}"
    if re.search(rf"^{re.escape(k)}=.*$", src, flags=re.M):
        src = re.sub(rf"^{re.escape(k)}=.*$", line, src, flags=re.M)
    else:
        src = src.rstrip("\n") + "\n" + line + "\n"
open(path, "w").write(src)
PY
  chmod 600 "$target"
}

# conf_require_uint NAME VALUE
#
# Returns 0 when VALUE is one to five decimal digits; otherwise prints a refusal
# naming NAME to stderr and returns 2. The caller exits on that status.
#
# Why this exists (R101W4-02). A value that reaches `$(( ... ))` is parsed as an
# arithmetic EXPRESSION, and an array subscript inside one is expanded first:
# `a[$(cmd)]` runs `cmd`. The workflow's `module_timeout` dispatch input arrived
# here by way of CONFORMANCE_MODULE_TIMEOUT, so anyone who may dispatch the
# workflow could execute commands on the runner. Pinning the value to digits
# before any arithmetic closes the class.
#
# The check is a REGEX, never arithmetic: `[[ "$x" -eq 0 ]]` evaluates `$x` as an
# expression too, so "validating" with it would run the very command it is meant
# to refuse. `[[ =~ ]]` does no expansion of the value. The pattern sits in a
# variable so bash treats it as a regex, and a POSIX ERE `$` matches only at the
# end of the whole string, so `5<newline>anything` does not match.
#
# The value is quoted with `%q` in the message: control characters are escaped
# and it stays on one line, so the refusal cannot forge a workflow command
# (`::error::` at the start of a line) or hide text in the log. The value is
# only ever PRINTED; nothing here evaluates it.
conf_require_uint() {
  local name="$1" value="$2"
  local re='^[0-9]{1,5}$'
  if ! [[ "$value" =~ $re ]]; then
    printf '%s must be a whole number of seconds, 1 to 5 digits. Got: %q\n' \
      "$name" "$value" >&2
    return 2
  fi
}
