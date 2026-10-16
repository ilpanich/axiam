#!/bin/sh
# fetch-crl.sh: keep FreeRADIUS's copy of AXIAM's revocation list fresh.
#
#   fetch-crl.sh <crl-url> <ca.pem> <capath>
#
#   <crl-url>  AXIAM's list for the tenant signing CA:
#              https://axiam.example.com/pki/v1/<org>/ca/<ca>/crl
#   <ca.pem>   the tenant signing CA's certificate: FreeRADIUS's `ca_file`
#   <capath>   FreeRADIUS's `ca_path`; the list lands there as `<hash>.r0`,
#              the name OpenSSL looks an issuer's list up by
#
# Run it from cron or a systemd timer, every five minutes. The guide is
# docs/pki/freeradius.md, section 4; the end-to-end test
# crates/axiam-server/tests/radius_e2e.rs runs THIS file, so a claim below is a
# case of that test.
#
# It installs a list only when
#   1. the server answered 200 and the body is a CRL (a 304 means "unchanged",
#      and nothing is touched, but only when its ETag is the one this run sent);
#   2. `ca.pem` signed it. `openssl crl -verify` exits 0 on "verify failure"
#      when the list names the CA but another key signed it (probed on OpenSSL
#      3.0.13), so the exit status is not the check: the text "verify OK" is;
#   3. its CRL number is not lower than the one already installed, so a
#      replayed, older, validly signed list cannot undo a revocation (equal is
#      accepted: the same list again is not a replay);
# and it installs it atomically: written beside its destination, then `mv`.
#
# It remembers the ETag of the list it installed, with the file's name and its
# SHA-256 (in `<capath>/.fetch-crl.<key>`, a name OpenSSL never looks up), and
# sends the tag as `If-None-Match`. The tag is stored only after the list it
# belongs to is in place, so a run cut short at worst fetches the list once more.
# A tag is stored only when it is ONE entity-tag, `"..."` or `W/"..."` with no
# inner quote: never `*` and never a list, which AXIAM's route (RFC 9110) would
# match against every list, so that a stored `*` would make every later run read
# "304 unchanged" for ever (R110W5-01). The whole list is fetched, with no
# `If-None-Match`, when
#   - no valid tag is stored, or the installed file's SHA-256 is no longer the
#     one stored beside the tag (the file was replaced, or the tag was paired
#     with a list it does not name); or
#   - the server answers 304 with an ETag other than the one sent, or none.
#
# One run at a time per URL: the whole run, from reading the state to writing it,
# holds a lock on `<capath>/.fetch-crl.<key>.lock` (`flock` where it exists; else
# a directory of that name plus `.d`, which a run breaks when its owner is gone
# or it is older than 120 s, longer than any run lasts). A run that finds the lock
# held says so, exits 0 and touches nothing: the run that holds it is doing the
# same job, and two that overlapped could install the older of two lists and pair
# it with the newer one's ETag (R110W5-02). The lock file stays in `capath`.
#
# curl is called as `curl -q ... --url <url>` (R110W5-03). `-q`, which must be
# its first argument, stops it reading the `~/.curlrc` of whoever runs this (a
# `location` or `insecure` line there would undo what follows). The URL is given
# as the value of `--url`, so it can never be read as an option, and it must start
# with `https://`. A URL starting `http://` is refused unless FETCH_CRL_ALLOW_HTTP=1
# is set in the environment: the list is signed, so plain HTTP costs no integrity,
# but it lets whoever answers the fetch withhold a newer list, and the guide says
# to use HTTPS; the end-to-end test's stand-in for the route is plain HTTP on a
# loopback port and sets it. Any other scheme (`file:`, `ftp:`, ...) is refused.
# `--proto` pins curl to the scheme given, no `-L` and `--max-redirs 0` mean a
# redirect is never followed (it is reported as the HTTP status it is), and
# `--globoff` turns URL globbing off. `--max-filesize` stops an unsized (chunked)
# body only from curl 8.4; before that `--max-time` alone bounds it.
#
# Exit 0: installed, unchanged, or another run holds the lock. Exit 1: the list
# was refused or could not be fetched; the installed list is untouched and the
# reason is on stderr. Alert on a non-zero exit, and on a list in `capath` older
# than half its lifetime (the guide says why).
#
# Needs: sh, curl, openssl, sed, sort, tr, cut, head, tail, mktemp, date; `flock`
# is used when it is there.

set -eu
LC_ALL=C
export LC_ALL
umask 022

fail() {
	echo "fetch-crl: $*" >&2
	exit 1
}

[ "$#" -eq 3 ] || {
	echo "usage: fetch-crl.sh <crl-url> <ca.pem> <capath>" >&2
	exit 2
}
url=$1
ca_file=$2
capath=$3
# https:// always; http:// only when the operator said so. Checked here, before
# anything else, so that a URL that looks like an option never reaches curl.
case $url in
https://*) proto='=https' ;;
http://*)
	[ "${FETCH_CRL_ALLOW_HTTP:-}" = 1 ] ||
		fail "refusing to run: $url is plain HTTP; use https://, or set FETCH_CRL_ALLOW_HTTP=1 to accept it (the list is signed, but whoever answers can withhold a newer one)"
	proto='=http'
	;;
*) fail "refusing to run: the URL must start with https:// (or http:// with FETCH_CRL_ALLOW_HTTP=1)" ;;
esac
[ -r "$ca_file" ] || fail "refusing to run: cannot read the CA certificate $ca_file"
[ -d "$capath" ] && [ -w "$capath" ] || fail "refusing to run: $capath is not a writable directory"

# The URL's key names the state and the lock.
key=$(printf '%s' "$url" | openssl dgst -sha256 -r | cut -c1-16)
state="$capath/.fetch-crl.$key"
lock_file="$state.lock"
lock_dir="$state.lock.d" # the lock where there is no flock
lock_held=

work=$(mktemp -d)
stage=
cleanup() {
	rm -rf "$work"
	[ -z "$stage" ] || rm -f "$stage"
	# Take the directory lock down only if it is still ours: a run that outlived
	# 120 s may have had it broken, and the lock is then someone else's.
	if [ -n "$lock_held" ] && [ -f "$lock_dir/owner" ] && [ "$(head -n 1 "$lock_dir/owner")" = "$$" ]; then
		rm -rf "$lock_dir"
	fi
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM

# ---- one run at a time ---------------------------------------------------------
busy() {
	echo "fetch-crl: another run holds the lock on $capath; nothing touched"
	exit 0
}

# True when the directory lock's owner is gone, or it is older than 120 s, or it
# says nothing sensible. A lock whose owner file is not there yet is given a
# second: its owner writes it right after the mkdir.
lock_is_stale() {
	holder=
	since=
	for _ in 1 2; do
		if [ -f "$lock_dir/owner" ]; then
			{
				IFS= read -r holder
				IFS= read -r since
			} <"$lock_dir/owner" || true
		fi
		[ -z "$holder" ] || break
		sleep 1
	done
	case $holder in '' | *[!0-9]*) return 0 ;; esac
	case $since in '' | *[!0-9]*) return 0 ;; esac
	kill -0 "$holder" 2>/dev/null || return 0
	[ $(($(date +%s) - since)) -gt 120 ]
}

if command -v flock >/dev/null 2>&1; then
	{ : >>"$lock_file"; } 2>/dev/null || fail "refusing to run: cannot create the lock file $lock_file"
	exec 9>"$lock_file"
	flock -n 9 || busy
else
	tries=0
	until mkdir "$lock_dir" 2>/dev/null; do
		[ -d "$lock_dir" ] || fail "refusing to run: cannot create the lock directory $lock_dir"
		lock_is_stale || busy
		# Only one of several runs that find it stale can move it away.
		if mv "$lock_dir" "$lock_dir.stale.$$" 2>/dev/null; then
			rm -rf "$lock_dir.stale.$$"
			echo "fetch-crl: broke a stale lock on $capath" >&2
		fi
		tries=$((tries + 1))
		[ "$tries" -lt 5 ] || busy
	done
	lock_held=1
	printf '%s\n%s\n' "$$" "$(date +%s)" >"$lock_dir/owner"
fi

# A CRL number as upper-case hex without leading zeros, for comparison; fails
# when the list carries none.
crl_number() {
	raw=$(openssl crl -in "$1" -noout -crlnumber 2>/dev/null) || return 1
	case $raw in crlNumber=*) ;; *) return 1 ;; esac
	n=$(printf '%s\n' "$raw" | sed 's/^crlNumber=\(0[xX]\)\{0,1\}//' | tr 'a-f' 'A-F' | sed 's/^0*//')
	case $n in *[!0-9A-F]*) return 1 ;; esac
	printf '%s' "${n:-0}"
}

# True when the hex number $1 is lower than $2 (both normalised: no leading
# zeros, so the longer one is the larger, and equal lengths sort as numbers).
number_lower() {
	[ "${#1}" -eq "${#2}" ] || {
		[ "${#1}" -lt "${#2}" ]
		return
	}
	[ "$1" != "$2" ] || return 1
	[ "$(printf '%s\n%s\n' "$1" "$2" | sort | head -n 1)" = "$1" ]
}

# The SHA-256 of a file, as 64 lower-case hex digits.
file_sha() {
	openssl dgst -sha256 -r <"$1" | cut -d' ' -f1
}

# True when $1 is ONE entity-tag (RFC 9110 8.8.3): `"` etagc* `"`, optionally
# after `W/`, etagc being printable ASCII but the double quote and the space.
# So not `*`, not a comma list, and nothing with a control character.
valid_etag() {
	t=$1
	case $t in W/*) t=${t#W/} ;; esac
	case $t in
	\"*\") ;;
	*) return 1 ;;
	esac
	t=${t#\"}
	t=${t%\"}
	case $t in
	*\"* | *[![:graph:]]*) return 1 ;;
	esac
	return 0
}

# The ETag of the response in $work/headers (the last one, without CR), or none.
response_etag() {
	sed -n 's/^[Ee][Tt][Aa][Gg]:[[:space:]]*//p' "$work/headers" | tr -d '\r' |
		sed 's/[[:space:]]*$//' | tail -n 1
}

# One request for the list; $1 is the ETag to revalidate, or empty for an
# unconditional one. Sets `code` to the HTTP status. The body lands in
# $work/crl.der and the headers in $work/headers.
request() {
	rm -f "$work/crl.der" "$work/headers"
	tag=$1
	set -- -sS --proto "$proto" --max-redirs 0 --globoff --connect-timeout 10 --max-time 20 --max-filesize 16777216 -o "$work/crl.der" -D "$work/headers" -w '%{http_code}'
	if [ -n "$tag" ]; then
		set -- "$@" -H "If-None-Match: $tag"
	fi
	rc=0
	code=$(curl -q "$@" --url "$url") || rc=$?
	[ "$rc" -eq 0 ] || fail "the fetch of $url failed (curl exit $rc)"
}

# ---- the request ------------------------------------------------------------
# The state: the ETag of the installed list, the file it was installed as and
# the file's SHA-256. Anything missing, malformed or not matching the file on
# disk means "no tag": the request is then unconditional.
etag=
installed=
held_sha=
if [ -f "$state" ]; then
	{
		IFS= read -r etag
		IFS= read -r installed
		IFS= read -r held_sha
	} <"$state" || true
fi
valid_etag "$etag" || etag=
case $installed in
'' | *[!0-9a-f.r]*) etag= ;;
*)
	if [ -f "$capath/$installed" ]; then
		# The file in place must be the one the tag was stored for.
		case $held_sha in
		*[!0-9a-f]* | '') etag= ;;
		*)
			{ [ "${#held_sha}" -eq 64 ] && [ "$(file_sha "$capath/$installed")" = "$held_sha" ]; } || etag=
			;;
		esac
	else
		etag= # no list on disk: nothing to revalidate
	fi
	;;
esac

request "$etag"
if [ "$code" = 304 ] && [ -n "$etag" ] && [ "$(response_etag)" != "$etag" ]; then
	echo "fetch-crl: the 304 carries an ETag other than the one sent; fetching the list unconditionally" >&2
	etag=
	request ""
fi

case $code in
200) ;;
304)
	[ -n "$etag" ] || fail "refusing a 304 to a request that held no ETag"
	echo "fetch-crl: unchanged (304); $capath/$installed stays"
	exit 0
	;;
*) fail "$url answered HTTP $code; the installed list stays" ;;
esac

# ---- the list -----------------------------------------------------------------
openssl crl -inform DER -in "$work/crl.der" -outform PEM -out "$work/crl.pem" 2>/dev/null ||
	fail "refusing the list: the body is not a DER certificate revocation list"

# Never install a list the trusted CA did not sign.
rc=0
out=$(openssl crl -in "$work/crl.pem" -CAfile "$ca_file" -noout -verify 2>&1) || rc=$?
{ [ "$rc" -eq 0 ] && [ "$out" = "verify OK" ]; } ||
	fail "refusing the list: it was not signed by $ca_file (openssl: ${out:-exit $rc})"

hash=$(openssl crl -in "$work/crl.pem" -noout -hash)
case $hash in
*[!0-9a-f]* | '') fail "refusing the list: no issuer name hash" ;;
esac
target="$capath/$hash.r0"

# Never install an older list than the one in place (a replay).
new=$(crl_number "$work/crl.pem") || fail "refusing the list: it carries no CRL number"
if [ -f "$target" ]; then
	if old=$(crl_number "$target"); then
		if number_lower "$new" "$old"; then
			fail "refusing the list: its CRL number 0x$new is lower than the installed list's 0x$old"
		fi
	else
		echo "fetch-crl: $target has no readable CRL number; replacing it" >&2
	fi
fi

# ---- install: beside the destination, then rename -----------------------------
stage=$(mktemp "$capath/.incoming.XXXXXX")
cat "$work/crl.pem" >"$stage"
chmod 0644 "$stage"
mv -f "$stage" "$target"
stage=

# Remember the ETag only now that the list it names is in place, and only when
# it is one entity-tag; the file's SHA-256 goes with it.
new_etag=$(response_etag)
if [ -n "$new_etag" ] && valid_etag "$new_etag"; then
	stage=$(mktemp "$capath/.incoming.XXXXXX")
	printf '%s\n%s\n%s\n' "$new_etag" "$hash.r0" "$(file_sha "$target")" >"$stage"
	chmod 0644 "$stage"
	mv -f "$stage" "$state"
	stage=
else
	[ -z "$new_etag" ] || echo "fetch-crl: the ETag is not a single entity-tag; not stored" >&2
	rm -f "$state"
fi
echo "fetch-crl: installed $target (CRL number 0x$new)"
