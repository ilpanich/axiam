#!/bin/sh
# The two halves of getting a certificate's fingerprint to the decision
# (docs/pki/freeradius.md, "The decision per authentication").
#
#   axiam-d4.sh stash <pem-file>   run by the `verify { client = ... }` hook of
#                                  the eap module, while FreeRADIUS holds the
#                                  client certificate in <pem-file>
#   axiam-d4.sh take <serial>      run by sites-enabled/check-eap-tls a moment
#                                  later in the same conversation; prints the
#                                  SHA-256 of the certificate's DER, 64 hex digits
#
# Why a file, and why the SERIAL is the key. FreeRADIUS 3.2.8 does not show the
# configuration the certificate or its fingerprint in any attribute; the PEM
# file the hook is given is deleted when the hook returns, and the name of that
# file is not visible to check-eap-tls. The serial is: it is an attribute of the
# verified certificate on both sides. AXIAM assigns it, from the certificate's
# public key, so two certificates that carry one serial carry one key.
#
# A stash is read only if it is younger than two EAP timers (timer_expire = 60);
# it is overwritten by the next certificate verified under the same serial and it
# lives on a tmpfs that is gone with the container.
set -eu
umask 077
DIR=/var/run/axiam-d4

hex_only() {
	case "$1" in '' | *[!0-9a-f]*) return 1 ;; esac
}

case "${1:-}" in
stash)
	pem=$2
	serial=$(openssl x509 -in "$pem" -noout -serial | sed 's/^serial=//' | tr 'A-F' 'a-f')
	fp=$(openssl x509 -in "$pem" -outform DER | sha256sum | cut -d' ' -f1)
	hex_only "$serial" || exit 1
	[ "${#fp}" -eq 64 ] && hex_only "$fp" || exit 1
	printf '%s\n' "$fp" >"$DIR/.$serial.$$"
	mv "$DIR/.$serial.$$" "$DIR/$serial"
	;;
take)
	serial=$2
	hex_only "$serial" || exit 1
	stash=$DIR/$serial
	[ -f "$stash" ] || exit 1
	[ $(($(date +%s) - $(stat -c %Y "$stash"))) -le 120 ] || exit 1
	cat "$stash"
	;;
*)
	exit 2
	;;
esac
