#!/bin/bash
# shellcheck disable=SC2016,SC2329,SC2120,SC2034  # the checks are eval-ed strings; run takes optional env
# fetch-crl-test.sh <shell>    e.g. `fetch-crl-test.sh dash`, `fetch-crl-test.sh bash`
#
# Runs docker/radius/fetch-crl.sh under <shell> against a stand-in for AXIAM's
# CRL route (crl-stub.py) and a throwaway CA, and checks what the script's header
# promises: the ETag handling (R110W5-01), the lock (R110W5-02), curl's options
# (R110W5-03), the exit status 3 of a list near its nextUpdate (R110W5-07). No FreeRADIUS, no docker, no AXIAM: needs sh, bash, curl, openssl,
# python3 (and flock for the flock half of the lock cases). The stand-in is plain
# HTTP on a loopback port, so the runs set FETCH_CRL_ALLOW_HTTP=1 except where a
# case is about that.
# Exit status: the number of failed checks.
SH=${1:-sh}
HERE=$(cd "$(dirname "$0")" && pwd)
SCRIPT=$HERE/../fetch-crl.sh
T=$(mktemp -d "${TMPDIR:-/tmp}/fetch-crl-test.XXXXXX")
fails=0; passes=0
t() { # t "name" 'expr'
  if eval "$2"; then passes=$((passes+1)); echo "  ok   $1"; else fails=$((fails+1)); echo "  FAIL $1   [$2]"; fi
}
cleanup() { kill "$SRVPID" 2>/dev/null; rm -rf "$T"; }
trap cleanup EXIT

# ---- the CA, the lists --------------------------------------------------
mkdir -p "$T/ca" "$T/lists" "$T/home"
openssl req -x509 -newkey ed25519 -nodes -days 2 -subj /CN=probe-ca -keyout "$T/ca/key.pem" -out "$T/ca/ca.pem" 2>/dev/null
CA=$T/ca/ca.pem
mkcrl() { # mkcrl <dir> <crl number, hex, two digits> <out.der>: a list the CA signs
  mkdir -p "$1"; : >"$1/index.txt"; printf '%s\n' "$2" >"$1/crlnumber"
  printf '[ca]\ndefault_ca=x\n[x]\ndatabase=%s/index.txt\ncrlnumber=%s/crlnumber\ndefault_md=default\ndefault_crl_days=1\n' "$1" "$1" >"$1/cnf"
  openssl ca -config "$1/cnf" -cert "$CA" -keyfile "$T/ca/key.pem" -gencrl -out "$1/crl.pem" 2>/dev/null &&
    openssl crl -in "$1/crl.pem" -outform DER -out "$3"
}
mkcrl_dated() { # mkcrl_dated <dir> <number> <out.der> <lastUpdate> <nextUpdate> (YYYYMMDDHHMMSSZ)
  mkdir -p "$1"; : >"$1/index.txt"; printf '%s\n' "$2" >"$1/crlnumber"
  printf '[ca]\ndefault_ca=x\n[x]\ndatabase=%s/index.txt\ncrlnumber=%s/crlnumber\ndefault_md=default\n' "$1" "$1" >"$1/cnf"
  openssl ca -config "$1/cnf" -cert "$CA" -keyfile "$T/ca/key.pem" -gencrl -crl_lastupdate "$4" -crl_nextupdate "$5" -out "$1/crl.pem" 2>/dev/null &&
    openssl crl -in "$1/crl.pem" -outform DER -out "$3"
}
at() { python3 -c 'import sys,datetime as d; print((d.datetime.now(d.timezone.utc)+d.timedelta(seconds=int(sys.argv[1]))).strftime("%Y%m%d%H%M%SZ"))' "$1"; }
for n in 1 2 3 10; do mkcrl "$T/mk$n" "$(printf %02d "$n")" "$T/lists/L$n.der" || { echo "cannot make a list"; exit 99; }; done
# 20: a day's list with 100 minutes left (6.9 %: near); 21: with 12 h left (50 %: not); 22: expired
mkcrl_dated "$T/mk20" 20 "$T/lists/L20.der" "$(at -85700)" "$(at 6000)" || { echo "cannot make a list"; exit 99; }
mkcrl_dated "$T/mk21" 21 "$T/lists/L21.der" "$(at -43200)" "$(at 43200)" || { echo "cannot make a list"; exit 99; }
mkcrl_dated "$T/mk22" 22 "$T/lists/L22.der" "$(at -90000)" "$(at -3600)" || { echo "cannot make a list"; exit 99; }
: >"$T/ctl"; : >"$T/req.log"
python3 "$HERE/crl-stub.py" "$T/ctl" "$T/req.log" "$T/port" 2>/dev/null & SRVPID=$!
for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do [ -s "$T/port" ] && break; sleep 0.25; done
PORT=$(cat "$T/port" 2>/dev/null) || { echo "the stand-in did not start"; exit 99; }
URL=http://127.0.0.1:$PORT/crl

ctl() { : >"$T/ctl"; while [ $# -gt 0 ]; do printf '%s\t%s\n' "$1" "$2" >>"$T/ctl"; shift 2; done; }
serve() { # serve <n> <etag> [extra k v ...]
  n=$1; e=$2; shift 2; ctl file "$T/lists/L$n.der" etag "$e" "$@"; }
newcap() { CAPATH=$T/cap.$((++capn)); mkdir -p "$CAPATH"; }
capn=0
run() { # run [VAR=val ...]  (extra env for the script)
  : >"$T/req.log"
  env HOME="$T/home" FETCH_CRL_ALLOW_HTTP=1 "$@" "$SH" "$SCRIPT" "$URL" "$CA" "$CAPATH" >"$T/out" 2>"$T/err"; rc=$?
}
runu() { # run with a given URL
  u=$1; shift; : >"$T/req.log"
  env HOME="$T/home" FETCH_CRL_ALLOW_HTTP=1 "$@" "$SH" "$SCRIPT" "$u" "$CA" "$CAPATH" >"$T/out" 2>"$T/err"; rc=$?
}
reqs() { wc -l <"$T/req.log" | tr -d ' '; }
lastinm() { tail -n 1 "$T/req.log" | cut -f2; }
hashname=$(openssl crl -in "$T/mk1/crl.pem" -noout -hash)
installed() { echo "$CAPATH/$hashname.r0"; }
capnum() { openssl crl -in "$(installed)" -noout -crlnumber | sed 's/crlNumber=0x//;s/^0*//'; }
statefile() { echo "$CAPATH/.fetch-crl.$(printf '%s' "$URL" | openssl dgst -sha256 -r | cut -c1-16)"; }
sha() { openssl dgst -sha256 -r <"$1" | cut -d' ' -f1; }
msg() { cat "$T/out" "$T/err" | tr '\n' ' '; }

echo "== fetch-crl.sh under $SH"

# ---- baseline ----------------------------------------------------------------
newcap; serve 1 '"t1"'; run
t "baseline: first run installs (rc 0)" '[ $rc -eq 0 ] && [ "$(capnum)" = 1 ]'
t "baseline: state is etag, name, sha256" '[ "$(sed -n 1p "$(statefile)")" = "\"t1\"" ] && [ "$(sed -n 2p "$(statefile)")" = "$hashname.r0" ] && [ "$(sed -n 3p "$(statefile)")" = "$(sha "$(installed)")" ]'
run
t "baseline: same tag -> 304 unchanged, sent If-None-Match" '[ $rc -eq 0 ] && msg | grep -q "unchanged (304)" && [ "$(lastinm)" = "\"t1\"" ] && [ "$(reqs)" = 1 ]'

# ---- R110W5-01 -----------------------------------------------------------------
echo "-- R110W5-01"
newcap; serve 1 '*'; run
t "01: ETag * answer installs the list but stores no tag" '[ $rc -eq 0 ] && [ "$(capnum)" = 1 ] && [ ! -e "$(statefile)" ]'
serve 3 '"t3"'; run
t "01: next run is unconditional and installs the newer list (not frozen)" '[ $rc -eq 0 ] && [ "$(lastinm)" = "-" ] && [ "$(capnum)" = 3 ]'
newcap; serve 1 '"a", "b"'; run
t "01: a comma list is not stored" '[ $rc -eq 0 ] && [ ! -e "$(statefile)" ]'
for bad in '"a"b"' 'abc' '"a b"' 'W/' '""x' '"' ; do
  newcap; serve 1 "$bad"; run
  t "01: ETag [$bad] is not stored" '[ $rc -eq 0 ] && [ ! -e "$(statefile)" ]'
done
newcap; serve 1 'W/"w1"'; run
t "01: weak tag W/\"w1\" is stored" '[ "$(sed -n 1p "$(statefile)")" = "W/\"w1\"" ]'
run
t "01: weak tag revalidates (304, equal ETag)" '[ $rc -eq 0 ] && msg | grep -q "unchanged (304)"'
newcap; serve 1 '""'; run
t "01: empty quoted tag \"\" is a valid entity-tag, stored" '[ "$(sed -n 1p "$(statefile)")" = "\"\"" ]'

# a pre-fix state file that holds * (or a file with no sha) is not trusted
newcap; serve 1 '"t1"'; run; serve 2 '"t2"'
printf '*\n%s\n' "$hashname.r0" >"$(statefile)"; run
t "01: a stored * (old state) is not sent; full fetch installs the newer list" '[ $rc -eq 0 ] && [ "$(lastinm)" = "-" ] && [ "$(capnum)" = 2 ]'
newcap; serve 1 '"t1"'; run
printf '"t1"\n%s\n' "$hashname.r0" >"$(statefile)"; run
t "01: a two-line (pre-sha) state is not revalidated; list refetched" '[ $rc -eq 0 ] && [ "$(lastinm)" = "-" ] && [ "$(reqs)" = 1 ] && msg | grep -q installed'

# 304 whose ETag differs / is missing
for e304 in '"other"' '@none' '*' 'W/"t1x"'; do
  newcap; serve 1 '"t1"'; run
  serve 1 '"t1"' etag304 "$e304"; run
  t "01: 304 with ETag [$e304] != sent -> refetch without If-None-Match (2 requests)" '[ $rc -eq 0 ] && [ "$(reqs)" = 2 ] && [ "$(lastinm)" = "-" ] && msg | grep -q "unconditionally" && msg | grep -q "installed"'
done
# a 304 even to the unconditional re-request is refused
newcap; serve 1 '"t1"'; run
cat >"$T/srv304.py" <<'PY'
import http.server,sys
class H(http.server.BaseHTTPRequestHandler):
    protocol_version='HTTP/1.0'
    def log_message(self,*a):pass
    def do_GET(self):
        self.send_response(304); self.send_header('ETag','"zz"'); self.send_header('Content-Length','0'); self.end_headers()
http.server.HTTPServer(('127.0.0.1',int(sys.argv[1])),H).serve_forever()
PY
python3 "$T/srv304.py" $((PORT+1)) 2>/dev/null & P304=$!; sleep 0.5
# state keyed by that URL: copy
U2=http://127.0.0.1:$((PORT+1))/crl
k2=$(printf '%s' "$U2" | openssl dgst -sha256 -r | cut -c1-16); cp "$(statefile)" "$CAPATH/.fetch-crl.$k2"
runu "$U2"; kill $P304 2>/dev/null
t "01: a server that answers 304 to everything cannot freeze it: refused (exit 1), list stays" '[ $rc -eq 1 ] && [ "$(capnum)" = 1 ] && msg | grep -q "304"'

# replaced installed file
newcap; serve 1 '"t1"'; run
cp "$T/lists/L10.der" "$T/l10.pem.tmp"; openssl crl -inform DER -in "$T/lists/L10.der" -outform PEM -out "$(installed)"
serve 1 '"t1"'; run
t "01: installed file replaced -> no If-None-Match, full fetch" '[ "$(lastinm)" = "-" ]'
t "01:   (the replacement is numbered 0x10 > 1: the older list is refused as a replay)" '[ $rc -eq 1 ] && msg | grep -q "lower than the installed" && [ "$(capnum)" = 10 ]'
newcap; serve 2 '"t2"'; run
printf 'garbage\n' >"$(installed)"; run
t "01: installed file corrupted -> full fetch restores it" '[ $rc -eq 0 ] && [ "$(lastinm)" = "-" ] && [ "$(capnum)" = 2 ] && [ "$(sed -n 3p "$(statefile)")" = "$(sha "$(installed)")" ]'
newcap; serve 2 '"t2"'; run; rm -f "$(installed)"; run
t "01: installed file deleted -> full fetch" '[ $rc -eq 0 ] && [ "$(lastinm)" = "-" ] && [ -f "$(installed)" ]'
# touched but identical content (mtime only) still revalidates
newcap; serve 2 '"t2"'; run; touch "$(installed)"; run
t "01: same content, new mtime -> still a 304" '[ $rc -eq 0 ] && msg | grep -q "unchanged (304)"'

echo "-- R110W5-02"
# The openssl shim: the run that has FETCH_SLOW=<counter file> in its environment
# sleeps 3 s after its second `openssl crl -crlnumber` (the installed list's
# number, read before the comparison and the rename): the window two overlapping
# runs race in.
mkdir -p "$T/shim"
REAL=$(command -v openssl)
cat >"$T/shim/openssl" <<SH
#!/bin/sh
"$REAL" "\$@"; r=\$?
case " \$* " in
*" -crlnumber "*)
	if [ -n "\${FETCH_SLOW:-}" ]; then
		n=\$(cat "\$FETCH_SLOW" 2>/dev/null || echo 0); n=\$((n + 1)); echo "\$n" >"\$FETCH_SLOW"
		[ "\$n" -ne 2 ] || sleep 3
	fi ;;
esac
exit \$r
SH
chmod +x "$T/shim/openssl"
# A PATH without flock, for the directory lock.
mkdir -p "$T/noflock"
for f in /usr/bin/* /usr/sbin/*; do b=${f##*/}; [ "$b" = flock ] || [ "$b" = openssl ] || ln -sf "$f" "$T/noflock/$b" 2>/dev/null; done
cp "$T/shim/openssl" "$T/noflock/openssl"
NOFLOCK_PATH="$T/noflock"
FLOCK_PATH="$T/shim:$PATH"

race() { # race <PATH>: list 1 is installed; A (slowed) fetches list 2, B starts 1 s later and fetches list 3
  newcap; serve 1 '"t1"'; run
  ctl file "$T/lists/L2.der" etag '"t2"'; rm -f "$T/slow"
  : >"$T/req.log"
  env PATH="$1" HOME="$T/home" FETCH_SLOW="$T/slow" FETCH_CRL_ALLOW_HTTP=1 "$SH" "$SCRIPT" "$URL" "$CA" "$CAPATH" >"$T/outA" 2>"$T/errA" & pa=$!
  sleep 1
  ctl file "$T/lists/L3.der" etag '"t3"'
  env PATH="$1" HOME="$T/home" FETCH_CRL_ALLOW_HTTP=1 "$SH" "$SCRIPT" "$URL" "$CA" "$CAPATH" >"$T/outB" 2>"$T/errB"; rcB=$?
  wait $pa; rcA=$?
}
for variant in flock mkdir; do
  if [ $variant = flock ]; then P=$FLOCK_PATH; else P=$NOFLOCK_PATH; fi
  race "$P"
  t "02/$variant: both exit 0" '[ $rcA -eq 0 ] && [ $rcB -eq 0 ]'
  t "02/$variant: installed list and state agree (sha)" '[ "$(sed -n 3p "$(statefile)")" = "$(sha "$(installed)")" ]'
  t "02/$variant: no rollback: installed number >= every number a run reported installing" '
     hi=0; for f in outA outB; do v=$(sed -n "s/.*CRL number 0x\([0-9A-F]*\)).*/\1/p" "$T/$f"); [ -z "$v" ] || [ "$v" -le "$(capnum)" ] || hi=1; done; [ $hi -eq 0 ]'
  t "02/$variant: the second run said it was busy and touched nothing" 'cat "$T/outB" "$T/errB" | grep -qi "lock"'
  ctl file "$T/lists/L3.der" etag '"t3"'; : >"$T/req.log"
  env PATH="$P" HOME="$T/home" FETCH_CRL_ALLOW_HTTP=1 "$SH" "$SCRIPT" "$URL" "$CA" "$CAPATH" >"$T/out" 2>"$T/err"; rc=$?
  t "02/$variant: the next run installs the newest list; state agrees" '[ $rc -eq 0 ] && [ "$(capnum)" = 3 ] && [ "$(sed -n 3p "$(statefile)")" = "$(sha "$(installed)")" ] && [ "$(sed -n 1p "$(statefile)")" = "\"t3\"" ]'
done

# the lock is released after success and after a refusal
newcap; serve 1 '"t1"'; run; run2=$rc
serve 2 '"t2"' ; printf junk >"$T/bad.der"; ctl file "$T/bad.der" etag '"x"'; run
t "02: a refused list exits 1" '[ $rc -eq 1 ]'
serve 2 '"t2"'; run
t "02: the lock was released by the refused run" '[ $rc -eq 0 ] && [ "$(capnum)" = 2 ]'

# mkdir lock: stale handling
mk_run() { env PATH="$NOFLOCK_PATH" HOME="$T/home" FETCH_CRL_ALLOW_HTTP=1 "$SH" "$SCRIPT" "$URL" "$CA" "$CAPATH" >"$T/out" 2>"$T/err"; rc=$?; }
lockdir() { echo "$(statefile).lock.d"; }
newcap; serve 1 '"t1"'
mkdir "$(lockdir)"; printf '%s\n%s\n' "$$" "$(date +%s)" >"$(lockdir)/owner"
mk_run
t "02/mkdir: a live, fresh holder -> exit 0, nothing installed, lock left alone" '[ $rc -eq 0 ] && [ ! -e "$(installed)" ] && [ -d "$(lockdir)" ] && grep -qi lock "$T/out" "$T/err"'
rm -rf "$(lockdir)"
mkdir "$(lockdir)"; env true & dead=$!; wait "$dead" # a process id that is gone now
printf '%s\n%s\n' "$dead" "$(date +%s)" >"$(lockdir)/owner"
mk_run
t "02/mkdir: owner pid gone -> stale lock broken, list installed, lock removed" '[ $rc -eq 0 ] && [ "$(capnum)" = 1 ] && [ ! -e "$(lockdir)" ]'
newcap; serve 1 '"t1"'
mkdir "$(lockdir)"; printf '%s\n%s\n' "$$" "$(( $(date +%s) - 500 ))" >"$(lockdir)/owner"
mk_run
t "02/mkdir: live pid but lock older than 120 s -> stale, broken, installed" '[ $rc -eq 0 ] && [ "$(capnum)" = 1 ] && [ ! -e "$(lockdir)" ]'
newcap; serve 1 '"t1"'
mkdir "$(lockdir)"
mk_run
t "02/mkdir: a lock with no owner file -> stale, broken, installed" '[ $rc -eq 0 ] && [ "$(capnum)" = 1 ] && [ ! -e "$(lockdir)" ]'
newcap; serve 1 '"t1"'
mkdir "$(lockdir)"; printf 'junk\nnonsense\n' >"$(lockdir)/owner"
mk_run
t "02/mkdir: a garbled owner file -> stale, broken, installed" '[ $rc -eq 0 ] && [ "$(capnum)" = 1 ] && [ ! -e "$(lockdir)" ]'
# lock released on SIGTERM
newcap; serve 1 '"t1"'; ctl file "$T/lists/L1.der" etag '"t1"' delay 3
env PATH="$NOFLOCK_PATH" HOME="$T/home" FETCH_CRL_ALLOW_HTTP=1 "$SH" "$SCRIPT" "$URL" "$CA" "$CAPATH" >/dev/null 2>&1 & pk=$!
sleep 1; held=0; [ -d "$(lockdir)" ] && held=1
kill -TERM $pk; wait $pk 2>/dev/null; sleep 0.3
t "02/mkdir: the lock is held while running and removed after SIGTERM" '[ $held -eq 1 ] && [ ! -e "$(lockdir)" ]'
# flock: held lock -> exit 0
newcap; serve 1 '"t1"'
lf=$(statefile).lock
( trap - EXIT; exec 8>"$lf"; flock -n 8 && sleep 3 ) & fl=$!; sleep 0.5
env HOME="$T/home" FETCH_CRL_ALLOW_HTTP=1 "$SH" "$SCRIPT" "$URL" "$CA" "$CAPATH" >"$T/out" 2>"$T/err"; rc=$?
t "02/flock: lock held elsewhere -> exit 0, message, nothing installed" '[ $rc -eq 0 ] && [ ! -e "$(installed)" ] && grep -qi lock "$T/out" "$T/err"'
wait $fl
env HOME="$T/home" FETCH_CRL_ALLOW_HTTP=1 "$SH" "$SCRIPT" "$URL" "$CA" "$CAPATH" >"$T/out" 2>"$T/err"; rc=$?
t "02/flock: after the holder exits the run proceeds" '[ $rc -eq 0 ] && [ "$(capnum)" = 1 ]'

echo "-- R110W5-03"
newcap; serve 1 '"t1"' redirect "http://127.0.0.1:$PORT/other"
printf 'location\n' >"$T/home/.curlrc"
run
t "03: ~/.curlrc 'location' does not make the script follow a redirect (exit 1, HTTP 302)" '[ $rc -eq 1 ] && msg | grep -q "HTTP 302" && [ ! -e "$(installed)" ] && [ "$(reqs)" = 1 ]'
printf 'output = "%s/pwned"\n' "$T" >"$T/home/.curlrc"; serve 1 '"t1"'; newcap; run
t "03: ~/.curlrc 'output' is not read" '[ $rc -eq 0 ] && [ ! -e "$T/pwned" ]'
rm -f "$T/home/.curlrc"
serve 1 '"t1"'
newcap; runu "-o$T/pwn2"
t "03: a URL that is an option (-o...) is refused, nothing written" '[ $rc -ne 0 ] && [ ! -e "$T/pwn2" ] && [ "$(reqs)" = 0 ]'
newcap; runu "--output=$T/pwn3"
t "03: a URL --output=... is refused" '[ $rc -ne 0 ] && [ ! -e "$T/pwn3" ]'
printf 'url = "%s"\n' "$URL" >"$T/cfg"
newcap; runu "-K$T/cfg"
t "03: a URL -K<config file> is refused, and curl is never run (no request reaches the stand-in)" '[ $rc -ne 0 ] && [ "$(reqs)" = 0 ] && [ ! -e "$(installed)" ]'
newcap; runu "file:///etc/passwd"
t "03: file:// refused" '[ $rc -ne 0 ] && [ ! -e "$(installed)" ] && msg | grep -qi "refus"'
for u in "ftp://127.0.0.1/crl" "gopher://127.0.0.1/x" "HTTP://127.0.0.1:$PORT/crl" " http://127.0.0.1:$PORT/crl" "https:/x" ""; do
  newcap; runu "$u"; t "03: URL [$u] refused" '[ $rc -ne 0 ] && [ ! -e "$(installed)" ]'
done
newcap; serve 1 '"t1"'; run FETCH_CRL_ALLOW_HTTP=
t "03: http:// without the opt-in is refused" '[ $rc -ne 0 ] && [ ! -e "$(installed)" ] && [ "$(reqs)" = 0 ]'
newcap; env HOME="$T/home" FETCH_CRL_ALLOW_HTTP=yes "$SH" "$SCRIPT" "$URL" "$CA" "$CAPATH" >"$T/out" 2>"$T/err"; rc=$?
t "03: FETCH_CRL_ALLOW_HTTP=yes (not 1) does not open it" '[ $rc -ne 0 ]'
newcap; run FETCH_CRL_ALLOW_HTTP=1
t "03: http:// with FETCH_CRL_ALLOW_HTTP=1 works" '[ $rc -eq 0 ] && [ "$(capnum)" = 1 ]'
newcap; ctl file "$T/lists/L1.der" etag '"t1"' redirect "https://127.0.0.1:1/"; run FETCH_CRL_ALLOW_HTTP=1
t "03: a redirect is not followed even with the opt-in" '[ $rc -eq 1 ] && msg | grep -q "HTTP 302" && [ "$(reqs)" = 1 ]'
newcap; serve 1 '"t1"'; runu "https://127.0.0.1:$PORT/crl"
t "03: https:// is attempted (a TLS failure against the plain server, not a scheme refusal)" '[ $rc -eq 1 ] && msg | grep -q "curl exit" && [ ! -e "$(installed)" ]'
# ---- R110W5-06 -----------------------------------------------------------------
echo "-- R110W5-06"
# dash runs no EXIT trap when a signal kills it; the script's HUP/INT/TERM trap
# turns the signal into `exit 1`, which does (INT is not tested: a shell started in the
# background ignores SIGINT). A run killed mid-fetch (the stand-in
# answers after 3 s) must leave no mktemp directory and no .incoming.* behind.
for sig in TERM HUP; do
  newcap; serve 1 '"t1"' delay 3; rm -rf "$T/tmp06"; mkdir "$T/tmp06"
  env TMPDIR="$T/tmp06" HOME="$T/home" FETCH_CRL_ALLOW_HTTP=1 "$SH" "$SCRIPT" "$URL" "$CA" "$CAPATH" >"$T/out" 2>"$T/err" & pk=$!
  sleep 1
  mid=$(ls -A "$T/tmp06" | wc -l | tr -d ' ')
  kill -$sig $pk 2>/dev/null; wait $pk; rc=$?
  t "06/$sig: the run was in flight (its work directory existed) when signalled" '[ "$mid" -ge 1 ]'
  t "06/$sig: a killed run exits non-zero and installs nothing" '[ $rc -ne 0 ] && [ ! -e "$(installed)" ]'
  t "06/$sig: a killed run leaves no work directory and no .incoming.*" '[ -z "$(ls -A "$T/tmp06")" ] && [ -z "$(ls -A "$CAPATH" | grep "^\.incoming\.")" ]'
done
ctl file "$T/lists/L1.der" etag '"t1"'

# ---- R110W5-07 -----------------------------------------------------------------
echo "-- R110W5-07"
newcap; serve 1 '"t1"'; run
t "07: a fresh list (a day left of a day): exit 0" '[ $rc -eq 0 ] && [ "$(capnum)" = 1 ]'
newcap; serve 21 '"t21"'; run
t "07: half the lifetime left: installed, exit 0" '[ $rc -eq 0 ] && [ "$(capnum)" = 21 ]'
run
t "07: ... and its 304: exit 0" '[ $rc -eq 0 ] && msg | grep -q "unchanged (304)"'
newcap; serve 20 '"t20"'; run
t "07: a list with under a quarter left, just installed: exit 3, installed" '[ $rc -eq 3 ] && [ "$(capnum)" = 20 ] && msg | grep -q "less than a quarter"'
run
t "07: its 304: exit 3 (the list is not touched), saying when it expires" '[ $rc -eq 3 ] && msg | grep -q "unchanged (304)" && msg | grep -q "expires in" && [ "$(reqs)" = 1 ]'
serve 21 '"t21"'; run
t "07: a newer list with half its life left replaces it: exit 0 again" '[ $rc -eq 0 ] && [ "$(capnum)" = 21 ]'
ctl file "$T/bad.der" etag '"x"'; run
t "07: a refusal beside a healthy list stays exit 1" '[ $rc -eq 1 ]'
newcap; serve 20 '"t20"'; run; ctl file "$T/bad.der" etag '"x"'; run
t "07: a refusal beside a list near its end: exit 3, with the refusal on stderr" '[ $rc -eq 3 ] && msg | grep -q "refusing the list" && msg | grep -q "less than a quarter"'
newcap; serve 20 '"t20"'; run; ctl file "$T/lists/L20.der" etag '"t20"' redirect "http://127.0.0.1:1/"; run
t "07: an HTTP error beside a list near its end: exit 3" '[ $rc -eq 3 ] && msg | grep -q "HTTP 302"'
newcap; serve 22 '"t22"'; run
t "07: an expired list: exit 3, saying so" '[ $rc -eq 3 ] && msg | grep -q "expired"'
newcap; ctl file "$T/bad.der" etag '"x"'; run
t "07: nothing installed yet, and a refusal: exit 1 (no list to age)" '[ $rc -eq 1 ]'
newcap; serve 20 '"t20"'; run; printf 'garbage\n' >"$(installed)"; ctl file "$T/bad.der" etag '"x"'; run
t "07: an unreadable installed list does not turn a refusal into exit 3" '[ $rc -eq 1 ]'
# A run that finds the lock held still reads the installed list's age (R111W5-02):
# the check is read-only, so it needs no lock. "Nothing touched": the same files with
# the same contents in capath, and no request made.
snap() { (cd "$CAPATH" && for f in $(ls -A | sort); do [ -f "$f" ] && printf '%s %s\n' "$f" "$(sha "$f")"; done; ls -A | sort); }
hold_flock() { : >>"$(statefile).lock"; flock "$(statefile).lock" sleep 5 & holder=$!; sleep 1; }
release_flock() { kill "$holder" 2>/dev/null; wait "$holder" 2>/dev/null; }
newcap; serve 20 '"t20"'; run; before=$(snap); hold_flock; run
t "07/lock-held (flock): a list near its end -> exit 3, lock named, nothing touched, no request" '[ $rc -eq 3 ] && msg | grep -qi "holds the lock" && msg | grep -q "less than a quarter" && [ "$(snap)" = "$before" ] && [ "$(reqs)" = 0 ]'
release_flock
newcap; serve 22 '"t22"'; run; before=$(snap); hold_flock; run
t "07/lock-held (flock): an expired list -> exit 3, nothing touched" '[ $rc -eq 3 ] && msg | grep -q "expired" && [ "$(snap)" = "$before" ] && [ "$(reqs)" = 0 ]'
release_flock
newcap; serve 21 '"t21"'; run; before=$(snap); hold_flock; run
t "07/lock-held (flock): a healthy list -> exit 0, nothing touched" '[ $rc -eq 0 ] && msg | grep -qi "holds the lock" && [ "$(snap)" = "$before" ] && [ "$(reqs)" = 0 ]'
release_flock
newcap; hold_flock; serve 20 '"t20"'; run
t "07/lock-held (flock): no installed list to age -> exit 0, nothing installed" '[ $rc -eq 0 ] && [ ! -e "$(installed)" ] && [ "$(reqs)" = 0 ]'
release_flock
newcap; serve 20 '"t20"'; run; mkdir "$(statefile).lock.d"; printf '%s\n%s\n' "$$" "$(date +%s)" >"$(statefile).lock.d/owner"; before=$(snap)
env PATH="$NOFLOCK_PATH" HOME="$T/home" FETCH_CRL_ALLOW_HTTP=1 "$SH" "$SCRIPT" "$URL" "$CA" "$CAPATH" >"$T/out" 2>"$T/err"; rc=$?
t "07/lock-held (mkdir): a list near its end -> exit 3, lock left alone, nothing touched" '[ $rc -eq 3 ] && msg | grep -qi "holds the lock" && [ -d "$(statefile).lock.d" ] && [ "$(snap)" = "$before" ]'

# ---- R110W5-08 -----------------------------------------------------------------
echo "-- R110W5-08"
ccs() { cut -f3 "$T/req.log" | sort -u | tr '\n' ' '; }
newcap; serve 1 '"t1"'; run
t "08: the first (unconditional) request carries Cache-Control: no-cache" '[ $rc -eq 0 ] && [ "$(reqs)" = 1 ] && [ "$(ccs)" = "no-cache " ]'
run
t "08: the revalidation (If-None-Match) carries it too" '[ $rc -eq 0 ] && [ "$(reqs)" = 1 ] && [ "$(lastinm)" = "\"t1\"" ] && [ "$(ccs)" = "no-cache " ]'
newcap; serve 1 '"t1"' etag304 '"zz"'; run; run
t "08: the unconditional re-request after a mismatched 304 carries it too" '[ "$(reqs)" = 2 ] && [ "$(ccs)" = "no-cache " ]'

echo "== $passes passed, $fails failed"
exit $fails
