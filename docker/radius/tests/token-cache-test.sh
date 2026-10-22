#!/bin/sh
# token-cache-test.sh    the Live token cache's rules, in the pinned FreeRADIUS image
#
# check-token-cache.py checks the SHAPE of every call raddb/live/check-eap-tls makes on
# axiam_token_cache: read-only, or a store with a negative TTL of a token the request
# fetched. This script checks that those shapes do in the pinned image what that test
# relies on (rlm_cache.c, release_3_2_8, mod_cache_it :436-570), and that the shapes
# it refuses do what R111W5-01 (#720) and R112W5-01 (#764) say.
#
# The cache is keyed on a constant, so two FreeRADIUS threads share one entry, and
# each call on it is atomic. A thread's state is its own control:Tmp-String-2. So
# an interleaving of threads at the granularity of a call is a sequence of calls,
# each made with that thread's Tmp-String-2, and one request can play it out
# deterministically. Each case below is one Access-Request (User-Name = the case)
# to a virtual server of this script's own, beside the image's defaults, with the
# cache module copied verbatim from raddb/live/axiam_live; the server writes what
# each call answered and what the request then holds into Reply-Message lines,
# which are compared with what the 3.2.8 source says, line by line.
#
# Needs docker and the pinned image (named once, in docker/docker-compose.radius.yml).
# Exit status: the number of failed cases; 2 when FreeRADIUS does not start.
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$HERE/../../..
IMAGE=$(sed -n 's/^ *image: *//p' "$ROOT/docker/docker-compose.radius.yml" | head -n1)
NAME=axiam-token-cache-cases-$$
T=$(mktemp -d "${TMPDIR:-/tmp}/token-cache-test.XXXXXX")
# shellcheck disable=SC2317,SC2329 # invoked by the EXIT trap below; shellcheck cannot see trap callees
cleanup() { docker rm -f "$NAME" >/dev/null 2>&1; rm -rf "$T"; }
trap cleanup EXIT
trap 'exit 1' HUP INT TERM

# ---- the module, verbatim ----------------------------------------------------
awk '/^cache axiam_token_cache \{/ { on = 1 } on { print } on && /^\}/ { exit }' \
  "$ROOT/docker/radius/raddb/live/axiam_live" >"$T/axiam_token_cache"
grep -q 'key = "axiam-decide-caller"' "$T/axiam_token_cache" || {
  echo "token-cache-test: no cache axiam_token_cache module in raddb/live/axiam_live"; exit 2; }

# ---- the virtual server --------------------------------------------------------
# say <text>: one Reply-Message line.
say() { printf '\t\t\tupdate reply {\n\t\t\t\tReply-Message += "%s"\n\t\t\t}\n' "$1"; }
# raw <Cache-* lines>: one call, its answer not written down. An empty `update`
# section does not parse, so a plain call has none.
raw() {
  [ -n "$1" ] && printf '\t\t\tupdate control {\n%s\n\t\t\t}\n' "$1"
  printf '\t\t\taxiam_token_cache\n'
}
# call <label> <Cache-* lines>: one call, with the label and its answer written down.
call() {
  raw "$2"
  printf '\t\t\tif (notfound) {\n'; say "$1:notfound"
  printf '\t\t\t}\n\t\t\telsif (updated) {\n'; say "$1:updated"
  printf '\t\t\t}\n\t\t\telsif (ok) {\n'; say "$1:ok"
  printf '\t\t\t}\n\t\t\telse {\n'; say "$1:other"
  printf '\t\t\t}\n'
}
# as <value>: the next calls are made by a thread whose Tmp-String-2 is <value>.
as() { printf '\t\t\tupdate control {\n\t\t\t\tTmp-String-2 := "%s"\n\t\t\t}\n' "$1"; }
# holds <label>: what this request's Tmp-String-2 is now.
holds() { say "$1:%{control:Tmp-String-2}"; }
# entry <label>: what the cache holds, read read-only (inserts nothing).
entry() { as none; call "$1" "$READ"; holds "$1-holds"; }
# reset: no entry, whatever the case before left.
reset() { as none; raw "$DROP"; }
STATUS='				Cache-Status-Only := yes'
READ='				Cache-Read-Only := yes'
DROP='				Cache-Read-Only := yes
				Cache-TTL := 0'
OLD_DROP='				Cache-TTL := 0'
STORE='				Cache-TTL := "%{expr:0 - 900 / 2}"'
OLD_STORE='				Cache-TTL := "%{expr:900 / 2}"'
case_() { printf '\t\tif (&User-Name == "%s") {\n' "$1"; }
end() { printf '\t\t}\n'; }

{
  printf 'server token-cache-cases {\n\tlisten {\n\t\ttype = auth\n\t\tipaddr = 127.0.0.1\n\t\tport = 18190\n\t}\n'
  printf '\tauthorize {\n\t\tupdate control {\n\t\t\tAuth-Type := Accept\n\t\t}\n'

  # R112W5-01, the old read: X probes (found), A drops, X's plain call INSERTS X's
  # sentinel; C, which fetched FRESH, stores with a positive TTL and gets the sentinel.
  case_ old-read
  reset; as OLD; call a-store "$STORE"
  as -; call x-probe "$STATUS"
  as OLD; call a-drop "$DROP"
  as -; call x-plain ""; holds x-holds
  entry after-x
  as FRESH; call c-store "$OLD_STORE"; holds c-holds
  end

  # The new read: X reads read-only (merged, ok); A drops; nothing X does after can
  # put anything back. A thread that reads after the drop gets notfound and keeps its
  # sentinel, and the cache stays empty.
  case_ new-read
  reset; as OLD; call a-store "$STORE"
  as '!'; call x-read "$READ"; holds x-holds
  as OLD; call a-drop "$DROP"
  as '!'; call y-read "$READ"; holds y-holds
  entry after-y
  end

  # The new first-fetch store, over another thread's fresh entry: C keeps its own.
  case_ new-store
  reset; as B-TOKEN; call b-store "$STORE"
  as C-TOKEN; call c-store "$STORE"; holds c-holds
  entry after-c
  end

  # The old first-fetch store over another thread's entry: C decides with B's.
  case_ old-store
  reset; as B-TOKEN; call b-store "$STORE"
  as C-TOKEN; call c-store "$OLD_STORE"; holds c-holds
  entry after-c
  end

  # R111W5-01, the drops: 1.1.1's on an absent entry inserts the refused token; the
  # read-only one (W5.1) creates nothing.
  case_ drops
  reset; as OLD; call old-drop "$OLD_DROP"
  entry after-old
  reset; as OLD; call new-drop "$DROP"
  entry after-new
  end

  printf '\t}\n}\n'
} >"$T/token-cache-cases"
chmod 0644 "$T/axiam_token_cache" "$T/token-cache-cases"

# ---- FreeRADIUS --------------------------------------------------------------------
docker run -d --name "$NAME" \
  -v "$T/axiam_token_cache:/etc/freeradius/mods-enabled/axiam_token_cache:ro" \
  -v "$T/token-cache-cases:/etc/freeradius/sites-enabled/token-cache-cases:ro" \
  "$IMAGE" freeradius -f -X >/dev/null || exit 2
i=0
until docker logs "$NAME" 2>&1 | grep -q 'Ready to process requests'; do
  i=$((i+1))
  if [ "$i" -gt 60 ] || [ "$(docker inspect -f '{{.State.Running}}' "$NAME" 2>/dev/null)" != true ]; then
    echo "token-cache-test: FreeRADIUS did not start:"; docker logs --tail=60 "$NAME" 2>&1; exit 2
  fi
  sleep 1
done

# ---- the cases -----------------------------------------------------------------------
fails=0; passes=0
# expect <case> <the Reply-Message lines, one per line>
expect() {
  got=$(printf 'User-Name = "%s"\n' "$1" |
    docker exec -i "$NAME" radclient -x -r 1 -t 5 127.0.0.1:18190 auth testing123 2>&1 |
    sed -n 's/^[[:space:]]*Reply-Message = "\(.*\)"$/\1/p')
  if [ "$got" = "$2" ]; then
    passes=$((passes+1)); echo "  ok   $1"
  else
    fails=$((fails+1)); echo "  FAIL $1"
    printf '         expected:\n%s\n         got:\n%s\n' "$2" "$got" | sed 's/^/         /'
  fi
}

expect old-read 'a-store:updated
x-probe:ok
a-drop:ok
x-plain:updated
x-holds:-
after-x:ok
after-x-holds:-
c-store:ok
c-holds:-'

expect new-read 'a-store:updated
x-read:ok
x-holds:OLD
a-drop:ok
y-read:notfound
y-holds:!
after-y:notfound
after-y-holds:none'

expect new-store 'b-store:updated
c-store:updated
c-holds:C-TOKEN
after-c:ok
after-c-holds:C-TOKEN'

expect old-store 'b-store:updated
c-store:ok
c-holds:B-TOKEN
after-c:ok
after-c-holds:B-TOKEN'

expect drops 'old-drop:updated
after-old:ok
after-old-holds:OLD
new-drop:notfound
after-new:notfound
after-new-holds:none'

echo "token-cache cases: $passes passed, $fails failed"
[ "$fails" -eq 0 ] || docker logs --tail=200 "$NAME" 2>&1
exit "$fails"
