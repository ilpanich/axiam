#!/usr/bin/env bash
# e2e-console-resolver-check.sh — the console resolves its backend per request (DF-026).
#
# Usage: scripts/e2e-console-resolver-check.sh <frontend-image>
#
# The console's nginx used to name the backend literally in `proxy_pass`, which
# nginx resolves once, while loading its configuration. Two failures followed:
#
#   1. Started before axiam-server, the console did not start at all —
#      `[emerg] host not found in upstream "axiam-server"` — so a compose stack
#      brought up in the "wrong" order, or a backend that was slow to join the
#      network, took the admin UI down with it.
#   2. The address found at startup was kept for the life of the process, so a
#      recreated backend on a new IP answered 502 until the console was
#      restarted as well.
#
# This drives exactly those two scenarios against a BUILT image, with plain
# `docker` on a user-defined network — the only kind that has Docker's embedded
# DNS at 127.0.0.11, which is what the image's resolver hook finds in
# /etc/resolv.conf. The backend is a stand-in that echoes the request line it
# received: what is under test is how nginx finds and addresses its upstream,
# and an echo is what makes "the URI reached the backend unchanged" assertable.
#
# Asserted, in order:
#   - the console starts and serves the SPA with no backend on the network;
#   - the rendered `resolver` is the one the hook read from resolv.conf;
#   - /api, /oauth2/ and /.well-known answer 502 while there is no backend;
#   - they answer 200 once the backend exists, with no console restart;
#   - each proxied request reaches the backend with its URI as the client sent
#     it (the pre-fix form forwarded the unparsed URI too — this pins that);
#   - a backend recreated on a different IP is found, again with no restart;
#   - an operator-set AXIAM_BACKEND_RESOLVER is rendered verbatim and works —
#     the twin of the default: a deployment that sets it keeps its value.

set -euo pipefail

IMAGE="${1:?usage: $0 <frontend-image>}"
STANDIN_IMAGE="${STANDIN_IMAGE:-python:3-alpine}"

NET=axiam-console-resolver
SUBNET=172.31.250.0/24
A_IP=172.31.250.10
B_IP=172.31.250.20
PORT=18080
PINNED_PORT=18081
# The resolver's `valid=30s` bounds how long nginx reuses an answer, a negative
# one included, so every wait below allows twice that.
WAIT_SECS=60

# An HTTP server that answers every GET with "<TAG> <request-target>".
STANDIN='
import http.server, os
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = ("%s %s" % (os.environ["TAG"], self.path)).encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
http.server.ThreadingHTTPServer(("", 8090), H).serve_forever()
'

cleanup() {
    docker rm -f axiam-console axiam-console-pinned axiam-server >/dev/null 2>&1 || true
    docker network rm "$NET" >/dev/null 2>&1 || true
}
trap cleanup EXIT

fail() {
    echo "::error::$*" >&2
    echo "--- axiam-console logs ---" >&2
    docker logs axiam-console 2>&1 | tail -40 >&2 || true
    exit 1
}

pass() { echo "ok - $*"; }

# curl prints 000 for a refused connection and exits non-zero; the status is
# what is asserted, so the exit code is not. --max-time because a request nginx
# sends to the address of a removed container can wait out proxy_connect_timeout
# (60s) before the cached answer expires and it asks the resolver again.
status() { curl -s --max-time 10 -o /dev/null -w '%{http_code}' --path-as-is "http://127.0.0.1:$1$2" || true; }
body() { curl -s --max-time 10 --path-as-is "http://127.0.0.1:$1$2" || true; }

# wait_for <description> <command...> — retries once a second up to WAIT_SECS.
wait_for() {
    local what=$1; shift
    local i
    for ((i = 0; i < WAIT_SECS; i++)); do
        if "$@"; then return 0; fi
        sleep 1
    done
    fail "timed out after ${WAIT_SECS}s waiting for: $what"
}

start_backend() {
    docker run -d --name axiam-server --network "$NET" --ip "$2" \
        -e TAG="$1" "$STANDIN_IMAGE" python3 -c "$STANDIN" >/dev/null
}

console_running() { [ "$(docker inspect -f '{{.State.Running}}' axiam-console 2>/dev/null)" = true ]; }
spa_up() { console_running && [ "$(status "$PORT" /)" = 200 ]; }
served_by() { case "$(body "$1" /api/health)" in "$2 /api/health") return 0 ;; *) return 1 ;; esac; }

cleanup
docker pull -q "$STANDIN_IMAGE" >/dev/null
docker network create --subnet "$SUBNET" "$NET" >/dev/null

# --- 1. console first, no backend anywhere --------------------------------
docker run -d --name axiam-console --network "$NET" -p "127.0.0.1:${PORT}:8080" "$IMAGE" >/dev/null
started_at=$(docker inspect -f '{{.State.StartedAt}}' axiam-console)
wait_for "the console to serve / with no backend (it exits here without a request-time resolver)" spa_up
pass "console started before the backend and serves the SPA"

rendered=$(docker exec axiam-console grep -E '^[[:space:]]*resolver ' /etc/nginx/conf.d/default.conf) \
    || fail "no resolver directive in the rendered config"
expected=$(docker exec axiam-console awk '$1 == "nameserver" { print $2; exit }' /etc/resolv.conf)
case "$rendered" in
    *"resolver ${expected} valid=30s ipv6=off;"*) pass "rendered resolver is the resolv.conf nameserver ($expected)" ;;
    *) fail "rendered resolver '$rendered' does not name resolv.conf's nameserver '$expected'" ;;
esac

for p in /api/health /oauth2/token /.well-known/openid-configuration; do
    s=$(status "$PORT" "$p")
    [ "$s" = 502 ] || fail "$p answered $s with no backend, expected 502"
    pass "$p is 502 while the backend is absent"
done

# --- 2. the backend appears ------------------------------------------------
start_backend A "$A_IP"
wait_for "the console to reach backend A" served_by "$PORT" A
pass "backend A reached with no console restart"

for p in '/api/health' '/api' '/api?q=1' '/api/v1/a%2Fb/../c?x=1%20y&z' '/api//double' \
         '/oauth2/token?grant_type=x' '/.well-known/openid-configuration'; do
    got=$(body "$PORT" "$p")
    [ "$got" = "A $p" ] || fail "$p reached the backend as '${got#A }'"
    pass "$p reaches the backend unchanged"
done

s=$(status "$PORT" /oauth2-clients)
[ "$s" = 200 ] && [ "$(body "$PORT" /oauth2-clients)" != "A /oauth2-clients" ] \
    || fail "/oauth2-clients is an SPA route and must not be proxied"
pass "/oauth2-clients stays with the SPA"

# --- 3. the backend moves ---------------------------------------------------
docker rm -f axiam-server >/dev/null
start_backend B "$B_IP"
wait_for "the console to follow the backend to its new address" served_by "$PORT" B
[ "$(docker inspect -f '{{.State.StartedAt}}' axiam-console)" = "$started_at" ] \
    || fail "the console was restarted; the test proves nothing"
pass "backend recreated on a new IP is found with no console restart"

# --- 4. an operator-set resolver is kept -----------------------------------
docker run -d --name axiam-console-pinned --network "$NET" -p "127.0.0.1:${PINNED_PORT}:8080" \
    -e AXIAM_BACKEND_RESOLVER=127.0.0.11 "$IMAGE" >/dev/null
wait_for "the pinned-resolver console to reach backend B" served_by "$PINNED_PORT" B
docker exec axiam-console-pinned grep -qE '^[[:space:]]*resolver 127\.0\.0\.11 valid=30s ipv6=off;' \
    /etc/nginx/conf.d/default.conf || fail "AXIAM_BACKEND_RESOLVER was not rendered verbatim"
pass "an explicit AXIAM_BACKEND_RESOLVER is rendered verbatim and used"

echo "console resolver check: all assertions passed"
