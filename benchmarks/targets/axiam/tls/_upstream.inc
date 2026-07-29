# Shared upstream definition for every nginx edge conf in this directory.
#
# WHY THIS EXISTS (H6). Until H6 every conf here used
# `proxy_pass http://axiam-server:8090;` with no `upstream` block. nginx only
# keeps connections to a backend alive when the backend is declared as an
# `upstream` WITH a `keepalive` directive — `proxy_http_version 1.1` and
# `proxy_set_header Connection ""` are necessary but NOT sufficient on their
# own. Every one of those confs therefore opened, used and closed a fresh TCP
# connection to axiam-server for EVERY proxied request.
#
# That is not a small tax. It gave the edge cells:
#   * a TCP handshake + a socket in TIME_WAIT per request, so a sustained
#     high-rate cell walks the container's ephemeral port range and starts
#     failing to connect — the most likely origin of the 1 059 `bench_failed`
#     ops in G8's `p2-h1` refresh cell (benchmarks/PRIVATE_BENCH_ANALYSIS.md,
#     claude_dev/improvement-after-g-benchmark.md §1 G8 row);
#   * an accept + fresh-connection cost on the AXIAM side of every request,
#     inflating the *server's* work in exactly the cells used as the "h1
#     control", which is the one place an untrustworthy control does real
#     damage: it makes h1-over-TLS look slow and thereby ACQUITS h2 for the
#     wrong reason.
#
# `keepalive 256` is the idle-connection cache size per worker. It must be
# comfortably above the offered concurrency (bench default BENCH_VUS=50) so the
# cache never thrashes; it is not a connection limit.
upstream axiam_backend {
    server axiam-server:8090;
    keepalive 256;
    keepalive_requests 100000;
    keepalive_timeout 300s;
}
