# H6: the PLAINTEXT-through-the-edge control listener.
#
# Included by tls13.conf and tls13-h1.conf, so whenever a p2 nginx-fronted
# stack is up there is a second, cleartext HTTP/1.1 vhost in the SAME nginx
# process, with the SAME proxy hop and the SAME keep-alive upstream, differing
# from the TLS vhosts only in that it does no TLS.
#
# Why: "p2-h1 (nginx) vs p0 (direct)" is not a TLS measurement — it bundles
# TLS together with an extra process, an extra network hop and an extra
# container CPU budget. That confound is what made G8's h1 control unusable as
# evidence. With this listener the edge cells decompose cleanly:
#
#   nginx-plain-h1 (:8080)  vs  direct p0 (:8090)   = the proxy hop, alone
#   nginx-tls-h1   (:8443)  vs  nginx-plain-h1      = TLS at the edge, alone
#   nginx-tls-h2   (:8443)  vs  nginx-tls-h1        = h2 vs h1, alone
#
# Each of those three has exactly one variable. Published on the host as
# BENCH_EDGE_PLAIN_PORT (default 18080) by targets/axiam/docker-compose.yml.
# No profile drives it automatically; it is measured by pointing k6 at it
# directly (see run-improvement-tasks.sh h6-tls-proto).
server {
    listen 8080;
    server_name localhost;
    # No `http2` directive: cleartext HTTP/1.1 only, matching the p0 listener's
    # protocol so the hop can be priced without changing protocol at the same
    # time. (nginx 1.25+ would serve h2c here with `http2 on;`, but k6's Go
    # client never attempts a cleartext h2 upgrade, so it would be inert.)

    keepalive_requests 1000000;
    keepalive_timeout 300s;
    access_log off;

    location / {
        proxy_pass http://axiam_backend;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-Proto http;
        proxy_http_version 1.1;
        proxy_set_header Connection "";
        proxy_buffering off;
    }
}
