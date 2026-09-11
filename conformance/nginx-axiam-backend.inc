# Shared proxy directives for every location that reaches axiam-server.
#
# Kept in one include rather than repeated three times because the FIRST thing
# that goes wrong when they are repeated is that they stop being identical, and
# the symptom (one endpoint behaving differently from its siblings) is a long
# way from the cause.

proxy_set_header Host $host;
proxy_set_header X-Real-IP $remote_addr;
proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
proxy_set_header X-Forwarded-Proto $scheme;

# This proxy terminates server-auth TLS at most: it never asked the client for
# a certificate, so it has no verified peer identity to forward and must not
# appear to. axiam_oauth2::mtls refuses this header for OAuth2 client
# authentication regardless, and the device-auth extractor refuses it unless
# AXIAM__AUTH__TRUST_FORWARDED_CLIENT_CERT is on (it is not, here). Clearing it
# is the third layer, and it is the cheap one.
proxy_set_header X-Client-Certificate "";

# The backend's own certificate is verified — it is the same CA this harness
# minted, so verification is available and turning it off would make the
# proxy hop the one link in the chain nobody checks.
proxy_ssl_server_name on;
proxy_ssl_name host.docker.internal;
proxy_ssl_verify on;
proxy_ssl_verify_depth 3;
proxy_ssl_trusted_certificate /etc/axiam/certs/ca.crt;
proxy_ssl_protocols TLSv1.3;
