# crl-stub.py <ctl> <log> <port-file>
# The stand-in for AXIAM's CRL route that fetch-crl-test.sh fetches from, on a
# free loopback port (written to <port-file>). Each request is logged as
# "<path><TAB><If-None-Match or -><TAB><Cache-Control or ->". The ctl file, re-read per request, holds
# lines "key<TAB>value":
#   file      path of the DER list to serve with 200
#   etag      ETag for the 200 ("" = none); sent verbatim
#   etag304   ETag on a 304: "@same" (default), "@none", or a literal
#   redirect  if set, answer 302 with this Location for /crl
#   delay     seconds to sleep before answering (every request)
# Matching is AXIAM's (RFC 9110 weak comparison; "*" and lists match).
import http.server, socketserver, sys, time, os
CTL, LOG, PORTFILE = sys.argv[1], sys.argv[2], sys.argv[3]
def ctl():
    c = {}
    for line in open(CTL, encoding='latin-1'):
        line = line.rstrip('\n')
        if '\t' in line:
            k, v = line.split('\t', 1); c[k] = v
    return c
class H(http.server.BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.0'
    def log_message(self, *a): pass
    def do_GET(self):
        c = ctl()
        inm = self.headers.get('If-None-Match')
        cc = self.headers.get('Cache-Control')
        open(LOG, 'a').write(f"{self.path}\t{inm if inm is not None else '-'}\t{cc if cc is not None else '-'}\n")
        if c.get('delay'): time.sleep(float(c['delay']))
        if c.get('redirect'):
            self.send_response(302); self.send_header('Location', c['redirect']); self.send_header('Content-Length', '0'); self.end_headers(); return
        body = open(c['file'], 'rb').read()
        etag = c.get('etag', '')
        if inm is not None and etag and etag != '*':
            weak = lambda t: t[2:] if t.startswith('W/') else t
            if any(x.strip() == '*' or weak(x.strip()) == weak(etag) for x in inm.split(',')):
                self.send_response(304)
                e = c.get('etag304', '@same')
                if e == '@same': e = etag
                if e != '@none': self._headers_buffer.append(b'ETag: ' + e.encode('latin-1') + b'\r\n')
                self.send_header('Content-Length', '0'); self.end_headers(); return
        self.send_response(200)
        if etag: self._headers_buffer.append(b'ETag: ' + etag.encode('latin-1') + b'\r\n')
        self.send_header('Content-Type', 'application/pkix-crl')
        self.send_header('Content-Length', str(len(body))); self.end_headers(); self.wfile.write(body)
class S(socketserver.ThreadingMixIn, http.server.HTTPServer): daemon_threads = True
srv = S(('127.0.0.1', 0), H)
with open(PORTFILE + '.tmp', 'w') as f: f.write(str(srv.server_address[1]))
os.rename(PORTFILE + '.tmp', PORTFILE)
srv.serve_forever()
