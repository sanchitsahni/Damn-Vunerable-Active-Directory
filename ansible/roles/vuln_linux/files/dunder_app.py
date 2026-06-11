#!/usr/bin/env python3
"""
DUNDER MIFFLIN Paper Company — "Schrute Logistics" portal.
Intentionally vulnerable Flask app for the DUNDER lab (linux01).

Vulns (the spec):
  * OS command injection  -> /ping?host=10.10.0.1;id      (reverse shell)
  * Unrestricted upload    -> POST /upload (drops to ./uploads, e.g. webshell.py)
Listens 0.0.0.0:5000. Standard library only — no pip needed.
"""
import os
import subprocess
import cgi
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

UPLOAD_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "uploads")
os.makedirs(UPLOAD_DIR, exist_ok=True)

PAGE = b"""<html><head><title>Schrute Logistics - Dunder Mifflin</title></head>
<body style="font-family:sans-serif;background:#f4f4e8">
<h1>Dunder Mifflin :: Schrute Logistics Portal</h1>
<p>"Whenever I'm about to do something, I think 'would an idiot do that?'
and if they would, I do not do that thing." &mdash; Dwight</p>
<h3>Network diagnostics</h3>
<form action="/ping" method="get">
  Host: <input name="host" value="127.0.0.1"><input type="submit" value="Ping">
</form>
<h3>Upload shipping manifest</h3>
<form action="/upload" method="post" enctype="multipart/form-data">
  <input type="file" name="file"><input type="submit" value="Upload">
</form>
</body></html>"""


class H(BaseHTTPRequestHandler):
    def _send(self, code, body, ctype="text/html"):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.end_headers()
        if isinstance(body, str):
            body = body.encode()
        self.wfile.write(body)

    def do_GET(self):
        u = urlparse(self.path)
        if u.path == "/":
            self._send(200, PAGE)
        elif u.path == "/ping":
            host = parse_qs(u.query).get("host", ["127.0.0.1"])[0]
            # VULN: command injection — host is shelled out unsanitised.
            out = subprocess.run("ping -c1 " + host, shell=True,
                                 capture_output=True, text=True)
            self._send(200, "<pre>%s%s</pre>" % (out.stdout, out.stderr))
        else:
            self._send(404, "not found")

    def do_POST(self):
        if self.path != "/upload":
            self._send(404, "not found")
            return
        # VULN: unrestricted file upload — any extension, written verbatim.
        form = cgi.FieldStorage(fp=self.rfile, headers=self.headers,
                                environ={"REQUEST_METHOD": "POST",
                                         "CONTENT_TYPE": self.headers["Content-Type"]})
        if "file" in form and form["file"].filename:
            fn = os.path.basename(form["file"].filename)
            with open(os.path.join(UPLOAD_DIR, fn), "wb") as f:
                f.write(form["file"].file.read())
            self._send(200, "uploaded to /uploads/%s" % fn)
        else:
            self._send(400, "no file")

    def log_message(self, *a):
        pass


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", 5000), H).serve_forever()
