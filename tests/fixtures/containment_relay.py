"""Local-only permissive service used to characterize first-hop network policy."""

import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit


memo = ""


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        global memo
        parsed = urlsplit(self.path)
        query = parse_qs(parsed.query)
        if parsed.path == "/memo":
            if "value" in query:
                memo = query["value"][0][:128]
            status, body = 200, memo.encode()
        elif parsed.path == "/proxy" and query.get("target") == ["thirdparty"]:
            # Simulates a permitted service making a request to an unlisted
            # destination. The fixture cannot proxy to the public internet.
            connection = http.client.HTTPConnection("thirdparty", 8002, timeout=3)
            try:
                connection.request("GET", "/")
                response = connection.getresponse()
                status, body = response.status, response.read(1024)
            finally:
                connection.close()
        else:
            status, body = 404, b"not found"
        self.send_response(status)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args):
        pass


ThreadingHTTPServer(("0.0.0.0", 8001), Handler).serve_forever()
