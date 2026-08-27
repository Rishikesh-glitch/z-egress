import json
from http.server import BaseHTTPRequestHandler, HTTPServer

class H(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    def _handle(self):
        n = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(n) if n else b""
        out = {
            "method": self.command,
            "bytes_received": n,
            "content_encoding": self.headers.get("Content-Encoding"),
            "proxy_engine": self.headers.get("X-Proxy-Engine"),
            "wire_bytes": self.headers.get("X-Z-Egress-Wire-Bytes"),
            "json_valid": True,
        }
        try:
            json.loads(raw)
        except Exception:
            out["json_valid"] = False
        body = json.dumps(out, indent=2).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    do_POST = do_PUT = do_GET = _handle
    def log_message(self, *a): pass

HTTPServer(("127.0.0.1", 9001), H).serve_forever()
