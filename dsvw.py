#!/usr/bin/env python3
from http.server import BaseHTTPRequestHandler, HTTPServer
import html

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/":
            content = "<h1>Hello, world! (secure demo)</h1>"
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Content-Security-Policy", "default-src 'none'; style-src 'self';")
            self.end_headers()
            self.wfile.write(content.encode())
        else:
            self.send_error(404, "Not found")

if __name__ == "__main__":
    HTTPServer(("127.0.0.1", 8000), Handler).serve_forever()
