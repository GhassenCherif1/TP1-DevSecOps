#!/usr/bin/env python3
"""Hardened local demo HTTP server.

This is a secure replacement for an intentionally-vulnerable demo.
It removes unsafe features (exec, pickle, subprocess, remote includes, lxml DTD resolution)
and applies input validation, parameterized SQL, and safe file handling.
"""

import html
import http.client
import http.server
import json
import os
import random
import re
import socket
import socketserver
import sqlite3
import string
import time
import traceback
import urllib.parse
import xml.etree.ElementTree as ET

NAME = "Damn Small Vulnerable Web (Hardened)"
VERSION = "0.3-secure"
AUTHOR = "migrated"
LISTEN_ADDRESS, LISTEN_PORT = "127.0.0.1", 65412

HTML_PREFIX = (
    "<!DOCTYPE html>\n<html>\n<head>\n<meta charset=\"utf-8\">\n<title>%s</title>\n"
    "<style>body{font:12px monospace}table{border-collapse:collapse;border:1px solid #333}th,td{border:1px solid #666;padding:4px}</style>\n"
    "</head>\n<body>\n"
    % html.escape(NAME)
)
HTML_POSTFIX = (
    "<div style=\"position: fixed; bottom: 5px; text-align: center; width: 100%;\">Powered (secure) - v%s</div>\n"
    "</body>\n</html>" % VERSION
)

USERS_XML = """<?xml version="1.0" encoding="utf-8"?>
<users>
  <user id="0"><username>admin</username><name>admin</name><surname>admin</surname><password>7en8aiDoh!</password></user>
  <user id="1"><username>dricci</username><name>dian</name><surname>ricci</surname><password>12345</password></user>
  <user id="2"><username>amason</username><name>anthony</name><surname>mason</surname><password>gandalf</password></user>
  <user id="3"><username>svargas</username><name>sandra</name><surname>vargas</surname><password>phest1945</password></user>
</users>
"""


def init():
    global connection
    http.server.HTTPServer.allow_reuse_address = True
    connection = sqlite3.connect(":memory:", isolation_level=None, check_same_thread=False)
    cursor = connection.cursor()
    cursor.execute(
        "CREATE TABLE users(id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT, name TEXT, surname TEXT, password TEXT)"
    )
    # populate users table from USERS_XML using safe XML parsing (no external entities)
    root = ET.fromstring(USERS_XML)
    users = [
        (u.findtext("username"), u.findtext("name"), u.findtext("surname"), u.findtext("password"))
        for u in root.findall("user")
    ]
    cursor.executemany(
        "INSERT INTO users(id, username, name, surname, password) VALUES(NULL, ?, ?, ?, ?)",
        users,
    )
    cursor.execute("CREATE TABLE comments(id INTEGER PRIMARY KEY AUTOINCREMENT, comment TEXT, time TEXT)")

class ReqHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        # parse path and params safely
        path, _, query = self.path.partition("?")
        params = urllib.parse.parse_qs(query, keep_blank_values=True)
        cursor = connection.cursor()

        def get_param(name, default=None):
            v = params.get(name)
            return v[0] if v else default

        def send(code, content, content_type="text/html; charset=utf-8", extra_headers=None):
            try:
                self.send_response(code)
                # security headers
                self.send_header("Connection", "close")
                self.send_header("X-Content-Type-Options", "nosniff")
                self.send_header("X-Frame-Options", "DENY")
                self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'none'; object-src 'none';")
                if extra_headers:
                    for k, v in extra_headers.items():
                        self.send_header(k, v)
                self.send_header("Content-Type", content_type)
                self.end_headers()
                if isinstance(content, str):
                    content = content.encode("utf-8")
                self.wfile.write(content)
                self.wfile.flush()
            except Exception:
                # best-effort; nothing more to do
                pass

        try:
            if path == "/":
                # id -> parameterized DB lookup
                if get_param("id") is not None:
                    try:
                        idv = int(get_param("id"))
                    except ValueError:
                        return send(http.client.BAD_REQUEST, HTML_PREFIX + "<p>invalid id</p>" + HTML_POSTFIX)
                    cursor.execute(
                        "SELECT id, username, name, surname FROM users WHERE id=?", (idv,)
                    )
                    rows = cursor.fetchall()
                    table = "".join(
                        "<tr>%s</tr>" % "".join(
                            "<td>%s</td>" % ("-" if c is None else html.escape(str(c))) for c in row
                        )
                        for row in rows
                    )
                    content = HTML_PREFIX + "<div><span>Result(s):</span></div><table><thead><th>id</th><th>username</th><th>name</th><th>surname</th></thead>%s</table>" % table + HTML_POSTFIX
                    return send(http.client.OK, content)

                # simple version display
                if get_param("v") is not None:
                    ver = html.escape(get_param("v"))
                    return send(http.client.OK, HTML_PREFIX + "<p>Version: %s</p>" % ver + HTML_POSTFIX)

                # safe file read: only files under cwd, limit size
                if get_param("path") is not None:
                    requested = get_param("path")
                    # normalize and prevent traversal
                    base = os.path.abspath(os.getcwd())
                    target = os.path.abspath(os.path.join(base, requested.lstrip("/\\")))
                    if not target.startswith(base):
                        return send(http.client.FORBIDDEN, HTML_PREFIX + "<p>access denied</p>" + HTML_POSTFIX)
                    if not os.path.isfile(target):
                        return send(http.client.NOT_FOUND, HTML_PREFIX + "<p>not found</p>" + HTML_POSTFIX)
                    max_bytes = 100 * 1024
                    if os.path.getsize(target) > max_bytes:
                        return send(http.client.FORBIDDEN, HTML_PREFIX + "<p>file too large</p>" + HTML_POSTFIX)
                    with open(target, "rb") as fh:
                        data = fh.read()
                    return send(http.client.OK, HTML_PREFIX + "<pre>%s</pre>" % html.escape(data.decode("utf-8", errors="replace")) + HTML_POSTFIX)

                # safe xml parsing: do not resolve external entities
                if get_param("xml") is not None:
                    xml_text = get_param("xml")
                    try:
                        root = ET.fromstring(xml_text)
                        txt = ET.tostring(root, encoding="unicode")
                        return send(http.client.OK, HTML_PREFIX + "<pre>%s</pre>" % html.escape(txt) + HTML_POSTFIX)
                    except ET.ParseError:
                        return send(http.client.BAD_REQUEST, HTML_PREFIX + "<p>invalid xml</p>" + HTML_POSTFIX)

                # lookup by name in USERS_XML
                if get_param("name") is not None:
                    name = get_param("name")
                    root = ET.fromstring(USERS_XML)
                    found = None
                    for u in root.findall("user"):
                        n = u.findtext("name")
                        if n == name:
                            found = u.findtext("surname")
                    return send(http.client.OK, HTML_PREFIX + "<b>Surname:</b> %s" % html.escape(found or "-") + HTML_POSTFIX)

                # size: bounded generation
                if get_param("size") is not None:
                    try:
                        size = int(get_param("size"))
                    except ValueError:
                        return send(http.client.BAD_REQUEST, HTML_PREFIX + "<p>invalid size</p>" + HTML_POSTFIX)
                    if size < 0 or size > 2000:
                        return send(http.client.FORBIDDEN, HTML_PREFIX + "<p>size out of range</p>" + HTML_POSTFIX)
                    start = time.time()
                    body = "<br>".join("#" * size for _ in range(max(1, min(size, 10))))
                    return send(http.client.OK, HTML_PREFIX + "<b>Time required</b> (to 'resize image'): %.6f seconds" % (time.time() - start) + "<div>%s</div>" % body + HTML_POSTFIX)

                # comments: parameterized insert and safe display
                if get_param("comment") is not None or query == "comment=":
                    if get_param("comment"):
                        comment_text = get_param("comment")
                        cursor.execute("INSERT INTO comments(comment, time) VALUES(?, ?)", (comment_text, time.ctime()))
                        return send(http.client.OK, HTML_PREFIX + "Thank you for leaving the comment. Please click here <a href=\"/?comment=\">here</a> to see all comments" + HTML_POSTFIX)
                    else:
                        cursor.execute("SELECT id, comment, time FROM comments")
                        rows = cursor.fetchall()
                        table = "".join(
                            "<tr>%s</tr>" % "".join(
                                "<td>%s</td>" % ("-" if c is None else html.escape(str(c))) for c in row
                            )
                            for row in rows
                        )
                        return send(http.client.OK, HTML_PREFIX + "<div><span>Comment(s):</span></div><table><thead><th>id</th><th>comment</th><th>time</th></thead>%s</table>" % table + HTML_POSTFIX)

                # redirection: validate URL scheme (allow http/https only)
                if get_param("redir") is not None:
                    dest = get_param("redir")
                    parsed = urllib.parse.urlparse(dest)
                    if parsed.scheme in ("http", "https"):
                        return send(http.client.OK, HTML_PREFIX + "<meta http-equiv=\"refresh\" content=\"0; url=%s\"/>" % html.escape(dest) + HTML_POSTFIX)
                    else:
                        return send(http.client.BAD_REQUEST, HTML_PREFIX + "<p>invalid redirect</p>" + HTML_POSTFIX)

                # default root page
                return send(http.client.OK, HTML_PREFIX + "<h1>Welcome (secure)</h1>" + HTML_POSTFIX)

            elif path == "/users.json":
                # build simple JSON mapping username -> surname
                root = ET.fromstring(USERS_XML)
                mapping = {u.findtext("username"): u.findtext("surname") for u in root.findall("user")}
                callback = get_param("callback")
                if callback:
                    # allow only safe JS function names
                    if re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", callback):
                        body = "%s(%s)" % (callback, json.dumps(mapping))
                        return send(http.client.OK, body, content_type="application/javascript; charset=utf-8")
                    else:
                        return send(http.client.BAD_REQUEST, "/* invalid callback */\n" + json.dumps(mapping), content_type="application/json; charset=utf-8")
                return send(http.client.OK, json.dumps(mapping), content_type="application/json; charset=utf-8")

            elif path == "/login":
                username = get_param("username") or ""
                password = get_param("password") or ""
                # sanitize username on input but use parameterized query
                username_sanitized = re.sub(r"[^\w]", "", username)
                cursor.execute("SELECT 1 FROM users WHERE username=? AND password=?", (username_sanitized, password))
                if cursor.fetchone():
                    sessionid = "".join(random.sample((string.ascii_letters + string.digits), 20))
                    headers = {"Set-Cookie": f"SESSIONID={sessionid}; Path=/; HttpOnly"}
                    return send(http.client.OK, HTML_PREFIX + f"Welcome <b>{html.escape(username_sanitized)}</b>" + HTML_POSTFIX, extra_headers=headers)
                else:
                    headers = {"Set-Cookie": "SESSIONID=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT"}
                    return send(http.client.UNAUTHORIZED, HTML_PREFIX + "The username and/or password is incorrect" + HTML_POSTFIX, extra_headers=headers)

            else:
                return send(http.client.NOT_FOUND, HTML_PREFIX + "<p>not found</p>" + HTML_POSTFIX)

        except Exception:
            tb = traceback.format_exc()
            return send(http.client.INTERNAL_SERVER_ERROR, HTML_PREFIX + "<pre>%s</pre>" % html.escape(tb) + HTML_POSTFIX)

class ThreadingServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    def server_bind(self):
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        http.server.HTTPServer.server_bind(self)

if __name__ == "__main__":
    init()
    print("%s #v%s\n by: %s\n\n[i] running HTTP server at 'http://%s:%d'..." % (NAME, VERSION, AUTHOR, LISTEN_ADDRESS, LISTEN_PORT))
    try:
        ThreadingServer((LISTEN_ADDRESS, LISTEN_PORT), ReqHandler).serve_forever()
    except KeyboardInterrupt:
        pass
    except Exception as ex:
        print("[x] exception occurred ('%s')" % ex)
    finally:
        os._exit(0)
