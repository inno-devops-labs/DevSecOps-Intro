#!/usr/bin/env python3
import socket
import ssl
import time

host = "127.0.0.1"
port = 8443
ctx = ssl._create_unverified_context()

started = time.monotonic()
with socket.create_connection((host, port), timeout=5) as raw:
    with ctx.wrap_socket(raw, server_hostname="localhost") as tls:
        tls.settimeout(15)
        tls.sendall(b"GET / HTTP/1.1\r\nHost: localhost\r\n")
        try:
            data = tls.recv(4096)
            elapsed = time.monotonic() - started
            if data:
                print(f"Connection closed/responded after {elapsed:.1f}s")
                print(data.decode("utf-8", errors="replace").strip())
            else:
                print(f"Connection closed by Nginx after {elapsed:.1f}s with no response body")
        except (socket.timeout, ssl.SSLError) as exc:
            elapsed = time.monotonic() - started
            print(f"TLS connection ended after {elapsed:.1f}s: {type(exc).__name__}: {exc}")
