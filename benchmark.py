#!/usr/bin/env python3

import socket
import ssl
import json
import hashlib
import hmac
import struct
import time
import os
import sys
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import datetime

BASE_DIR  = os.path.dirname(os.path.abspath(__file__))
CERT_FILE = os.path.join(BASE_DIR, "certs/server.crt")


def send_msg(conn, payload):
    raw   = json.dumps(payload).encode()
    frame = struct.pack(">I", len(raw)) + raw
    conn.sendall(frame)

def recv_msg(conn):
    def recvexact(n):
        buf = b""
        while len(buf) < n:
            c = conn.recv(n - len(buf))
            if not c:
                return None
            buf += c
        return buf
    h = recvexact(4)
    if not h:
        return None
    return json.loads(recvexact(struct.unpack(">I", h)[0]).decode())


def create_session(host, port, username, password, insecure):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    if insecure:
        ctx.check_hostname = False
        ctx.verify_mode    = ssl.CERT_NONE
    else:
        ctx.load_verify_locations(CERT_FILE)

    raw  = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    raw.connect((host, port))
    conn = ctx.wrap_socket(raw, server_hostname=host)

    msg      = recv_msg(conn)
    nonce    = msg["nonce"]
    pw_hash  = hashlib.sha256(password.encode()).hexdigest()
    response = hmac.new(pw_hash.encode(), nonce.encode(), hashlib.sha256).hexdigest()
    send_msg(conn, {"type": "AUTH_RESPONSE", "username": username, "response": response})
    recv_msg(conn)
    return conn


BENCH_COMMANDS = ["echo hello", "hostname", "whoami", "echo test", "echo done", "ver"]

def bench_session(host, port, username, password, n_cmds, insecure):
    rtts = []
    try:
        conn = create_session(host, port, username, password, insecure)
        for i in range(n_cmds):
            cmd = BENCH_COMMANDS[i % len(BENCH_COMMANDS)]
            t0  = time.perf_counter()
            send_msg(conn, {"type": "COMMAND", "cmd": cmd})
            recv_msg(conn)
            rtts.append((time.perf_counter() - t0) * 1000)
        send_msg(conn, {"type": "COMMAND", "cmd": "QUIT"})
        conn.close()
    except Exception as e:
        print(f"Session error: {e}", file=sys.stderr)
    return rtts


def run_scenario(label, host, port, username, password, insecure, n_clients, n_cmds):
    all_rtts = []
    t_start  = time.perf_counter()

    with ThreadPoolExecutor(max_workers=n_clients) as ex:
        futures = [
            ex.submit(bench_session, host, port, username, password, n_cmds, insecure)
            for _ in range(n_clients)
        ]
        for f in as_completed(futures):
            all_rtts.extend(f.result())

    wall      = time.perf_counter() - t_start
    total_cmd = len(all_rtts)

    if not all_rtts:
        print(f"  {label}: no results collected")
        return

    avg        = sum(all_rtts) / len(all_rtts)
    throughput = total_cmd / wall

    print(f"\n  [{label}]")
    print(f"    Clients         : {n_clients}")
    print(f"    Commands/client : {n_cmds}")
    print(f"    Total commands  : {total_cmd}")
    print(f"    Wall time       : {wall:.3f} s")
    print(f"    Throughput      : {throughput:.2f} cmd/s")
    print(f"    Avg RTT         : {avg:.2f} ms")
    print(f"    Min RTT         : {min(all_rtts):.2f} ms")
    print(f"    Max RTT         : {max(all_rtts):.2f} ms")


def main():
    ap = argparse.ArgumentParser(description="Secure RCE Benchmark")
    ap.add_argument("--host",     default="127.0.0.1")
    ap.add_argument("--port",     type=int, default=9000)
    ap.add_argument("--user",     default="admin")
    ap.add_argument("--password", default="admin123")
    ap.add_argument("--insecure", action="store_true")
    args = ap.parse_args()

    print("=" * 52)
    print("  SECURE RCE - PERFORMANCE BENCHMARK")
    print(f"  Target : {args.host}:{args.port}")
    print(f"  Time   : {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 52)

    scenarios = [
        ("Latency Baseline (1 client  x 20 cmds)",  1, 20),
        ("Low Concurrency  (5 clients x 10 cmds)",  5, 10),
        ("Med Concurrency  (10 clients x 5 cmds)", 10,  5),
        ("High Concurrency (20 clients x 5 cmds)", 20,  5),
    ]

    for label, nc, cpc in scenarios:
        run_scenario(label, args.host, args.port,
                     args.user, args.password, args.insecure, nc, cpc)

    print(f"\n{'=' * 52}")


if __name__ == "__main__":
    main()