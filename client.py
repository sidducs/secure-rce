#!/usr/bin/env python3

import socket
import ssl
import json
import hashlib
import hmac
import struct
import time
import sys
import os
import argparse
import getpass

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 9000
BASE_DIR     = os.path.dirname(os.path.abspath(__file__))
CERT_FILE    = os.path.join(BASE_DIR, "certs/server.crt")


def send_msg(conn, payload):
    try:
        raw   = json.dumps(payload).encode()
        frame = struct.pack(">I", len(raw)) + raw
        conn.sendall(frame)
    except (BrokenPipeError, ssl.SSLError, OSError) as e:
        raise ConnectionError(f"Send failed: {e}")

def recv_msg(conn):
    def recvexact(n):
        buf = b""
        while len(buf) < n:
            try:
                chunk = conn.recv(n - len(buf))
            except (ssl.SSLError, OSError) as e:
                raise ConnectionError(f"Recv failed: {e}")
            if not chunk:
                return None
            buf += chunk
        return buf

    header = recvexact(4)
    if header is None:
        return None
    length = struct.unpack(">I", header)[0]
    body   = recvexact(length)
    if body is None:
        return None
    try:
        return json.loads(body.decode())
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid JSON from server: {e}")


def login(conn, username, password):
    try:
        msg = recv_msg(conn)
        if msg is None or msg.get("type") != "AUTH_CHALLENGE":
            print("Error: No challenge received from server.")
            return False

        nonce    = msg.get("nonce", "")
        if not nonce:
            print("Error: Empty nonce received.")
            return False

        pw_hash  = hashlib.sha256(password.encode()).hexdigest()
        response = hmac.new(pw_hash.encode(), nonce.encode(), hashlib.sha256).hexdigest()

        send_msg(conn, {"type": "AUTH_RESPONSE", "username": username, "response": response})

        msg = recv_msg(conn)
        if msg is None:
            print("Error: No auth result received.")
            return False

        if msg.get("type") == "AUTH_OK":
            print(msg.get("welcome", "Authenticated."))
            return True
        else:
            print(f"Auth failed: {msg.get('reason', 'unknown')}")
            return False

    except (ConnectionError, ValueError) as e:
        print(f"Auth error: {e}")
        return False


def run_shell(conn):
    total_cmds = 0
    total_ms   = 0.0

    print("\nType commands to execute remotely. Type 'quit' to exit.\n")
    while True:
        try:
            cmd = input("srce> ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            cmd = "quit"

        if not cmd:
            continue

        if cmd.lower() in ("quit", "exit"):
            try:
                send_msg(conn, {"type": "COMMAND", "cmd": "QUIT"})
            except ConnectionError:
                pass
            break

        try:
            t0 = time.perf_counter()
            send_msg(conn, {"type": "COMMAND", "cmd": cmd})
            msg    = recv_msg(conn)
            rtt_ms = (time.perf_counter() - t0) * 1000
        except ConnectionError as e:
            print(f"Connection lost: {e}")
            break
        except ValueError as e:
            print(f"Invalid response: {e}")
            continue

        if msg is None:
            print("Connection closed by server.")
            break

        mtype = msg.get("type")

        if mtype == "RESULT":
            stdout = msg.get("stdout", "")
            stderr = msg.get("stderr", "")
            rc     = msg.get("returncode", -1)

            if stdout:
                print(stdout, end="" if stdout.endswith("\n") else "\n")
            if stderr:
                print(f"[stderr] {stderr}", end="" if stderr.endswith("\n") else "\n")

            print(f"  [rc={rc}  server={msg.get('elapsed_ms', 0)}ms  rtt={rtt_ms:.2f}ms]")
            total_cmds += 1
            total_ms   += rtt_ms

        elif mtype == "ERROR":
            print(f"Server error: {msg.get('reason', 'unknown')}")

        else:
            print(f"Unexpected response type: {mtype}")

    if total_cmds > 0:
        print(f"\n--- Session Performance ---")
        print(f"  Commands  : {total_cmds}")
        print(f"  Avg RTT   : {total_ms / total_cmds:.2f} ms")
        print(f"  Total RTT : {total_ms:.2f} ms")
        print(f"---------------------------")


def main():
    ap = argparse.ArgumentParser(description="Secure RCE Client")
    ap.add_argument("--host",     default=DEFAULT_HOST)
    ap.add_argument("--port",     type=int, default=DEFAULT_PORT)
    ap.add_argument("--user",     default=None)
    ap.add_argument("--password", default=None)
    ap.add_argument("--insecure", action="store_true", help="Skip certificate verification")
    args = ap.parse_args()

    username = args.user     or input("Username: ")
    password = args.password or getpass.getpass("Password: ")

    if not username or not password:
        print("Error: Username and password are required.")
        sys.exit(1)

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    if args.insecure:
        ctx.check_hostname = False
        ctx.verify_mode    = ssl.CERT_NONE
        print("Warning: Certificate verification disabled.")
    else:
        try:
            ctx.load_verify_locations(CERT_FILE)
            ctx.verify_mode = ssl.CERT_REQUIRED
        except (ssl.SSLError, FileNotFoundError) as e:
            print(f"Error loading certificate: {e}")
            print("Use --insecure to skip verification.")
            sys.exit(1)

    raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    raw.settimeout(10)

    try:
        raw.connect((args.host, args.port))
    except ConnectionRefusedError:
        print(f"Connection refused. Is the server running on {args.host}:{args.port}?")
        sys.exit(1)
    except socket.timeout:
        print(f"Connection timed out to {args.host}:{args.port}")
        sys.exit(1)
    except OSError as e:
        print(f"Connection error: {e}")
        sys.exit(1)

    try:
        conn = ctx.wrap_socket(raw, server_hostname=args.host)
    except ssl.SSLError as e:
        print(f"TLS handshake failed: {e}")
        raw.close()
        sys.exit(1)

    print(f"Connected to {args.host}:{args.port} via {conn.version()}")

    if not login(conn, username, password):
        conn.close()
        sys.exit(1)

    try:
        run_shell(conn)
    finally:
        try:
            conn.close()
        except Exception:
            pass


if __name__ == "__main__":
    main()