#!/usr/bin/env python3

import socket
import ssl
import threading
import json
import hashlib
import hmac
import os
import subprocess
import logging
import time
import struct
import sys
import argparse

BASE_DIR  = os.path.dirname(os.path.abspath(__file__))
CERT_FILE = os.path.join(BASE_DIR, "certs/server.crt")
KEY_FILE  = os.path.join(BASE_DIR, "certs/server.key")
LOG_DIR   = os.path.join(BASE_DIR, "logs")
os.makedirs(LOG_DIR, exist_ok=True)

HOST        = "0.0.0.0"
PORT        = 9000
MAX_CMD_LEN = 4096

USER_DB = {
    "admin": hashlib.sha256("admin123".encode()).hexdigest(),
    "user1": hashlib.sha256("pass1234".encode()).hexdigest(),
    "guest": hashlib.sha256("guest000".encode()).hexdigest(),
}

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    handlers=[
        logging.FileHandler(os.path.join(LOG_DIR, "audit.log")),
        logging.StreamHandler(sys.stdout),
    ]
)
log = logging.getLogger()

request_count = 0
total_time_ms = 0.0
perf_lock     = threading.Lock()


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
    if length == 0 or length > MAX_CMD_LEN:
        raise ValueError(f"Invalid message length: {length}")

    body = recvexact(length)
    if body is None:
        return None

    try:
        return json.loads(body.decode())
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid JSON: {e}")


def authenticate(conn, addr):
    try:
        nonce = os.urandom(32).hex()
        send_msg(conn, {"type": "AUTH_CHALLENGE", "nonce": nonce})

        msg = recv_msg(conn)
        if msg is None or msg.get("type") != "AUTH_RESPONSE":
            send_msg(conn, {"type": "AUTH_FAIL", "reason": "Malformed response"})
            log.warning(f"AUTH_FAIL | {addr} | malformed response")
            return None

        username = str(msg.get("username", "")).strip()
        response = str(msg.get("response", "")).strip()

        if not username or not response:
            send_msg(conn, {"type": "AUTH_FAIL", "reason": "Missing fields"})
            log.warning(f"AUTH_FAIL | {addr} | missing username or response")
            return None

        pw_hash = USER_DB.get(username)
        if pw_hash is None:
            send_msg(conn, {"type": "AUTH_FAIL", "reason": "Unknown user"})
            log.warning(f"AUTH_FAIL | {addr} | unknown user '{username}'")
            return None

        expected = hmac.new(pw_hash.encode(), nonce.encode(), hashlib.sha256).hexdigest()
        if expected != response:
            send_msg(conn, {"type": "AUTH_FAIL", "reason": "Bad credentials"})
            log.warning(f"AUTH_FAIL | {addr} | wrong password for '{username}'")
            return None

        send_msg(conn, {"type": "AUTH_OK", "welcome": f"Authenticated as {username}"})
        log.info(f"AUTH_OK | {addr} | user='{username}'")
        return username

    except (ConnectionError, ValueError) as e:
        log.warning(f"AUTH_ERROR | {addr} | {e}")
        return None


def execute_command(cmd):
    if not cmd or not cmd.strip():
        return "", "Empty command", -1

    try:
        result = subprocess.run(
            cmd, shell=True, capture_output=True, text=True, timeout=15
        )
        return result.stdout, result.stderr, result.returncode
    except subprocess.TimeoutExpired:
        return "", "Command timed out (15s limit)", -1
    except Exception as e:
        return "", f"Execution error: {e}", -2


def handle_client(raw_conn, addr):
    global request_count, total_time_ms

    log.info(f"CONNECT | {addr}")

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    try:
        ctx.load_cert_chain(CERT_FILE, KEY_FILE)
    except ssl.SSLError as e:
        log.error(f"CERT_LOAD_ERROR | {addr} | {e}")
        raw_conn.close()
        return

    try:
        conn = ctx.wrap_socket(raw_conn, server_side=True)
    except ssl.SSLError as e:
        log.warning(f"TLS_HANDSHAKE_FAIL | {addr} | {e}")
        raw_conn.close()
        return
    except OSError as e:
        log.warning(f"CONNECTION_ERROR | {addr} | {e}")
        raw_conn.close()
        return

    try:
        conn.settimeout(60)

        username = authenticate(conn, addr)
        if username is None:
            return

        while True:
            try:
                msg = recv_msg(conn)
            except ConnectionError as e:
                log.warning(f"ABRUPT_DISCONNECT | {addr} | {username} | {e}")
                break
            except ValueError as e:
                log.warning(f"INVALID_MSG | {addr} | {username} | {e}")
                try:
                    send_msg(conn, {"type": "ERROR", "reason": f"Invalid message: {e}"})
                except ConnectionError:
                    break
                continue

            if msg is None:
                log.info(f"CLIENT_CLOSED | {addr} | {username}")
                break

            if msg.get("type") != "COMMAND":
                try:
                    send_msg(conn, {"type": "ERROR", "reason": "Expected COMMAND type"})
                except ConnectionError:
                    break
                continue

            cmd = msg.get("cmd", "").strip()

            if cmd == "QUIT":
                log.info(f"QUIT | {addr} | {username}")
                break

            if not cmd:
                try:
                    send_msg(conn, {"type": "ERROR", "reason": "Empty command"})
                except ConnectionError:
                    break
                continue

            t_start            = time.perf_counter()
            stdout, stderr, rc = execute_command(cmd)
            elapsed_ms         = (time.perf_counter() - t_start) * 1000

            try:
                send_msg(conn, {
                    "type":       "RESULT",
                    "stdout":     stdout,
                    "stderr":     stderr,
                    "returncode": rc,
                    "elapsed_ms": round(elapsed_ms, 3),
                })
            except ConnectionError as e:
                log.warning(f"SEND_FAIL | {addr} | {username} | {e}")
                break

            with perf_lock:
                request_count += 1
                total_time_ms += elapsed_ms

            log.info(f"EXEC | {addr} | {username} | rc={rc} | t={elapsed_ms:.1f}ms | '{cmd}'")

    except Exception as e:
        log.error(f"UNEXPECTED_ERROR | {addr} | {e}")
    finally:
        try:
            conn.close()
        except Exception:
            pass
        log.info(f"DISCONNECT | {addr}")


def main():
    ap = argparse.ArgumentParser(description="Secure RCE Server")
    ap.add_argument("--host", default=HOST)
    ap.add_argument("--port", type=int, default=PORT)
    args = ap.parse_args()

    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    try:
        server_sock.bind((args.host, args.port))
    except OSError as e:
        print(f"Bind failed on {args.host}:{args.port} — {e}")
        sys.exit(1)

    server_sock.listen(10)
    print(f"Server listening on {args.host}:{args.port} (TLS)")
    print(f"Logs: {LOG_DIR}/audit.log")

    try:
        while True:
            try:
                raw_conn, addr = server_sock.accept()
            except OSError as e:
                log.error(f"ACCEPT_ERROR | {e}")
                continue
            t = threading.Thread(
                target=handle_client,
                args=(raw_conn, f"{addr[0]}:{addr[1]}"),
                daemon=True
            )
            t.start()

    except KeyboardInterrupt:
        print("\nShutting down...")
        with perf_lock:
            if request_count > 0:
                print(f"  Total requests : {request_count}")
                print(f"  Avg response   : {total_time_ms / request_count:.2f} ms")
            else:
                print("  No requests handled.")
        server_sock.close()


if __name__ == "__main__":
    main()