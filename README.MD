# Secure Remote Command Execution System

**Project No:** 17  
**Protocol:** TCP  
**Language:** Python 3  

---

## Problem Statement

Build a secure client-server system that allows authenticated clients to execute commands remotely and receive outputs.

---

## System Architecture

```
  CLIENT                          SERVER
  ------                          ------
  client.py                       server.py
     |                                |
     |---[ TCP Connect ]------------->|
     |<--[ TLS Handshake ]----------->|
     |                                |
     |---[ AUTH_CHALLENGE ]---------->|  (server sends nonce)
     |<--[ AUTH_RESPONSE ]------------|  (client sends HMAC)
     |---[ AUTH_OK / AUTH_FAIL ]----->|
     |                                |
     |---[ COMMAND: "ls -la" ]------->|
     |<--[ RESULT: stdout/stderr/rc ]-|  (subprocess runs cmd)
     |                                |
     |---[ COMMAND: "QUIT" ]--------->|
     |<--[ connection closed ]--------|

  benchmark.py
     |--- spawns N concurrent clients simultaneously
     |--- each client sends M commands
     |--- measures RTT, throughput, latency per scenario
```

### Components

| File | Role |
|------|------|
| `server.py` | TCP server — TLS, auth, threading, command execution, audit logging |
| `client.py` | TCP client — TLS connect, login, interactive shell, session metrics |
| `benchmark.py` | Performance tool — concurrent load testing, RTT and throughput analysis |
| `certs/` | TLS certificate and private key |
| `logs/audit.log` | All auth events and command executions logged here |

### Protocol Design

All messages use **length-prefixed JSON framing**:

```
[ 4 bytes: payload length (big-endian) ][ N bytes: JSON payload ]
```

Message types:

| Type | Direction | Description |
|------|-----------|-------------|
| AUTH_CHALLENGE | Server → Client | Random 64-char hex nonce |
| AUTH_RESPONSE  | Client → Server | username + HMAC-SHA256(nonce, SHA256(password)) |
| AUTH_OK        | Server → Client | Login success confirmation |
| AUTH_FAIL      | Server → Client | Login failure with reason |
| COMMAND        | Client → Server | Shell command string to execute |
| RESULT         | Server → Client | stdout, stderr, returncode, elapsed_ms |
| ERROR          | Server → Client | Protocol or input error message |

---

## Setup

### Step 1 — Generate TLS Certificate

```bash
openssl req -x509 -newkey rsa:2048 \
  -keyout certs/server.key \
  -out certs/server.crt \
  -days 365 -nodes \
  -subj "/CN=localhost" \
  -addext "subjectAltName=IP:127.0.0.1,DNS:localhost"
```

### Step 2 — Install Requirements

No external packages needed. Uses Python standard library only:
```
socket, ssl, threading, json, hashlib, hmac, subprocess, logging, struct
```

Python version required: **3.10 or above**

---

## Usage

### Start the Server

```bash
python3 server.py
# or with custom host/port:
python3 server.py --host 0.0.0.0 --port 9000
```

### Connect with the Client

```bash
python3 client.py
# or with arguments:
python3 client.py --host 127.0.0.1 --port 9000 --user admin --password admin123
```

### Run the Benchmark

```bash
python3 benchmark.py
# or with custom target:
python3 benchmark.py --host 127.0.0.1 --port 9000 --user admin --password admin123
```

---

## Default Credentials

| Username | Password |
|----------|----------|
| admin    | admin123 |
| user1    | pass1234 |
| guest    | guest000 |

---

## Features Implemented

### 1. Authentication Mechanism
- HMAC-SHA256 challenge-response protocol
- Server sends a random nonce each session
- Client computes `HMAC(nonce, SHA256(password))` — password never sent in plaintext
- Stored passwords are SHA-256 hashed

### 2. Structured Command Protocol
- Custom length-prefixed JSON framing over TCP
- Every message has a `type` field for clear identification
- Handles partial TCP reads correctly using `recvexact()`

### 3. Secure Data Transmission
- Full TLS encryption on every connection using Python `ssl` module
- RSA-2048 certificate with Subject Alternative Name (SAN)
- Client verifies server certificate before sending credentials

### 4. Audit Logging
- Every event written to `logs/audit.log` with timestamp
- Logged events: `CONNECT`, `AUTH_OK`, `AUTH_FAIL`, `EXEC`, `QUIT`, `DISCONNECT`
- Each log entry includes client IP, port, username, return code, and timing

### 5. Performance Overhead Analysis
- `benchmark.py` runs 4 concurrency scenarios
- Measures: throughput (cmd/s), avg/min/max RTT per scenario
- Tests: 1, 5, 10, 20 concurrent clients

---

## Edge Cases Handled

| Scenario | How It's Handled |
|----------|-----------------|
| Abrupt client disconnect | `ConnectionError` caught in `recv_msg`, logged as `ABRUPT_DISCONNECT` |
| SSL handshake failure | `ssl.SSLError` caught in `wrap_socket`, logged as `TLS_HANDSHAKE_FAIL` |
| Invalid JSON message | `json.JSONDecodeError` caught, `ERROR` response sent to client |
| Empty or oversized message | Length validated before read (`0 < length <= 4096`) |
| Empty command input | Checked before `subprocess.run`, `ERROR` response sent |
| Command timeout | `subprocess.TimeoutExpired` caught after 15 seconds |
| Port already in use | `OSError` caught on `bind`, clear error message shown |
| Wrong certificate path | `FileNotFoundError` caught on `load_verify_locations` |
| Client sends wrong message type | Validated and `ERROR` response sent |
| Missing auth fields | Username/response checked for empty before HMAC verification |

---

## Audit Log Sample

```
2026-02-20 09:00:01 | INFO     | CONNECT | 127.0.0.1:52341
2026-02-20 09:00:01 | INFO     | AUTH_OK | 127.0.0.1:52341 | user='admin'
2026-02-20 09:00:03 | INFO     | EXEC | 127.0.0.1:52341 | admin | rc=0 | t=6.2ms | 'ls -la'
2026-02-20 09:00:05 | WARNING  | AUTH_FAIL | 127.0.0.1:52342 | wrong password for 'admin'
2026-02-20 09:00:07 | WARNING  | ABRUPT_DISCONNECT | 127.0.0.1:52343 | admin | Recv failed
2026-02-20 09:00:09 | INFO     | QUIT | 127.0.0.1:52341 | admin
2026-02-20 09:00:09 | INFO     | DISCONNECT | 127.0.0.1:52341
```

---

## Performance Results (Sample)

| Scenario | Throughput | Avg RTT | Min RTT | Max RTT |
|----------|-----------|---------|---------|---------|
| 1 client  × 20 cmds | ~111 cmd/s | ~8 ms  | ~3 ms | ~24 ms |
| 5 clients × 10 cmds | ~247 cmd/s | ~18 ms | ~6 ms | ~29 ms |
| 10 clients × 5 cmds | ~212 cmd/s | ~39 ms | ~19 ms | ~54 ms |
| 20 clients × 5 cmds | ~221 cmd/s | ~66 ms | ~18 ms | ~94 ms |

---

## GitHub Repository Structure

```
secure-rce/
├── server.py
├── client.py
├── benchmark.py
├── README.md
├── certs/
│   ├── server.crt
│   └── server.key
└── logs/
    └── audit.log
```

---

