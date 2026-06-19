from transport.legacy.unity_connection import UnityConnection
import sys
import json
import struct
import socket
import threading
import time
import select
from pathlib import Path

import pytest

# locate server src dynamically to avoid hardcoded layout assumptions
ROOT = Path(__file__).resolve().parents[2]  # tests/integration -> tests -> Server
candidates = [
    ROOT / "src",
]
SRC = next((p for p in candidates if p.exists()), None)
if SRC is None:
    searched = "\n".join(str(p) for p in candidates)
    pytest.skip(
        "MCP for Unity server source not found. Tried:\n" + searched,
        allow_module_level=True,
    )
# Tests can now import directly from parent package


def start_dummy_server(greeting: bytes, respond_ping: bool = False):
    """Start a minimal TCP server for handshake tests."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    sock.listen(1)
    port = sock.getsockname()[1]
    ready = threading.Event()

    def _run():
        ready.set()
        conn, _ = sock.accept()
        conn.settimeout(1.0)
        if greeting:
            conn.sendall(greeting)
        if respond_ping:
            try:
                # Read exactly n bytes helper
                def _read_exact(n: int) -> bytes:
                    buf = b""
                    while len(buf) < n:
                        chunk = conn.recv(n - len(buf))
                        if not chunk:
                            break
                        buf += chunk
                    return buf

                # Complete the bridge auth handshake (harden/security, R4): the
                # client's first framed message is {"auth_token": ...}. This stub
                # doesn't validate the token (that's covered elsewhere) — it just
                # acks success so connect() proceeds and the framing path can be tested.
                auth_header = _read_exact(8)
                if len(auth_header) == 8:
                    auth_len = struct.unpack(">Q", auth_header)[0]
                    _read_exact(auth_len)  # consume the auth frame
                    ack = b'{"status":"success","result":{"message":"authenticated"}}'
                    conn.sendall(struct.pack(">Q", len(ack)) + ack)

                header = _read_exact(8)
                if len(header) == 8:
                    length = struct.unpack(">Q", header)[0]
                    payload = _read_exact(length)
                    if payload == b'{"type":"ping"}':
                        resp = b'{"type":"pong"}'
                        conn.sendall(struct.pack(">Q", len(resp)) + resp)
            except Exception:
                pass
        time.sleep(0.1)
        try:
            conn.close()
        except Exception:
            pass
        finally:
            sock.close()

    threading.Thread(target=_run, daemon=True).start()
    ready.wait()
    return port


def start_handshake_enforcing_server():
    """Server that drops connection if client sends data before handshake."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    sock.listen(1)
    port = sock.getsockname()[1]
    ready = threading.Event()

    def _run():
        ready.set()
        conn, _ = sock.accept()
        # If client sends any data before greeting, disconnect (poll briefly)
        try:
            conn.setblocking(False)
            deadline = time.time() + 0.15  # short, reduces race with legitimate clients
            while time.time() < deadline:
                r, _, _ = select.select([conn], [], [], 0.01)
                if r:
                    try:
                        peek = conn.recv(1, socket.MSG_PEEK)
                    except BlockingIOError:
                        peek = b""
                    except Exception:
                        peek = b"\x00"
                    if peek:
                        conn.close()
                        sock.close()
                        return
            # No pre-handshake data observed; send greeting
            conn.setblocking(True)
            conn.sendall(b"MCP/0.1 FRAMING=1\n")
            time.sleep(0.1)
        finally:
            try:
                conn.close()
            finally:
                sock.close()

    threading.Thread(target=_run, daemon=True).start()
    ready.wait()
    return port


def test_handshake_requires_framing():
    port = start_dummy_server(b"MCP/0.1\n")
    conn = UnityConnection(host="127.0.0.1", port=port)
    assert conn.connect() is False
    assert conn.sock is None


def test_small_frame_ping_pong():
    port = start_dummy_server(b"MCP/0.1 FRAMING=1\n", respond_ping=True)
    conn = UnityConnection(host="127.0.0.1", port=port)
    try:
        assert conn.connect() is True
        assert conn.use_framing is True
        payload = b'{"type":"ping"}'
        conn.sock.sendall(struct.pack(">Q", len(payload)) + payload)
        resp = conn.receive_full_response(conn.sock)
        assert json.loads(resp.decode("utf-8"))["type"] == "pong"
    finally:
        conn.disconnect()


def test_unframed_data_disconnect():
    port = start_handshake_enforcing_server()
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect(("127.0.0.1", port))
    sock.settimeout(1.0)
    sock.sendall(b"BAD")
    time.sleep(0.4)
    try:
        data = sock.recv(1024)
        assert data == b""
    except (ConnectionResetError, ConnectionAbortedError):
        # Some platforms raise instead of returning empty bytes when the
        # server closes the connection after detecting pre-handshake data.
        pass
    finally:
        sock.close()


def test_zero_length_payload_heartbeat():
    # Server that sends handshake and a zero-length heartbeat frame followed by a pong payload
    import socket
    import struct
    import threading
    import time

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    sock.listen(1)
    port = sock.getsockname()[1]
    ready = threading.Event()

    def _run():
        ready.set()
        conn, _ = sock.accept()
        conn.settimeout(1.0)
        try:
            conn.sendall(b"MCP/0.1 FRAMING=1\n")
            time.sleep(0.02)

            # Complete the bridge auth handshake (harden/security, R4) before the
            # heartbeat/pong sequence so connect() proceeds.
            def _read_exact(n: int) -> bytes:
                buf = b""
                while len(buf) < n:
                    chunk = conn.recv(n - len(buf))
                    if not chunk:
                        break
                    buf += chunk
                return buf

            auth_header = _read_exact(8)
            if len(auth_header) == 8:
                auth_len = struct.unpack(">Q", auth_header)[0]
                _read_exact(auth_len)  # consume the auth frame
                ack = b'{"status":"success","result":{"message":"authenticated"}}'
                conn.sendall(struct.pack(">Q", len(ack)) + ack)

            # Heartbeat frame (length=0)
            conn.sendall(struct.pack(">Q", 0))
            time.sleep(0.02)
            # Real payload frame
            payload = b'{"type":"pong"}'
            conn.sendall(struct.pack(">Q", len(payload)) + payload)
            time.sleep(0.02)
        finally:
            try:
                conn.close()
            except Exception:
                pass
            sock.close()

    threading.Thread(target=_run, daemon=True).start()
    ready.wait()

    conn = UnityConnection(host="127.0.0.1", port=port)
    try:
        assert conn.connect() is True
        # Receive should skip heartbeat and return the pong payload (or empty if only heartbeats seen)
        resp = conn.receive_full_response(conn.sock)
        assert resp in (b'{"type":"pong"}', b"")
    finally:
        conn.disconnect()


def start_auth_enforcing_bridge(expected_token: str):
    """In-process stand-in for the hardened Unity bridge (StdioBridgeHost).

    Mirrors the auth gate exactly: it greets with FRAMING=1, then requires the
    client's FIRST framed message to be {"auth_token": <expected_token>}. A wrong
    or missing token is denied and the connection closed — same as the real gate.
    Only after a successful auth does it answer a framed ``ping`` with a framed
    pong. Accepts repeated connections until ``stop`` is set.

    Returns ``(port, stop)`` where ``stop`` is a threading.Event.
    """
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.bind(("127.0.0.1", 0))
    srv.listen(8)
    srv.settimeout(0.2)
    port = srv.getsockname()[1]
    stop = threading.Event()

    def _read_exact(conn, n: int):
        buf = b""
        while len(buf) < n:
            chunk = conn.recv(n - len(buf))
            if not chunk:
                return None
            buf += chunk
        return buf

    def _serve_one(conn):
        try:
            conn.settimeout(1.0)
            conn.sendall(b"WELCOME UNITY-MCP 1 FRAMING=1\n")

            # Auth gate: first framed message must be a valid {"auth_token": ...}
            header = _read_exact(conn, 8)
            if header is None:
                return
            body = _read_exact(conn, struct.unpack(">Q", header)[0]) or b""
            try:
                presented = json.loads(body.decode("utf-8")).get("auth_token")
            except Exception:
                presented = None
            if presented != expected_token:
                deny = b'{"status":"error","error":"unauthorized: invalid or missing bridge token"}'
                conn.sendall(struct.pack(">Q", len(deny)) + deny)
                return
            ack = b'{"status":"success","result":{"message":"authenticated"}}'
            conn.sendall(struct.pack(">Q", len(ack)) + ack)

            # Command loop (single round-trip is enough for the probe): pong a ping.
            header = _read_exact(conn, 8)
            if header is None:
                return
            cmd = _read_exact(conn, struct.unpack(">Q", header)[0]) or b""
            if cmd.strip() == b"ping":
                pong = b'{"status":"success","result":{"message":"pong"}}'
                conn.sendall(struct.pack(">Q", len(pong)) + pong)
        except Exception:
            pass
        finally:
            try:
                conn.close()
            except Exception:
                pass

    def _run():
        try:
            while not stop.is_set():
                try:
                    conn, _ = srv.accept()
                except socket.timeout:
                    continue
                except OSError:
                    break
                _serve_one(conn)
        finally:
            try:
                srv.close()
            except Exception:
                pass

    threading.Thread(target=_run, daemon=True).start()
    return port, stop


def test_probe_authenticates_against_hardened_gate(monkeypatch):
    """Regression: the discovery probe must present the bridge token before ping.

    Before the fix, _try_probe_unity_mcp sent a bare framed ``ping`` as its first
    frame. The hardened bridge rejects any unauthenticated connection, so the probe
    was denied and discovery reported the live, healthy port as dead (0 instances).
    """
    from transport.legacy.port_discovery import PortDiscovery

    token = "regression-bridge-token-abc123"
    monkeypatch.setenv("UNITY_MCP_BRIDGE_TOKEN", token)
    port, stop = start_auth_enforcing_bridge(token)
    try:
        assert PortDiscovery._try_probe_unity_mcp(port) is True
    finally:
        stop.set()


def test_probe_rejected_on_token_mismatch(monkeypatch):
    """The probe genuinely presents the token: a wrong token is rejected by the gate.

    This guards against a "fix" that makes the probe pass by ignoring auth rather
    than by actually authenticating.
    """
    from transport.legacy.port_discovery import PortDiscovery

    monkeypatch.setenv("UNITY_MCP_BRIDGE_TOKEN", "the-wrong-token")
    port, stop = start_auth_enforcing_bridge("the-expected-token")
    try:
        assert PortDiscovery._try_probe_unity_mcp(port) is False
    finally:
        stop.set()


def test_discovery_finds_instance_behind_auth_gate(monkeypatch, tmp_path):
    """End-to-end discovery against the hardened gate.

    A status file points discovery at an auth-enforcing bridge. Discovery probes
    the port while enumerating instances; the probe must authenticate for the
    instance to be surfaced. Before the fix this returned 0 instances.
    """
    from datetime import datetime, timezone
    from transport.legacy.port_discovery import PortDiscovery

    token = "regression-bridge-token-xyz789"
    monkeypatch.setenv("UNITY_MCP_BRIDGE_TOKEN", token)
    # PortDiscovery.get_registry_dir() honors UNITY_MCP_STATUS_DIR.
    monkeypatch.setenv("UNITY_MCP_STATUS_DIR", str(tmp_path))
    port, stop = start_auth_enforcing_bridge(token)
    try:
        status = {
            "unity_port": port,
            "reason": "ready",
            "project_path": "/tmp/MyProj/Assets",
            "project_name": "MyProj",
            "last_heartbeat": datetime.now(timezone.utc).isoformat(),
        }
        (tmp_path / "unity-mcp-status-deadbeef.json").write_text(json.dumps(status))

        instances = PortDiscovery.discover_all_unity_instances()
        assert len(instances) == 1
        assert instances[0].port == port
    finally:
        stop.set()


