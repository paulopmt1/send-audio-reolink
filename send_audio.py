#!/usr/bin/env python3
"""
Minimal ONVIF Audio Backchannel sender for Reolink doorbells (and similar RTSP devices).

Requires: Python 3.9+, ffmpeg in PATH.

Example:
  python send_audio.py \\
    --camera rtsp://admin:pass@192.168.1.50:554/h264Preview_01_main \\
    --url https://samplelib.com/mp3/sample-3s.mp3 \\
    --low-latency
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import re
import secrets
import socket
import struct
import subprocess
import sys
import threading
from typing import Optional
from urllib.parse import unquote, urlparse, urlunparse


def _parse_rtsp_url(camera: str) -> tuple[str, str, str, str, int]:
    """Return (user, password, host, path, port). Path includes leading /."""
    u = urlparse(camera)
    if u.scheme not in ("rtsp", "rtsps"):
        raise SystemExit(f"Unsupported scheme: {u.scheme} (need rtsp://)")
    user = unquote(u.username or "")
    password = unquote(u.password or "")
    host = u.hostname or ""
    if not host:
        raise SystemExit("Invalid --camera: missing host")
    port = u.port or 554
    path = u.path or "/"
    if not path.startswith("/"):
        path = "/" + path
    return user, password, host, path, port


def _make_rtsp_request_uri(host: str, port: int, path: str) -> str:
    """Absolute RTSP URI without userinfo (Digest uri= must match request line)."""
    return f"rtsp://{host}:{port}{path}"


class RtspClient:
    def __init__(
        self,
        sock: socket.socket,
        user: str,
        password: str,
        base_uri: str,
        debug: bool = False,
    ) -> None:
        self.sock = sock
        self.user = user
        self.password = password
        self.base_uri = base_uri
        self.debug = debug
        self._cseq = 0
        self.session: Optional[str] = None
        self._digest_realm: Optional[str] = None
        self._digest_nonce: Optional[str] = None
        self._digest_opaque: Optional[str] = None
        self._digest_stale: bool = False
        self._digest_qop: Optional[str] = None
        self._digest_nc = 0
        self._use_basic: bool = False

    def _log(self, msg: str) -> None:
        if self.debug:
            print(msg, file=sys.stderr)

    def _recv_until_headers(self) -> tuple[int, dict[str, str], bytes]:
        buf = bytearray()
        while True:
            self._strip_leading_interleaved(buf)
            if buf.startswith(b"RTSP") and b"\r\n\r\n" in buf:
                break
            chunk = self.sock.recv(4096)
            if not chunk:
                raise RuntimeError("RTSP connection closed while reading headers")
            buf.extend(chunk)
            if len(buf) > 1024 * 1024:
                raise RuntimeError("RTSP response headers too large")
        idx = buf.find(b"\r\n\r\n")
        if idx < 0:
            raise RuntimeError("Incomplete RTSP response")
        header_bytes = bytes(buf[: idx + 4])
        rest = bytes(buf[idx + 4 :])

        lines = header_bytes.decode("latin-1", errors="replace").split("\r\n")
        status_line = lines[0]
        m = re.match(r"RTSP/\d\.\d\s+(\d+)", status_line)
        status = int(m.group(1)) if m else 0

        headers: dict[str, str] = {}
        for line in lines[1:]:
            if not line:
                continue
            if ":" in line:
                k, v = line.split(":", 1)
                headers[k.strip().lower()] = v.strip()

        content_length = int(headers.get("content-length", "0") or "0")
        body = rest
        while len(body) < content_length:
            chunk = self.sock.recv(max(4096, content_length - len(body)))
            if not chunk:
                raise RuntimeError("Short read on RTSP body")
            body += chunk

        return status, headers, body[:content_length]

    def _strip_leading_interleaved(self, buf: bytearray) -> None:
        """Remove RTP-over-RTSP interleaved frames ($ + 1 byte channel + 2 byte size + payload)."""
        while len(buf) >= 4 and buf[0] == ord("$"):
            sz = int.from_bytes(buf[2:4], "big")
            if len(buf) < 4 + sz:
                return
            del buf[: 4 + sz]

    def _digest_challenge(self, headers: dict[str, str]) -> None:
        www = headers.get("www-authenticate", "")
        if "Digest" not in www:
            return
        def grab(key: str) -> Optional[str]:
            mm = re.search(rf'{key}="([^"]*)"', www)
            return mm.group(1) if mm else None

        self._digest_realm = grab("realm")
        self._digest_nonce = grab("nonce")
        self._digest_opaque = grab("opaque")
        self._digest_stale = grab("stale") == "true"
        qq = re.search(r'qop="([^"]*)"', www)
        self._digest_qop = qq.group(1) if qq else None

    def _digest_authorization(self, method: str, uri: str) -> Optional[str]:
        if not self.user or not self._digest_realm or not self._digest_nonce:
            return None
        realm = self._digest_realm
        nonce = self._digest_nonce
        ha1 = hashlib.md5(f"{self.user}:{realm}:{self.password}".encode()).hexdigest()
        ha2 = hashlib.md5(f"{method}:{uri}".encode()).hexdigest()

        parts = [
            f'username="{self.user}"',
            f'realm="{realm}"',
            f'nonce="{nonce}"',
            f'uri="{uri}"',
        ]
        if self._digest_qop:
            qop = self._digest_qop.split(",")[0].strip()
            self._digest_nc += 1
            nc = f"{self._digest_nc:08x}"
            cnonce = secrets.token_hex(8)
            response = hashlib.md5(
                f"{ha1}:{nonce}:{nc}:{cnonce}:{qop}:{ha2}".encode()
            ).hexdigest()
            parts.extend(
                [
                    f'response="{response}"',
                    f"qop={qop}",
                    f"nc={nc}",
                    f'cnonce="{cnonce}"',
                ]
            )
        else:
            response = hashlib.md5(f"{ha1}:{nonce}:{ha2}".encode()).hexdigest()
            parts.append(f'response="{response}"')
        if self._digest_opaque:
            parts.append(f'opaque="{self._digest_opaque}"')
        return "Digest " + ", ".join(parts)

    def _basic_authorization(self) -> str:
        raw = f"{self.user}:{self.password}".encode()
        return "Basic " + base64.b64encode(raw).decode("ascii")

    def request(
        self,
        method: str,
        uri: str,
        extra_headers: Optional[dict[str, str]] = None,
        body: Optional[bytes] = None,
    ) -> tuple[int, dict[str, str], bytes]:
        """Send RTSP request; on 401 parse challenge and retry (Digest or Basic)."""
        extra_headers = extra_headers or {}
        last: tuple[int, dict[str, str], bytes] = (0, {}, b"")

        for _ in range(8):
            self._cseq += 1
            lines = [
                f"{method} {uri} RTSP/1.0",
                f"CSeq: {self._cseq}",
                "User-Agent: send_audio.py/1.0",
            ]
            if self.session:
                lines.append(f"Session: {self.session}")
            if body is not None:
                lines.append(f"Content-Length: {len(body)}")
            for k, v in extra_headers.items():
                lines.append(f"{k}: {v}")
            if self.user:
                if self._use_basic:
                    lines.append(f"Authorization: {self._basic_authorization()}")
                elif self._digest_realm and self._digest_nonce:
                    auth = self._digest_authorization(method, uri)
                    if auth:
                        lines.append(f"Authorization: {auth}")
            lines.append("")
            msg = "\r\n".join(lines).encode("latin-1") + b"\r\n"
            if body:
                msg += body

            self._log(f">>> {method} {uri}")
            self.sock.sendall(msg)

            status, headers, resp_body = self._recv_until_headers()
            self._log(f"<<< {status} ({method} {uri})")

            if status != 401:
                return status, headers, resp_body

            www = headers.get("www-authenticate", "")
            if "Digest" in www:
                self._digest_challenge(headers)
            if "Basic" in www and self.user:
                self._use_basic = True
            if not self.user:
                raise RuntimeError("RTSP 401 but no credentials in --camera URL")

        raise RuntimeError("Too many RTSP 401 responses (check credentials)")

    def options(self, uri: str) -> None:
        status, _, _ = self.request("OPTIONS", uri)
        if status not in (200, 404):
            raise RuntimeError(f"OPTIONS failed: {status}")

    def describe(self, uri: str) -> tuple[str, dict[str, str]]:
        status, headers, body = self.request(
            "DESCRIBE",
            uri,
            {
                "Accept": "application/sdp",
                "Require": "www.onvif.org/ver20/backchannel",
            },
        )
        if status != 200:
            raise RuntimeError(f"DESCRIBE failed: {status}")
        sdp = body.decode("utf-8", errors="replace")
        return sdp, headers

    def setup(self, track_uri: str, interleaved: tuple[int, int]) -> None:
        transport = (
            f"RTP/AVP/TCP;unicast;interleaved={interleaved[0]}-{interleaved[1]}"
        )
        status, headers, _ = self.request(
            "SETUP",
            track_uri,
            {"Transport": transport},
        )
        if status != 200:
            raise RuntimeError(f"SETUP failed: {status}")
        sess = headers.get("session", "")
        if sess:
            self.session = sess.split(";")[0].strip()

    def play(self, uri: str) -> None:
        status, _, _ = self.request("PLAY", uri, {"Range": "npt=0.000-"})
        if status != 200:
            raise RuntimeError(f"PLAY failed: {status}")

    def teardown(self, uri: str) -> None:
        try:
            self.request("TEARDOWN", uri)
        except OSError:
            pass


def _sdp_media_blocks(sdp: str) -> list[str]:
    lines = sdp.replace("\r\n", "\n").split("\n")
    blocks: list[str] = []
    cur: list[str] = []
    for line in lines:
        if line.startswith("m="):
            if cur:
                blocks.append("\n".join(cur))
            cur = [line]
        elif cur:
            cur.append(line)
    if cur:
        blocks.append("\n".join(cur))
    return blocks


def list_all_track_setups(sdp: str, content_base: str) -> list[tuple[str, tuple[int, int]]]:
    """SETUP each m= block in SDP order (same interleaved mapping as go2rtc)."""
    blocks = _sdp_media_blocks(sdp)
    out: list[tuple[str, tuple[int, int]]] = []
    for i, block in enumerate(blocks):
        if not block.startswith("m="):
            continue
        ctrl: Optional[str] = None
        for line in block.splitlines():
            ls = line.strip()
            if ls.startswith("a=control:"):
                ctrl = ls.split(":", 1)[1].strip()
                break
        if not ctrl:
            continue
        tu = _resolve_track_uri(content_base, ctrl)
        out.append((tu, (i * 2, i * 2 + 1)))
    return out


def _resolve_track_uri(content_base: str, control: str) -> str:
    if control.startswith("rtsp://") or control.startswith("rtsps://"):
        return control
    if control == "*":
        return content_base.rstrip("/")
    bu = urlparse(content_base)
    if control.startswith("/"):
        return urlunparse((bu.scheme, bu.netloc, control, "", "", ""))
    base_path = bu.path.rstrip("/")
    new_path = f"{base_path}/{control}" if base_path else "/" + control
    return urlunparse((bu.scheme, bu.netloc, new_path, "", "", ""))


def parse_backchannel_track(
    sdp: str, describe_headers: dict[str, str], request_uri: str
) -> tuple[str, str, int, tuple[int, int], str]:
    """
    Find audio sendonly track, resolve SETUP URL, ffmpeg format (alaw/mulaw),
    RTP payload type, interleaved channel pair, and aggregate PLAY URI.
    """
    content_base = describe_headers.get("content-base", "").strip()
    if not content_base:
        content_base = request_uri
    # Aggregate PLAY uses trailing slash (matches libav/ffmpeg against Reolink).
    play_uri = content_base.rstrip("/") + "/"

    blocks = _sdp_media_blocks(sdp)
    for idx, block in enumerate(blocks):
        if not block.startswith("m=audio"):
            continue
        if "a=sendonly" not in block and "a=sendrecv" not in block:
            continue

        first = block.split("\n", 1)[0].strip()
        parts = first.split()
        enc: Optional[str] = None
        rate: Optional[int] = None
        payload_type: Optional[int] = None

        if len(parts) >= 4 and parts[2] == "RTP/AVP":
            pts = []
            for x in parts[3:]:
                try:
                    pts.append(int(x))
                except ValueError:
                    pass
            for pt in pts:
                if pt == 8:
                    enc, rate, payload_type = "PCMA", 8000, 8
                    break
                if pt == 0:
                    enc, rate, payload_type = "PCMU", 8000, 0
                    break
            if enc is None:
                for pt in pts:
                    rm = re.search(rf"a=rtpmap:{pt}\s+([\w.-]+)/(\d+)", block)
                    if not rm:
                        continue
                    name = rm.group(1).upper().replace(".", "")
                    rate = int(rm.group(2))
                    if "PCMA" in name or "G711A" in name or name == "G711ALAW":
                        enc = "PCMA"
                        payload_type = pt
                        break
                    if "PCMU" in name or "G711U" in name or name == "G711MULAW":
                        enc = "PCMU"
                        payload_type = pt
                        break

        if enc is None or rate is None or payload_type is None:
            continue

        if rate != 8000:
            raise RuntimeError(f"Expected 8000 Hz audio backchannel, got {rate}")

        if enc == "PCMA":
            ff_fmt = "alaw"
        elif enc == "PCMU":
            ff_fmt = "mulaw"
        else:
            raise RuntimeError(f"Unsupported audio encoding: {enc}")

        ctrl = None
        for line in block.splitlines():
            line = line.strip()
            if line.startswith("a=control:"):
                ctrl = line.split(":", 1)[1].strip()
                break
        if not ctrl:
            raise RuntimeError("No a=control in audio sendonly block")

        track_uri = _resolve_track_uri(content_base, ctrl)
        ich = (idx * 2, idx * 2 + 1)
        return track_uri, ff_fmt, payload_type, ich, play_uri

    raise RuntimeError("No m=audio sendonly track found in SDP")


def build_rtp_packet(
    seq: int, ssrc: int, payload_type: int, payload: bytes
) -> bytes:
    """RTP v2, marker=1, timestamp=0 (Reolink doorbell quirk)."""
    b0 = 0x80
    b1 = 0x80 | (payload_type & 0x7F)
    return struct.pack("!BBHII", b0, b1, seq & 0xFFFF, 0, ssrc & 0xFFFFFFFF) + payload


def send_interleaved(sock: socket.socket, rtp_chan: int, pkt: bytes) -> None:
    size = len(pkt)
    frame = b"$" + bytes([rtp_chan]) + struct.pack("!H", size) + pkt
    sock.sendall(frame)


def run_ffmpeg(url: str, ff_fmt: str, *, low_latency: bool) -> subprocess.Popen:
    fmt_flag = "alaw" if ff_fmt == "alaw" else "mulaw"
    cmd: list[str] = [
        "ffmpeg",
        "-hide_banner",
        "-loglevel",
        "error",
        "-nostdin",
    ]
    if low_latency:
        # Menos análise de formato + menos buffer no demuxer (início mais rápido).
        cmd += [
            "-fflags",
            "nobuffer",
            "-flags",
            "low_delay",
            "-probesize",
            "32",
            "-analyzeduration",
            "0",
        ]
    else:
        # Ritmo da fonte (~tempo real); primeiro áudio demora mais (probe + buffer).
        cmd.append("-re")
    cmd += [
        "-i",
        url,
        "-vn",
        "-ac",
        "1",
        "-ar",
        "8000",
        "-f",
        fmt_flag,
        "-",
    ]
    return subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
    )


def main() -> None:
    ap = argparse.ArgumentParser(description="Send audio URL to Reolink ONVIF backchannel")
    ap.add_argument(
        "--camera",
        required=True,
        help="rtsp://user:pass@host:554/path",
    )
    ap.add_argument(
        "--url",
        required=True,
        help="HTTP(S) URL to audio (e.g. MP3)",
    )
    ap.add_argument("--debug", action="store_true")
    ap.add_argument(
        "--low-latency",
        action="store_true",
        help="Início quase imediato: sem -re, probesize mínimo, menos buffer no input. "
        "Clips curtos são ideais; áudio longo pode ser enviado muito rápido à câmara.",
    )
    args = ap.parse_args()

    user, password, host, path, port = _parse_rtsp_url(args.camera)
    request_uri = _make_rtsp_request_uri(host, port, path)

    sock = socket.create_connection((host, port), timeout=10)
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

    client = RtspClient(sock, user, password, request_uri, debug=args.debug)
    ff: Optional[subprocess.Popen] = None
    play_uri: str = request_uri
    stop_drain: Optional[threading.Event] = None
    drain_thread: Optional[threading.Thread] = None

    try:
        client.options(request_uri)
        sdp, dhdr = client.describe(request_uri)
        track_uri, ff_fmt, pt, interleaved, play_uri = parse_backchannel_track(
            sdp, dhdr, request_uri
        )  # play_uri from Content-Base when present
        content_base = dhdr.get("content-base", "").strip() or request_uri
        setups = list_all_track_setups(sdp, content_base)
        if args.debug:
            print(f"SETUP all tracks ({len(setups)}):", file=sys.stderr)
            for tu, ich in setups:
                print(f"  {ich} -> {tu}", file=sys.stderr)
            print(f"Backchannel send: {track_uri} ch {interleaved}", file=sys.stderr)
            print(f"PLAY URI: {play_uri}", file=sys.stderr)
            print(
                f"ffmpeg format: {ff_fmt}, RTP PT={pt}, interleaved={interleaved}",
                file=sys.stderr,
            )

        for tu, ich in setups:
            client.setup(tu, ich)
        client.play(play_uri)

        stop_drain = threading.Event()

        def _drain() -> None:
            sock.settimeout(0.25)
            assert stop_drain is not None
            while not stop_drain.is_set():
                try:
                    d = sock.recv(65536)
                    if not d:
                        break
                except socket.timeout:
                    continue
                except OSError:
                    break

        drain_thread = threading.Thread(target=_drain, daemon=True)
        drain_thread.start()

        ff = run_ffmpeg(args.url, ff_fmt, low_latency=args.low_latency)
        assert ff.stdout is not None

        ssrc = secrets.randbits(32)
        seq = 0
        buf = bytearray()
        rtp_chan = interleaved[0]

        while True:
            chunk = ff.stdout.read(4096)
            if not chunk:
                break
            buf.extend(chunk)
            while len(buf) >= 1024:
                payload = bytes(buf[:1024])
                del buf[:1024]
                pkt = build_rtp_packet(seq, ssrc, pt, payload)
                seq = (seq + 1) & 0xFFFF
                send_interleaved(sock, rtp_chan, pkt)

    finally:
        if stop_drain is not None:
            stop_drain.set()
        if drain_thread is not None:
            drain_thread.join(timeout=2.0)
        if ff and ff.poll() is None:
            ff.terminate()
            try:
                ff.wait(timeout=2)
            except subprocess.TimeoutExpired:
                ff.kill()
        try:
            client.teardown(play_uri)
        except Exception:
            pass
        sock.close()

    print("Done.", file=sys.stderr)


if __name__ == "__main__":
    main()
