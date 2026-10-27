from __future__ import annotations

import base64
import ctypes
import json
import logging
import os
import re
import secrets
import socket
import sys
import threading
import tkinter as tk
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from meta_attest import Policy, Result, verify_sync

APP_NAME = "QuestAttest"
PACKAGE_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z][A-Za-z0-9_]*)+$")

# discord palette
BG = "#313338"
CARD = "#2b2d31"
FIELD = "#383a40"
FG = "#f2f3f5"
MUTED = "#949ba4"
BLURPLE = "#5865f2"
BLURPLE_HI = "#4752c4"
GREEN = "#23a55a"
RED = "#f23f43"
YELLOW = "#f0b232"

CONFIG_DIR = Path(os.environ.get("APPDATA", Path.home())) / APP_NAME
CONFIG_FILE = CONFIG_DIR / "config.json"
LOG_FILE = CONFIG_DIR / "app.log"
CONFIG_DIR.mkdir(parents=True, exist_ok=True)
logging.basicConfig(filename=LOG_FILE, level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

UI = "Segoe UI"
UI_SEMI = "Segoe UI Semibold"


def new_nonce(nbytes: int = 16) -> str:
    return base64.urlsafe_b64encode(secrets.token_bytes(nbytes)).rstrip(b"=").decode("ascii")


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def lan_ip() -> str:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except OSError:
        try:
            return socket.gethostbyname(socket.gethostname())
        except OSError:
            return "127.0.0.1"


def _pair_page(code: str, package: str) -> bytes:
    safe_code = code or ""
    safe_pkg = package or ""
    return f"""<!doctype html>
<html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>pair</title>
<style>
 body{{margin:0;background:#313338;color:#f2f3f5;font:16px/1.5 'Segoe UI',system-ui,sans-serif;
      display:flex;min-height:100vh;align-items:center;justify-content:center;padding:24px}}
 .card{{background:#2b2d31;border-radius:16px;padding:28px;max-width:640px;width:100%}}
 h1{{font-size:20px;margin:0 0 6px}} p{{color:#949ba4;margin:0 0 18px;font-size:14px}}
 code{{display:block;background:#383a40;color:#f2f3f5;padding:14px;border-radius:10px;
       font:12px/1.5 Consolas,monospace;word-break:break-all;max-height:170px;overflow:auto}}
 button{{margin-top:18px;width:100%;padding:16px;border:0;border-radius:10px;background:#5865f2;
         color:#fff;font:600 16px 'Segoe UI',sans-serif;cursor:pointer}}
 button:active{{background:#4752c4}}
 .ok{{color:#23a55a;font-size:13px;margin-top:10px;min-height:18px}}
 .pkg{{color:#949ba4;font-size:13px;margin-top:14px;font-family:Consolas,monospace}}
</style></head><body>
<div class="card">
 <h1>pairing code</h1>
 <p>tap copy, then paste into QuestAttest on the headset</p>
 <code id="c">{safe_code}</code>
 <button onclick="copy()">copy code</button>
 <div class="ok" id="s"></div>
 <div class="pkg">package: {safe_pkg}</div>
</div>
<script>
function copy(){{
  const t = document.getElementById('c').innerText.trim();
  const done = () => document.getElementById('s').textContent = 'copied — switch to QuestAttest and paste';
  if (navigator.clipboard && navigator.clipboard.writeText) {{
    navigator.clipboard.writeText(t).then(done).catch(fallback);
  }} else {{ fallback(); }}
  function fallback(){{
    const ta = document.createElement('textarea');
    ta.value = t; document.body.appendChild(ta); ta.select();
    try {{ document.execCommand('copy'); done(); }}
    catch(e) {{ document.getElementById('s').textContent = 'select the code and copy manually'; }}
    document.body.removeChild(ta);
  }}
}}
</script></body></html>""".encode("utf-8")


def load_config() -> dict:
    try:
        return json.loads(CONFIG_FILE.read_text("utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}


def save_config(data: dict) -> None:
    try:
        CONFIG_FILE.write_text(json.dumps(data, indent=2), "utf-8")
    except OSError as exc:
        logging.warning("config save failed: %s", exc)


def resource_path(name: str) -> str:
    base = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(base, name)


class Receiver:
    def __init__(self, on_token, code_getter) -> None:
        self._on_token = on_token
        self._code = code_getter
        self._httpd: ThreadingHTTPServer | None = None
        self.port = 0

    def start(self, preferred: int = 8787) -> int:
        for port in range(preferred, preferred + 20):
            try:
                httpd = ThreadingHTTPServer(("0.0.0.0", port), self._handler())
                httpd.daemon_threads = True
                self._httpd = httpd
                self.port = port
                threading.Thread(target=httpd.serve_forever, daemon=True).start()
                return port
            except OSError:
                continue
        raise OSError("no free port from 8787")

    def stop(self) -> None:
        if self._httpd is not None:
            self._httpd.shutdown()
            self._httpd.server_close()
            self._httpd = None

    def _handler(self):
        on_token = self._on_token
        code_getter = self._code

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, fmt, *args):
                logging.debug("http %s", fmt % args)

            def _send(self, code: int, payload: dict) -> None:
                body = json.dumps(payload).encode("utf-8")
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self):
                if self.path == "/healthz":
                    self._send(200, {"ok": True})
                elif self.path == "/v1/request":
                    code, package = code_getter()
                    self._send(200, {"code": code, "package": package})
                elif self.path.split("?")[0] == "/pair":
                    code, package = code_getter()
                    page = _pair_page(code, package)
                    self.send_response(200)
                    self.send_header("Content-Type", "text/html; charset=utf-8")
                    self.send_header("Content-Length", str(len(page)))
                    self.end_headers()
                    self.wfile.write(page)
                else:
                    self._send(404, {"ok": False, "message": "not found"})

            def do_POST(self):
                if self.path != "/v1/attest":
                    self._send(404, {"ok": False, "message": "not found"})
                    return
                try:
                    length = int(self.headers.get("Content-Length") or 0)
                    payload = json.loads(self.rfile.read(length) or b"{}")
                except (ValueError, json.JSONDecodeError):
                    self._send(400, {"ok": False, "message": "json body required"})
                    return
                ok, message = on_token(str(payload.get("code", "")), str(payload.get("token", "")))
                self._send(200 if ok else 403, {"ok": ok, "message": message})

        return Handler


class App(tk.Tk):
    W, H = 860, 620

    def __init__(self) -> None:
        super().__init__()
        self.title("Quest Attestation")
        self.geometry(f"{self.W}x{self.H}")
        self.resizable(False, False)
        self.configure(bg=BG)
        try:
            self.iconbitmap(resource_path("icon.ico"))
        except Exception:
            logging.info("window icon not available")

        cfg = load_config()
        self.package_var = tk.StringVar(value=cfg.get("package", "com.AnotherAxiom.GorillaTag"))
        self.access_var = tk.StringVar(value=cfg.get("access_token", ""))
        self.code_var = tk.StringVar(value="")
        self.status_var = tk.StringVar(value="")
        self.min_integrity_var = tk.StringVar(value=cfg.get("min_integrity", "Basic"))
        self.store_var = tk.BooleanVar(value=cfg.get("require_store", True))
        self.certs_var = tk.StringVar(value=cfg.get("allowed_certs", ""))
        self.max_age_var = tk.StringVar(value=str(cfg.get("max_age", 300)))

        self._session: dict = {}
        self._token = ""
        self._busy = False
        self._has_code = False
        self._buttons: dict[str, tuple] = {}

        self.receiver = Receiver(self._device_post, self._code_current)
        try:
            self.receiver.start()
        except OSError as exc:
            logging.error("listener failed: %s", exc)
            self.receiver.port = 0

        self.canvas = tk.Canvas(self, bg=BG, highlightthickness=0, bd=0)
        self.canvas.place(x=0, y=0, width=self.W, height=self.H)

        self._build_widgets()
        self._layout()
        self.protocol("WM_DELETE_WINDOW", self._close)

    # ------------------------------------------------------------- widgets

    def _build_widgets(self) -> None:
        self.pkg_cap = tk.Label(self, text="PACKAGE NAME", bg=CARD, fg=MUTED, font=(UI_SEMI, 8), anchor="w")
        self.pkg_entry = tk.Entry(
            self, textvariable=self.package_var, bg=FIELD, fg=FG, insertbackground=FG,
            relief="flat", bd=0, highlightthickness=0, font=("Consolas", 12),
        )
        self.pkg_entry.bind("<Return>", lambda _: self.on_get_token())

        self.pair_cap = tk.Label(self, text="PAIRING CODE", bg=CARD, fg=MUTED, font=(UI_SEMI, 8), anchor="w")
        self.pair_hint = tk.Label(self, text="paste it into QuestAttest on the headset, press Send",
                                  bg=CARD, fg=MUTED, font=(UI, 9), anchor="w")
        self.code_entry = tk.Entry(
            self, textvariable=self.code_var, bg=FIELD, fg=FG, insertbackground=FG,
            relief="flat", bd=0, highlightthickness=0, font=("Consolas", 10), state="readonly",
            readonlybackground=FIELD,
        )

        self.token_cap = tk.Label(self, text="ATTESTATION TOKEN", bg=CARD, fg=MUTED, font=(UI_SEMI, 8), anchor="w")
        self.verdict_lbl = tk.Label(self, text="", bg=CARD, fg=MUTED, font=(UI_SEMI, 10), anchor="e")
        self.token_box = tk.Text(
            self, bg=FIELD, fg=FG, insertbackground=FG, relief="flat", bd=0,
            highlightthickness=0, wrap="char", font=("Consolas", 9), padx=14, pady=12,
        )

        self.status_lbl = tk.Label(self, textvariable=self.status_var, bg=BG, fg=MUTED, font=(UI, 9), anchor="w")

    # ------------------------------------------------------------- drawing

    def _rr(self, x1, y1, x2, y2, r, **kw):
        r = min(r, (x2 - x1) / 2, (y2 - y1) / 2)
        pts = [
            x1 + r, y1, x2 - r, y1, x2, y1, x2, y1 + r,
            x2, y2 - r, x2, y2, x2 - r, y2, x1 + r, y2,
            x1, y2, x1, y2 - r, x1, y1 + r, x1, y1,
        ]
        return self.canvas.create_polygon(pts, smooth=True, **kw)

    def _button(self, key, x1, y1, x2, y2, text, cmd, fill, hover, fg="#ffffff",
                font=(UI_SEMI, 11), radius=9) -> None:
        bg = self._rr(x1, y1, x2, y2, radius, fill=fill, outline="")
        label = self.canvas.create_text((x1 + x2) / 2, (y1 + y2) / 2, text=text, fill=fg, font=font)
        self._buttons[key] = (bg, label, cmd, fill, hover)
        for item in (bg, label):
            self.canvas.tag_bind(item, "<Button-1>", lambda _e, k=key: self._fire(k))
            self.canvas.tag_bind(item, "<Enter>", lambda _e, k=key: self._hover(k, True))
            self.canvas.tag_bind(item, "<Leave>", lambda _e, k=key: self._hover(k, False))

    def _fire(self, key: str) -> None:
        entry = self._buttons.get(key)
        if entry is not None and entry[2] is not None:
            entry[2]()

    def _hover(self, key: str, on: bool) -> None:
        entry = self._buttons.get(key)
        if entry is None:
            return
        bg, _label, _cmd, fill, hover = entry
        self.canvas.itemconfigure(bg, fill=hover if on else fill)
        self.canvas.configure(cursor="hand2" if on else "")

    def _layout(self) -> None:
        self.canvas.delete("all")
        self._buttons.clear()

        pad = 24
        x0, x1 = pad, self.W - pad
        iw = x1 - x0
        y = 24

        # card 1 — package + button
        card1_h = 150
        self._rr(x0, y, x1, y + card1_h, 14, fill=CARD, outline="")
        self.pkg_cap.place(x=x0 + 20, y=y + 18)
        e_x, e_w = x0 + 20, iw - 40
        self._rr(e_x, y + 40, e_x + e_w, y + 84, 9, fill=FIELD, outline="")
        self.pkg_entry.place(x=e_x + 14, y=y + 40 + 10, width=e_w - 28, height=24)
        self._button("go", e_x, y + 96, e_x + e_w, y + 140,
                     "Get token", self.on_get_token, BLURPLE, BLURPLE_HI, font=(UI_SEMI, 12))
        y += card1_h + 16

        # card 2 — pairing code
        if self._has_code:
            card2_h = 118
            self._rr(x0, y, x1, y + card2_h, 14, fill=CARD, outline="")
            self.pair_cap.place(x=x0 + 20, y=y + 16)
            c_x = x0 + 20
            c_w = iw - 40
            btn_w = 92
            self._rr(c_x, y + 38, c_x + c_w - btn_w - 10, y + 80, 9, fill=FIELD, outline="")
            self.code_entry.place(x=c_x + 12, y=y + 38 + 10, width=c_w - btn_w - 10 - 24, height=22)
            self._button("copycode", c_x + c_w - btn_w, y + 38, c_x + c_w, y + 80,
                         "copy", self.copy_code, FIELD, "#42454d", fg=FG, font=(UI_SEMI, 10))
            self.pair_hint.place(x=x0 + 20, y=y + 88)
            y += card2_h + 16

        # card 3 — token
        card3_top = y
        card3_bottom = self.H - 52
        self._rr(x0, card3_top, x1, card3_bottom, 14, fill=CARD, outline="")
        self.token_cap.place(x=x0 + 20, y=card3_top + 16)
        self.verdict_lbl.place(x=x1 - 220, y=card3_top + 13, width=200)

        t_x, t_w = x0 + 20, iw - 40
        t_y = card3_top + 40
        t_h = card3_bottom - t_y - 62
        self._rr(t_x, t_y, t_x + t_w, t_y + t_h, 9, fill=FIELD, outline="")
        self.token_box.place(x=t_x + 2, y=t_y + 2, width=t_w - 4, height=t_h - 4)

        b_y = t_y + t_h + 12
        self._button("copytoken", t_x, b_y, t_x + 118, b_y + 38,
                     "copy token", self.copy_token, FIELD, "#42454d", fg=FG, font=(UI_SEMI, 10))
        self._button("save", t_x + 128, b_y, t_x + 218, b_y + 38,
                     "save .txt", self.save_token, FIELD, "#42454d", fg=FG, font=(UI_SEMI, 10))

        self.status_lbl.place(x=x0, y=self.H - 34, width=iw)

    # -------------------------------------------------------------- actions

    def on_get_token(self) -> None:
        package = self.package_var.get().strip()
        if PACKAGE_RE.fullmatch(package) is None:
            self.status("package name looks wrong — com.Example.App", RED)
            return
        if self.receiver.port == 0:
            self.status("listener could not bind a port — restart the app", RED)
            return

        nonce = new_nonce()
        secret = secrets.token_urlsafe(12)
        self._session = {"nonce": nonce, "package": package, "secret": secret}

        payload = {
            "u": f"http://{lan_ip()}:{self.receiver.port}/v1/attest",
            "s": secret,
            "n": nonce,
            "p": package,
        }
        self.pair_hint.configure(
            text=f"no typing: open http://{lan_ip()}:{self.receiver.port}/pair in Quest Browser, tap copy, then Paste in the app"
        )
        self.code_var.set(b64url_encode(json.dumps(payload, separators=(",", ":")).encode("utf-8")))
        self._has_code = True
        self._token = ""
        self.token_box.delete("1.0", "end")
        self.verdict_lbl.configure(text="", fg=MUTED)
        self._layout()
        self.copy_code()
        self.status("waiting for the headset …")

    def _code_current(self) -> tuple[str, str]:
        return self.code_var.get(), str(self._session.get("package", ""))

    def copy_code(self) -> None:
        code = self.code_var.get()
        if code:
            self.clipboard_clear()
            self.clipboard_append(code)
            self.status("pairing code copied")

    def copy_token(self) -> None:
        token = self._token or self.token_box.get("1.0", "end").strip()
        if token:
            self.clipboard_clear()
            self.clipboard_append(token)
            self.status("token copied")
        else:
            self.status("no token yet", RED)

    def save_token(self) -> None:
        token = self._token or self.token_box.get("1.0", "end").strip()
        if not token:
            self.status("no token yet", RED)
            return
        path = Path(os.environ.get("USERPROFILE", ".")) / "Downloads" / "attestation_token.txt"
        try:
            path.write_text(token, "utf-8")
            self.status(f"saved to {path}")
        except OSError as exc:
            self.status(f"save failed: {exc}", RED)

    # ------------------------------------------------------------ device in

    def _device_post(self, code: str, token: str) -> tuple[bool, str]:
        if not code or not token:
            return False, "code and token required"
        try:
            pair = json.loads(b64url_decode(code).decode("utf-8"))
        except (ValueError, json.JSONDecodeError, UnicodeDecodeError):
            return False, "unreadable pairing code"

        session = self._session
        if not session:
            return False, "no open request — press Get token first"
        if pair.get("s") != session.get("secret"):
            return False, "pairing code does not match this request"
        if pair.get("n") != session.get("nonce"):
            return False, "nonce does not match this request"
        if pair.get("p") != session.get("package"):
            return False, "package does not match this request"

        self.after(0, self._show_token, token.strip())
        return True, "token received"

    def _show_token(self, token: str) -> None:
        self._token = token
        self.token_box.delete("1.0", "end")
        self.token_box.insert("1.0", token)
        self.status("token received — verifying …")
        self.verify_in_background(token)

    # ------------------------------------------------------------- verify

    def verify_in_background(self, token: str) -> None:
        if self._busy:
            return
        access = self.access_var.get().strip()
        package = (self._session.get("package") or self.package_var.get()).strip()
        nonce = self._session.get("nonce", "")

        if not access:
            self.verdict_lbl.configure(text="UNVERIFIED", fg=YELLOW)
            self.status("token received — verification needs an access token in config.json", YELLOW)
            return
        if not nonce:
            nonce = "unchecked"

        try:
            max_age = max(30, int(self.max_age_var.get()))
        except ValueError:
            max_age = 300

        policy = Policy(
            expected_nonce=nonce,
            expected_package=package,
            allowed_certs={c.strip().lower() for c in self.certs_var.get().split(",") if c.strip()},
            max_token_age_seconds=max_age,
            min_device_integrity=self.min_integrity_var.get(),
            require_store_recognized=self.store_var.get(),
        )
        save_config({
            "package": self.package_var.get().strip(),
            "access_token": access,
            "min_integrity": self.min_integrity_var.get(),
            "require_store": self.store_var.get(),
            "allowed_certs": self.certs_var.get(),
            "max_age": max_age,
        })

        self._busy = True
        threading.Thread(target=self._worker, args=(access, token, policy), daemon=True).start()

    def _worker(self, access: str, token: str, policy: Policy) -> None:
        try:
            result = verify_sync(access, token, policy)
        except Exception as exc:
            logging.exception("verify crashed")
            result = Result(False, f"local failure: {exc}")
        self.after(0, self._render, result)

    def _render(self, result: Result) -> None:
        self._busy = False
        claims = result.claims or {}
        app = claims.get("app_state") or {}
        dev = claims.get("device_state") or {}

        if result.verified:
            self.verdict_lbl.configure(text="VERIFIED", fg=GREEN)
            detail = " · ".join(
                str(x) for x in (dev.get("device_integrity_state"), app.get("app_integrity_state"),
                                 app.get("package_id")) if x
            )
            self.status(f"verified · {detail}" if detail else "verified", GREEN)
        else:
            self.verdict_lbl.configure(text="REJECTED", fg=RED)
            self.status(f"rejected · {result.message}", RED)

    # -------------------------------------------------------------- chrome

    def status(self, text: str, colour: str = MUTED) -> None:
        self.status_var.set(text)
        self.status_lbl.configure(fg=colour)

    def _close(self) -> None:
        self.receiver.stop()
        self.destroy()


def main() -> int:
    if sys.platform == "win32":
        try:
            ctypes.windll.shcore.SetProcessDpiAwareness(1)
        except Exception:
            pass
    App().mainloop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
