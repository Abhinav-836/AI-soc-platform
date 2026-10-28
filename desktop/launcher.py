"""
AI SOC Platform - desktop app.

Runs the same engine and dashboard as the server version, locally, in its own
window. No Python needed once packaged (see build_desktop.ps1).

  * data (database, logs, model, raw logs, your rules/IOCs/playbooks)
      -> %LOCALAPPDATA%\\AISOCPlatform  (~/.local/share/AISOCPlatform on Linux,
         ~/Library/Application Support/AISOCPlatform on macOS)
  * drop log files into <data>\\raw\\ and they are ingested live
  * the API listens on 127.0.0.1 only, on a free port
  * response mode stays dry-run unless you set mode: enforce in
    <data>\\config\\response.yaml (needs the app to run as administrator)

Run from source:  python desktop/launcher.py [--browser] [--no-open] [--port 8080] [--simulate]
"""
import argparse
import os
import socket
import sys
import threading
import time
import urllib.request
import webbrowser
from pathlib import Path

APP_NAME = "AI SOC Platform"
APP_ID = "AISOCPlatform"


def user_data_dir() -> Path:
    if sys.platform == "win32":
        base = Path(os.environ.get("LOCALAPPDATA") or Path.home() / "AppData" / "Local")
    elif sys.platform == "darwin":
        base = Path.home() / "Library" / "Application Support"
    else:
        base = Path(os.environ.get("XDG_DATA_HOME") or Path.home() / ".local" / "share")
    path = base / APP_ID
    path.mkdir(parents=True, exist_ok=True)
    return path


# Must be set before anything from src/ is imported (paths resolve at import)
DATA_DIR = Path(os.environ.setdefault("SOC_DATA_DIR", str(user_data_dir())))
(DATA_DIR / "raw").mkdir(parents=True, exist_ok=True)

# A windowed (no console) build has sys.stdout/stderr = None; logging and
# uvicorn would crash writing to them, so send them to a file.
if sys.stdout is None or sys.stderr is None:
    (DATA_DIR / "logs").mkdir(parents=True, exist_ok=True)
    _log = open(DATA_DIR / "logs" / "desktop.log", "a", encoding="utf-8", buffering=1)
    sys.stdout = sys.stdout or _log
    sys.stderr = sys.stderr or _log

if not getattr(sys, "frozen", False):  # running from source
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import uvicorn  # noqa: E402

from src.api.app import create_app  # noqa: E402  (direct import so PyInstaller bundles it)


def free_port(preferred: int = 0) -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.bind(("127.0.0.1", preferred))
        except OSError:
            s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def wait_until_healthy(url: str, timeout: float = 90.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(f"{url}/health", timeout=2) as r:
                if r.status == 200:
                    return True
        except OSError:
            pass
        time.sleep(0.3)
    return False


def open_window(url: str) -> bool:
    try:
        import webview
    except ImportError:
        return False
    try:
        webview.create_window(APP_NAME, f"{url}/ui/", width=1500, height=950, min_size=(1100, 700))
        webview.start()  # blocks until the window is closed
        return True
    except Exception as e:  # WebView2 missing, no GUI backend...
        print(f"Native window unavailable ({e}); using the browser", flush=True)
        return False


def main():
    p = argparse.ArgumentParser(description=APP_NAME)
    p.add_argument("--browser", action="store_true", help="open in the default browser instead of a window")
    p.add_argument("--no-open", action="store_true", help="run the server only")
    p.add_argument("--port", type=int, default=0)
    p.add_argument("--simulate", action="store_true", help="start the traffic simulator on launch")
    args = p.parse_args()

    port = free_port(args.port)
    url = f"http://127.0.0.1:{port}"
    app = create_app(simulate=args.simulate or None)
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_config=None,
                                           log_level="warning", loop="asyncio", ws="auto"))
    threading.Thread(target=server.run, name="soc-server", daemon=True).start()
    if not wait_until_healthy(url):
        print("The SOC engine did not start; see logs in", DATA_DIR / "logs", flush=True)
        sys.exit(1)
    print(f"{APP_NAME} running at {url}  (data: {DATA_DIR})", flush=True)

    try:
        if args.no_open:
            while not server.should_exit:
                time.sleep(0.5)
        elif args.browser or not open_window(url):
            webbrowser.open(f"{url}/ui/")
            print("Close this window or press Ctrl+C to quit.", flush=True)
            while not server.should_exit:
                time.sleep(0.5)
    except KeyboardInterrupt:
        pass
    finally:
        server.should_exit = True
        time.sleep(1)


if __name__ == "__main__":
    main()
