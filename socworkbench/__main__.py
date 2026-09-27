"""
Start the workbench.

    python -m socworkbench                 native window (pywebview), else browser
    python -m socworkbench FILES...        ...and analyse these straight away
    python -m socworkbench --browser       always use the default browser
    python -m socworkbench --no-open       just serve; print the URL

Files dropped onto "SOC Workbench.bat" arrive here as arguments.
"""

from __future__ import annotations

import argparse
import logging
import os
import sys
import tempfile
import threading
import time
import traceback
import webbrowser

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from socworkbench import __version__  # noqa: E402
from socworkbench.server import IDLE_SHUTDOWN_S, make_server, url_for  # noqa: E402

LOG_DIR = os.path.join(os.environ.get("LOCALAPPDATA") or tempfile.gettempdir(), "SOCWorkbench", "logs")
log = logging.getLogger("socworkbench")


def _setup_logging() -> None:
    """The log is the only diagnostic under pythonw (no console). It lives
    with the user's app data, never in the project folder: it holds local
    paths (user name included) that must not travel with a shared copy."""
    for folder in (LOG_DIR, os.path.join(tempfile.gettempdir(), "SOCWorkbench", "logs")):
        try:
            os.makedirs(folder, exist_ok=True)
            handler = logging.FileHandler(os.path.join(folder, "last-run.log"), mode="w", encoding="utf-8")
            break
        except OSError:
            continue
    else:
        handler = logging.NullHandler()
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    root = logging.getLogger()
    root.setLevel(logging.INFO)
    root.addHandler(handler)
    if sys.stderr is not None and sys.stderr.isatty():
        root.addHandler(logging.StreamHandler())


class WindowApi:
    """Exposed to the page as window.pywebview.api -- native dialogs, so
    picked files are analysed in place and exports go where the user says."""

    def __init__(self, session):
        self._session = session
        self._window = None

    def _dialog(self, kind: str):
        import webview
        fd = getattr(webview, "FileDialog", None)
        if fd is not None:
            return {"open": fd.OPEN, "save": fd.SAVE, "folder": fd.FOLDER}[kind]
        return {"open": webview.OPEN_DIALOG, "save": webview.SAVE_DIALOG,
                "folder": webview.FOLDER_DIALOG}[kind]

    def pick_files(self):
        paths = self._window.create_file_dialog(self._dialog("open"), allow_multiple=True)
        return self._session.analyze_paths(list(paths or []))

    def pick_folder(self):
        paths = self._window.create_file_dialog(self._dialog("folder"))
        return self._session.analyze_paths(list(paths or [])[:1])

    def save_export(self, case_id: str, fmt: str):
        from socworkbench.export import filename, render
        case = self._session.cases[case_id]
        body, _ctype = render(case, fmt)
        chosen = self._window.create_file_dialog(self._dialog("save"),
                                                 save_filename=filename(case, fmt))
        if not chosen:
            return None
        path = chosen if isinstance(chosen, str) else chosen[0]
        with open(path, "wb") as fh:
            fh.write(body)
        return path

    def open_report(self, case_id: str):
        """Open the HTML report in the default browser (to read or print)."""
        from socworkbench.export import filename, render
        case = self._session.cases[case_id]
        body, _ = render(case, "html")
        path = os.path.join(self._session.workdir, filename(case, "html"))
        with open(path, "wb") as fh:
            fh.write(body)
        os.startfile(path) if os.name == "nt" else webbrowser.open("file://" + path)
        return path


def _open_window(url: str, session) -> bool:
    try:
        import webview
    except ImportError:
        log.info("pywebview not installed; using the browser")
        return False
    api = WindowApi(session)
    try:
        window = webview.create_window(
            "SOC Workbench", url, js_api=api, width=1400, height=900, min_size=(980, 640),
            text_select=True, zoomable=True, background_color="#15181D")
        api._window = window
        os.environ["SOCWB_WINDOW"] = "1"
        store = os.path.join(os.environ.get("LOCALAPPDATA", ROOT), "SOCWorkbench", "webview")
        webview.start(private_mode=False, storage_path=store)
        return True
    except Exception:  # noqa: BLE001 -- missing WebView2, no display, ...
        log.warning("native window failed, falling back to the browser:\n%s", traceback.format_exc())
        os.environ.pop("SOCWB_WINDOW", None)
        return False


def _idle_watchdog(session) -> None:
    while True:
        time.sleep(30)
        if time.time() - session.last_ping > IDLE_SHUTDOWN_S and session.running_jobs() == 0:
            log.info("no page open for %ss; shutting down", IDLE_SHUTDOWN_S)
            session.server.shutdown()
            return


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="socworkbench", description="SOC Workbench")
    ap.add_argument("files", nargs="*", help="evidence to analyse on start")
    ap.add_argument("--browser", action="store_true", help="use the default browser, not a window")
    ap.add_argument("--no-open", action="store_true", help="only serve; print the URL")
    ap.add_argument("--port", type=int, default=0, help="port (default: a random free one)")
    ap.add_argument("--version", action="version", version=f"SOC Workbench {__version__}")
    args = ap.parse_args(argv)
    _setup_logging()

    httpd, session = make_server(args.port)
    url = url_for(httpd)
    log.info("SOC Workbench %s at %s (workdir %s)", __version__, url, session.workdir)
    if args.files:
        session.analyze_paths(args.files, ", ".join(os.path.basename(f) for f in args.files)[:80])

    thread = threading.Thread(target=httpd.serve_forever, name="http", daemon=True)
    thread.start()

    def wait() -> None:
        while thread.is_alive():            # a bare join() ignores Ctrl+C on Windows
            thread.join(0.5)

    try:
        if args.no_open:
            print(f"SOC Workbench running at {url}  (Ctrl+C to stop)", flush=True)
            wait()
        elif not args.browser and _open_window(url, session):
            pass                                            # window closed -> exit
        else:
            webbrowser.open(url)
            threading.Thread(target=_idle_watchdog, args=(session,), daemon=True).start()
            if sys.stdout is not None and sys.stdout.isatty():
                print(f"SOC Workbench running at {url}  (Ctrl+C to stop)", flush=True)
            wait()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.shutdown()
        httpd.server_close()
        session.cleanup()
        log.info("stopped")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
