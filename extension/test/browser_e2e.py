#!/usr/bin/env python3
"""Real Chromium UI/native-IPC test. Software simulator only; no card or network send."""
import argparse
import functools
import hashlib
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import sys
import tempfile
import threading

from playwright.sync_api import sync_playwright

EXT_ID = "hlljlndpkgephgelnfgcpnneecmklnmf"


def run(extension, evidence, executable=None):
    extension = Path(extension).resolve()
    evidence = Path(evidence).resolve()
    evidence.mkdir(parents=True, exist_ok=True)
    assert (extension / "manifest.json").is_file(), "Select the extension folder, not its parent"
    build = json.loads((extension / "BUILD.json").read_text())
    for name, digest in build["files_sha256"].items():
        assert hashlib.sha256((extension / name).read_bytes()).hexdigest() == digest, name
    with tempfile.TemporaryDirectory(prefix="nuri-chrome-", dir=os.environ.get("TMPDIR")) as tmp:
        tmp = Path(tmp)
        config = tmp / "config"
        launcher = tmp / "native-host"
        import shlex
        launcher.write_text("#!/bin/sh\nexport NURI_CARD_SIM=1\nunset NURI_ALLOW_ETH1_DEMO\nexec " +
                            shlex.quote(sys.executable) + " " +
                            shlex.quote(str(extension / "host/nuri_card_host.py")) + ' --sim "$@"\n')
        launcher.chmod(0o700)
        manifest = {"name": "com.nuri.card", "description": "Nuri explicit software simulator test",
                    "path": str(launcher), "type": "stdio",
                    "allowed_origins": [f"chrome-extension://{EXT_ID}/"]}
        for product in ("chromium", "google-chrome", "google-chrome-for-testing"):
            directory = config / product / "NativeMessagingHosts"
            directory.mkdir(parents=True)
            (directory / "com.nuri.card.json").write_text(json.dumps(manifest))
        server = ThreadingHTTPServer(("127.0.0.1", 0), functools.partial(SimpleHTTPRequestHandler, directory=str(extension)))
        threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            with sync_playwright() as p:
                exe = executable or p.chromium.executable_path
                ctx = p.chromium.launch_persistent_context(str(tmp / "profile"), headless=False,
                    executable_path=exe, env={**os.environ, "XDG_CONFIG_HOME": str(config)},
                    args=["--headless=new", f"--disable-extensions-except={extension}", f"--load-extension={extension}"])
                try:
                    sw = ctx.service_workers[0] if ctx.service_workers else ctx.wait_for_event("serviceworker")
                    assert sw.url == f"chrome-extension://{EXT_ID}/background.js", sw.url
                    page = ctx.new_page()
                    errors = []
                    page.on("pageerror", lambda error: errors.append(str(error)))
                    page.goto(f"http://127.0.0.1:{server.server_port}/test-dapp.html")
                    page.wait_for_function("document.querySelector('#prov').textContent === 'Nuri Card (com.nuri.card)'")

                    def approve(button, reject=False):
                        with ctx.expect_page() as opened:
                            page.locator(button).click()
                        popup = opened.value
                        popup.wait_for_load_state()
                        popup.wait_for_function("document.querySelector('#kind').textContent.length > 0 && document.querySelector('#approve').onclick !== null")
                        assert popup.url.startswith(f"chrome-extension://{EXT_ID}/approve.html?")
                        assert not popup.locator("#sim").is_hidden(), "Simulator must be labelled"
                        popup.locator("#reject" if reject else "#approve").click()
                        popup.wait_for_event("close") if not popup.is_closed() else None

                    approve("#connect")
                    page.wait_for_function("/^0x[0-9a-fA-F]{40}$/.test(document.querySelector('#acct').textContent)")
                    account = page.locator("#acct").inner_text()
                    approve("#sign", reject=True)
                    page.wait_for_function("document.querySelector('#log').textContent.includes('User rejected')")
                    for button in ("#sign", "#typed", "#tx"):
                        count = page.locator("#log .ok").count()
                        approve(button)
                        page.wait_for_function("n => document.querySelectorAll('#log .ok').length === n", arg=count + 1)
                    assert "MISMATCH" not in page.locator("#log").inner_text()
                    assert not errors, errors
                    assert page.locator("#log .ok").count() == 3
                    page.screenshot(path=str(evidence / "browser.png"), full_page=True)
                    assert ctx.browser is not None
                    result = {"browser": ctx.browser.version, "extension_id": EXT_ID,
                              "source_revision": build["source_revision"], "files_sha256": build["files_sha256"],
                              "mode": "explicit-software-simulator", "account": account,
                              "checks": ["unpacked manifest load", "service worker", "EIP-6963 discovery",
                                         "native messaging with real Python host", "connect approval",
                                         "reject message", "personal_sign recovery", "typed-data recovery",
                                         "transaction recovery without broadcast"],
                              "verified_signatures": 3, "page_errors": errors,
                              "real_card_tested": False, "broadcast_performed": False,
                              "log": page.locator("#log").inner_text()}
                    (evidence / "browser-evidence.json").write_text(json.dumps(result, indent=2) + "\n")
                    print(json.dumps(result, indent=2))
                finally:
                    ctx.close()
        finally:
            server.shutdown()
            server.server_close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("extension")
    parser.add_argument("evidence")
    parser.add_argument("--executable")
    args = parser.parse_args()
    run(args.extension, args.evidence, args.executable)
