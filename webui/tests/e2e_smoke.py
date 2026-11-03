"""End-to-end smoke test of the Krypton Console against a running demo.

Drives a real browser through every feature and saves a screenshot of each
screen. Run it in the official Playwright image, sharing the demo
container's network (see webui/tests/e2e_smoke.sh):

    python e2e_smoke.py <base url> <access token> <screenshot dir>
"""

from __future__ import annotations

import hashlib
import re
import sys
from pathlib import Path

from playwright.sync_api import Page, expect, sync_playwright

BASE, TOKEN, OUT = sys.argv[1].rstrip("/"), sys.argv[2], Path(sys.argv[3])
OUT.mkdir(parents=True, exist_ok=True)
PAYLOAD = b"KryptonFS end-to-end check. " * 400  # ~11 KiB: three 4 KiB blocks


def shot(page: Page, name: str) -> None:
    page.wait_for_timeout(400)
    page.screenshot(path=str(OUT / f"{name}.png"), full_page=True)
    print(f"  screenshot {name}.png")


def step(title: str) -> None:
    print(f"- {title}")


def nav(page: Page, label: str) -> None:
    page.get_by_role("navigation", name="Main").get_by_role("button", name=label).click()


def main() -> None:
    errors: list[str] = []
    with sync_playwright() as pw:
        browser = pw.chromium.launch()
        ctx = browser.new_context(viewport={"width": 1440, "height": 960}, accept_downloads=True)
        page = ctx.new_page()
        page.on("pageerror", lambda e: errors.append(f"page error: {e}"))
        # Expected refusals (401, 403) are checked through the UI; the browser also
        # logs them as failed loads.
        page.on("console", lambda m: m.type == "error" and "Failed to load resource" not in m.text
                and errors.append(f"console: {m.text}"))
        page.on("dialog", lambda d: d.accept())  # "Replace it?" when rerun on the same volume

        step("refused without the token")
        r = page.goto(f"{BASE}/api/status")
        assert r is not None and r.status == 401, r and r.status

        step("the launch link becomes a cookie")
        page.goto(f"{BASE}/?token={TOKEN}")
        expect(page).to_have_url(re.compile(r"/(#overview)?$"))
        assert "token" not in page.url
        expect(page.get_by_text("Live", exact=True)).to_be_visible(timeout=15_000)
        expect(page.get_by_text("Volume unlocked", exact=True)).to_be_visible()

        step("overview: three servers up")
        hero = page.locator("#learn-overview\\.map svg")  # the phone list is hidden here
        for n in (1, 2, 3):
            expect(hero.get_by_text(f"Server {n}")).to_be_visible()
        expect(hero.get_by_text("Up", exact=True)).to_have_count(3, timeout=15_000)
        page.wait_for_timeout(3000)  # let the charts collect a few seconds
        shot(page, "01-overview")

        step("files: upload, list, download, stored blocks")
        nav(page, "Files")
        expect(page.get_by_text("documents")).to_be_visible()
        page.locator('input[type="file"]').set_input_files(
            {"name": "e2e-check.txt", "mimeType": "text/plain", "buffer": PAYLOAD})
        expect(page.get_by_text("e2e-check.txt is stored, encrypted.")).to_be_visible(timeout=15_000)
        row = page.get_by_role("button", name="e2e-check.txt")
        row.click()
        with page.expect_download() as dl:
            page.get_by_role("link", name="Download").first.click()
        got = Path(dl.value.path()).read_bytes()
        assert hashlib.sha256(got).digest() == hashlib.sha256(PAYLOAD).digest(), "download differs"
        stored = page.locator("#learn-files\\.stored")
        expect(stored.get_by_text("What a server sees").first).to_be_visible(timeout=20_000)
        shot(page, "02-files-stored")

        step("files: the scanner blocks a program")
        page.locator('input[type="file"]').set_input_files(
            {"name": "tool.elf", "mimeType": "application/octet-stream",
             "buffer": b"\x7fELF\x02\x01\x01" + bytes(200)})
        expect(page.get_by_text("tool.elf was blocked by the malware scanner.")).to_be_visible(timeout=15_000)
        shot(page, "03-files-blocked")

        step("attack lab: all three attacks are defended")
        nav(page, "Attack lab")
        for card in page.locator("li", has=page.get_by_role("button", name="Run attack")).all():
            card.get_by_role("button", name="Run attack").click()
            expect(card.get_by_text(re.compile(r"^(Defended|Not defended)$"))).to_be_visible(timeout=90_000)
            expect(card.get_by_text("Defended", exact=True)).to_be_visible()
        shot(page, "04-attack-lab")

        step("overview: the feed shows the blocked upload and the integrity alert")
        nav(page, "Overview")
        feed = page.locator("#learn-overview\\.feed")
        expect(feed.get_by_text(re.compile("blocked write")).first).to_be_visible(timeout=10_000)
        expect(feed.get_by_text(re.compile("failed its integrity check")).first).to_be_visible()

        step("cluster: the server crashed by the attack restarts")
        nav(page, "Cluster")
        start = page.get_by_role("button", name="Start", exact=True)
        expect(start).to_have_count(1, timeout=10_000)
        start.click()
        expect(start).to_have_count(0, timeout=15_000)
        expect(page.get_by_text(re.compile(r"^Running"))).to_have_count(3)
        shot(page, "05-cluster")

        step("lock, refuse a wrong passphrase, unlock")
        page.get_by_role("button", name="Lock volume").click()
        expect(page.get_by_text("Volume locked", exact=True)).to_be_visible(timeout=20_000)
        page.get_by_label("Volume passphrase").fill("not the passphrase")
        page.get_by_role("button", name="Unlock volume").click()
        expect(page.get_by_text("That passphrase does not unlock this volume.").first).to_be_visible(timeout=60_000)
        shot(page, "06-locked")
        page.get_by_label("Volume passphrase").fill("krypton demo passphrase")
        page.get_by_role("button", name="Unlock volume").click()
        expect(page.get_by_text("Volume unlocked", exact=True)).to_be_visible(timeout=60_000)

        step("learn mode in Hindi")
        nav(page, "Overview")
        page.get_by_role("button", name="हिंदी").click()
        page.get_by_role("button", name="सीखें").click()
        page.locator("#learn-overview\\.map").get_by_role("button").first.click()
        shot(page, "07-learn-hindi")
        page.get_by_role("button", name="English").click()

        step("phone width")
        phone = browser.new_context(viewport={"width": 390, "height": 844}, device_scale_factor=2)
        m = phone.new_page()
        m.goto(f"{BASE}/?token={TOKEN}")
        expect(m.get_by_text("Live", exact=True)).to_be_visible(timeout=15_000)
        width = m.evaluate("document.documentElement.scrollWidth")
        assert width <= 390, f"horizontal scroll at phone width ({width}px)"
        shot(m, "08-phone")
        browser.close()

    if errors:
        print("\n".join(errors))
        sys.exit("browser errors")
    print("e2e: all checks passed")


if __name__ == "__main__":
    main()
