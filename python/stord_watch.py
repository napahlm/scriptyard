#!/usr/bin/env python3
"""Watch Stord Hotell (Mews booking engine) for one night 20-21 Oct 2026 and push a phone alert via ntfy.

Loads the hotel's real booking page in headless Chromium and reads the availability response the
page itself fetches, so it needs no API registration and stays in step with the widget.

Usage:
    pip install playwright && python -m playwright install --with-deps chromium
    python3 stord_watch.py --topic <ntfy-topic> [--interval 60] [--max-minutes 0] [--start-ping] [--heartbeat]
"""
import argparse
import asyncio
import json
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from zoneinfo import ZoneInfo

from playwright.async_api import async_playwright

BOOKING_ENGINE_ID = "4151883d-7521-43f9-8187-b1f500cf26fa"
START_UTC = "2026-10-19T22:00:00"  # night of 20 Oct (Oslo midnight in UTC)
BOOK_URL = f"https://app.mews.com/distributor/{BOOKING_ENGINE_ID}?mewsStart=2026-10-20&mewsEnd=2026-10-21&language=en-GB"
AVAIL_PATH = "/bookingEngine/v1/services/getAvailability"


def now():
    return f"{datetime.now(timezone.utc):%H:%M:%S}Z"


def notify(topic, title, msg, priority="urgent"):
    print(f"[{now()}] {title}: {msg}", flush=True)
    if not topic:
        return
    req = urllib.request.Request(
        f"https://ntfy.sh/{topic}",
        data=msg.encode(),
        headers={"Title": title, "Priority": priority, "Tags": "hotel", "Click": BOOK_URL},
        method="POST",
    )
    try:
        urllib.request.urlopen(req, timeout=15).read()
    except urllib.error.URLError as e:
        print(f"ntfy push failed: {e}", file=sys.stderr)


def tonight(res):
    """Rooms free for the night of START_UTC, per category, from a getAvailability response."""
    starts = [s[:19] for s in res["timeUnitStartsUtc"]]
    if START_UTC not in starts:
        return None
    i = starts.index(START_UTC)
    return {c["categoryId"]: c["availabilities"][i] for c in res["categoryAvailabilities"]}


async def check(page):
    """Reload the booking page and return {categoryId: free rooms} for 20 Oct."""
    results = []

    async def on_resp(r):
        if AVAIL_PATH in r.url and r.status == 200:
            try:
                n = tonight(json.loads(await r.text()))
                if n is not None:
                    results.append(n)
            except Exception:
                pass

    handler = lambda r: asyncio.ensure_future(on_resp(r))
    page.on("response", handler)
    try:
        await page.goto(BOOK_URL, wait_until="networkidle", timeout=60000)
        for _ in range(30):
            if results:
                break
            await page.wait_for_timeout(500)
    finally:
        page.remove_listener("response", handler)
    if not results:
        raise RuntimeError("booking page loaded but no availability response for 20 Oct")
    # The widget can fetch both the exact stay and a calendar range; take the most optimistic view.
    merged = {}
    for r in results:
        for k, v in r.items():
            merged[k] = max(merged.get(k, 0), v)
    return merged


async def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--topic", help="ntfy.sh topic")
    ap.add_argument("--interval", type=int, default=60, help="seconds between checks")
    ap.add_argument("--max-minutes", type=float, default=0, help="exit cleanly after this long (0 = forever)")
    ap.add_argument("--heartbeat", action="store_true", help="silent push after every check, as proof of life")
    ap.add_argument("--start-ping", action="store_true", help="send a low-priority 'running' push")
    args = ap.parse_args()
    deadline = time.time() + args.max_minutes * 60 if args.max_minutes else None

    async with async_playwright() as p:
        browser = await p.chromium.launch()
        page = await browser.new_page()
        avail = await check(page)  # fail fast if the page flow is broken
        print(f"[{now()}] OK, {len(avail)} room types, free tonight: {sum(avail.values())}", flush=True)
        if args.start_ping:
            notify(args.topic, "Stord watch running", f"Checking {len(avail)} room types every {args.interval}s.", "low")

        failures = 0
        while True:
            if datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S") > START_UTC:
                print("arrival date passed, exiting", flush=True)
                return
            free = sum(avail.values())
            if free > 0:
                types = sum(1 for v in avail.values() if v > 0)
                notify(args.topic, "Stord Hotell 20-21 Oct AVAILABLE",
                       f"{free} room(s) across {types} room type(s). Tap to book.")
                return
            if deadline and time.time() > deadline:
                print("max runtime reached, exiting", flush=True)
                return
            print(f"[{now()}] not available", flush=True)
            if args.heartbeat:
                oslo = datetime.now(ZoneInfo("Europe/Oslo"))
                notify(args.topic, "Stord check", f"{oslo:%H:%M}: no rooms yet for 20-21 Oct", "min")
            await asyncio.sleep(args.interval)
            try:
                avail = await check(page)
                failures = 0
            except Exception as e:  # keep polling through transient errors
                avail = {}
                failures += 1
                print(f"[{now()}] error: {e}", file=sys.stderr, flush=True)
                if failures == 5:
                    notify(args.topic, "Stord watch is failing", f"5 errors in a row, last: {e}", "high")
                if failures % 3 == 0:  # fresh page in case the session went stale
                    await page.close()
                    page = await browser.new_page()


if __name__ == "__main__":
    asyncio.run(main())
