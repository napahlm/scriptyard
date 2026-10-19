#!/usr/bin/env python3
"""Poll Stord Hotell (Mews booking engine) for one night 20-21 Oct 2026 and push a phone alert via ntfy.

Uses the same call the hotel's own booking widget makes (bookingEngine/v1/services/getAvailability).

Usage:
    python3 stord_watch.py --topic <ntfy-topic> [--interval 60] [--max-minutes 0]
"""
import argparse
import json
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone

API = "https://api.mews.com/api/bookingEngine/v1/services/getAvailability"
BOOKING_ENGINE_ID = "4151883d-7521-43f9-8187-b1f500cf26fa"
SERVICE_ID = "fb83c231-3de0-4a20-899a-b1f500cf2391"
ENTERPRISE_ID = "0cbc3f32-5c82-430a-b5f6-b1d300a9cae7"
CLIENT = "Mews Distributor 5965.0.0"
# Hotel-local midnight (Europe/Oslo, UTC+2 until 25 Oct) expressed in UTC.
START_UTC = "2026-10-19T22:00:00.000Z"  # night of 20 Oct
END_UTC = "2026-10-20T22:00:00.000Z"
BOOK_URL = f"https://app.mews.com/distributor/{BOOKING_ENGINE_ID}?mewsStart=2026-10-20&mewsEnd=2026-10-21&language=en-GB"


def now():
    return f"{datetime.now(timezone.utc):%H:%M:%S}Z"


def check():
    body = {
        "serviceId": SERVICE_ID,
        "bookingEngineId": BOOKING_ENGINE_ID,
        "startUtc": START_UTC,
        "endUtc": END_UTC,
        "enterpriseId": ENTERPRISE_ID,
        "fullAmounts": False,
        "languageCode": "en-GB",
        "client": CLIENT,
    }
    req = urllib.request.Request(
        API,
        data=json.dumps(body).encode(),
        headers={"Content-Type": "application/json", "Accept": "application/json",
                 "Origin": "https://app.mews.com", "Referer": "https://app.mews.com/"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            res = json.load(r)
    except urllib.error.HTTPError as e:
        raise RuntimeError(f"HTTP {e.code}: {e.read()[:300]!r}") from e
    cats = res["categoryAvailabilities"]
    # Index 0 is the night starting START_UTC (20 Oct).
    return [c for c in cats if c["availabilities"] and c["availabilities"][0] > 0], len(cats)


def notify(topic, title, msg, priority="urgent"):
    print(f"\a[{now()}] {title}: {msg}", flush=True)
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


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--topic", help="ntfy.sh topic")
    ap.add_argument("--interval", type=int, default=60, help="seconds between checks")
    ap.add_argument("--max-minutes", type=float, default=0, help="exit cleanly after this long (0 = forever)")
    ap.add_argument("--start-ping", action="store_true", help="send a low-priority 'started' push")
    args = ap.parse_args()

    avail, n = check()  # fail fast if the API call is broken
    print(f"[{now()}] API OK, {n} room categories, watching every {args.interval}s", flush=True)
    if args.start_ping:
        notify(args.topic, "Stord watch running", f"Checking {n} room types every {args.interval}s.", "low")

    deadline = time.time() + args.max_minutes * 60 if args.max_minutes else None
    failures = 0
    while True:
        if datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z") > START_UTC:
            print("arrival date passed, exiting", flush=True)
            return
        if avail:
            rooms = sum(c["availabilities"][0] for c in avail)
            notify(args.topic, "Stord Hotell 20-21 Oct AVAILABLE",
                   f"{rooms} room(s) across {len(avail)} room type(s). Tap to book.")
            return
        if deadline and time.time() > deadline:
            print("max runtime reached, exiting", flush=True)
            return
        print(f"[{now()}] not available", flush=True)
        time.sleep(args.interval)
        try:
            avail, n = check()
            failures = 0
        except Exception as e:  # keep polling through transient errors
            avail = []
            failures += 1
            print(f"[{now()}] error: {e}", file=sys.stderr, flush=True)
            if failures == 5:
                notify(args.topic, "Stord watch is failing", f"5 errors in a row, last: {e}", "high")


if __name__ == "__main__":
    main()
