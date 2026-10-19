#!/usr/bin/env python3
"""Poll Stord Hotell (Mews booking engine) for 20-21 Oct availability and push a phone alert via ntfy.

Usage:
    python3 stord_watch.py --topic <your-secret-ntfy-topic>
Install the ntfy app (iOS/Android), subscribe to the same topic, done.
"""
import argparse
import json
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone

API = "https://api.mews.com/api/distributor/v1"
CONFIG_ID = "4151883d-7521-43f9-8187-b1f500cf26fa"  # "Hotellrom" booking engine on stord-hotell.no
CLIENT = "stord-watch 1.0"
# Hotel-local midnight (Europe/Oslo, UTC+2 until 25 Oct) expressed in UTC.
START_UTC = "2026-10-19T22:00:00Z"  # arrival 20 Oct
END_UTC = "2026-10-20T22:00:00Z"    # departure 21 Oct
BOOK_URL = f"https://app.mews.com/distributor/{CONFIG_ID}?mewsStart=2026-10-20&mewsEnd=2026-10-21&language=en-GB"


def post(endpoint, body):
    req = urllib.request.Request(
        f"{API}/{endpoint}",
        data=json.dumps(body).encode(),
        headers={"Content-Type": "application/json", "Accept": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            return json.load(r)
    except urllib.error.HTTPError as e:
        raise urllib.error.URLError(f"{endpoint} HTTP {e.code}: {e.read()[:500]!r}") from e


def find_key(obj, names):
    """Depth-first search for the first value under any of the given keys."""
    if isinstance(obj, dict):
        for k in names:
            if isinstance(obj.get(k), str):
                return obj[k]
        obj = list(obj.values())
    if isinstance(obj, list):
        for v in obj:
            hit = find_key(v, names)
            if hit:
                return hit
    return None


def resolve_hotel(cfg):
    hotel = find_key(cfg, ("EnterpriseId", "HotelId"))
    if not hotel:
        sys.exit("Could not find hotel id in configuration response. Pass --hotel-id.\n" + json.dumps(cfg)[:2000])
    return hotel


def category_names(cfg):
    names = {}

    def walk(o):
        if isinstance(o, dict):
            if "Id" in o and isinstance(o.get("Name"), dict) and o.get("SpaceType"):
                n = o["Name"]
                names[o["Id"]] = n.get("en-GB") or n.get("en-US") or next(iter(n.values()), o["Id"])
            for v in o.values():
                walk(v)
        elif isinstance(o, list):
            for v in o:
                walk(v)

    walk(cfg)
    return names


def check(hotel_id):
    res = post("hotels/getAvailability", {
        "Client": CLIENT,
        "ConfigurationId": CONFIG_ID,
        "HotelId": hotel_id,
        "StartUtc": START_UTC,
        "EndUtc": END_UTC,
        "CurrencyCode": "NOK",
    })
    cats = res.get("RoomCategoryAvailabilities") or res.get("RoomCategoryAvailabilites") or []
    return [c for c in cats if c.get("AvailableRoomCount", 0) > 0 and c.get("RoomOccupancyAvailabilities")]


def notify(topic, title, msg, priority="urgent"):
    print(f"\a[{datetime.now():%H:%M:%S}] {title}: {msg}", flush=True)
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
    ap.add_argument("--topic", help="ntfy.sh topic (make it long and random)")
    ap.add_argument("--interval", type=int, default=60, help="seconds between checks (default 60)")
    ap.add_argument("--hotel-id", help="override hotel id if auto-detect fails")
    ap.add_argument("--max-minutes", type=float, default=0, help="exit cleanly after this long (0 = forever)")
    args = ap.parse_args()

    cfg = post("configuration/get", {"Client": CLIENT, "Ids": [CONFIG_ID], "PrimaryId": CONFIG_ID})
    hotel_id = args.hotel_id or resolve_hotel(cfg)
    names = category_names(cfg)
    print(f"Watching hotel {hotel_id}, 20-21 Oct, every {args.interval}s. Ctrl+C to stop.", flush=True)
    notify(args.topic, "Stord watch started", "You will get an urgent alert when 20-21 Oct opens up.", "low")

    failures = 0
    deadline = time.time() + args.max_minutes * 60 if args.max_minutes else None
    while True:
        if deadline and time.time() > deadline:
            print("max runtime reached, exiting", flush=True)
            return
        if datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ") > START_UTC:
            notify(args.topic, "Stord watch stopped", "Arrival date has passed.", "default")
            return
        try:
            avail = check(hotel_id)
            failures = 0
            if avail:
                summary = ", ".join(f"{names.get(c['RoomCategoryId'], 'room')} x{c['AvailableRoomCount']}" for c in avail)
                notify(args.topic, "Stord Hotell 20-21 Oct AVAILABLE", f"{summary}. Tap to book.")
                return
            print(f"[{datetime.now():%H:%M:%S}] not available", flush=True)
        except (urllib.error.URLError, ValueError, KeyError) as e:
            failures += 1
            print(f"[{datetime.now():%H:%M:%S}] error: {e}", file=sys.stderr, flush=True)
            if failures == 5:
                notify(args.topic, "Stord watch is failing", f"5 errors in a row, last: {e}", "high")
        time.sleep(args.interval)


if __name__ == "__main__":
    main()
