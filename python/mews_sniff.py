"""One-off: load the Mews booking page headless and print the API calls it makes."""
import asyncio
import sys

from playwright.async_api import async_playwright

URL = sys.argv[1]


async def main():
    seen = []
    async with async_playwright() as p:
        b = await p.chromium.launch()
        page = await b.new_page()

        async def on_resp(r):
            req = r.request
            if "mews" in r.url and req.method == "POST":
                body = (req.post_data or "")[:400]
                try:
                    txt = (await r.text())[:300]
                except Exception:
                    txt = "?"
                seen.append(f"{r.status} {r.url} REQ={body} RESP={txt}")

        page.on("response", lambda r: asyncio.ensure_future(on_resp(r)))
        await page.goto(URL, wait_until="networkidle", timeout=90000)
        await page.wait_for_timeout(15000)
        await b.close()
    for s in seen:
        print(s.replace("\n", " "))


asyncio.run(main())
