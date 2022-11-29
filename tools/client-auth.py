#!/usr/bin/env python3

import json
import asyncio
import aiohttp

async def req():
    resp = await aiohttp.ClientSession().request(
        "post", 'http://localhost:8080/auth',
        data=json.dumps({"version": "1.0", "tee": "tdx", "extra-params": "foo"}),
        headers={"content-type": "application/json"})
    print(str(resp))
    print(await resp.text())
    assert 200 == resp.status

asyncio.get_event_loop().run_until_complete(req())
