#!/usr/bin/env python3
import ipaddress
import json
import re
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from urllib.request import Request, urlopen

BASE = "https://raw.githubusercontent.com/OpenFilters/internet-scanners/main/cidr/"
INDEX = "https://api.github.com/repos/OpenFilters/internet-scanners/contents/cidr?ref=main"
PATTERN = re.compile(r"[a-z0-9_]+_v([46])\.txt\Z")
OUTPUT = Path("openfilters-all.txt")


def fetch(url):
    request = Request(url, headers={"User-Agent": "feed-compiler/1"})
    with urlopen(request, timeout=40) as response:
        data = response.read(2_000_001)
    if len(data) > 2_000_000:
        raise ValueError("Source too large")
    return data


def discover():
    entries = json.loads(fetch(INDEX))
    if not isinstance(entries, list):
        raise ValueError("Invalid source index")
    sources = []
    for entry in entries:
        name = entry.get("name", "")
        if entry.get("type") != "file" or not name.endswith(".txt"):
            continue
        match = PATTERN.fullmatch(name)
        if not match:
            continue
        if entry.get("download_url") != BASE + name:
            raise ValueError("Unexpected source URL")
        sources.append((name, int(match.group(1))))
    if sum(v == 4 for _, v in sources) < 70 or sum(v == 6 for _, v in sources) < 20:
        raise ValueError("Too few source lists")
    if len(sources) > 400 or len({n for n, _ in sources}) != len(sources):
        raise ValueError("Invalid source list")
    return sources


def read_source(source):
    name, version = source
    result = set()
    for raw in fetch(BASE + name).decode("utf-8-sig").splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        network = ipaddress.ip_network(line, strict=False)
        if network.version != version or network.prefixlen < (8 if version == 4 else 24):
            raise ValueError("Unexpected network")
        result.add(network)
    if not result:
        raise ValueError("Empty source")
    return result


def main():
    sources = discover()
    networks = {4: set(), 6: set()}
    with ThreadPoolExecutor(max_workers=8) as pool:
        for (_, version), result in zip(sources, pool.map(read_source, sources)):
            networks[version].update(result)
    combined = []
    for version in (4, 6):
        collapsed = ipaddress.collapse_addresses(networks[version])
        combined.extend(sorted(collapsed, key=lambda n: (int(n.network_address), n.prefixlen)))
    if len(combined) < 500:
        raise ValueError("Combined list unexpectedly small")
    temp = OUTPUT.with_suffix(".tmp")
    temp.write_text("".join(f"{network}\n" for network in combined), encoding="utf-8")
    temp.replace(OUTPUT)
    print(f"{len(sources)} sources; {len(combined)} CIDRs")


if __name__ == "__main__":
    main()
