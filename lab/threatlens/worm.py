"""Worms fail at propagation, so propagation is what gets modelled: fan-out, repeats, spread shapes."""
from __future__ import annotations

from collections import Counter, defaultdict

from lab.telemetry import sorted_events

from ._common import LATERAL_PROTOCOLS, finding

BEHAVIOUR = "worm_propagation"


def pattern_similarity(events: list[dict]) -> list[dict]:
    """Identical process shapes across hosts are a *shape*, not evidence.

    An office rollout puts the same image under the same parent on every workstation, so this only
    reports a group when the hosts in it also talk to each other over a lateral protocol.
    """
    shapes: dict[tuple[str, str], set[str]] = defaultdict(set)
    for e in events:
        if e.get("kind") == "process":
            shapes[(str(e.get("image", "")).lower(), str(e.get("parent", "")).lower())].add(e["host"])
    edges = {(e["host"], e["dst"]) for e in events
             if e.get("kind") == "network" and e.get("proto") in LATERAL_PROTOCOLS}
    out = []
    for (image, parent), hosts in shapes.items():
        if len(hosts) < 3:
            continue
        coupled = any(a in hosts and b in hosts for a, b in edges)
        if coupled:
            out.append({"image": image, "parent": parent, "hosts": sorted(hosts)})
    return out


def analyse(events: list[dict]) -> dict:
    events = sorted_events(events)
    lateral = [e for e in events if e.get("kind") == "network" and e.get("proto") in LATERAL_PROTOCOLS]
    services = [e for e in events if e.get("kind") == "service" and e.get("state") == "created"]
    failures = [e for e in events if e.get("kind") == "auth" and e.get("result") == "failure"]

    fanout: dict[str, set[str]] = defaultdict(set)
    repeats: Counter[tuple[str, str]] = Counter()
    for e in lateral:
        fanout[e["host"]].add(e["dst"])
        repeats[(e["host"], e["dst"])] += 1

    spreaders = {h: d for h, d in fanout.items() if len(d) >= 3}
    repeated = {k: n for k, n in repeats.items() if n >= 3}
    failed_hosts = defaultdict(int)
    for e in failures:
        failed_hosts[(e["host"], e.get("user", ""))] += 1

    observations: list[str] = []
    sources: set[str] = set()

    if spreaders:
        worst = max(spreaders, key=lambda h: len(spreaders[h]))
        observations.append(f"{worst} opened {len(spreaders[worst])} lateral connections to distinct hosts")
        sources.add("network")
    if repeated:
        (src, dst), n = max(repeated.items(), key=lambda kv: kv[1])
        observations.append(f"{n} repeated attempts from {src} to {dst}")
        sources.add("network")
    reached = {dst for dsts in spreaders.values() for dst in dsts}
    services = [e for e in services if e["host"] in reached]
    if services:
        hosts = {e["host"] for e in services}
        if len(hosts) >= 2:
            observations.append(f"services created on {len(hosts)} hosts: {', '.join(sorted(hosts)[:4])}")
            sources.add("service")
    brute = {k: n for k, n in failed_hosts.items() if n >= 3}
    if brute and spreaders:
        (host, user), n = max(brute.items(), key=lambda kv: kv[1])
        observations.append(f"{n} failed authentications for {user} on {host} alongside lateral traffic")
        sources.add("auth")
    similar = pattern_similarity(events)
    if similar and spreaders:
        shape = similar[0]
        observations.append(f"{shape['image']} under {shape['parent']} on {len(shape['hosts'])} coupled hosts")
        sources.add("process")

    limits = [
        "fan-out is also what a deployment tool, a backup agent or a vulnerability scanner produces",
        "the window supplied bounds what can be seen; silence outside it is not evidence",
        "identical process shapes across hosts are normal in any standardised build",
        "service creation is only counted on hosts the fan-out already reached; a service elsewhere is another incident",
    ]
    return finding(BEHAVIOUR, observations, limits,
                   ["T1021 remote services", "T1570 lateral tool transfer"] if observations else [],
                   sources, {"hosts": sorted(spreaders)})
