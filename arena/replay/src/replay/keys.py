"""A round-robin pool over several API credentials.

One key's rate limit is a ceiling on the whole fleet, and this box carries three distinct
credentials (HIGH, LOW, BATCH; HIGH is the same value as the bare ANTHROPIC_API_KEY). Spreading
requests across them raises the ceiling without changing a single thing about what is measured
-- the request bodies are byte-identical and which key carried one is not an experimental axis.

WHY A PROXY RATHER THAN A CLIENT PER ARM. Assigning arm 1 to HIGH and arm 2 to LOW would make
the key a per-arm property, and if the two credentials ever behaved differently -- different
tier, different throttling, different model routing -- that difference would land squarely on
the comparison between arms. Round-robining per REQUEST spreads any such difference evenly
across every arm, so it cannot be mistaken for an effect.
"""
from __future__ import annotations

import itertools
import os
import threading


class KeyPool:
    """Presents one `.messages.create`, dispatching across several real clients."""

    def __init__(self, clients: list) -> None:
        if not clients:
            raise ValueError("KeyPool needs at least one client")
        self._clients = clients
        self._turn = itertools.cycle(range(len(clients)))
        self._lock = threading.Lock()
        self.messages = _Messages(self)

    def _next(self):
        # itertools.cycle is not thread-safe; the lock is held only for the counter, never
        # across the request, so it costs nothing at fleet concurrency.
        with self._lock:
            return self._clients[next(self._turn)]

    def __len__(self) -> int:
        return len(self._clients)


class _Messages:
    def __init__(self, pool: KeyPool) -> None:
        self._pool = pool

    def create(self, **kw):
        return self._pool._next().messages.create(**kw)


def from_env(names: list[str], factory) -> tuple[object, list[str]]:
    """Build a pool from environment variable names, skipping absent or DUPLICATE keys.

    Duplicates are dropped because `ANTHROPIC_API_KEY` and `ANTHROPIC_API_KEY_HIGH` hold the
    same value on this box: pooling them would double that key's share of the round robin and
    quietly concentrate load on the credential the pool exists to relieve.
    """
    seen: set[str] = set()
    clients, used = [], []
    for n in names:
        v = os.environ.get(n)
        if not v or v in seen:
            continue
        seen.add(v)
        clients.append(factory(api_key=v))
        used.append(n)
    return (KeyPool(clients) if clients else None), used
