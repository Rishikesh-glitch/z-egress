#!/usr/bin/env python3
"""
bench_vs_envoy.py — head-to-head, with Envoy given its best case.

Envoy's compressor filter calls libzstd directly, so its byte output is
reproducible here exactly: level 3 by default, streaming with a 4096-byte
output chunk, no dictionary. We also run Envoy at levels 1, 9 and 19 so
nobody can accuse the comparison of picking a weak configuration.

Z-Egress is run at level 1 WITH a dictionary trained on held-out traffic.
If it wins at level 1 against Envoy at level 19, the result is not a
tuning artifact.

    python3 bench_vs_envoy.py                    # synthetic traffic
    python3 bench_vs_envoy.py payloads.jsonl     # your own
"""

import json
import random
import string
import sys
import time

import zstandard as zstd

ENVOY_DEFAULT_LEVEL = 3      # envoy zstd compressor default
ENVOY_CHUNK = 4096           # envoy default chunk_size
DICT_SIZE = 112640


def synth(n):
    hx = string.hexdigits.lower()
    return [json.dumps({
        "event_id": "evt_" + "".join(random.choices(hx, k=16)),
        "user_id": "usr_" + "".join(random.choices(hx, k=12)),
        "event_type": random.choice(["checkout.completed", "cart.updated",
                                     "page.view", "auth.login"]),
        "status": "ok", "currency": "USD",
        "amount_cents": random.randint(100, 99999),
        "region": "ap-south-1", "service": "payments-api",
        "version": "v2.3.1", "timestamp": "2026-08-26T10:00:00Z",
        "trace_id": "".join(random.choices(hx, k=32)),
        "tags": ["prod", "billing", "v2"],
    }).encode() for _ in range(n)]


def envoy_compress(payload, level):
    """Streaming, 4096-byte chunks — how the Envoy filter actually runs."""
    c = zstd.ZstdCompressor(level=level, write_content_size=False)
    out = []
    with c.stream_writer(_Sink(out), closefd=False) as w:
        for i in range(0, len(payload), ENVOY_CHUNK):
            w.write(payload[i:i + ENVOY_CHUNK])
    return sum(len(b) for b in out)


class _Sink:
    def __init__(self, bucket): self.bucket = bucket
    def write(self, b): self.bucket.append(bytes(b)); return len(b)
    def flush(self): pass


def main():
    random.seed(19)
    if len(sys.argv) > 1:
        pool = [l.strip() for l in open(sys.argv[1], "rb") if l.strip()]
        random.shuffle(pool)
        half = len(pool) // 2
        train, base = pool[:half], pool[half:]
        batches = [1]
    else:
        train, base = synth(6000), synth(3000)
        batches = [1, 5, 25, 100]

    d = zstd.train_dictionary(DICT_SIZE, train, level=1)
    zx = zstd.ZstdCompressor(level=1, dict_data=d)

    print(f"dictionary id {d.dict_id()}  |  trained on {len(train):,} samples, "
          f"measured on {len(base):,} held-out samples\n")

    hdr = (f"{'payload':>10} {'ENVOY L1':>9} {'ENVOY L3*':>10} {'ENVOY L9':>9} "
           f"{'ENVOY L19':>10} {'Z-EGRESS':>9} | {'vs best Envoy':>14}")
    print(hdr); print("-" * len(hdr))

    for b in batches:
        msgs = []
        for i in range(0, min(len(base), 2000), b):
            grp = base[i:i + b]
            msgs.append(b"[" + b",".join(grp) + b"]" if b > 1 else grp[0])

        raw = sum(len(m) for m in msgs)
        env = {lv: sum(envoy_compress(m, lv) for m in msgs)
               for lv in (1, ENVOY_DEFAULT_LEVEL, 9, 19)}
        mine = sum(len(zx.compress(m)) for m in msgs)

        best = min(env.values())
        pct = lambda v: 100 * (1 - v / raw)
        gain = 100 * (1 - mine / best)

        print(f"{raw//len(msgs):>9}B {pct(env[1]):>8.1f}% {pct(env[3]):>9.1f}% "
              f"{pct(env[9]):>8.1f}% {pct(env[19]):>9.1f}% {pct(mine):>8.1f}% | "
              f"{gain:>13.1f}%")

    print("\n* Envoy's documented default level.")
    print("'vs best Envoy' = bytes saved against whichever Envoy level did best.")

    # latency, so nobody can claim the win costs CPU
    sample = base[0]
    e3 = zstd.ZstdCompressor(level=ENVOY_DEFAULT_LEVEL)
    t = time.perf_counter()
    for _ in range(20000): e3.compress(sample)
    te = (time.perf_counter() - t) / 20000 * 1e6
    t = time.perf_counter()
    for _ in range(20000): zx.compress(sample)
    tz = (time.perf_counter() - t) / 20000 * 1e6
    print(f"\nlatency on a {len(sample)}B message: "
          f"Envoy L3 {te:.1f}us   Z-Egress {tz:.1f}us")


if __name__ == "__main__":
    main()
