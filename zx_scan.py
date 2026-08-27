#!/usr/bin/env python3
"""
zx-scan — read-only traffic analyzer for Z-Egress.

Answers one question for a prospect, before anything is installed in their
data path: "how much of your network bill is recoverable, and how much of
that does the free Envoy filter already get?"

Honest by construction:
  * dictionaries are trained on one half of the sample and measured on the
    other half, so the reported ratio is what you'd see on unseen traffic
  * generic zstd is measured on the same held-out set, so the comparison
    is apples-to-apples
  * per-message compression, not batched, because that is how request/
    response traffic actually goes over the wire

Usage:
    zx_scan.py --input payloads.jsonl --monthly-gb 4000 --path cross-az
    zx_scan.py --demo --monthly-gb 4000 --path nat
"""

import argparse
import json
import random
import statistics
import string
import sys

try:
    import zstandard as zstd
except ImportError:
    sys.exit("pip install zstandard")

# AWS $/GB. Cross-AZ is billed both directions, hence 0.02 round trip.
EGRESS_PRICES = {
    "cross-az": (0.02, "Cross-AZ traffic (round trip)"),
    "nat":      (0.045, "NAT Gateway data processing"),
    "internet": (0.09, "Internet egress (post free tier)"),
    "cross-region": (0.02, "Cross-region transfer"),
}

ZSTD_LEVEL = 1
DICT_SIZE = 112640  # 110 KiB — the zstd default


def load_payloads(path):
    out = []
    with open(path, "rb") as fh:
        for line in fh:
            line = line.strip()
            if line:
                out.append(line)
    return out


def demo_payloads(n=6000):
    """Synthetic microservice event traffic, for demoing the report."""
    random.seed(11)
    hexs = string.hexdigits.lower()
    out = []
    for _ in range(n):
        out.append(json.dumps({
            "event_id": "evt_" + "".join(random.choices(hexs, k=16)),
            "user_id": "usr_" + "".join(random.choices(hexs, k=12)),
            "event_type": random.choice(
                ["checkout.completed", "cart.updated", "page.view", "auth.login"]),
            "status": "ok", "currency": "USD",
            "amount_cents": random.randint(100, 99999),
            "region": "ap-south-1", "service": "payments-api",
            "version": "v2.3.1", "timestamp": "2026-08-26T10:00:00Z",
            "trace_id": "".join(random.choices(hexs, k=32)),
            "tags": ["prod", "billing", "v2"],
        }).encode())
    return out


def analyze(payloads, monthly_gb, path_key):
    if len(payloads) < 200:
        sys.exit("need at least 200 sample payloads for a meaningful dictionary")

    random.shuffle(payloads)
    split = len(payloads) // 2
    train, test = payloads[:split], payloads[split:]

    sizes = sorted(len(p) for p in test)
    p50 = sizes[len(sizes) // 2]
    p90 = sizes[int(len(sizes) * 0.90)]
    p99 = sizes[int(len(sizes) * 0.99)]

    # Held-out measurement: the dictionary never saw `test`.
    dictionary = zstd.train_dictionary(DICT_SIZE, train, level=ZSTD_LEVEL)
    c_generic = zstd.ZstdCompressor(level=ZSTD_LEVEL)
    c_dict = zstd.ZstdCompressor(level=ZSTD_LEVEL, dict_data=dictionary)

    raw = sum(len(p) for p in test)
    gen = sum(len(c_generic.compress(p)) for p in test)
    dct = sum(len(c_dict.compress(p)) for p in test)

    gen_ratio = 1 - gen / raw
    dct_ratio = 1 - dct / raw
    price, label = EGRESS_PRICES[path_key]

    bill = monthly_gb * price
    save_gen = bill * gen_ratio
    save_dct = bill * dct_ratio

    return {
        "n_test": len(test), "p50": p50, "p90": p90, "p99": p99,
        "mean": statistics.mean(sizes),
        "gen_ratio": gen_ratio, "dct_ratio": dct_ratio,
        "headroom": 1 - dct / gen if gen else 0,
        "label": label, "price": price, "bill": bill,
        "save_gen": save_gen, "save_dct": save_dct,
        "delta": save_dct - save_gen,
        "dict_id": dictionary.dict_id(),
    }


def report(r, monthly_gb):
    w = 64
    print("=" * w)
    print("  Z-EGRESS TRAFFIC SCAN — read-only, nothing installed in-path")
    print("=" * w)
    print(f"\nSample: {r['n_test']:,} held-out payloads (dictionary never saw these)\n")
    print("PAYLOAD SIZE DISTRIBUTION")
    print(f"  median (p50)      {r['p50']:>10,} B")
    print(f"  p90               {r['p90']:>10,} B")
    print(f"  p99               {r['p99']:>10,} B")
    print(f"  mean              {r['mean']:>10,.0f} B")

    print("\nCOMPRESSION, MEASURED ON UNSEEN TRAFFIC")
    print(f"  Envoy generic zstd      {r['gen_ratio']*100:>6.1f}% reduction")
    print(f"  Z-Egress trained dict   {r['dct_ratio']*100:>6.1f}% reduction")
    print(f"  -> of the bytes generic leaves behind, "
          f"the dictionary removes {r['headroom']*100:.1f}%")
    print(f"  dictionary id: {r['dict_id']}  (travels in the zstd frame header)")

    print(f"\nCOST MODEL — {r['label']} @ ${r['price']}/GB")
    print(f"  {monthly_gb:,} GB/month on this path      ${r['bill']:>12,.0f}/mo")
    print(f"  with Envoy's free filter             -${r['save_gen']:>12,.0f}/mo")
    print(f"  with Z-Egress dictionaries           -${r['save_dct']:>12,.0f}/mo")
    print(f"  incremental value of Z-Egress         ${r['delta']:>12,.0f}/mo"
          f"   (${r['delta']*12:,.0f}/yr)")

    print("\nVERDICT")
    if r["p50"] < 2048 and r["headroom"] > 0.30:
        print("  STRONG FIT. Small median payload — generic zstd underperforms")
        print("  badly here and trained dictionaries recover most of the gap.")
    elif r["headroom"] > 0.15:
        print("  MODERATE FIT. Some dictionary headroom, but batching is")
        print("  eroding it. Worth a pilot; expect a shrinking margin.")
    else:
        print("  POOR FIT. Payloads are large enough that generic zstd already")
        print("  captures nearly everything. Tell them to enable Envoy's filter")
        print("  and walk away — you have no differentiated value here.")
    print("=" * w)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", help="JSONL file of sampled payloads, one per line")
    ap.add_argument("--demo", action="store_true", help="use synthetic traffic")
    ap.add_argument("--monthly-gb", type=float, required=True)
    ap.add_argument("--path", default="cross-az", choices=list(EGRESS_PRICES))
    a = ap.parse_args()

    payloads = demo_payloads() if a.demo else load_payloads(a.input)
    report(analyze(payloads, a.monthly_gb, a.path), a.monthly_gb)


if __name__ == "__main__":
    main()