#!/usr/bin/env python3
"""
Z-Egress Scan — the SaaS front end.

A prospect uploads a sample of their payloads (JSONL, one per line) and gets
back a real measurement: what Envoy's free filter recovers, what a trained
dictionary recovers, and what that is worth per month on their egress path.

Nothing is installed in their data path. The sample never leaves the process.

Run:
    pip install flask zstandard
    python3 app.py
    open http://localhost:5000
"""

import io
import json
import random
import string

import zstandard as zstd
from flask import Flask, render_template, request

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 64 * 1024 * 1024

ZSTD_LEVEL = 1
DICT_SIZE = 112640
MIN_SAMPLES = 200

PATHS = {
    "cross-az":     (0.020, "Cross-AZ, round trip"),
    "nat":          (0.045, "NAT Gateway processing"),
    "internet":     (0.090, "Internet egress"),
    "cross-region": (0.020, "Cross-region transfer"),
}


def demo_payloads(n=6000):
    random.seed(11)
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


def analyze(payloads, monthly_gb, path_key):
    """Train on half, measure on the other half. Never report training-set
    numbers — they overstate the ratio badly and a customer running their
    own test would catch it immediately."""
    random.shuffle(payloads)
    half = len(payloads) // 2
    train, test = payloads[:half], payloads[half:]

    sizes = sorted(len(p) for p in test)
    pick = lambda q: sizes[min(int(len(sizes) * q), len(sizes) - 1)]

    dictionary = zstd.train_dictionary(DICT_SIZE, train, level=ZSTD_LEVEL)
    c_gen = zstd.ZstdCompressor(level=ZSTD_LEVEL)
    c_dic = zstd.ZstdCompressor(level=ZSTD_LEVEL, dict_data=dictionary)

    raw = sum(len(p) for p in test)
    gen = sum(len(c_gen.compress(p)) for p in test)
    dic = sum(len(c_dic.compress(p)) for p in test)

    gen_r, dic_r = 1 - gen / raw, 1 - dic / raw
    price, label = PATHS[path_key]
    bill = monthly_gb * price

    if pick(0.5) < 2048 and (1 - dic / gen) > 0.30:
        verdict, tone = "Strong fit", "good"
        note = ("Payloads are small enough that generic zstd underperforms. "
                "A trained dictionary recovers most of what it leaves behind.")
    elif (1 - dic / gen) > 0.15:
        verdict, tone = "Moderate fit", "mid"
        note = ("Some headroom, but batching is eroding it. Worth a pilot with "
                "a shrinking margin as batch sizes grow.")
    else:
        verdict, tone = "Poor fit", "bad"
        note = ("Payloads are large enough that generic zstd already captures "
                "nearly everything. Enable Envoy's built-in filter instead — "
                "a dictionary would not earn its keep here.")

    return {
        "n": len(test), "raw": raw,
        "p50": pick(0.50), "p90": pick(0.90), "p99": pick(0.99),
        "gen_pct": gen_r * 100, "dic_pct": dic_r * 100,
        "headroom": (1 - dic / gen) * 100 if gen else 0,
        # wire segments, as percentages of original bytes
        "seg_gen": gen_r * 100,
        "seg_extra": (dic_r - gen_r) * 100,
        "seg_left": (1 - dic_r) * 100,
        "dict_id": dictionary.dict_id(),
        "path_label": label, "price": price, "monthly_gb": monthly_gb,
        "bill": bill,
        "save_gen": bill * gen_r,
        "save_dic": bill * dic_r,
        "delta": bill * (dic_r - gen_r),
        "verdict": verdict, "tone": tone, "note": note,
    }


@app.route("/", methods=["GET"])
def index():
    return render_template("index.html", result=None, error=None)


@app.route("/scan", methods=["POST"])
def scan():
    try:
        monthly_gb = float(request.form.get("monthly_gb") or 0)
    except ValueError:
        monthly_gb = 0
    path_key = request.form.get("path", "cross-az")
    if path_key not in PATHS:
        path_key = "cross-az"

    if request.form.get("demo"):
        payloads = demo_payloads()
    else:
        upload = request.files.get("sample")
        if not upload or not upload.filename:
            return render_template("index.html", result=None,
                                   error="Choose a JSONL file, or run the sample dataset.")
        payloads = [ln.strip() for ln in
                    io.BytesIO(upload.read()).readlines() if ln.strip()]

    if len(payloads) < MIN_SAMPLES:
        return render_template(
            "index.html", result=None,
            error=f"Need at least {MIN_SAMPLES} payloads to train a dictionary "
                  f"worth measuring. This file has {len(payloads)}.")
    if monthly_gb <= 0:
        return render_template("index.html", result=None,
                               error="Enter the monthly volume on this path, in GB.")

    return render_template("index.html",
                           result=analyze(payloads, monthly_gb, path_key),
                           error=None)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)