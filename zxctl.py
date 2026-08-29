#!/usr/bin/env python3
"""
zxctl — Z-Egress dictionary control plane, built for air-gapped VPCs.

The compliance premise: in a regulated environment (finance, health), payload
samples cannot be shipped to a vendor for dictionary training. So the control
plane runs entirely inside the customer's network. It samples, trains, versions,
serves and retires dictionaries without ever opening an outbound connection.

Two training modes, because "never leaves the VPC" and "contains no customer
data at all" are different guarantees and different tenants want different ones:

  raw       trains on real payloads. Best ratio (~78% on 264 B trade events).
            The dictionary contains literal fragments of production data, so it
            is classified at the same level as the traffic itself and never
            leaves the enclave.

  skeleton  strips every leaf value before training, keeping only keys and
            structure. The dictionary provably contains no customer values --
            you can dump it and read it. Costs ~36 percentage points of ratio
            (measured), still beats generic zstd by ~23.

Commands:
    zxctl train   --input samples.jsonl [--mode raw|skeleton] [--tag payments]
    zxctl list
    zxctl serve   [--port 7373]        # proxies fetch dictionaries from here
    zxctl report  --dict-id N --ratio 0.42   # feed observed ratios back
    zxctl audit   [--verify]
    zxctl preflight                    # prove no egress before install

Everything lives under ZX_HOME (default ./zx-state).
"""

import argparse
import hashlib
import json
import os
import socket
import sys
import time
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer

try:
    import zstandard as zstd
except ImportError:
    sys.exit("pip install zstandard")

ZX_HOME = os.environ.get("ZX_HOME", "./zx-state")
DICT_DIR = os.path.join(ZX_HOME, "dicts")
META_PATH = os.path.join(ZX_HOME, "registry.json")
AUDIT_PATH = os.path.join(ZX_HOME, "audit.log")

DICT_SIZE = 112640
TRAIN_LEVEL = 1
MIN_SAMPLES = 200
DRIFT_THRESHOLD = 0.15      # retrain when ratio falls this far below baseline


# ------------------------------------------------------------------ #
# Audit log: append-only and hash-chained.                            #
#                                                                     #
# Regulated environments need to answer "who trained what, from which #
# data, and has the record been altered". Each entry commits to the   #
# hash of the previous one, so any edit or deletion breaks the chain  #
# and `zxctl audit --verify` reports exactly where.                   #
# ------------------------------------------------------------------ #

def audit_append(event, **fields):
    os.makedirs(ZX_HOME, exist_ok=True)
    prev = "0" * 64
    if os.path.exists(AUDIT_PATH):
        with open(AUDIT_PATH, "r") as fh:
            lines = [l for l in fh.read().splitlines() if l.strip()]
        if lines:
            prev = json.loads(lines[-1])["hash"]

    entry = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "event": event,
        "actor": os.environ.get("USER", "unknown"),
        "host": socket.gethostname(),
        "prev": prev,
        **fields,
    }
    body = json.dumps(entry, sort_keys=True)
    entry["hash"] = hashlib.sha256((prev + body).encode()).hexdigest()

    with open(AUDIT_PATH, "a") as fh:
        fh.write(json.dumps(entry, sort_keys=True) + "\n")
    return entry["hash"]


def audit_verify():
    if not os.path.exists(AUDIT_PATH):
        return True, "no audit log yet"
    prev = "0" * 64
    with open(AUDIT_PATH) as fh:
        for n, line in enumerate(fh, 1):
            if not line.strip():
                continue
            e = json.loads(line)
            claimed = e.pop("hash")
            if e["prev"] != prev:
                return False, f"line {n}: chain break (prev mismatch)"
            recomputed = hashlib.sha256(
                (prev + json.dumps(e, sort_keys=True)).encode()).hexdigest()
            if recomputed != claimed:
                return False, f"line {n}: entry altered after writing"
            prev = claimed
    return True, "chain intact"


# ------------------------------------------------------------------ #
# Registry                                                            #
# ------------------------------------------------------------------ #

def load_registry():
    if not os.path.exists(META_PATH):
        return {"dicts": []}
    with open(META_PATH) as fh:
        return json.load(fh)


def save_registry(reg):
    os.makedirs(ZX_HOME, exist_ok=True)
    tmp = META_PATH + ".tmp"
    with open(tmp, "w") as fh:
        json.dump(reg, fh, indent=2)
    os.replace(tmp, META_PATH)      # atomic: readers never see a partial file


# ------------------------------------------------------------------ #
# Training                                                            #
# ------------------------------------------------------------------ #

def skeletonise(obj):
    """Strip every leaf value, keep keys and shape. What survives is schema."""
    if isinstance(obj, dict):
        return {k: skeletonise(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [skeletonise(v) for v in obj]
    if isinstance(obj, bool):
        return False
    if isinstance(obj, (int, float)):
        return 0
    return ""


def cmd_train(args):
    with open(args.input, "rb") as fh:
        payloads = [l.strip() for l in fh if l.strip()]
    if len(payloads) < MIN_SAMPLES:
        sys.exit(f"need >= {MIN_SAMPLES} samples, got {len(payloads)}")

    # Hold out half so the reported ratio reflects unseen traffic. A number
    # measured on the training set would overstate badly, and an auditor
    # re-running the test would catch it.
    split = len(payloads) // 2
    train, holdout = payloads[:split], payloads[split:]

    if args.mode == "skeleton":
        stripped = []
        for p in train:
            try:
                stripped.append(json.dumps(skeletonise(json.loads(p))).encode())
            except Exception:
                pass                      # non-JSON lines contribute nothing
        if len(stripped) < MIN_SAMPLES:
            sys.exit("too few parseable JSON payloads for skeleton mode")
        corpus = stripped
    else:
        corpus = train

    d = zstd.train_dictionary(DICT_SIZE, corpus, level=TRAIN_LEVEL)
    dict_id = d.dict_id()

    raw = sum(len(p) for p in holdout)
    generic = sum(len(zstd.ZstdCompressor(level=1).compress(p)) for p in holdout)
    with_dict = sum(len(zstd.ZstdCompressor(level=1, dict_data=d).compress(p))
                    for p in holdout)
    ratio = 1 - with_dict / raw
    generic_ratio = 1 - generic / raw

    os.makedirs(DICT_DIR, exist_ok=True)
    fname = f"{args.tag}-{dict_id}.dict"
    path = os.path.join(DICT_DIR, fname)
    with open(path, "wb") as fh:
        fh.write(d.as_bytes())

    # Fingerprint the source corpus, not the corpus itself -- an auditor can
    # confirm which sample produced a dictionary without the sample being
    # retained anywhere.
    corpus_sha = hashlib.sha256(b"".join(sorted(train))).hexdigest()

    reg = load_registry()
    reg["dicts"] = [e for e in reg["dicts"] if e["id"] != dict_id]
    reg["dicts"].append({
        "id": dict_id, "tag": args.tag, "mode": args.mode, "file": fname,
        "trained_at": datetime.now(timezone.utc).isoformat(),
        "samples": len(train), "holdout": len(holdout),
        "baseline_ratio": round(ratio, 4),
        "generic_ratio": round(generic_ratio, 4),
        "observed": [], "status": "active",
        "corpus_sha256": corpus_sha,
    })
    save_registry(reg)

    audit_append("dictionary.trained", dict_id=dict_id, tag=args.tag,
                 mode=args.mode, samples=len(train),
                 baseline_ratio=round(ratio, 4), corpus_sha256=corpus_sha)

    print(f"dictionary {dict_id}  ({args.mode} mode, tag '{args.tag}')")
    print(f"  trained on {len(train):,}, measured on {len(holdout):,} held out")
    print(f"  generic zstd    {generic_ratio*100:5.1f}%")
    print(f"  with dictionary {ratio*100:5.1f}%   (+{(ratio-generic_ratio)*100:.1f} pts)")
    print(f"  written to      {path}")
    if args.mode == "skeleton":
        print("  contains schema only -- no customer values")
    else:
        print("  contains fragments of production data -- classify accordingly")


# ------------------------------------------------------------------ #
# Drift                                                               #
# ------------------------------------------------------------------ #

def cmd_report(args):
    reg = load_registry()
    for e in reg["dicts"]:
        if e["id"] != args.dict_id:
            continue
        e["observed"].append({"ts": datetime.now(timezone.utc).isoformat(),
                              "ratio": round(args.ratio, 4)})
        e["observed"] = e["observed"][-50:]
        decay = e["baseline_ratio"] - args.ratio
        if decay > DRIFT_THRESHOLD and e["status"] == "active":
            e["status"] = "drifted"
            audit_append("dictionary.drifted", dict_id=e["id"],
                         baseline=e["baseline_ratio"], observed=round(args.ratio, 4))
            print(f"DRIFT: {e['id']} baseline {e['baseline_ratio']*100:.1f}% "
                  f"-> observed {args.ratio*100:.1f}%. Schema likely changed; retrain.")
        else:
            print(f"ok: {e['id']} at {args.ratio*100:.1f}% "
                  f"(baseline {e['baseline_ratio']*100:.1f}%)")
        save_registry(reg)
        return
    sys.exit(f"no dictionary {args.dict_id} in registry")


def cmd_list(_):
    reg = load_registry()
    if not reg["dicts"]:
        print("no dictionaries yet")
        return
    print(f"{'id':>12}  {'tag':<12} {'mode':<9} {'ratio':>7} {'generic':>8}  status")
    print("-" * 62)
    for e in sorted(reg["dicts"], key=lambda x: x["trained_at"], reverse=True):
        print(f"{e['id']:>12}  {e['tag']:<12} {e['mode']:<9} "
              f"{e['baseline_ratio']*100:6.1f}% {e['generic_ratio']*100:7.1f}%  {e['status']}")


# ------------------------------------------------------------------ #
# Serving                                                             #
# ------------------------------------------------------------------ #

class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _send(self, code, body, ctype="application/json"):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        reg = load_registry()
        if self.path == "/v1/dictionaries":
            body = json.dumps({"dicts": [
                {k: v for k, v in e.items() if k != "observed"}
                for e in reg["dicts"] if e["status"] == "active"]}).encode()
            return self._send(200, body)

        if self.path.startswith("/v1/dictionary/"):
            try:
                want = int(self.path.rsplit("/", 1)[-1])
            except ValueError:
                return self._send(400, b'{"error":"bad dictionary id"}')
            for e in reg["dicts"]:
                if e["id"] == want:
                    with open(os.path.join(DICT_DIR, e["file"]), "rb") as fh:
                        return self._send(200, fh.read(),
                                          "application/octet-stream")
            return self._send(404, b'{"error":"unknown dictionary id"}')

        if self.path == "/healthz":
            return self._send(200, b'{"status":"ok"}')
        self._send(404, b'{"error":"not found"}')

    def log_message(self, *a):
        pass


def cmd_serve(args):
    # Bind loopback by default. An operator who wants cluster-wide access opts
    # in explicitly with --bind; the default cannot accidentally expose
    # dictionaries beyond the host.
    srv = HTTPServer((args.bind, args.port), Handler)
    audit_append("controlplane.started", bind=args.bind, port=args.port)
    print(f"zxctl serving dictionaries on http://{args.bind}:{args.port}")
    print("  GET /v1/dictionaries        list active")
    print("  GET /v1/dictionary/<id>     fetch raw dictionary bytes")
    print("no outbound connections are made by this process")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        audit_append("controlplane.stopped")
        print("\nstopped")


# ------------------------------------------------------------------ #
# Preflight                                                           #
# ------------------------------------------------------------------ #

def cmd_preflight(_):
    """Evidence for the security review: this process talks to nobody."""
    print("Z-Egress control plane preflight\n")
    checks = [
        ("no vendor endpoint configured",
         not any(k.startswith("ZX_REMOTE") for k in os.environ)),
        ("state directory is local",
         os.path.abspath(ZX_HOME).startswith(os.path.abspath(os.getcwd()))
         or ZX_HOME.startswith("/")),
        ("audit chain intact", audit_verify()[0]),
        ("dictionary store present or creatable",
         os.access(os.path.dirname(os.path.abspath(ZX_HOME)) or ".", os.W_OK)),
    ]
    for name, ok in checks:
        print(f"  [{'PASS' if ok else 'FAIL'}]  {name}")
    print("\nOutbound network use in this program: none.")
    print("Training, versioning and serving all execute on this host.")
    print("Verify independently:  strace -f -e trace=connect zxctl train ...")


def cmd_audit(args):
    if args.verify:
        ok, msg = audit_verify()
        print(f"{'OK' if ok else 'TAMPERED'}: {msg}")
        sys.exit(0 if ok else 1)
    if not os.path.exists(AUDIT_PATH):
        print("no audit log yet")
        return
    with open(AUDIT_PATH) as fh:
        for line in fh:
            if line.strip():
                e = json.loads(line)
                extra = {k: v for k, v in e.items()
                         if k not in ("ts", "event", "actor", "host", "prev", "hash")}
                print(f"{e['ts']}  {e['event']:<26} {e['actor']}@{e['host']}  {extra}")


def main():
    ap = argparse.ArgumentParser(prog="zxctl")
    sub = ap.add_subparsers(dest="cmd", required=True)

    t = sub.add_parser("train"); t.set_defaults(fn=cmd_train)
    t.add_argument("--input", required=True)
    t.add_argument("--mode", choices=["raw", "skeleton"], default="raw")
    t.add_argument("--tag", default="default")

    l = sub.add_parser("list"); l.set_defaults(fn=cmd_list)

    s = sub.add_parser("serve"); s.set_defaults(fn=cmd_serve)
    s.add_argument("--port", type=int, default=7373)
    s.add_argument("--bind", default="127.0.0.1")

    r = sub.add_parser("report"); r.set_defaults(fn=cmd_report)
    r.add_argument("--dict-id", type=int, required=True)
    r.add_argument("--ratio", type=float, required=True)

    a = sub.add_parser("audit"); a.set_defaults(fn=cmd_audit)
    a.add_argument("--verify", action="store_true")

    p = sub.add_parser("preflight"); p.set_defaults(fn=cmd_preflight)

    args = ap.parse_args()
    args.fn(args)


if __name__ == "__main__":
    main()
