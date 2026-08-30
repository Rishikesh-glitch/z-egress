# Z-Egress

Dictionary-trained zstd compression for microservice traffic.

On small JSON payloads, Envoy's built-in zstd filter removes about 23% of
the bytes. A zstd dictionary trained on the same traffic removes 80%.

## Benchmark

Envoy is run at levels 1, 3, 9 and 19 so the comparison cannot be accused
of picking a weak configuration. Z-Egress runs at level 1. Dictionaries are
trained on one half of the sample and measured on the other, so every number
reflects traffic the dictionary has never seen.

| payload | Envoy best | Z-Egress |
|---------|-----------|----------|
| 347 B   | 29.1%     | **80.0%** |
| 1.7 KB  | 72.6%     | 84.8%    |
| 8.7 KB  | 84.8%     | 87.0%    |
| 34.8 KB | **87.8%** | 87.5%    |

The last row is a loss. This only pays off when median payloads are under
about 2 KB. Above that, use Envoy's filter — it's free and it's enough.

Reproduce: `python3 bench_vs_envoy.py`

## Why the gap exists

A 350-byte message has almost no history for the LZ matcher to reference,
so raising the compression level barely helps — Envoy at level 19 still only
reaches 29%. A pre-trained dictionary supplies that history up front.

Envoy supports dictionaries, but the field is a static `DataSource` and the
docs tell you to train it by hand with the zstd CLI. It works until your
schema changes, and rotating means a redeploy.

## Build and run

    sudo apt install -y build-essential libzstd-dev
    gcc -std=c11 -O2 -Wall -Wextra -pthread egress.c  -o z-egress  -lzstd
    gcc -std=c11 -O2 -Wall -Wextra -pthread ingress.c -o z-ingress -lzstd

Train a dictionary from a traffic sample (JSONL, one payload per line):

    python3 -c "
    import zstandard as zs
    p=[l.strip() for l in open('samples.jsonl','rb') if l.strip()]
    d=zs.train_dictionary(112640,p,level=1)
    open('dicts/app.dict','wb').write(d.as_bytes())"

Run both halves:

    ./z-ingress 8081 127.0.0.1 9001 ./dicts        # decompresses
    ./z-egress  8080 127.0.0.1 8081 ./dicts/app.dict   # compresses

    185 B -> 34 B on the wire -> 185 B delivered, byte-identical.

## Version skew

Dictionary ids travel in the zstd frame header, so the sender never announces
which dictionary it used. An ingress lacking that id answers 415 with
`X-Z-Egress-Missing-Dict`, and the sender falls back to generic zstd. Skewed
rollouts degrade to Envoy's behaviour; they do not corrupt payloads.

## Safety

Both proxies pass through anything they cannot safely rewrite: chunked
bodies, non-JSON, already-encoded bodies, and payloads where compression
does not win. The ingress caps decompressed size by both an absolute
ceiling and a maximum expansion ratio — a 12 KB frame claiming 400 MB is
refused before allocating.

Tested clean under ASan, UBSan and LeakSanitizer, including 60 concurrent
requests and deliberately malformed input.

## Status

Working prototype. Not yet run in production anywhere.
EOF

The proxies and control plane are AGPL-3.0. Commercial licenses for closed-source use are available — contact r88747000@gmail.com.
