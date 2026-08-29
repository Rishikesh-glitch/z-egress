# Installing Z-Egress

You install this yourself. We never touch your cluster, your machines or your
data. What we ship is container images, a Helm chart and source.

## 1. Build the images in your own environment

Regulated environments do not pull from public registries, so build and push
to your own:

    docker build -f deploy/docker/Dockerfile.proxy        -t registry.internal/z-egress/proxy:0.1.0 .
    docker build -f deploy/docker/Dockerfile.controlplane -t registry.internal/z-egress/controlplane:0.1.0 .
    docker push registry.internal/z-egress/proxy:0.1.0
    docker push registry.internal/z-egress/controlplane:0.1.0

Both images run as uid 65532, drop all capabilities and use a read-only root
filesystem. The proxy image is multi-stage: the compiler is not in the
artefact that reaches your cluster.

## 2. Install the chart

    helm install zx deploy/helm/z-egress \
      --namespace zx --create-namespace \
      --set image.registry=registry.internal/ \
      --set ingressProxy.upstream.host=my-app \
      --set ingressProxy.upstream.port=9001

This installs the control plane and the ingress proxy. The egress proxy is a
sidecar in your sending application -- see `helm/z-egress/sidecar.yaml`.

## 3. Train a dictionary on your own traffic

Sample a few thousand payloads to JSONL, one per line, then:

    kubectl cp samples.jsonl zx/<controlplane-pod>:/zx-state/
    kubectl exec -n zx <controlplane-pod> -- \
      python3 /usr/local/bin/zxctl.py train --input /zx-state/samples.jsonl --tag mytraffic

It prints a dictionary id and the measured ratio, held out on payloads the
dictionary never saw.

`--mode skeleton` strips every leaf value before training, so the dictionary
provably contains no customer data. It costs roughly 36 percentage points of
ratio. Default `--mode raw` keeps the better ratio; the dictionary then holds
fragments of production data and should be classified accordingly. It never
leaves the namespace either way.

## 4. Add the egress sidecar

Paste the block from `sidecar.yaml` into your sending workload and point the
application at `127.0.0.1:8080`.

## 5. Verify the saving from your own monitoring

    kubectl port-forward -n zx svc/zx-z-egress-ingress 9091
    curl -s localhost:9091/metrics | grep zegress_

`zegress_plain_bytes_total` minus `zegress_wire_bytes_total` is the saving.
Your Prometheus computes it; we do not report it to anyone.

## For the security review

| Concern | What to check |
|---|---|
| Does it call out? | `zxctl preflight`, plus the NetworkPolicy restricting these pods to in-namespace traffic and DNS |
| Does our data leave? | No outbound path exists. Training, storage and serving are all in-namespace |
| What is in a dictionary? | Schema in skeleton mode; payload fragments in raw mode. Dump and inspect it |
| Can training be audited? | Hash-chained audit log; `zxctl audit --verify` names the line if anything was altered |
| Can we roll back? | Remove the sidecar, repoint the app. No state to unwind |
| What if the control plane dies? | Egress runs uncompressed; ingress answers 415 and senders fall back to generic zstd. Degraded, never corrupted |
| Decompression bomb? | Absolute size ceiling plus a maximum expansion ratio; the declared frame size is verified, not trusted |
| Privileges? | uid 65532, no capabilities, read-only root filesystem, no privilege escalation |

## Rollback

    helm uninstall zx -n zx

Then remove the sidecar from your workload. Nothing persists.
