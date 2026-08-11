# deploy — hardened Kubernetes deployment

Helm chart plus the hardening that makes a chokepoint an actual chokepoint. If an agent can reach a tool without traversing the proxy, none of the controls apply.

Required:
- Non-root, read-only root filesystem, dropped capabilities
- Dedicated ServiceAccount, minimal RBAC
- NetworkPolicy with **default-deny egress**, explicit allows only
- Secrets from a secrets manager, never inline env
- Resource limits, liveness/readiness probes

**Done when:** `helm install` on a clean cluster yields a working gateway, and this directory contains committed config-scan output (kube-score / Trivy / Polaris) showing what passed and what was accepted, with reasons.

## What is here

**The proof artifact is [`scan/SCAN-REPORT.md`](scan/SCAN-REPORT.md)** — what passed, and
what was accepted with the reason for each acceptance. The raw scanner outputs sit beside
it, each with a provenance header naming the tool version and exact command, and a trailer
carrying the exit code.

```
Dockerfile              the gateway image (non-root 65532, pinned PATH, COPY not pip install)
chart/                  Helm chart agent-chokepoint 0.1.0
  values-no-networkpolicy.yaml   guard-off control: removes ONLY the NetworkPolicy
  values-unpinned-path.yaml      guard-off control: flips ONLY the upstream argv[0]
demo/gateway_driver.py  the client in the pod — puts real calls through the deployed proxy
demo/path_pinning.py    D-020 acceptance artifact, both controls
demo/cluster_acceptance.py   host-side harness; drives the pod, reads the API server
scan/run-scans.sh       regenerates every file in scan/
```

Install and verify:

```sh
kind create cluster --config <kind config with disableDefaultCNI: true>   # see below
kubectl apply -f https://raw.githubusercontent.com/projectcalico/calico/v3.31.0/manifests/calico.yaml
docker build -f deploy/Dockerfile -t agent-chokepoint:ci .
kind load docker-image agent-chokepoint:ci --name <cluster>
helm install chokepoint deploy/chart --namespace chokepoint --create-namespace --wait
```

**`Ready` means enforcement ran and was right.** The container's command is the driver,
which is the client in the `client → proxy → upstream` chain: it puts real tool calls
through the deployed proxy and writes `/sandbox/ready` only when every leg returned the
verdict the live policy owes it. Liveness separately requires `/sandbox/heartbeat` to be
**fresh**, so a wedged driver is restarted rather than sitting there looking healthy.

**Use a CNI that enforces NetworkPolicy.** kind's default CNI (kindnet) does **not** —
measured with both controls: the same request succeeded with and without a
`default-deny-egress` policy applied, while the policy object showed as present. On
kindnet every "the NetworkPolicy blocked it" claim in this directory would be vacuous.
The measurements here were taken on Calico v3.31.0.

**D-020 is enforced here, not in the policy file.** The chart pins command resolution
three ways — an absolute upstream command, a pinned `PATH`, and no directory on that PATH
writable by the workload — and `scan/04-d020-pinning-evidence.txt` shows each, measured in
the running pod. This does **not** close B-035 for a deployment that does not use this
chart: the requirement travels with the chart, not with the policy file.
