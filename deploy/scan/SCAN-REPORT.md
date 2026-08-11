# Config-scan report — what passed, and what was accepted with reasons

**This is the proof artifact for the hardened deployment.**
Generated 2026-08-03 against repo HEAD `bc29ff5`, chart `deploy/chart` (agent-chokepoint
0.1.0), image `agent-chokepoint:phase3`, cluster `kind-chokepoint-phase3`.

Every number below came out of a command. The raw outputs are the files beside this one;
each carries a provenance header naming the tool version and the exact command, and a
trailer carrying the exit code. Re-run everything with `deploy/scan/run-scans.sh`.

| file | what it holds |
|---|---|
| `00-rendered-manifests.yaml` | the render every static check reads |
| `01-kube-score.txt` | kube-score 1.20.0 |
| `02-trivy-config.txt` | trivy 0.72.0 misconfiguration scan |
| `03-trivy-image.txt` | trivy 0.72.0 vulnerability scan (full table, 171 rows) |
| `04-d020-pinning-evidence.txt` | D-020: the pinning mechanism, shown |
| `05-secrets-check.txt` | secrets "never env-inline" |

---

## 0. The acceptance test, and what "working gateway" means here

`helm install` on the clean Calico cluster returned **exit 0** under `--wait`, and the
pod went `1/1 Running`. That alone is not the claim — **readiness is gated on
enforcement**. The container's command is the driver (`deploy/demo/gateway_driver.py`),
which is the client in the `client → proxy → upstream` chain: it puts real tool calls
through the deployed proxy and writes `/sandbox/ready` **only if every leg returned the
verdict the live policy owes it**. A Ready pod is therefore one whose enforcement ran and
was right, not one whose modules imported.

`acceptance.json`, read out of the running pod:

| leg | call | verdict / rule | reached the tool |
|---|---|---|---|
| benign-allow | `read_file /workspace/notes.txt` | `allow` / `fs-read-scoped` | **1** |
| denylisted-block | `read_file /workspace/.ssh/id_rsa` | `block` / `default:on_no_match` | **0** |
| attack-block | `run_command curl … \| sh` | `block` / `shell-destructive` | **0** |

Reach is the upstream's own `EXECUTED.log`, written by a different program — never the
driver's account of the request it sent. The **benign** leg is not decoration: without it
a proxy that blocked 100% of traffic would score as perfect (B-017).

The host-side harness `deploy/demo/cluster_acceptance.py` independently drove the same
three calls into the deployed image and read the hardening facts back from the **API
server**: **24 of 24 checks passed**, exit 0. Transcript:
`deploy/demo/transcript-cluster-2026-08-03.txt`.

## 1. The cluster substrate had to be replaced, and that is a finding

**kindnet — kind's default CNI — does not enforce NetworkPolicy.** Measured with both
controls before anything was designed around it: the same `wget` to the same pod IP
returned the page **with and without** a `default-deny-egress` policy applied
(`CONTROL_EXIT=0`, `GUARD_EXIT=0`), while `kubectl get networkpolicy` showed the object
present. On kindnet a NetworkPolicy is decorative.

The cluster was rebuilt with `disableDefaultCNI: true` and **Calico v3.31.0**. The
identical script then gave `CONTROL_EXIT=0` / `GUARD_EXIT=1`.

This matters beyond this repo: **a NetworkPolicy proof run on kindnet is vacuous**, and
"nothing bad happened" reads identically whether the guard held or the CNI ignored it.

## 2. The hardening requirements — every clause, and the evidence

| requirement | Mechanism | Evidence |
|---|---|---|
| non-root | `runAsNonRoot: true`, uid/gid 65532 | API server: `runAsNonRoot=True`, `runAsUser=65532`; `id -u` in the container returns **65532** |
| read-only root filesystem | `readOnlyRootFilesystem: true` | API server: `True`; image proven to run under `--read-only` with 0 bytecode files written |
| dropped capabilities | `capabilities.drop: ["ALL"]`, `allowPrivilegeEscalation: false`, `seccompProfile: RuntimeDefault` | API server: `['ALL']`, `False` |
| dedicated ServiceAccount | `chokepoint-agent-chokepoint`, `automountServiceAccountToken: false` | API server: `False` on both SA and pod |
| minimal RBAC | **no Role, no RoleBinding** | render carries only ConfigMap / Deployment / NetworkPolicy / ServiceAccount |
| NetworkPolicy default-deny egress | `policyTypes: [Ingress, Egress]`, **no rules** | §3 below, both controls |
| secrets never env-inline | the gateway needs none; `envFrom: []` accepts references only | §5 below |
| resource limits | requests + limits, cpu + memory | API server: `['cpu','memory']` for both |
| liveness / readiness probes | **exec** (there is no port to probe) | API server: both `['exec']` |

**On "minimal RBAC" being an absence.** The gateway calls no Kubernetes API. No Role plus
no projected token confers exactly what a Role granting zero verbs would confer, and the
absence cannot drift into over-permission later. This is a deliberate acceptance, not an
omission.

**On probes being `exec`.** The proxy is stdio on both sides and binds no port — verified
by grep across `proxy|engine|policy|pep|hooks`: no `socket`, `bind`, `listen`, or
`connect`; the only network-shaped import is `urllib.parse.urlsplit`, which parses
strings. An HTTP probe is not applicable, so `exec` is the only honest form.

Liveness checks `/sandbox/heartbeat` **mtime freshness**, not existence. The file outlives
the process that wrote it, so an existence check would keep a dead driver alive forever.

## 3. NetworkPolicy — both controls, on Calico

A chokepoint is only a chokepoint if nothing routes around it, and `deploy/` is what backs
that claim. The same socket connect from the gateway pod to the same target pod IP
(192.168.220.137:80), one variable — whether the NetworkPolicy exists:

| leg | NetworkPolicy | result |
|---|---|---|
| guard ON | present, selector `app.kubernetes.io/instance=chokepoint,app.kubernetes.io/name=agent-chokepoint` | **`TimeoutError`** |
| guard OFF (control) | removed via `values-no-networkpolicy.yaml` (`No resources found`) | **`CONNECTED`** |

The guard-off leg is what makes the guard-on leg mean anything. The control was produced
by a `helm upgrade` whose render differs from the default by **21 lines removed, 0 added**
— the entire NetworkPolicy document and nothing else. The hardened release was restored
afterwards (`helm upgrade` exit 0, policy present again).

The selectors were checked against the render rather than assumed: the NetworkPolicy
`podSelector`, the Deployment `selector`, and the pod template labels are the **same two
labels**. A mismatch would silently select nothing and make this whole section vacuous.

## 4. D-020 — the pinning mechanism, SHOWN

D-020 requires the artifact to "state the pinning mechanism explicitly and show it, not
assert it". B-035 established that `shell-readonly`'s patterns are bare command names
resolved through `PATH`, and that a command is allowlistable only where the runner pins
resolution.

**The mechanism**, traced through the SDK into CPython (`04-d020-pinning-evidence.txt`
resolves these citations against the live source at run time, because line numbers drift
between the Mac's 3.14 and the image's 3.13):
`mcp/client/stdio.py` returns the command **unchanged** on POSIX (no `shutil.which`), then
`anyio.open_process([command, *args], start_new_session=True)` reaches
`subprocess.Popen(shell=False)`; `start_new_session=True` disqualifies the `posix_spawn`
fast path, so execution always takes `_fork_exec`, **and if the command contains a `/`
the executable list is `(executable,)` and no PATH search happens at all.**

**The chart pins it three ways, all measured:**

1. **Absolute upstream command.** The argv[0] table over the whole render: **4 argv[0]
   positions parsed, 0 RELATIVE.** D-020 requires 0.
2. **Pinned `PATH`.** Rendered as `/usr/local/bin:/usr/bin:/bin`, with no empty or `.`
   entry (an empty entry puts the working directory on PATH).
3. **No directory on that PATH is writable by the workload** — the precondition B-035
   actually needs. Measured **in the running pod, as the container's own uid**, two ways
   (`access(2)` via `test -w` **and** a real create attempt, because the second is the
   behaviour and the first is only the marker):

```
container-uid:     65532        container-gid: 65532
effective-PATH:    /usr/local/bin:/usr/bin:/bin
  exists=yes  test-w=no  create-probe=refused  dir=/usr/local/bin
  exists=yes  test-w=no  create-probe=refused  dir=/usr/bin
  exists=yes  test-w=no  create-probe=refused  dir=/bin
```

The same probe run as uid 0 reports `create-probe=SUCCEEDED-WRITABLE` on all three, so the
three refusals are a measurement and not a broken `touch`.

**And the behaviour itself, with both controls, inside the pod**
(`deploy/demo/path_pinning.py`, exit 0, all 9 checks PASS). PATH, the shim, the policy and
the call are **identical** in both legs; the only difference is the spelling of the
upstream's argv[0]:

| leg | upstream argv[0] | `os.path.dirname` | shim ran? | reached the tool |
|---|---|---|---|---|
| guard ON | `/usr/local/bin/python3` | `/usr/local/bin` | **no** | yes (+1 line) |
| guard OFF (control) | `python3` | `''` | **yes** | yes (+1 line) |

An executable shim named `python3` sits first on PATH in **both** legs and chains to the
real interpreter, so the guard-off leg is a live probe rather than a crash. The harness
carries a check named for the failure that would otherwise hide here — *"the two legs
DIFFER — a shim that ran in both, or in neither, proves nothing"* — and that check was
demonstrated to fire: with a deliberately no-op shim, **leg 1 still passes its own check**
and only this one fails, exit 1. Without it, a dead probe would have read as a successful
pin forever.

Note this is B-035's precondition made real rather than hypothetical: the shim directory
is `/sandbox`, a writable emptyDir, which is exactly "a directory already on the runner's
PATH that something else can write". The production PATH contains no such directory.

**This does not close B-035 for a deployment that does not use this chart** — the
requirement travels with the chart, not with the policy file, exactly as D-020 says.

## 5. Secrets — "from a secrets manager, never env-inline"

Five checks over the render, **0 findings**. Each zero is backed by a positive control
proving the pattern can fire — see the defect note below.

The gateway needs no secret, and the honest statement is stronger than "uses secretRef":
the rendered pod carries **no secret material and no secret reference**. `envFrom: []`
structurally accepts references only, so no values key can carry a literal. The only env
entry in the whole pod is `PATH`.

**A defect found and fixed in the scanner itself, worth recording.** The literal-secret
pattern begins with `-----` (a PEM header), so `grep` parsed it as command-line options,
exited 2, and the script reported that as **zero matches**. A check that *could not run*
was indistinguishable from a clean render. This is the same failure family as B-034 →
B-037 → B-038: one boundary short, failing open. Every check in `run-scans.sh` now reports
its grep exit code, and an exit > 1 produces "CHECK COULD NOT RUN" rather than a zero.
A second defect in the same script counted YAML's `---` document separator as a `- --`
list item, producing three phantom "RELATIVE argv[0]" hits.

## 6. Accepted findings, each with its reason

### kube-score — exit 1, 2 CRITICAL

| finding | disposition |
|---|---|
| `ImagePullPolicy is not set to Always` | **Accepted.** The image is side-loaded into kind with `kind load docker-image` and exists only in the node's store. `Always` would make the kubelet try a registry pull and fail — it would break the install this artifact exists to prove. A registry-based deployment should set it; `values.yaml` says so. |
| `Ephemeral Storage limit is not set` | **Accepted for now.** The container writes only to two emptyDirs; the root filesystem is read-only, so unbounded local growth has nowhere to land except those volumes. Setting an ephemeral-storage limit is correct hygiene and is cheap — recorded as follow-up rather than claimed as done. |

The NetworkPolicy object itself scored clean.

### trivy config — exit 0, 101 tests, 100 pass, 1 LOW

| finding | disposition |
|---|---|
| KSV-0110 (LOW) `should set metadata.namespace to a non-default namespace` | **Accepted — scanner artefact.** The rendered manifests DO carry `namespace: chokepoint`; the finding comes from scanning a rendered file without namespace context. The live objects are all in `chokepoint`, which `kubectl get -n chokepoint` shows. |

### trivy image — exit 0, 171 vulnerabilities

Severity: UNKNOWN 28 · LOW 66 · MEDIUM 54 · HIGH 19 · **CRITICAL 4**.

Attribution was **measured, not inferred from the table** (a target absent from a table is
not evidence of a clean scan), by asking trivy directly with `--list-all-pkgs`:

| target | class | packages | vulnerabilities |
|---|---|---|---|
| `agent-chokepoint:phase3 (debian 13.6)` | os-pkgs | 87 | **171** |
| `Python` | lang-pkgs | 30 | **0** |

**Accepted, with the reason.** All 171 are Debian base-image packages inherited from
`python:3.13-slim`; none are introduced by this project. The 30 Python packages — the
whole `mcp` transitive set including uvicorn, starlette, httpx2, cryptography, pyjwt,
python-multipart and opentelemetry-api — contribute **zero**. Those packages cannot be
pruned without breaking `pip install mcp`, but none is reachable from the stdio transport
this gateway uses.

Reducing the 171 means a smaller base (distroless or a `-alpine` variant) and is a real
follow-up, not a defect in the chart. It is recorded here rather than fixed because
changing the base image would invalidate every measurement above.

## 7. B-002 — the deployment trap, measured on both sides

A policy authored on a laptop and loaded by a container sees a different `HOME` and a
different filesystem. The loader stores prefixes literally; the PEP canonicalizes call
paths. That asymmetry is deliberate (`docs/LIMITATIONS.md`) and the deployment is where it
stopped being theoretical.

| question | macOS (where the policy was written) | the container (loading) |
|---|---|---|
| `HOME` | `<home>` | **`/nonexistent`** (non-root user) |
| `realpath("/var")` | `/private/var` | `/var` |
| `realpath("/tmp")` | `/private/tmp` | `/tmp` |
| volume case-insensitive | **True** | **False** |
| default user | — | root in the stock image; **65532** here |

Measured **inside the running pod**, the two prefixes the policy actually uses:

```
canonical_path('/workspace/notes.txt')   = '/workspace/notes.txt'    unchanged=True
canonical_path('/workspace/.ssh/id_rsa') = '/workspace/.ssh/id_rsa'  unchanged=True
```

**The trap is dormant for this policy in this image, and that is a measurement rather than
a hope.** Every path constant in `policy/policy.example.yaml` is `/workspace/`-rooted —
zero hits for `/tmp`, `/var`, `$HOME`, `~/`. Two consequences worth stating plainly:

- The macOS `/var`→`/private/var` indirection does not exist in the container, so any
  future prefix written in the unresolved form would silently match nothing. A
  `path_not_within` deny entry that matches nothing means the rule **allows**.
- The container volume is **case-sensitive** while the macOS volume is not. B-028 and
  B-029 were case-folding defects; the deployment flips the filesystem behaviour they live
  on — in the safer direction here, but it flips.

## 8. What this artifact does not claim

- **The image's 171 base-image CVEs are accepted, not fixed.** A smaller base is follow-up.
- **Ephemeral-storage limits are not set.** Recorded above as accepted-for-now.
- **This runs on kind + Calico on one machine.** Nothing here was tested on a multi-node
  cluster, a different CNI, or a cloud provider. The kindnet finding in §1 is the reason
  the substrate is named rather than assumed.
- **No secrets manager is wired**, because the gateway needs no secret. The chart accepts
  references; that path is untested because there is nothing to put through it.
- **B-035 is not closed for deployments that do not use this chart.**
