# agent-chokepoint:ci — the co-located chokepoint container.
#
# Build (context is the REPO ROOT, not deploy/):
#   docker build -f deploy/Dockerfile -t agent-chokepoint:ci .
#
# This image deliberately has NO server ENTRYPOINT. The Helm chart supplies the
# full argv; see CMD at the bottom.

FROM python:3.13-slim

# Runtime dependencies ONLY — the two from pyproject.toml:20-23, copied verbatim.
# We do NOT `pip install .`: pyproject.toml:38 lists packages explicitly and
# non-recursively as ["engine","policy","proxy","hooks","pep"], with no
# package-data, no include-package-data and no MANIFEST.in. A wheel would
# therefore ship WITHOUT proxy/demo/upstream_server.py, proxy/demo/run_demo.py
# and policy/policy.example.yaml — the exact files the acceptance workload runs.
# The source tree is COPYed instead and reached via PYTHONPATH.
RUN pip install --no-cache-dir "mcp>=2.0,<2.1" "PyYAML>=6"

# PATH is PINNED, not inherited. If PATH is absent from the environment CPython
# falls back to os.defpath silently (os.py:688-689) rather than failing closed,
# so it must be set explicitly. This is one half of the D-020 pinning; the other
# half is the chart spelling the upstream command as an absolute path.
# The stock base image PATH also lists a writable /usr/local/bin twice and adds
# sbin dirs; this pins it to exactly the three directories the contract names.
ENV PATH=/usr/local/bin:/usr/bin:/bin \
    PYTHONPATH=/app \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Non-root identity, the read-only workspace, and the sandbox mount point.
#   - 65532:65532 matches the chart's runAsUser/runAsGroup.
#   - home is /nonexistent (Debian's `nobody` convention): nothing in this image
#     needs a home, and a home that does not exist cannot be written to under a
#     read-only root filesystem.
#   - /workspace is the prefix policy/policy.example.yaml scopes its path rules
#     to. It is ABSENT from a stock python:3.13-slim, so it is baked here.
#     Content is root-owned and mode 0444/0555: read-only, but READABLE by
#     65532 on purpose — a blocked read must be attributable to the policy, not
#     to a filesystem permission that would have blocked it anyway.
#   - id_rsa is a placeholder with no PEM header. It is not a key, not secret,
#     and deliberately not shaped like one so a secret scanner does not report
#     the fixture as a finding.
#   - /sandbox is owned by 65532 and is mounted over by an emptyDir at runtime;
#     it must exist in the image for the mount point to be sane either way.
#   - groupadd/useradd are called by ABSOLUTE path: they live in /usr/sbin,
#     which the pinned PATH above deliberately excludes, so a bare name is not
#     found at build time. Pinning stays; the call adapts.
RUN /usr/sbin/groupadd --gid 65532 nonroot \
 && /usr/sbin/useradd --uid 65532 --gid 65532 --no-create-home \
            --home-dir /nonexistent --shell /usr/sbin/nologin nonroot \
 && mkdir -p /workspace/.ssh /sandbox \
 && echo 'benign workspace note used by the fs-read-scoped allow case' > /workspace/notes.txt \
 && echo 'NOT-A-REAL-KEY placeholder fixture for agent-chokepoint policy tests' > /workspace/.ssh/id_rsa \
 && chmod 0444 /workspace/notes.txt /workspace/.ssh/id_rsa \
 && chmod 0555 /workspace /workspace/.ssh \
 && chown 65532:65532 /sandbox \
 && chmod 0755 /sandbox

# The source tree. The COPY list is ENUMERATED, not `COPY . /app`, and that is
# load-bearing: findings/ is pre-disclosure material (.gitignore:221) and MUST
# NOT enter the image. deploy/.dockerignore does NOT protect it — measured
# 2026-08-03 on this builder: with the identical ignore bytes at deploy/ the
# findings dir landed in the image, and at the context root it did not. Only the
# context-root path is read, so exclusion here is structural. Do not "simplify"
# this back to `COPY . /app`.
COPY engine/ /app/engine/
COPY policy/ /app/policy/
COPY proxy/ /app/proxy/
COPY hooks/ /app/hooks/
COPY pep/ /app/pep/
COPY deploy/ /app/deploy/

# Same reason: with the ignore file inert, __pycache__ dirs and stray .pyc left
# behind by a local checkout ride along inside those package dirs. Strip them so
# the image carries no bytecode — the same thing PYTHONDONTWRITEBYTECODE
# prevents at runtime.
RUN find /app -depth -type d -name '__pycache__' -exec rm -rf {} + \
 && find /app -type f -name '*.pyc' -delete

USER 65532:65532

# NO server entrypoint on purpose — the chart supplies command+args in full.
# This CMD is inert (it does no work) and fails LOUDLY: if a manifest ever
# forgets to set the command, the container exits 2 with a message and lands in
# CrashLoopBackOff instead of inheriting the base image's `python3`, which would
# read EOF on a non-TTY stdin and exit 0, looking like a clean run.
CMD ["/usr/local/bin/python3", "-c", "import sys; sys.stderr.write('agent-chokepoint: no default command; the chart supplies argv\\n'); sys.exit(2)"]
