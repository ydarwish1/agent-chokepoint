#!/usr/bin/env bash
#
# run-scans.sh - produce the config-scan evidence for agent-chokepoint.
#
# This script COLLECTS FACTS. It does not judge them: a scanner that runs and
# reports findings is a success, because findings are the artifact. The only
# real failures are "a scanner binary is missing" and "a command could not run
# at all", and those are reported separately from findings and separately from
# each other.
#
# It never installs, upgrades, deletes or patches anything. It renders the
# chart, runs three scanners, reads the running pod if there is one, and greps
# the render. Every cluster call is a read.
#
# Outputs, all under --outdir (default deploy/scan/):
#   00-rendered-manifests.yaml   the render every static check below reads
#   01-kube-score.txt            kube-score over the render
#   02-trivy-config.txt          trivy misconfiguration scan over the render
#   03-trivy-image.txt           trivy vulnerability scan over the image
#   04-d020-pinning-evidence.txt D-020: command resolution pinning, SHOWN
#   05-secrets-check.txt         secrets never env-inline
#
# Every output file carries a provenance header (date, tool version, the exact
# command) and a trailer (exit code, status). A number with no command behind
# it is worthless to this project.
#
# Exit: 0 = every section ran (or skipped for a stated, benign reason)
#       1 = at least one section could not run
#       2 = fatal preflight failure (missing tool, unusable output directory)

set -u

# --- frozen constants --------------------------------------------------------
RELEASE="chokepoint"
NAMESPACE="chokepoint"
KUBE_CONTEXT="kind-chokepoint"
IMAGE="agent-chokepoint:ci"

# --- absolute paths, resolved from this script's own location ----------------
# A backgrounded command can reset cwd, so nothing here is relative.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
CHART_DIR="${REPO_ROOT}/deploy/chart"
OUTDIR="${SCRIPT_DIR}"

usage() {
    cat <<'USAGE'
usage: run-scans.sh [--outdir DIR]

  --outdir DIR   where to write the scan outputs (default: deploy/scan/)
  -h, --help     this message

Reads the cluster and runs scanners. Installs nothing, changes nothing.
USAGE
}

while [ $# -gt 0 ]; do
    case "$1" in
        --outdir)
            if [ $# -lt 2 ]; then
                echo "run-scans.sh: --outdir needs a directory" >&2
                exit 2
            fi
            OUTDIR="$2"
            shift 2
            ;;
        -h|--help) usage; exit 0 ;;
        *)
            echo "run-scans.sh: unknown argument: $1" >&2
            usage >&2
            exit 2
            ;;
    esac
done

# ============================================================================
# preflight - a missing tool is FATAL and loud, and is not a "finding"
# ============================================================================
fatal() {
    echo "" >&2
    echo "FATAL: $*" >&2
    echo "       Nothing was scanned. This is an environment failure, not a finding." >&2
    exit 2
}

require_tool() {
    # $1 = binary name; echoes its absolute path
    local p
    p="$(command -v "$1" 2>/dev/null)"
    if [ -z "$p" ]; then
        fatal "required tool not found on PATH: $1"
    fi
    printf '%s\n' "$p"
}

HELM="$(require_tool helm)"       || exit 2
KUBE_SCORE="$(require_tool kube-score)" || exit 2
TRIVY="$(require_tool trivy)"     || exit 2
KUBECTL="$(require_tool kubectl)" || exit 2
DOCKER="$(require_tool docker)"   || exit 2

mkdir -p "$OUTDIR" 2>/dev/null
if [ ! -d "$OUTDIR" ]; then
    fatal "output directory could not be created: $OUTDIR"
fi
OUTDIR="$(cd "$OUTDIR" && pwd)"
if [ ! -w "$OUTDIR" ]; then
    fatal "output directory is not writable: $OUTDIR"
fi

TMPDIR_RUN="$(mktemp -d "${TMPDIR:-/tmp}/chokepoint-scan.XXXXXX")"
if [ ! -d "$TMPDIR_RUN" ]; then
    fatal "could not create a temporary working directory"
fi
cleanup() {
    if [ -n "${TMPDIR_RUN:-}" ] && [ -d "${TMPDIR_RUN}" ]; then
        rm -rf "${TMPDIR_RUN}"
    fi
}
trap cleanup EXIT

# --- provenance facts, asked of the tools, not remembered --------------------
RUN_TS="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
HOST_DESC="$(uname -srm)"
HELM_VER="$("$HELM" version --short 2>&1 | head -1)"
KUBE_SCORE_VER="$("$KUBE_SCORE" version 2>&1 | head -1)"
TRIVY_VER="trivy $("$TRIVY" --version 2>&1 | head -1)"
KUBECTL_VER="kubectl $("$KUBECTL" version --client 2>&1 | head -1)"
DOCKER_VER="$("$DOCKER" --version 2>&1 | head -1)"
if [ -d "${REPO_ROOT}/.git" ]; then
    REPO_HEAD="$(git -C "$REPO_ROOT" rev-parse HEAD 2>/dev/null)"
    if [ -z "$REPO_HEAD" ]; then REPO_HEAD="(unknown)"; fi
else
    REPO_HEAD="(not a git checkout)"
fi

# --- per-section bookkeeping -------------------------------------------------
SEC_NAME=(); SEC_FILE=(); SEC_RC=(); SEC_STATUS=(); SEC_NOTE=()
record() {  # name file rc status note
    SEC_NAME+=("$1"); SEC_FILE+=("$2"); SEC_RC+=("$3"); SEC_STATUS+=("$4"); SEC_NOTE+=("$5")
}

write_header() {  # out title toolver command-line...
    local out="$1" title="$2" toolver="$3"
    shift 3
    {
        echo "# ==========================================================================="
        echo "# agent-chokepoint - config-scan evidence"
        echo "# artifact  : ${title}"
        echo "# ---------------------------------------------------------------------------"
        echo "# generated : ${RUN_TS}"
        echo "# host      : ${HOST_DESC}"
        # The absolute root is deliberately not printed: these artifacts are
        # committed, and the path of whoever ran the scan is not evidence.
        echo "# repo      : <repo root>"
        echo "# repo HEAD : ${REPO_HEAD}"
        echo "# tool      : ${toolver}"
        echo "# command   :"
        local c
        for c in "$@"; do
            echo "#     ${c}"
        done
        echo "# ---------------------------------------------------------------------------"
        echo "# The exit code and status of the command above are in the TRAILER at the"
        echo "# end of this file. Findings are DATA: a non-zero exit here means the"
        echo "# scanner reported something, not that the scan failed."
        echo "# ==========================================================================="
        echo ""
    } > "$out"
}

write_trailer() {  # out rc status note
    local out="$1" rc="$2" status="$3" note="$4"
    {
        echo ""
        echo "# ==========================================================================="
        echo "# TRAILER"
        echo "# exit code : ${rc}"
        echo "# status    : ${status}"
        if [ -n "$note" ]; then
            echo "# note      : ${note}"
        fi
        echo "# ==========================================================================="
    } >> "$out"
}

echo "run-scans.sh  repo=${REPO_ROOT}  outdir=${OUTDIR}  ts=${RUN_TS}"
echo ""

# ============================================================================
# 0. render the chart - the input to sections 1, 2, 4a, 4b and 5
# ============================================================================
RENDER_FILE="${OUTDIR}/00-rendered-manifests.yaml"
RENDER_CMD="${HELM} template ${RELEASE} ${CHART_DIR} --namespace ${NAMESPACE}"
RENDER_ERR="${TMPDIR_RUN}/render.stderr"

write_header "$RENDER_FILE" "rendered chart manifests" "$HELM_VER" "$RENDER_CMD"

echo "[0/5] rendering chart ..."
if [ ! -d "$CHART_DIR" ]; then
    RENDER_RC=127
    RENDER_STATUS="ERROR"
    RENDER_NOTE="chart directory does not exist: ${CHART_DIR}"
    echo "# NOT RENDERED: ${RENDER_NOTE}" >> "$RENDER_FILE"
else
    "$HELM" template "$RELEASE" "$CHART_DIR" --namespace "$NAMESPACE" >> "$RENDER_FILE" 2> "$RENDER_ERR"
    RENDER_RC=$?
    if [ "$RENDER_RC" -eq 0 ]; then
        RENDER_STATUS="RAN"
        RENDER_NOTE=""
    else
        RENDER_STATUS="ERROR"
        RENDER_NOTE="helm template failed; its stderr is quoted in this file"
    fi
fi

# helm writes its warnings (e.g. the chart's policy symlink notice) to stderr.
# Keep them OUT of the YAML body and quote them as comments instead, so the
# render stays parseable by kube-score and trivy.
if [ -s "$RENDER_ERR" ]; then
    {
        echo ""
        echo "# --- helm template stderr ---"
        sed -e 's/^/# /' "$RENDER_ERR"
    } >> "$RENDER_FILE"
fi
write_trailer "$RENDER_FILE" "$RENDER_RC" "$RENDER_STATUS" "$RENDER_NOTE"
record "render (helm template)" "$RENDER_FILE" "$RENDER_RC" "$RENDER_STATUS" "$RENDER_NOTE"

if [ "$RENDER_STATUS" = "RAN" ]; then
    RENDER_OK=1
else
    RENDER_OK=0
fi

# ============================================================================
# 1. kube-score over the rendered chart
#    kube-score exits non-zero when it finds criticals. That is a finding, not
#    an error, and it must not stop this script.
# ============================================================================
KS_FILE="${OUTDIR}/01-kube-score.txt"
KS_CMD1="${RENDER_CMD} > 00-rendered-manifests.yaml"
KS_CMD2="${KUBE_SCORE} score - --color never < 00-rendered-manifests.yaml"
write_header "$KS_FILE" "kube-score over the rendered chart" "$KUBE_SCORE_VER" "$KS_CMD1" "$KS_CMD2"

echo "[1/5] kube-score ..."
if [ "$RENDER_OK" -eq 0 ]; then
    KS_RC=127
    KS_STATUS="ERROR"
    KS_NOTE="skipped: the chart did not render, so there was nothing to score"
    echo "NOT SCORED: ${KS_NOTE}" >> "$KS_FILE"
else
    # No pipe: the exit code below belongs to kube-score and nothing else.
    "$KUBE_SCORE" score - --color never < "$RENDER_FILE" >> "$KS_FILE" 2>&1
    KS_RC=$?
    KS_STATUS="RAN"
    if [ "$KS_RC" -ne 0 ]; then
        KS_NOTE="non-zero exit = kube-score reported findings (expected; see the report above)"
    else
        KS_NOTE="clean"
    fi
fi
write_trailer "$KS_FILE" "$KS_RC" "$KS_STATUS" "$KS_NOTE"
record "kube-score" "$KS_FILE" "$KS_RC" "$KS_STATUS" "$KS_NOTE"

# ============================================================================
# 2. trivy config over the rendered manifests
# ============================================================================
TC_FILE="${OUTDIR}/02-trivy-config.txt"
TC_CMD="NO_COLOR=1 ${TRIVY} config --format table --skip-version-check ${RENDER_FILE}"
write_header "$TC_FILE" "trivy misconfiguration scan over the rendered manifests" "$TRIVY_VER" "$TC_CMD"

echo "[2/5] trivy config ..."
if [ "$RENDER_OK" -eq 0 ]; then
    TC_RC=127
    TC_STATUS="ERROR"
    TC_NOTE="skipped: the chart did not render, so there were no manifests to scan"
    echo "NOT SCANNED: ${TC_NOTE}" >> "$TC_FILE"
else
    NO_COLOR=1 "$TRIVY" config --format table --skip-version-check "$RENDER_FILE" >> "$TC_FILE" 2>&1
    TC_RC=$?
    if [ "$TC_RC" -eq 0 ]; then
        TC_STATUS="RAN"
        TC_NOTE="trivy config exits 0 whether or not it finds misconfigurations; read the report"
    else
        TC_STATUS="ERROR"
        TC_NOTE="trivy config exited non-zero, which for this invocation means it could not run"
    fi
fi
write_trailer "$TC_FILE" "$TC_RC" "$TC_STATUS" "$TC_NOTE"
record "trivy config" "$TC_FILE" "$TC_RC" "$TC_STATUS" "$TC_NOTE"

# ============================================================================
# 3. trivy image over the built image
# ============================================================================
TI_FILE="${OUTDIR}/03-trivy-image.txt"
TI_CMD="NO_COLOR=1 ${TRIVY} image --scanners vuln --format table --skip-version-check --no-progress ${IMAGE}"
write_header "$TI_FILE" "trivy vulnerability scan over ${IMAGE}" "$TRIVY_VER" "$TI_CMD"

echo "[3/5] trivy image ..."
"$DOCKER" image inspect "$IMAGE" > "${TMPDIR_RUN}/img.json" 2> "${TMPDIR_RUN}/img.err"
IMG_RC=$?
if [ "$IMG_RC" -ne 0 ]; then
    TI_RC=127
    TI_STATUS="ERROR"
    TI_NOTE="image not present locally: ${IMAGE} (build it before scanning)"
    {
        echo "NOT SCANNED: ${TI_NOTE}"
        echo ""
        echo "--- docker image inspect ${IMAGE} (exit ${IMG_RC}) ---"
        cat "${TMPDIR_RUN}/img.err"
    } >> "$TI_FILE"
else
    NO_COLOR=1 "$TRIVY" image --scanners vuln --format table --skip-version-check --no-progress "$IMAGE" >> "$TI_FILE" 2>&1
    TI_RC=$?
    if [ "$TI_RC" -eq 0 ]; then
        TI_STATUS="RAN"
        TI_NOTE="trivy image exits 0 whether or not it finds vulnerabilities; read the report"
    else
        TI_STATUS="ERROR"
        TI_NOTE="trivy image exited non-zero, which for this invocation means it could not run"
    fi
fi
write_trailer "$TI_FILE" "$TI_RC" "$TI_STATUS" "$TI_NOTE"
record "trivy image" "$TI_FILE" "$TI_RC" "$TI_STATUS" "$TI_NOTE"

# ============================================================================
# 4. D-020 - command-resolution pinning, SHOWN rather than asserted
#
#    D-020: the config-scan output must state the pinning mechanism explicitly
#    and show it, not assert it.
#
#    4a  the upstream command as the chart actually renders it
#    4b  the PATH env value as the chart actually renders it
#    4c  the RUNNING pod's effective PATH, and whether the workload can write
#        any directory on it (a writable PATH directory re-opens B-035)
#    4d  the RUNNING pod's uid and gid
# ============================================================================
PIN_FILE="${OUTDIR}/04-d020-pinning-evidence.txt"
PIN_CMD1="awk over 00-rendered-manifests.yaml: argv[0] of every command:/args: block"
PIN_CMD2="/usr/bin/grep -a -n -B2 -A2 upstream_server.py 00-rendered-manifests.yaml"
PIN_CMD3="/usr/bin/grep -a -n -A1 'name: PATH' 00-rendered-manifests.yaml"
PIN_CMD4="${KUBECTL} --context ${KUBE_CONTEXT} exec -n ${NAMESPACE} <pod> -- /bin/sh -c '<uid/PATH/writability probe>'"
write_header "$PIN_FILE" "D-020 command-resolution pinning evidence" \
    "${HELM_VER} + ${KUBECTL_VER} + awk/grep" \
    "$PIN_CMD1" "$PIN_CMD2" "$PIN_CMD3" "$PIN_CMD4"

echo "[4/5] D-020 pinning evidence ..."
PIN_STATUS="RAN"
PIN_RC=0
PIN_NOTE=""

{
    echo "############################################################################"
    echo "## 4a  UPSTREAM COMMAND AS RENDERED BY THE CHART"
    echo "##     D-020 control 1 of 2: the command is spelled as an ABSOLUTE path, so"
    echo "##     subprocess.py:1911-1912 takes the executable_list = (executable,)"
    echo "##     branch and performs no PATH search at all."
    echo "############################################################################"
    echo ""
} >> "$PIN_FILE"

if [ "$RENDER_OK" -eq 0 ]; then
    echo "  ERROR: the chart did not render; 4a and 4b cannot be produced." >> "$PIN_FILE"
    PIN_STATUS="ERROR"
    PIN_RC=127
    PIN_NOTE="4a/4b unavailable: chart did not render"
else
    {
        echo "  argv[0] of every command:/args: list in the render, classified."
        echo "  ABSOLUTE = resolved by the kernel. RELATIVE = resolved against PATH."
        echo ""
        awk '
        {
          line = $0
          if (line ~ /^[[:space:]]*(command|args):[[:space:]]*$/) {
            key = line; sub(/^[[:space:]]*/, "", key); sub(/:.*$/, "", key)
            pending = 1; pkey = key; pline = NR; next
          }
          if (line ~ /^[[:space:]]*(command|args):[[:space:]]*[^[:space:]]/) {
            printf "  line %-5s  %-8s  NON-BLOCK FORM, not parsed: %s\n", NR, "cmd", line
            unparsed++; pending = 0; next
          }
          if (pending == 1) {
            if (line ~ /^[[:space:]]*-[[:space:]]+/) {
              tok = line
              sub(/^[[:space:]]*-[[:space:]]*/, "", tok)
              sub(/[[:space:]]+$/, "", tok)
              gsub(/^"|"$/, "", tok)
              if (substr(tok, 1, 1) == "/") { v = "ABSOLUTE" } else { v = "RELATIVE  <== PATH-RESOLVED"; rel++ }
              printf "  line %-5s  %-8s  argv[0] = %-44s %s\n", NR, pkey, tok, v
              parsed++
            } else {
              printf "  line %-5s  %-8s  EXPECTED a list item, got: %s\n", pline, pkey, line
              unparsed++
            }
            pending = 0
          }
          # The space after the dash is load-bearing: without it this pattern
          # also matches YAMLs own "---" document separator, which armed the
          # upstream state machine four times and reported three list items
          # from unrelated documents as RELATIVE argv[0] positions.
          if (line ~ /^[[:space:]]*-[[:space:]]+"?--"?[[:space:]]*$/) { sep = 1; next }
          if (sep == 1 && line ~ /^[[:space:]]*-[[:space:]]+/) {
            tok = line
            sub(/^[[:space:]]*-[[:space:]]*/, "", tok)
            sub(/[[:space:]]+$/, "", tok)
            gsub(/^"|"$/, "", tok)
            if (substr(tok, 1, 1) == "/") { v = "ABSOLUTE" } else { v = "RELATIVE  <== PATH-RESOLVED"; rel++ }
            printf "  line %-5s  %-8s  argv[0] = %-44s %s\n", NR, "upstream", tok, v
            parsed++; sep = 0
          }
        }
        END {
          printf "\n  argv[0] positions parsed  : %d\n", parsed + 0
          printf "  RELATIVE (PATH-resolved)  : %d    <== D-020 requires 0\n", rel + 0
          printf "  command/args not parsed   : %d    <== must be 0, else the YAML shape changed\n", unparsed + 0
        }
        ' "$RENDER_FILE"
        echo ""
        echo "  --- every rendered line naming the upstream server, with context ---"
        /usr/bin/grep -a -n -B2 -A2 'upstream_server\.py' "$RENDER_FILE"
        echo ""
        echo "  --- bare-name interpreter tokens anywhere in the render (expect none) ---"
    } >> "$PIN_FILE"

    BARE_HITS="$(/usr/bin/grep -a -n -E '^[[:space:]]*-[[:space:]]*"?(python|python3|sh|bash|env)"?[[:space:]]*$' "$RENDER_FILE" 2>/dev/null)"
    if [ -z "$BARE_HITS" ]; then
        echo "  ZERO MATCHES (/usr/bin/grep -a) - no bare interpreter name is rendered." >> "$PIN_FILE"
    else
        {
            echo "  MATCHES FOUND - a bare interpreter name is PATH-resolved:"
            printf '%s\n' "$BARE_HITS" | sed -e 's/^/    /'
        } >> "$PIN_FILE"
    fi

    {
        echo ""
        echo "############################################################################"
        echo "## 4b  PATH ENV VALUE AS RENDERED BY THE CHART"
        echo "##     D-020 control 2 of 2. Dropping PATH does NOT fail closed:"
        echo "##     os.py:688-689 falls back to os.defpath (/bin:/usr/bin), so the"
        echo "##     value has to be set explicitly and has to be shown."
        echo "############################################################################"
        echo ""
    } >> "$PIN_FILE"

    PATH_BLOCK="$(/usr/bin/grep -a -n -A1 -E '^[[:space:]]*-?[[:space:]]*name:[[:space:]]*"?PATH"?[[:space:]]*$' "$RENDER_FILE" 2>/dev/null)"
    if [ -z "$PATH_BLOCK" ]; then
        {
            echo "  ZERO MATCHES (/usr/bin/grep -a) - the chart renders NO explicit PATH env."
            echo "  That is a D-020 failure: with PATH unset the interpreter falls back to"
            echo "  os.defpath (/bin:/usr/bin) rather than failing closed."
        } >> "$PIN_FILE"
    else
        printf '%s\n' "$PATH_BLOCK" | sed -e 's/^/  /' >> "$PIN_FILE"
        RENDERED_PATH="$(printf '%s\n' "$PATH_BLOCK" \
            | /usr/bin/grep -a -m1 -E '^[0-9]+[-:][[:space:]]*value:' \
            | sed -e 's/^[0-9]*[-:][[:space:]]*value:[[:space:]]*//' -e 's/^"//' -e 's/"$//')"
        {
            echo ""
            echo "  rendered PATH value : ${RENDERED_PATH}"
        } >> "$PIN_FILE"
        # An empty PATH entry (leading ':', trailing ':', '::' or '.') means the
        # current working directory is on PATH, which re-opens B-035 statically.
        case ":${RENDERED_PATH}:" in
            *::*|*:.:*)
                echo "  empty/relative PATH entry : PRESENT  <== current directory is on PATH" >> "$PIN_FILE" ;;
            *)
                echo "  empty/relative PATH entry : none - every entry is an explicit directory" >> "$PIN_FILE" ;;
        esac
    fi
fi

{
    echo ""
    echo "############################################################################"
    echo "## 4c/4d  THE RUNNING POD - effective PATH, per-directory writability as the"
    echo "##        container's own uid, and the container's uid/gid."
    echo "##"
    echo "##        A directory on PATH that the workload can WRITE re-opens B-035:"
    echo "##        the agent could plant a shim there and win the resolution race."
    echo "##        Access is tested two ways - access(2) via test -w, and a real"
    echo "##        create attempt - because the second is the behaviour and the"
    echo "##        first is only the marker."
    echo "############################################################################"
    echo ""
} >> "$PIN_FILE"

POD_PROBE='
echo "container-id-line: $(id)"
echo "container-uid:     $(id -u)"
echo "container-gid:     $(id -g)"
echo "effective-PATH:    $PATH"
echo ""
echo "per-directory writability:"
OLDIFS=$IFS
IFS=:
set -f
for d in $PATH; do
    label=$d
    probe=$d
    if [ -z "$d" ]; then
        label="<EMPTY ENTRY == current working directory>"
        probe=.
    fi
    if [ ! -d "$probe" ]; then
        echo "  exists=NO   test-w=n/a  create-probe=n/a                 dir=$label"
    else
        if [ -w "$probe" ]; then aw=YES; else aw=no; fi
        if touch "$probe/.chokepoint-write-probe" 2>/dev/null; then
            tp="SUCCEEDED-WRITABLE"
            rm -f "$probe/.chokepoint-write-probe" 2>/dev/null
        else
            tp="refused"
        fi
        echo "  exists=yes  test-w=$aw  create-probe=$tp  dir=$label"
    fi
done
set +f
IFS=$OLDIFS
'

CTX_OK=0
"$KUBECTL" config get-contexts "$KUBE_CONTEXT" > "${TMPDIR_RUN}/ctx.out" 2>&1
CTX_RC=$?
if [ "$CTX_RC" -ne 0 ]; then
    {
        echo "  ERROR: kube context '${KUBE_CONTEXT}' is not configured on this machine."
        echo "  kubectl config get-contexts ${KUBE_CONTEXT} exited ${CTX_RC}:"
        sed -e 's/^/    /' "${TMPDIR_RUN}/ctx.out"
    } >> "$PIN_FILE"
    PIN_STATUS="ERROR"
    PIN_RC=127
    if [ -z "$PIN_NOTE" ]; then PIN_NOTE="kube context ${KUBE_CONTEXT} missing"; fi
else
    CTX_OK=1
fi

if [ "$CTX_OK" -eq 1 ]; then
    POD="$("$KUBECTL" --context "$KUBE_CONTEXT" get pods -n "$NAMESPACE" \
        --field-selector=status.phase=Running \
        -o jsonpath='{.items[0].metadata.name}' 2> "${TMPDIR_RUN}/pod.err")"
    if [ -z "$POD" ]; then
        {
            echo "  SKIPPED: no Running pod in namespace '${NAMESPACE}' on context"
            echo "  '${KUBE_CONTEXT}'. 4c and 4d are measurements of a live container and"
            echo "  cannot be faked from the chart; they are omitted rather than guessed."
            echo ""
            echo "  command : ${KUBECTL} --context ${KUBE_CONTEXT} get pods -n ${NAMESPACE} --field-selector=status.phase=Running -o jsonpath={.items[0].metadata.name}"
            echo "  result  : (empty)"
            if [ -s "${TMPDIR_RUN}/pod.err" ]; then
                echo "  stderr  :"
                sed -e 's/^/    /' "${TMPDIR_RUN}/pod.err"
            fi
            echo ""
            echo "  Re-run this script after the release is installed and the pod is Ready."
        } >> "$PIN_FILE"
        if [ "$PIN_STATUS" = "RAN" ]; then
            PIN_STATUS="RAN"
            PIN_NOTE="4c/4d SKIPPED - no Running pod in namespace ${NAMESPACE}"
        fi
    else
        {
            echo "  pod: ${POD}"
            echo ""
            echo "  --- the pod's container command as ADMITTED by the API server ---"
            echo "  (the render is what was asked for; this is what is actually running)"
        } >> "$PIN_FILE"
        "$KUBECTL" --context "$KUBE_CONTEXT" get pod "$POD" -n "$NAMESPACE" \
            -o jsonpath='{range .spec.containers[*]}  container={.name}{"\n"}  command={.command}{"\n"}  env={.env}{"\n"}{end}' \
            >> "$PIN_FILE" 2>&1
        PODSPEC_RC=$?
        {
            echo ""
            echo "  --- probe run INSIDE the container, as the container's own uid ---"
        } >> "$PIN_FILE"
        "$KUBECTL" --context "$KUBE_CONTEXT" exec -n "$NAMESPACE" "$POD" -- \
            /bin/sh -c "$POD_PROBE" >> "$PIN_FILE" 2>&1
        EXEC_RC=$?
        if [ "$EXEC_RC" -ne 0 ] || [ "$PODSPEC_RC" -ne 0 ]; then
            {
                echo ""
                echo "  ERROR: reading the running pod failed."
                echo "  kubectl get pod -o jsonpath exit : ${PODSPEC_RC}"
                echo "  kubectl exec exit                : ${EXEC_RC}"
            } >> "$PIN_FILE"
            PIN_STATUS="ERROR"
            if [ "$EXEC_RC" -ne 0 ]; then PIN_RC="$EXEC_RC"; else PIN_RC="$PODSPEC_RC"; fi
            PIN_NOTE="reading the running pod failed (see the file)"
        fi
    fi
fi

write_trailer "$PIN_FILE" "$PIN_RC" "$PIN_STATUS" "$PIN_NOTE"
record "D-020 pinning evidence" "$PIN_FILE" "$PIN_RC" "$PIN_STATUS" "$PIN_NOTE"

# ============================================================================
# 5. secrets check - secrets from a secrets manager, never env-inline
# ============================================================================
SEC_FILE_OUT="${OUTDIR}/05-secrets-check.txt"
SEC_CMD="/usr/bin/grep -a -n -E <pattern> ${RENDER_FILE}   (five patterns, listed per check below)"
write_header "$SEC_FILE_OUT" "secrets check over the rendered manifests" \
    "/usr/bin/grep (BSD grep, macOS base system)" "$SEC_CMD"

echo "[5/5] secrets check ..."
if [ "$RENDER_OK" -eq 0 ]; then
    SC_RC=127
    SC_STATUS="ERROR"
    SC_NOTE="skipped: the chart did not render, so there was nothing to grep"
    echo "NOT CHECKED: ${SC_NOTE}" >> "$SEC_FILE_OUT"
else
    SC_RC=0
    SC_STATUS="RAN"
    SC_NOTE=""
    SECRET_FINDINGS=0
    SECRET_CHECK_ERRORS=0

    # Every check reports its pattern, its command and its count. A zero is
    # only worth something if the pattern that produced it is on the page AND
    # the grep that produced it actually ran.
    #
    # Two things here are load-bearing, both learned the hard way:
    #   -e "$pattern"  - the 5.2 pattern starts with "-----", and without -e
    #                    grep parses it as options, exits 2 and matches nothing.
    #   grep exit 2    - is "could not run", NOT "no match". Swallowing it made
    #                    a structurally broken check read as a clean render.
    report_grep() {  # label pattern is_finding
        local label="$1" pattern="$2" is_finding="$3" rc count
        /usr/bin/grep -a -n -E -e "$pattern" "$RENDER_FILE" \
            > "${TMPDIR_RUN}/grep.out" 2> "${TMPDIR_RUN}/grep.err"
        rc=$?
        count="$(wc -l < "${TMPDIR_RUN}/grep.out" | tr -d ' ')"
        {
            echo "----------------------------------------------------------------------------"
            echo "${label}"
            echo "  pattern : ${pattern}"
            echo "  command : /usr/bin/grep -a -n -E -e '<pattern>' 00-rendered-manifests.yaml"
            echo "  grep rc : ${rc}   (0 = matched, 1 = no match, >1 = grep could not run)"
            if [ "$rc" -gt 1 ]; then
                echo "  matches : n/a"
                echo "  result  : CHECK COULD NOT RUN - this is an ERROR, not a clean result."
                sed -e 's/^/    /' "${TMPDIR_RUN}/grep.err"
            elif [ "$count" -eq 0 ]; then
                echo "  matches : 0"
                echo "  result  : ZERO MATCHES (verified with /usr/bin/grep -a)"
            else
                echo "  matches : ${count}"
                echo "  result  :"
                sed -e 's/^/    /' "${TMPDIR_RUN}/grep.out"
            fi
            echo ""
        } >> "$SEC_FILE_OUT"
        if [ "$rc" -gt 1 ]; then
            SECRET_CHECK_ERRORS=$((SECRET_CHECK_ERRORS + 1))
        elif [ "$is_finding" = "finding" ] && [ "$count" -ne 0 ]; then
            SECRET_FINDINGS=$((SECRET_FINDINGS + count))
        fi
    }

    report_grep \
        "5.1  Secret OBJECTS rendered by the chart (a Secret in the chart is secret material in git)" \
        '^kind:[[:space:]]*Secret[[:space:]]*$|^[[:space:]]*stringData:[[:space:]]*$' \
        finding

    report_grep \
        "5.2  LITERAL secret material anywhere in the render (key blocks, cloud keys, tokens)" \
        '-----BEGIN [A-Z ]*PRIVATE KEY-----|AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|xox[abprs]-[A-Za-z0-9-]{10,}|AIza[0-9A-Za-z_-]{35}|sk-[A-Za-z0-9]{20,}|eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.' \
        finding

    report_grep \
        "5.3  STRICT: env-var-shaped names that look like secrets (env vars are UPPER_SNAKE)" \
        '^[[:space:]]*-?[[:space:]]*name:[[:space:]]*"?[A-Z0-9_]*(PASS|PASSWORD|PASSWD|SECRET|TOKEN|APIKEY|API_KEY|ACCESS_KEY|PRIVATE_KEY|CREDENTIAL)[A-Z0-9_]*"?[[:space:]]*$' \
        finding

    # 5.4 is the one that answers "never env-inline" literally: a secret-ish env
    # NAME whose very next line is an inline `value:` is the banned shape.
    /usr/bin/grep -a -n -A1 -E -e '^[[:space:]]*-?[[:space:]]*name:[[:space:]]*"?[A-Za-z0-9_]*([Pp][Aa][Ss][Ss]|[Ss][Ee][Cc][Rr][Ee][Tt]|[Tt][Oo][Kk][Ee][Nn]|[Kk][Ee][Yy]|[Cc][Rr][Ee][Dd])[A-Za-z0-9_]*"?[[:space:]]*$' \
        "$RENDER_FILE" > "${TMPDIR_RUN}/inline.out" 2> "${TMPDIR_RUN}/inline.err"
    INLINE_RC=$?
    INLINE_COUNT="$(/usr/bin/grep -a -c -E -e '^[0-9]+-[[:space:]]*value:' "${TMPDIR_RUN}/inline.out")"
    {
        echo "----------------------------------------------------------------------------"
        echo "5.4  ENV-INLINE: a secret-ish env name immediately followed by a literal 'value:'"
        echo "     This is the exact shape spec 4.4 forbids. A 'valueFrom:' on the next"
        echo "     line is a REFERENCE and is not counted here."
        echo "  command : /usr/bin/grep -a -n -A1 -E -e '<secret-ish name>' 00-rendered-manifests.yaml"
        echo "            then count the context lines matching '^[0-9]+-[[:space:]]*value:'"
        echo "  grep rc : ${INLINE_RC}   (0 = matched, 1 = no match, >1 = grep could not run)"
        if [ "$INLINE_RC" -gt 1 ]; then
            echo "  matches : n/a"
            echo "  result  : CHECK COULD NOT RUN - this is an ERROR, not a clean result."
            sed -e 's/^/    /' "${TMPDIR_RUN}/inline.err"
        elif [ "$INLINE_COUNT" -eq 0 ]; then
            echo "  matches : 0"
            echo "  result  : ZERO MATCHES (verified with /usr/bin/grep -a)"
            if [ -s "${TMPDIR_RUN}/inline.out" ]; then
                echo "            (secret-ish names WERE present; none carried an inline value:)"
                sed -e 's/^/    /' "${TMPDIR_RUN}/inline.out"
            fi
        else
            echo "  matches : ${INLINE_COUNT}"
            echo "  result  : ENV-INLINE SECRET PRESENT - spec 4.4 violation"
            sed -e 's/^/    /' "${TMPDIR_RUN}/inline.out"
        fi
        echo ""
    } >> "$SEC_FILE_OUT"
    if [ "$INLINE_RC" -gt 1 ]; then
        SECRET_CHECK_ERRORS=$((SECRET_CHECK_ERRORS + 1))
    elif [ "$INLINE_COUNT" -ne 0 ]; then
        SECRET_FINDINGS=$((SECRET_FINDINGS + INLINE_COUNT))
    fi

    # Context, not a finding: the reference-shaped mechanisms. Secrets are meant
    # to come FROM a manager, so seeing these is the compliant shape.
    report_grep \
        "5.5  CONTEXT (not a finding): reference-shaped secret mechanisms in the render" \
        'secretRef|secretKeyRef|envFrom' \
        context

    {
        echo "----------------------------------------------------------------------------"
        echo "SECRETS CHECK RESULT"
        echo "  checks that could not run                                  : ${SECRET_CHECK_ERRORS}"
        echo "  literal/env-inline secret findings (5.1 + 5.2 + 5.3 + 5.4) : ${SECRET_FINDINGS}"
        if [ "$SECRET_CHECK_ERRORS" -ne 0 ]; then
            echo "  verdict : NO VERDICT. ${SECRET_CHECK_ERRORS} check(s) failed to run, so the"
            echo "            zero above would be an artefact of a broken grep rather than"
            echo "            evidence of a clean render."
        elif [ "$SECRET_FINDINGS" -eq 0 ]; then
            echo "  verdict : the rendered chart carries NO literal secret material and NO"
            echo "            env-inline secret. Spec 4.4's 'never env-inline' holds for this"
            echo "            render, measured, not asserted."
        else
            echo "  verdict : SECRET MATERIAL IS PRESENT IN THE RENDER - see the checks above."
        fi
        echo "----------------------------------------------------------------------------"
    } >> "$SEC_FILE_OUT"
    if [ "$SECRET_CHECK_ERRORS" -ne 0 ]; then
        SC_RC=2
        SC_STATUS="ERROR"
        SC_NOTE="${SECRET_CHECK_ERRORS} secrets check(s) could not run - the result is not a clean render"
    else
        SC_NOTE="${SECRET_FINDINGS} literal/env-inline secret finding(s)"
    fi
fi
write_trailer "$SEC_FILE_OUT" "$SC_RC" "$SC_STATUS" "$SC_NOTE"
record "secrets check" "$SEC_FILE_OUT" "$SC_RC" "$SC_STATUS" "$SC_NOTE"

# ============================================================================
# summary
# ============================================================================
ERRORS=0
SKIPS=0
echo ""
echo "============================================================================"
echo "run-scans.sh summary   ${RUN_TS}"
echo "outdir: ${OUTDIR}"
echo "----------------------------------------------------------------------------"
printf '%-8s  %-10s  %-28s  %s\n' "EXIT" "STATUS" "SECTION" "FILE"
i=0
while [ "$i" -lt "${#SEC_NAME[@]}" ]; do
    printf '%-8s  %-10s  %-28s  %s\n' \
        "${SEC_RC[$i]}" "${SEC_STATUS[$i]}" "${SEC_NAME[$i]}" "$(basename "${SEC_FILE[$i]}")"
    if [ -n "${SEC_NOTE[$i]}" ]; then
        printf '                                        %s\n' "${SEC_NOTE[$i]}"
    fi
    if [ "${SEC_STATUS[$i]}" = "ERROR" ]; then
        ERRORS=$((ERRORS + 1))
    fi
    case "${SEC_NOTE[$i]}" in
        *SKIPPED*) SKIPS=$((SKIPS + 1)) ;;
    esac
    i=$((i + 1))
done
echo "----------------------------------------------------------------------------"
if [ "$ERRORS" -eq 0 ]; then
    echo "RESULT: every section ran. Findings are in the files above; a non-zero"
    echo "        scanner exit means the scanner reported something, not that it failed."
    if [ "$SKIPS" -gt 0 ]; then
        echo "        ${SKIPS} measurement(s) skipped for a stated reason - see the files."
    fi
    echo "============================================================================"
    exit 0
else
    echo "RESULT: ${ERRORS} section(s) COULD NOT RUN. This is an error, not a finding."
    echo "        Read the TRAILER of each file marked ERROR above."
    echo "============================================================================"
    exit 1
fi
