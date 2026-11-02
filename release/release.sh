#!/usr/bin/env bash
# Prepare (or verify) a Trustee release. See release/release-guide.md.

set -euo pipefail

usage() {
    cat <<EOF
Usage:
  release/release.sh --version X.Y.Z --gc-rev <guest-components sha> [--trustee-rev <trustee sha>]
  release/release.sh --check --version X.Y.Z [--gc-rev <guest-components sha>]

Options:
  --version X.Y.Z        Release version without a leading v.
  --gc-rev <sha>         guest-components commit (40 hex chars) that this Trustee release ships.
  --trustee-rev <sha>    Create the branch release-vX.Y.Z from this Trustee commit and edit
                         there (default: edit the current checkout).
  --check                Only verify that every version/rev is consistent. Edits nothing.

The script only edits files. It does not commit, push or open a PR.
EOF
}

VERSION=""
GC_REV=""
TRUSTEE_REV=""
CHECK_ONLY=false

while [[ $# -gt 0 ]]; do
    case "$1" in
        --version)     VERSION="${2:?--version needs a value}"; shift 2 ;;
        --gc-rev)      GC_REV="${2:?--gc-rev needs a value}"; shift 2 ;;
        --trustee-rev) TRUSTEE_REV="${2:?--trustee-rev needs a value}"; shift 2 ;;
        --check)       CHECK_ONLY=true; shift ;;
        -h|--help)     usage; exit 0 ;;
        *)             echo "Unknown argument: $1" >&2; usage >&2; exit 1 ;;
    esac
done

die() { echo "error: $*" >&2; exit 1; }

[[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] ||
    die "--version must look like X.Y.Z, without a leading v (got '${VERSION}')"
if [[ -n "$GC_REV" ]]; then
    [[ "$GC_REV" =~ ^[0-9a-f]{40}$ ]] || die "--gc-rev must be a full 40 character commit sha"
fi
if ! $CHECK_ONLY && [[ -z "$GC_REV" ]]; then
    die "--gc-rev is required unless --check is used"
fi
if $CHECK_ONLY && [[ -n "$TRUSTEE_REV" ]]; then
    die "--trustee-rev cannot be used with --check"
fi

cd "$(git rev-parse --show-toplevel)"

CHART=deployment/helm-chart/Chart.yaml
KUSTOMIZATION=kbs/config/kubernetes/base/kustomization.yaml
ITA_KUSTOMIZATION=kbs/config/kubernetes/ita/kustomization.yaml
HELM_IMAGE_PREFIX=ghcr.io/confidential-containers/
README=deployment/helm-chart/README.md
IMAGE_TAG="v${VERSION}"

# Helm values files that pin release image tags (values.yaml and the scenarios).
# Repositories under staged-images/ (CI images, e.g. the nightly scenario) are not release images.
tag_files() {
    git grep -F "repository: ${HELM_IMAGE_PREFIX}" -- 'deployment/helm-chart/*.yaml' |
        { grep -vF "/staged-images/" || true; } | cut -d: -f1 | sort -u
}

# helm-docs output for the chart, printed to stdout (does not write README.md).
render_readme() {
    helm-docs -c deployment/helm-chart --dry-run 2>/dev/null
}

# Loaded after any branch switch so it reflects the files being released.
CARGO_TOMLS=()
load_cargo_tomls() { mapfile -t CARGO_TOMLS < <(git ls-files -- '*Cargo.toml'); }

# Print a helm values file with the tag after every release image repository set to IMAGE_TAG.
# Fails if a repository line has no tag after it.
set_tags() {
    awk -v prefix="$HELM_IMAGE_PREFIX" -v tag="$IMAGE_TAG" '
        index($0, "repository: " prefix) && !index($0, "/staged-images/") { pending = 1 }
        pending && /^[[:space:]]*tag:/ { sub(/tag:.*/, "tag: \"" tag "\""); pending = 0 }
        { print }
        END { exit pending }
    ' "$1"
}

# inplace <function> <file>: replace the file with the function's output, keeping its mode.
inplace() {
    local tmp
    tmp=$(mktemp)
    "$1" "$2" > "$tmp"
    cat "$tmp" > "$2"
    rm -f "$tmp"
}

edit() {
    if [[ -n "$TRUSTEE_REV" ]]; then
        [[ -z "$(git status --porcelain)" ]] || die "working tree is not clean; cannot switch to ${TRUSTEE_REV}"
        git switch -c "release-v${VERSION}" "$TRUSTEE_REV"
    fi
    load_cargo_tomls

    sed -i -E "s/^version: .*/version: ${VERSION}/; s/^appVersion: .*/appVersion: \"${VERSION}\"/" "$CHART"

    local f
    while read -r f; do inplace set_tags "$f"; done < <(tag_files)

    command -v helm-docs >/dev/null || die "helm-docs is needed to regenerate ${README}"
    helm-docs -c deployment/helm-chart

    sed -i -E "s/newTag: built-in-as-v[0-9]+\.[0-9]+\.[0-9]+/newTag: built-in-as-${IMAGE_TAG}/" "$KUSTOMIZATION"
    sed -i -E "s/newTag: ita-as-v[0-9]+\.[0-9]+\.[0-9]+/newTag: ita-as-${IMAGE_TAG}/" "$ITA_KUSTOMIZATION"

    sed -i -E "/guest-components\.git/ s/rev = \"[0-9a-f]{40}\"/rev = \"${GC_REV}\"/" "${CARGO_TOMLS[@]}"

    command -v cargo >/dev/null || die "cargo is needed to refresh Cargo.lock"
    cargo update --workspace
}

fail=0
bad() { echo "MISMATCH: $*" >&2; fail=1; }

check() {
    load_cargo_tomls
    grep -qE "^version: ${VERSION}\$" "$CHART" || bad "$CHART version is not ${VERSION}"
    grep -qE "^appVersion: \"${VERSION}\"\$" "$CHART" || bad "$CHART appVersion is not \"${VERSION}\""

    local tf
    while read -r tf; do
        set_tags "$tf" | cmp -s - "$tf" || bad "$tf: not every image tag is ${IMAGE_TAG}"
    done < <(tag_files)

    command -v helm-docs >/dev/null || die "helm-docs is needed to check ${README}"
    [[ "$(render_readme)" == "$(cat "$README")" ]] ||
        bad "$README is stale; regenerate it with: helm-docs -c deployment/helm-chart"

    grep -qE "newTag: built-in-as-${IMAGE_TAG}\$" "$KUSTOMIZATION" ||
        bad "$KUSTOMIZATION newTag is not built-in-as-${IMAGE_TAG}"
    grep -qE "newTag: ita-as-${IMAGE_TAG}\$" "$ITA_KUSTOMIZATION" ||
        bad "$ITA_KUSTOMIZATION newTag is not ita-as-${IMAGE_TAG}"

    local revs
    revs=$( { grep -h 'guest-components\.git' "${CARGO_TOMLS[@]}" |
                  grep -oE 'rev = "[0-9a-f]{40}"' | grep -oE '[0-9a-f]{40}'
              grep -oE 'guest-components\.git\?rev=[0-9a-f]{40}' Cargo.lock | grep -oE '[0-9a-f]{40}'
            } | sort -u)
    [[ -n "$revs" ]] || bad "no guest-components rev found in Cargo.toml / Cargo.lock"
    [[ "$(wc -l <<<"$revs")" -le 1 ]] ||
        bad "guest-components rev differs between Cargo.toml and Cargo.lock: $(tr '\n' ' ' <<<"$revs")"
    if [[ -n "$GC_REV" && -n "$revs" && "$revs" != "$GC_REV" ]]; then
        bad "guest-components rev is ${revs}, expected ${GC_REV}"
    fi

    [[ $fail -eq 0 ]] || die "release consistency check failed"
    echo "OK: everything is consistent for ${VERSION} (${IMAGE_TAG})"
}

$CHECK_ONLY || edit
check
$CHECK_ONLY || echo "Reminder: run a test build (e.g. cargo build --workspace) to check the new guest-components rev compiles."
