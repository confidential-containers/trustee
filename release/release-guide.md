# Trustee Release Guide

**Note:** `0.23.0` / `v0.23.0` is only an example version used throughout this guide.

## Steps

1. **The guest-components commit** that Trustee will ship is picked and tested.
2. **The release script is run** (it edits files only, then verifies them):

   ```bash
   release/release.sh --version 0.23.0 --gc-rev <guest-components sha> [--trustee-rev <trustee sha>]
   ```

   Checklist of what the script updates (to be reviewed in the PR diff):
   - [ ] `deployment/helm-chart/Chart.yaml`: `version` and `appVersion` (`0.23.0`)
   - [ ] `deployment/helm-chart/values.yaml` and `deployment/helm-chart/scenarios/*.yaml`: the tag
         of every Trustee image from the release repos listed below (`v0.23.0`);
         `scenarios/ibm-se-nightly-e2e.yaml` is for the nightly CI and stays on
         `staged-images/...:latest`
   - [ ] `deployment/helm-chart/README.md`: regenerated with `helm-docs` (needs `helm-docs`
         installed)
   - [ ] `kbs/config/kubernetes/base/kustomization.yaml`: `newTag` (`built-in-as-v0.23.0`)
   - [ ] the guest-components `rev` in `Cargo.toml` (the commit the kbs-client is built with. It is
         also the same commit the guest-components release uses)
   - [ ] `Cargo.lock`: refreshed with `cargo update --workspace` (needs `cargo` and network access)

   The script then runs the same consistency check as the workflow (`--check`) and fails if
   anything does not match.

   The version is passed as `X.Y.Z` (no leading `v`). It is used as is in `Chart.yaml` (`version`,
   `appVersion`). The image tags in `values.yaml` and the scenarios (replacing `latest`) and the
   kustomization, and the git tag / GitHub release, use `v0.23.0` (kustomization:
   `built-in-as-v0.23.0`). `docker-compose.yml` is not changed: it stays on `latest`, because the
   compose e2e builds and runs images under that name.
3. **A PR is opened** manually with the script's changes (the script only edits files; it does not
   commit, push or open a PR).
4. **The PR is reviewed and merged.** The merge commit is the release commit. Before the merge, a
   message is posted in Slack that a release is in progress, asking maintainers and admins to not
   merge anything to `main` until the release workflow has been triggered (next step). Until the
   workflow has finished, the image tags in the Helm chart do not exist yet. Another Slack message
   is posted when the workflow is done.
5. **The release workflow is run** (Actions > Release > Run workflow) soon after the merge, with
   `version` = `v0.23.0` (with the `v`) and `git-sha` = the merged release PR commit. If `git-sha`
   is empty the tip of `main` is released, so it must be set whenever anything else may have merged
   after the release PR. The workflow:
   - checks the commit is on `main`, the tag does not exist yet, and `release/release.sh --check`
     passes;
   - checks that every staged image and kbs-client binary of that commit exists, before publishing
     anything;
   - publishes the release images by retagging the staged images built for that commit by the
     merge to `main` (wait for the "Staged Images" run to finish first);
   - copies the staged kbs-client binaries (see below);
   - creates the tag `v0.23.0` on that commit (last, once all images are published).
6. **The result is checked**: tag `v0.23.0` and the images listed below must exist.
7. **Kata is updated**: the Trustee version in Kata's `versions.yaml` is bumped to the new tag.
   This is a separate manual PR; Trustee does not reference Kata.
8. **The GitHub release is created by hand** from the tag `v0.23.0` (release notes are not kept in
   the source tree; `--generate-notes` is a starting point, to be edited on GitHub afterwards):

   ```bash
   gh release create v0.23.0 --repo confidential-containers/trustee --verify-tag \
     --title v0.23.0 --generate-notes
   ```

If the workflow fails, the cause is fixed and the workflow is run again. If the cause is outside
the repo, the re-run uses the same `git-sha`. If it needs another PR, the re-run is against the
merge commit of that PR. Retagging the images is safe to repeat. The tag is created last, so a
failed run never leaves a tag behind.

Once the tag `v0.23.0` exists the workflow refuses to run again for that version. If a release
must be redone with a newer commit and nobody has used it yet, the tag and the GitHub release (if
any) are deleted, then the workflow is run with the new `git-sha`; the release script does not need
to be re-run. Otherwise the next version (`0.24.0`) is released.

## Images published

| Repository                                                         | Source image (staged) | Tag                    |
|--------------------------------------------------------------------|-----------------------|------------------------|
| `ghcr.io/confidential-containers/key-broker-service`               | `kbs-grpc-as`         | `v0.23.0`              |
| `ghcr.io/confidential-containers/key-broker-service`               | `kbs`                 | `built-in-as-v0.23.0`  |
| `ghcr.io/confidential-containers/attestation-service`              | `coco-as-grpc`        | `v0.23.0`              |
| `ghcr.io/confidential-containers/attestation-service`              | `coco-as-restful`     | `rest-v0.23.0`         |
| `ghcr.io/confidential-containers/reference-value-provider-service` | `rvps`                | `v0.23.0`              |
| `ghcr.io/confidential-containers/kbs-client`                       | `kbs-client-image`    | `v0.23.0`              |

`kbs-client` is the container image built from `kbs/docker/kbs-client-image/Dockerfile`, tagged like
the other components. Until now only the staged kbs-client was published; publishing a release
version is new with this process.

The kbs-client binary (an ORAS artifact, not a container) is copied, not rebuilt, from the staged
`staged-images/kbs-client:sample_only-<commit>-<arch>` (built when the release PR merged to `main`)
to `ghcr.io/confidential-containers/kbs-client:sample_only-v0.23.0-<arch>`, for `x86_64`, `s390x`
and `aarch64`.
