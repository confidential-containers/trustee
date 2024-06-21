# KBS Release Guide

The following steps are a guide for releasing kbs. Note that a
[helper script](hack/release-helper.sh)
can be used to automate steps 2 and 3.

1. Identify a valid release candidate. This is partly a sanity-checking step.
For example, assuming you want the most recent commit, start by checking the
tests of the last PR that was merged, and verify that the tests all passed (or
any failures were acceptable in that context). Similarly, locate the ghcr kbs
images that were created by the PR.

2. Copy the ghcr images you identified in step (1). The new copy will be the
released version. For example, if you are satisfied with the "latest" images in
ghcr, and assuming you are releasing v0.8.2, these would be the ghcr package
mappings:
```
staged-images/kbs:latest -> key-broker-service:built-in-as-v0.8.2
staged-images/kbs-grpc-as:latest -> key-broker-service:v0.8.2
staged-images/kbs-ita-as:latest -> key-broker-service:ita-as-v0.8.2
staged-images/rvps:latest -> reference-value-provider-service:v0.8.2
staged-images/coco-as-grpc:latest -> attestation-service:v0.8.2
staged-images/coco-as-restful:latest -> attestation-service:rest-v0.8.2
```

3. Create a PR for the release. This PR needs to update the kubernetes
kustomization.yaml file: `kbs/config/kubernetes/base/kustomization.yaml`. The
`newTag` should be bumped to reflect the new version, e.g.
`built-in-as-v0.8.2`.

4. After the PR passes all tests and is merged, use the kbs github page to
create the release. After the release is created, github will automatically
tag the main branch with the new release version.
