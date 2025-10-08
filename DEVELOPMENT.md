## Development containers
Development of Trustee can be done by using turnkey development containers, these are provided in [.devcontainer](.devcontainer) directory that allow you todo the following tasks:
| task    | path |
| -------- | ------- |
| **simple**, edit raw text files  | `.devcontainer/devcontainer.json`    |
| **image**, build and develop container images, update devcontainers | `.devcontainer/image-builder/devcontainer.json`     |
| **code**, write, compile and test code    | `.devcontainer/rust-development/devcontainer.json`    |

If new to development containers more information are on [containers.dev](https://containers.dev)

To have a quick check if your favorite IDE supports development containers check [here](https://containers.dev/supporting) or your IDE reference documentation.


### Maintaining devcontainers

#### Images

Development container images have been pinned to multiarch digests, to update start the [simple](.devcontainer/devcontainer.json) development container, add skopeo

```shell
sudo apk add skopeo
```

and extract the multiarch digest for the desired image, notice for development container images child tag must be removed. After generation add it to the corresponding devcontainer.json

```shell
#!/bin/bash

# This script retrieves the manifest digest for quay.io/podman/stable:v5
# and prints the pinned multi-architecture image reference.
IMAGE="quay.io/podman/stable:v5"
# Retrieve the manifest digest using skopeo and jq
DIGEST=$(skopeo inspect docker://$IMAGE | jq -r '.Digest')
# Print the pinned image reference
echo "Pinned multi-arch image reference:"
echo "${IMAGE%@*}@${DIGEST}"
```

#### Features
Development container features are pinned using a [lockfile](https://github.com/devcontainers/spec/blob/main/docs/specs/devcontainer-lockfile.md) per container, if wanting to change a development feature set, start the [image](.devcontainer/image-builder/devcontainer.json) development container, apply the changes then run:
```shell
devcontainer build --workspace-folder --docker-path podman --config .devcontainer/image-builder/devcontainer.json
```

#### Dependabot

Development container specifications have beend added to the dependabot eco system, more information [here](https://containers.dev/guide/dependabot).