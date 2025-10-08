#!/usr/bin/env bash
echo "ADD container file linter"
cp ${CONTAINER_WORKSPACE_FOLDER}/.devcontainer/image-builder/hadolint-linux-x86_64_v2.14.0.sha256 /tmp/hadolint-linux-x86_64_v2.14.0.sha256
curl -L -o /tmp/hadolint-linux-x86_64 https://github.com/hadolint/hadolint/releases/download/v2.14.0/hadolint-linux-x86_64
# Verify checksum
echo "Verifying checksum..."
cd /tmp
if sha256sum -c /tmp/hadolint-linux-x86_64_v2.14.0.sha256; then
    echo "Checksum verified. Installing..."
    sudo mv /tmp/hadolint-linux-x86_64 /usr/local/bin/hadolint
    sudo chmod +x /usr/local/bin/hadolint
else
    echo "Checksum verification failed!"
    exit 1
fi

