#!/usr/bin/env bash
echo "ADD container file linter"
sudo curl -L -o /usr/local/bin/hadolint https://github.com/hadolint/hadolint/releases/download/v2.13.1/hadolint-linux-x86_64 && sudo chmod +x /usr/local/bin/hadolint 