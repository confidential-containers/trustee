#!/usr/bin/env bash
#
# Copyright (c) 2023 Intel Corporation
#
# SPDX-License-Identifier: Apache-2.0
#

set -o errexit
set -o nounset
set -o pipefail

TARGET_BRANCH=${TARGET_BRANCH:-main}

function rebase_atop_of_the_latest_target_branch() {
        if [ -n "${TARGET_BRANCH}" ]; then
                echo "Rebasing atop of the latest ${TARGET_BRANCH}"
                # Recover from any previous rebase left halfway
                git rebase --abort 2> /dev/null || true
                if ! git rebase "origin/${TARGET_BRANCH}"; then
                        # if GITHUB_WORKSPACE is defined and an architecture is not equal to x86_64
                        # (mostly self-hosted runners), then remove the repository
                        if [ -n "${GITHUB_WORKSPACE:-}" ] && [ "$(uname -m)" != "x86_64" ]; then
                                echo "Rebase failed, cleaning up a repository for self-hosted runners and exiting"
                                cd "${GITHUB_WORKSPACE}"/..
                                sudo rm -rf "${GITHUB_WORKSPACE}"
                        else
                                echo "Rebase failed, exiting"
                        fi
                        exit 1
                fi
        fi
}

function main() {
    action="${1:-}"

    case "${action}" in
        rebase-atop-of-the-latest-target-branch) rebase_atop_of_the_latest_target_branch;;
        *) >&2 echo "Invalid argument"; exit 2 ;;
    esac
}

main "$@"
