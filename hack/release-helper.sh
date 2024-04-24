#!/bin/bash
set -euo pipefail


declare -g gh_username
declare -g gh_token
declare -g release_candidate_sha
declare -g release_tag
declare -A staged_to_release=(
    ["staged-images/kbs"]="key-broker-service"
    ["staged-images/kbs-grpc-as"]="key-broker-service"
    ["staged-images/rvps"]="reference-value-provider-service"
    ["staged-images/coco-as-grpc"]="attestation-service"
    ["staged-images/coco-as-restful"]="attestation-service"
)
declare -A staged_to_release_tag_prefix=(
    ["staged-images/kbs"]="built-in-as-"
    ["staged-images/coco-as-restful"]="rest-"
)


function usage_and_exit() {
    echo
    echo "Usage:"
    echo "  $0  -u github-username  -k github-token  -c release-candidate-sha  -r release-tag"
    echo
    echo "  -u  Your github username. You'll be opening a PR against "
    echo "      confidential-container's trustee/main."
    echo "  -k  A github token with permissions on trustee to write packages"
    echo "      and open PRs."
    echo "  -c  This is the commit sha that's been tested and that you're happy"
    echo "      with. You want to release from this commit sha."
    echo "      Example: dc01f454264fb4350e5f69eba05683a9a1882c41"
    echo "  -r  This is the new version tag that the release will have."
    echo "      Example: v0.8.2"
    echo
    echo "Example usage:"
    echo "    ./release-helper.sh -u \${gh_username} -k \${gh_token} -c dc01f454264fb4350e5f69eba05683a9a1882c41 -n v0.8.2"
    echo
    exit 1
}


function parse_args() {
    while getopts ":u:k:c:r:" opt; do
        case "${opt}" in
            u)
                gh_username=${OPTARG}
                ;;
            k)
                gh_token=${OPTARG}
                ;;
            c)
                release_candidate_sha=${OPTARG}
                ;;
            r)
                release_tag=${OPTARG}
                ;;
            *)
                usage_and_exit
                ;;
        esac
    done
    if [[ ! -v gh_username ]] || [[ ! -v gh_token ]] || [[ ! -v release_candidate_sha ]] || [[ ! -v release_tag ]]; then
        usage_and_exit
    fi
}


function tag_and_push_packages() {
    local ghcr_repo="ghcr.io/confidential-containers"

    echo
    echo "Tagging packages"
    echo "  Release candidate sha: ${release_candidate_sha}"
    echo "  Newly released tag will be: ${release_tag}"
    echo

    echo ${gh_token} | docker login ghcr.io -u ${gh_username} --password-stdin

    for staged_pkg_name in ${!staged_to_release[@]}; do
        release_pkg_name=${staged_to_release[${staged_pkg_name}]}

        # pull the staged package
        docker pull ${ghcr_repo}/${staged_pkg_name}:${release_candidate_sha}

        # set tag prefix (if needed)
        release_tag_prefix=
        if [[ -v staged_to_release_tag_prefix[${staged_pkg_name}] ]]; then
            release_tag_prefix=${staged_to_release_tag_prefix[${staged_pkg_name}]}
        fi
        release_tag_full=${release_tag_prefix}${release_tag}

        # tag it
        docker tag ${ghcr_repo}/${staged_pkg_name}:${release_candidate_sha} ${ghcr_repo}/${release_pkg_name}:${release_tag_full}

        # push it (i.e. release it)
        docker push ${ghcr_repo}/${release_pkg_name}:${release_tag_full}
    done
}


function bump_kustomization_with_pr() {
    local kust_file="kbs/config/kubernetes/base/kustomization.yaml"
    local update_branch="updates-for-release-${release_tag}"
    tmp_dir=$(mktemp -d)
    trap teardown EXIT

    echo
    echo "Bumping kustomization and opening PR"
    echo

    # clone user's trustee
    git clone git@github.com:${gh_username}/trustee ${tmp_dir}/trustee
    pushd ${tmp_dir}/trustee

    # bail if the (remote) origin already has the branch we need to use
    rv=$(git ls-remote --heads origin ${update_branch})
    if [[ "${rv}" =~ "refs/heads/${update_branch}" ]]; then
        echo "Error: origin/${update_branch} already exists, but this script"
        echo "expects to be able to push to a fresh ${update_branch} branch."
        echo "Please manually delete the branch or otherwise handle this"
        echo "before proceeding."
        exit 1
    fi

    # switch to a new branch that's tracking (upstream) main
    git remote add upstream git@github.com:confidential-containers/trustee
    git fetch upstream
    git checkout -b ${update_branch} upstream/main

    # update kustomization.yaml
    sed \
      -Ei \
      "s;newTag: built-in-as-v[0-9]+\.[0-9]+\.[0-9]+;newTag: built-in-as-${release_tag};g" \
      ${kust_file}

    # commit and push
    git add ${kust_file}
    git commit -sm 'Release: Update kbs kustomization.yaml for '${release_tag}
    git push --set-upstream origin ${update_branch}

    # open PR
    rv=$(curl \
      -L \
      -s \
      -i \
      -X POST \
      -H "Accept: application/vnd.github+json" \
      -H "Authorization: Bearer ${gh_token}" \
      -H "X-GitHub-Api-Version: 2022-11-28" \
      https://api.github.com/repos/confidential-containers/trustee/pulls \
      -d '{"title":"Release: Update KBS for '${release_tag}'",
           "body":"Updates kustomization.yaml for next release.",
           "head":"'${gh_username}':'${update_branch}'",
           "base":"main"}')
    rc=$(echo ${rv} | head -n 1 | cut -d' ' -f2)
    if ! [[ "${rc}" =~ 2[0-9][0-9] ]]; then
        echo "Error: POST to open a PR received a non-2xx response from github"
        echo "(${rc}). Dumping full response..."
        echo ${rv}
        echo "Attempting to delete origin/${update_branch}"
        git push origin :${update_branch}
        exit 1
    fi

    popd
}


function teardown() {
    rm -rf ${tmp_dir}
}


function main() {
    parse_args "$@"
    tag_and_push_packages
    bump_kustomization_with_pr
    echo "Success. Exiting..."
}


main "$@"
