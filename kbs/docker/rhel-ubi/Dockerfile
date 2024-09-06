# Use UBI to build.
FROM registry.access.redhat.com/ubi9 as builder

# Install build dependencies from CentOS or RHEL repos.
RUN \
# Update packages. Get CVE fixes sooner.
dnf -y update && \
# Enable additional repositories for CentOS or RHEL.
if command -v subscription-manager; then \
  REPO_ARCH=$(uname -m) && \
  subscription-manager register --org "$(cat /activation-key/org)" --activationkey "$(cat /activation-key/activationkey)" && \
  subscription-manager repos --enable rhel-9-for-${REPO_ARCH}-appstream-rpms --enable codeready-builder-for-rhel-9-${REPO_ARCH}-rpms; \
else \
  dnf -y install 'dnf-command(config-manager)' && dnf config-manager --enable crb; \
fi && \
# Install packages.
dnf -y --setopt=install_weak_deps=0 install \
  cargo pkg-config perl-FindBin openssl-devel perl-lib perl-IPC-Cmd perl-File-Compare perl-File-Copy clang-devel \
  # These two are only available in the CodeReady Builder repo.
  tpm2-tss-devel protobuf-compiler \
  # This one is needed to build the stub.
  meson

# Build.
WORKDIR /usr/src/kbs
COPY . .
ARG KBS_FEATURES=coco-as-builtin,resource,opa,openssl
RUN \
# Build sgx_dcap_quoteverify stub.
pushd sgx_dcap_quoteverify_stubs && \
meson setup build --prefix=/usr && \
meson compile -C build && \
meson install -C build && \
popd && \
# Build KBS.
cargo install --locked --root /usr/local/ --path kbs/src/kbs --no-default-features --features ${KBS_FEATURES} && \
# Check the sha256sum of the Intel provided RPMs on x86_64.
if [ $(uname -m) = "x86_64" ]; then \
  pushd sgx_dcap_quoteverify_stubs && \
  echo "2621eac23cb756bc238f88d6db5401f7efed55d87855fc2b7e446ddfc1bd37ca" libsgx-dcap-default-qpl-1.21.100.3-1.el9.x86_64.rpm | sha256sum --check && \
  echo "57da5fb2253a99bb2483d19b6f30d1170ebc384e2891937e2c89fa55886b7034" libsgx-dcap-quote-verify-1.21.100.3-1.el9.x86_64.rpm | sha256sum --check && \
  popd; \
fi

# Package UBI image.
FROM registry.access.redhat.com/ubi9

# Update packages. Get CVE fixes sooner.
RUN dnf -y update && dnf clean all

COPY --from=builder /usr/local/bin/kbs /usr/local/bin/kbs
COPY --from=builder /usr/src/kbs/sgx_dcap_quoteverify_stubs/libsgx-dcap-quote-verify-1.21.100.3-1.el9.x86_64.rpm /tmp/libsgx-dcap-quote-verify-1.21.100.3-1.el9.x86_64.rpm
COPY --from=builder /usr/src/kbs/sgx_dcap_quoteverify_stubs/libsgx-dcap-default-qpl-1.21.100.3-1.el9.x86_64.rpm /tmp/libsgx-dcap-default-qpl-1.21.100.3-1.el9.x86_64.rpm

# Install Intel binaries
RUN \
if [ $(uname -m) = "x86_64" ]; then \
  dnf -y --nogpgcheck --setopt=install_weak_deps=0 localinstall \
    /tmp/libsgx-dcap-quote-verify-1.21.100.3-1.el9.x86_64.rpm \
    /tmp/libsgx-dcap-default-qpl-1.21.100.3-1.el9.x86_64.rpm; \
fi && \
rm -f /tmp/libsgx-dcap-quote-verify-1.21.100.3-1.el9.x86_64.rpm /tmp/libsgx-dcap-default-qpl-1.21.100.3-1.el9.x86_64.rpm

# Declare build-time variables.
ARG NAME="trustee"
ARG DESCRIPTION="The Trustee server."

# Red Hat labels.
LABEL com.redhat.component=$NAME
LABEL description=$DESCRIPTION
LABEL io.k8s.description=$DESCRIPTION
LABEL io.k8s.display-name=$NAME
LABEL name=$NAME
LABEL summary=$DESCRIPTION
LABEL distribution-scope=public
LABEL release="1"
LABEL url="https://access.redhat.com/"
LABEL vendor="Red Hat, Inc."
LABEL version="1"
LABEL maintainer="Red Hat"
# Reset labels inherited from base image.
LABEL io.openshift.tags=""

# Licenses
COPY LICENSE /licenses/LICENSE
