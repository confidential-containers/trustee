# Use CentOS Stream to build.
FROM quay.io/centos/centos:stream9 AS builder

# Install build dependencies from CentOS repos.
RUN dnf -y --setopt=install_weak_deps=0 --enablerepo=crb install \
perl-core cargo pkg-config perl-FindBin openssl-devel perl-lib perl-IPC-Cmd perl-File-Compare perl-File-Copy tpm2-tss-devel clang-devel protobuf-compiler \
tar gzip

# Install build dependencies from Intel repo.
WORKDIR /root
RUN curl -O https://download.01.org/intel-sgx/sgx-linux/2.24/distro/centos-stream9/sgx_rpm_local_repo.tgz && \
tar -xaf sgx_rpm_local_repo.tgz && \
dnf -y install --nogpgcheck --repofrompath "sgx,file:///root/sgx_rpm_local_repo" libsgx-dcap-quote-verify-devel

# Build.
WORKDIR /usr/src/kbs
COPY . .
ARG KBS_FEATURES=coco-as-builtin
RUN \
cargo install --locked --root /usr/local/ --path kbs --bin kbs --no-default-features --features ${KBS_FEATURES} && \
# Collect linked files necessary for the binary to run.
mkdir -p /root/trustee/lib64 && \
ldd /usr/local/bin/kbs | sed 's@.*\s/@/@' | sed 's/\s.*//' | xargs -I {} cp {} /root/trustee/lib64

# Package UBI image.
FROM registry.access.redhat.com/ubi9

# Install runtime dependencies from Intel repo.
COPY --from=builder /root/sgx_rpm_local_repo /root/sgx_rpm_local_repo
RUN dnf -y install --nogpgcheck --setopt=install_weak_deps=0 --repofrompath "sgx,file:///root/sgx_rpm_local_repo" \
libsgx-dcap-default-qpl libsgx-dcap-quote-verify && \
rm -rf /root/sgx_rpm_local_repo

COPY --from=builder /usr/local/bin/kbs /usr/local/bin/kbs
