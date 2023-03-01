FROM rust:1.67-slim

WORKDIR /usr/src/kbs
COPY . .

# Install Build Dependencies
RUN apt-get update && apt-get install apt-utils
RUN apt-get install -y \
clang \
cmake \
curl \
gnupg \
libclang-dev \
libprotobuf-dev \
libssl-dev \
make \
pkg-config \
protobuf-compiler \
wget
RUN wget https://go.dev/dl/go1.20.1.linux-amd64.tar.gz
RUN tar -C /usr/local -xzf go1.20.1.linux-amd64.tar.gz
ENV PATH="/usr/local/go/bin:${PATH}"

# Install TDX Dependencies
RUN curl -L https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key | apt-key add -
RUN echo 'deb [arch=amd64] https://download.01.org/intel-sgx/sgx_repo/ubuntu focal main' | tee /etc/apt/sources.list.d/intel-sgx.list
RUN apt-get update
RUN apt-get install -y \
libtdx-attest \
libtdx-attest-dev \
libsgx-dcap-default-qpl \
libsgx-dcap-quote-verify \
libsgx-dcap-quote-verify-dev

# Intel PCCS URL Configurations
# If you want the AS in KBS to connect to your customized PCCS for Intel TDX/SGX evidence verification,
# please modify this parameter.
# Default using localhost PCCS (Run in Host which the container land on).
ENV INTEL_PCCS_URL "https://localhost:8081/sgx/certification/v4/"
ENV INTEL_PCCS_USE_SECURE_CERT false

# Setup Intel PCCS URL
RUN sed -i "s|\"pccs_url\":.*$|\"pccs_url\":$INTEL_PCCS_URL,|" /etc/sgx_default_qcnl.conf; \
sed -i "s/\"use_secure_cert\":.*$/\"use_secure_cert\":$INTEL_PCCS_USE_SECURE_CERT,/" /etc/sgx_default_qcnl.conf

# Build and Instll KBS
RUN cargo install --path src/kbs