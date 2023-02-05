FROM ubuntu:20.04

ENV VERSION=Latest
ENV OS=Linux
ENV ARCH=x86_64


RUN apt-get update && \
    apt-get install -y ca-certificates curl git jq wget && \
    curl -fsSLo /usr/share/keyrings/kubernetes-archive-keyring.gpg https://packages.cloud.google.com/apt/doc/apt-key.gpg && \
    echo "deb [signed-by=/usr/share/keyrings/kubernetes-archive-keyring.gpg] https://apt.kubernetes.io/ kubernetes-xenial main" | tee /etc/apt/sources.list.d/kubernetes.list && \
    apt-get update && \
    apt-get install -y kubectl && \
    wget "https://github.com/sigstore/cosign/releases/download/v1.13.1/cosign_1.13.1_amd64.deb" && \
    dpkg -i "cosign_1.13.1_amd64.deb" && \
    ln -s /usr/local/bin/cosign-linux-amd64 /usr/local/bin/cosign && \
    wget https://github.com/aquasecurity/trivy/releases/download/v0.37.1/trivy_0.37.1_Linux-64bit.deb && \
    dpkg -i trivy_0.37.1_Linux-64bit.deb && \
    curl -sL "https://github.com/google/go-containerregistry/releases/download/v0.13.0/go-containerregistry_Linux_x86_64.tar.gz" > go-containerregistry.tar.gz && \
    tar -xvzf go-containerregistry.tar.gz && \
    mv crane /bin && \
    mv gcrane /bin && \
    wget https://github.com/sigstore/rekor/releases/download/v1.0.1/rekor-cli-linux-amd64 && \
    mv rekor-cli-linux-amd64 /bin/rekor-cli && \
    chmod +x /bin/rekor-cli



CMD  while :; do echo 'Hit CTRL+C'; sleep 1; done