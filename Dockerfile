# The binary is built on the host with a recorded Go toolchain. Scratch has no
# moving base tag, shell, package manager, or provider credential.
FROM scratch
ARG TARGETARCH=amd64
COPY dist/linux-${TARGETARCH}/periscope /periscope
COPY dist/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
USER 65532:65532
ENTRYPOINT ["/periscope"]
