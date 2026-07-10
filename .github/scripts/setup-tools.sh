#!/bin/bash
set -e          # stop the pipeline if any command fails
set -o pipefail # Prevents silent pipeline successes if the curl download drops
set -u          # treat unset variables as an error

trap 'echo "[setup-tools] ERROR: command failed (exit $?) at line $LINENO: $BASH_COMMAND" >&2' ERR


# Tool versions and the SHA256 of the release asset we download.
# The "# renovate:" markers let Renovate bump version and checksum together
# (see renovate.json). When overriding a *_VERSION via env, the matching
# *_SHA256 must be overridden as well or verification will fail.

# renovate: datasource=github-release-attachments depName=aquasecurity/trivy
TRIVY_VERSION="${TRIVY_VERSION:-v0.71.1}"
TRIVY_SHA256="${TRIVY_SHA256:-3cbae37cd440cd8676e5ce9207fe460b5641c7579a17e9d00f8894928c41a88d}"

# renovate: datasource=github-release-attachments depName=google/osv-scanner
OSV_SCANNER_VERSION="${OSV_SCANNER_VERSION:-v2.4.0}"
OSV_SCANNER_SHA256="${OSV_SCANNER_SHA256:-15314940c10d26af9c6649f150b8a47c1262e8fc7e17b1d1029b0e479e8ed8a0}"

# renovate: datasource=npm depName=@cyclonedx/cyclonedx-npm
CYCLONEDX_NPM_VERSION="${CYCLONEDX_NPM_VERSION:-6.0.0}"

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "${TMP_DIR}"' EXIT

# Download a file and refuse to proceed unless its SHA256 matches the pinned one
download_and_verify() {
  local url="$1" dest="$2" sha256="$3"
  curl -fsSL --retry 3 "${url}" -o "${dest}"
  echo "${sha256}  ${dest}" | sha256sum -c -
}

# Installing Trivy from the release tarball (no install.sh piped from an unpinned branch)
echo "[setup-tools] Installing Trivy ${TRIVY_VERSION}"
TRIVY_TARBALL="trivy_${TRIVY_VERSION#v}_Linux-64bit.tar.gz"
download_and_verify \
  "https://github.com/aquasecurity/trivy/releases/download/${TRIVY_VERSION}/${TRIVY_TARBALL}" \
  "${TMP_DIR}/${TRIVY_TARBALL}" \
  "${TRIVY_SHA256}"
sudo tar -xzf "${TMP_DIR}/${TRIVY_TARBALL}" -C /usr/local/bin trivy
trivy --version
echo "Trivy installed OK"

# Installing OSV Scanner
echo "[setup-tools] Installing OSV Scanner ${OSV_SCANNER_VERSION}"
download_and_verify \
  "https://github.com/google/osv-scanner/releases/download/${OSV_SCANNER_VERSION}/osv-scanner_linux_amd64" \
  "${TMP_DIR}/osv-scanner" \
  "${OSV_SCANNER_SHA256}"
sudo install -m 0755 "${TMP_DIR}/osv-scanner" /usr/local/bin/osv-scanner
osv-scanner --version
echo "OSV Scanner installed OK"


# Generate SBOM based on project type
PROJECT_TYPE="${1:-none}"   # maven | npm | none

case "$PROJECT_TYPE" in
  maven)
    echo "Generating SBOM for Maven project"
    mvn org.cyclonedx:cyclonedx-maven-plugin:makeAggregateBom -q
    ;;
  npm)
    echo "Generating SBOM for NPM project"
    npx --yes "@cyclonedx/cyclonedx-npm@${CYCLONEDX_NPM_VERSION}" --output-file target/bom.json
    ;;
  none)
    echo "No SBOM generation needed"
    ;;
  *)
    echo "Unknown PROJECT_TYPE: $PROJECT_TYPE" >&2 # redirect error message to stderr
    exit 1
    ;;
esac
