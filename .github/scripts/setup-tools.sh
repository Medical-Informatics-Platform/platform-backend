#!/bin/bash
set -e          # stop the pipeline if any command fails
set -o pipefail # Prevents silent pipeline successes if the curl download drops
set -u          # treat unset variables as an error

trap 'echo "[setup-tools] ERROR: command failed (exit $?) at line $LINENO: $BASH_COMMAND" >&2' ERR 


TRIVY_VERSION="${TRIVY_VERSION:-v0.71.1}"
OSV_SCANNER_VERSION="${OSV_SCANNER_VERSION:-v2.4.0}"
 
# Installing Trivy
echo "[setup-tools] Installing Trivy ${TRIVY_VERSION}"
sudo curl -fsSL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh \
  | sh -s -- -b /usr/local/bin "${TRIVY_VERSION}"
trivy --version
echo "Trivy installed OK"
 
# Installing OSV Scanner
echo "[setup-tools] Installing OSV Scanner ${OSV_SCANNER_VERSION}"
sudo curl -fsSL "https://github.com/google/osv-scanner/releases/download/${OSV_SCANNER_VERSION}/osv-scanner_linux_amd64" \
  -o /usr/local/bin/osv-scanner
sudo chmod +x /usr/local/bin/osv-scanner
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
    npx --yes @cyclonedx/cyclonedx-npm --output-file target/bom.json
    ;;
  none)
    echo "No SBOM generation needed"
    ;;
  *)
    echo "Unknown PROJECT_TYPE: $PROJECT_TYPE" >&2 # redirect error message to stderr
    exit 1
    ;;
esac