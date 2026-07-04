#!/bin/bash
set -e

# Install Trivy
curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin v0.71.1

# Install OSV Scanner
curl -L https://github.com/google/osv-scanner/releases/download/v2.4.0/osv-scanner_linux_amd64 -o /usr/local/bin/osv-scanner
chmod +x /usr/local/bin/osv-scanner


# Generate SBOM based on project type

PROJECT_TYPE="${1:-none}"   # maven | npm | none
case "$PROJECT_TYPE" in
  maven)
    echo "Generating SBOM for Maven project"
    mvn org.cyclonedx:cyclonedx-maven-plugin:makeAggregateBom -q
    ;;
  npm)
    echo "Generating SBOM for NPM project"
    npx --yes @cyclonedx/cyclonedx-npm --output-file bom.json
    ;;
  none)
    echo "No SBOM generation needed for image pipelines"
    ;;
  *)
    echo "Unknown PROJECT_TYPE: $PROJECT_TYPE" >&2 # redirect error message to stderr
    exit 1
    ;;
esac