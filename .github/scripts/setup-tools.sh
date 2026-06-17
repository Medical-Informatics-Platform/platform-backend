#!/bin/bash
set -e

# Installing Maven for SCA dependency resolution
apt-get update -q
apt-get install -y curl ca-certificates maven

# Install Trivy
curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin v0.71.1