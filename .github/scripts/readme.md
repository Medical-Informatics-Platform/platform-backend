# SCA Pipeline

Security scanning runs automatically on every pull request to detect vulnerable dependencies before merging.
We generate a CycloneDX SBOM from the project to ensure accurate results with no false positives.

## Files

- **setup-tools.sh** : Installs the scanning tools: Trivy, OSV Scanner, and OWASP Dependency-Check.
- **run_sca.py** : Orchestrates all three tools and prints a pass/fail summary at the end.
- **osv-scanner.toml** : OSV Scanner suppression list for vulnerabilities that cannot be fixed yet, with reasons and expiry dates.