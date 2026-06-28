import subprocess
import os
import sys
import logging

GREEN = '\033[92m'
RED = '\033[91m'
RESET = '\033[0m'
BOLD = '\033[1m'

logging.basicConfig(
    level=logging.INFO,
    format='%(message)s'
)
logger = logging.getLogger("sca-orchestrator")

def run_trivy():
    cmd = [
        "trivy", "sbom",
        "target/bom.json",
        "--format", "sarif",
        "--output", "trivy.sarif",
        "--severity", "CRITICAL,HIGH",
        "--exit-code", "1"
    ]
    
    return subprocess.run(cmd).returncode

def run_osv_scanner():
    cmd = [
        "osv-scanner", "scan", "source",
        "--lockfile", "target/bom.json",
        "--config", ".github/scripts/osv-scanner.toml",
        "--format", "sarif",
        "--output-file", "osv-scanner.sarif",
    ]
    
    return subprocess.run(cmd).returncode

def run_dependency_check():
    cmd = [
        "./dependency-check/bin/dependency-check.sh",
        "--scan", "target/bom.json",
        "--nvdDatafeed", "https://dependency-check.github.io/DependencyCheck_Builder/nvd_cache/",
        "--format", "SARIF",
        "--out", ".",
        "--failOnCVSS", "8",
    ]

    return subprocess.run(cmd).returncode

def main():
    
    tools = [run_trivy, run_osv_scanner, run_dependency_check]

    failed_ci = False

    results = {}

    for tool in tools:
        code = tool()
        results[tool.__name__] = code

        if code and code != 0:
            logger.error(f"{RED}[!] Tool {tool.__name__} failed with exit code {code}{RESET}")
            failed_ci = True
        logger.info("-" * 40)

    logger.info(f"\n{BOLD}========== SCA PIPELINE SUMMARY =========={RESET}")
    for tool_name, code in results.items():
        if code == 0:
            logger.info(f"[{tool_name}]: {GREEN}PASSED{RESET}")
        else:
            logger.error(f"[{tool_name}]: {RED}FAILED (Exit Code {code}){RESET}")
    logger.info(f"{BOLD}=========================================={RESET}\n")

    if failed_ci:
        logger.error(f"{RED}Pipeline blocked due to security findings.{RESET}")
        sys.exit(1)

if __name__ == "__main__":
    main()
 