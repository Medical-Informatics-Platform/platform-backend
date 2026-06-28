import subprocess
import os
import sys


# TODO: Add structured logging 

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
            print(f"Tool {tool.__name__} failed with exit code {code}")
            failed_ci = True
        print("\n\n----------------------------------\n\n")


    print("\n\n========== SCA SUMMARY ==========")
    for tool_name, code in results.items():
        status = "PASSED" if code == 0 else f"FAILED (exit code {code})"
        print(f"{tool_name}: {status}")
    print("==================================\n\n")

    if failed_ci:
        sys.exit(1)

if __name__ == "__main__":
    main()
 