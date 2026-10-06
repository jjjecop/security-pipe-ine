from scanners.runner import run_tool, parse_json_output


def run_trivy_dependency_scan(target_path: str) -> dict:
    result = run_tool(["trivy", "fs", "--scanners", "vuln", "--format", "json", target_path])
    return parse_json_output("trivy fs", result.stdout)
