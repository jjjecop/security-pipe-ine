from scanners.runner import run_tool, parse_json_output


def run_trivy_container_scan(image_name: str) -> dict:
    result = run_tool(["trivy", "image", "--scanners", "vuln", "--format", "json", image_name])
    return parse_json_output("trivy image", result.stdout)
