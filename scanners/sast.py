from scanners.runner import run_tool, parse_json_output


def run_semgrep_scan(target_path: str) -> dict:
    # semgrep คืน 0 เมื่อสแกนสำเร็จ (1 เมื่อเจอ finding และเปิด --error)
    result = run_tool(
        ["semgrep", "--config", "auto", "--json", target_path],
        ok_exit_codes=(0, 1),
    )
    return parse_json_output("semgrep", result.stdout)
