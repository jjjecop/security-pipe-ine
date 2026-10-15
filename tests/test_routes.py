from main import app, get_scan_job, list_findings, list_scan_jobs, project_summary

# กันบั๊ก decorator หลุดไปติดฟังก์ชันอื่นตอนวางโค้ด: URL ต้องชี้ไปที่ฟังก์ชันของมันเอง
EXPECTED_GET_ROUTES = {
    "/projects/{project_name}/findings": list_findings,
    "/projects/{project_name}/summary": project_summary,
    "/projects/{project_name}/scan-jobs": list_scan_jobs,
    "/scan-jobs/{job_id}": get_scan_job,
}


def test_each_get_route_points_to_its_own_function():
    routes = {r.path: r.endpoint for r in app.routes if "GET" in getattr(r, "methods", set())}
    for path, endpoint in EXPECTED_GET_ROUTES.items():
        assert routes[path] is endpoint, path
