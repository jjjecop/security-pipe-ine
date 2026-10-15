export const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'] as const
export type Severity = (typeof SEVERITIES)[number]

export const SEVERITY_LABELS: Record<Severity, string> = {
  critical: 'วิกฤต',
  high: 'สูง',
  medium: 'ปานกลาง',
  low: 'ต่ำ',
  info: 'ข้อมูล',
}

export type Project = {
  id: number
  name: string
  repo_url: string | null
  target_url: string | null
  open_findings: number
}

export type LastScan = {
  id: number
  status: string
  triggered_by: string
  created_at: string | null
}

export type Summary = {
  project: string
  open_total: number
  by_severity: Record<Severity, number>
  by_tool: Record<string, number>
  last_scan: LastScan | null
}

export type FindingLocation =
  | { type: 'code'; code: { file_path: string; line_start: number | null } }
  | {
      type: 'dependency'
      dependency: { package_name: string; installed_version: string; fixed_version: string | null }
    }
  | {
      type: 'container_image'
      container_image: {
        image_ref: string
        os_package: string
        installed_version: string
        fixed_version: string | null
      }
    }
  | { type: 'http_endpoint'; http_endpoint: { method: string; url: string; parameter: string | null } }

export type Finding = {
  id: number
  title: string
  tool: string
  rule_id: string | null
  severity: Severity
  risk_score: number | null
  epss_score: number | null
  cwe_id: string | null
  location: FindingLocation
}

export type FindingPage = {
  total: number
  limit: number
  offset: number
  items: Finding[]
}

export type ScanJobSummary = {
  id: number
  status: string
  triggered_by: string
  requested_scans: string[]
  created_at: string | null
  has_report: boolean
}