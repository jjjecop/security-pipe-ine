export const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'] as const
export type Severity = (typeof SEVERITIES)[number]

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