import { useEffect, useState } from 'react'
import { apiFetch } from './api'
import ToolChart from './ToolChart'
import { SEVERITIES } from './types'
import type { Project, Severity, Summary } from './types'

const SEVERITY_LABELS: Record<Severity, string> = {
  critical: 'วิกฤต',
  high: 'สูง',
  medium: 'ปานกลาง',
  low: 'ต่ำ',
  info: 'ข้อมูล',
}

function errorMessage(err: unknown): string {
  return err instanceof Error ? err.message : String(err)
}

function formatDate(value: string | null): string {
  if (value === null) return '-'
  // API เก็บเวลาเป็น UTC แต่ไม่มี Z ต่อท้าย ต้องเติมเองก่อนแปลงเป็นเวลาไทย
  return new Date(value + 'Z').toLocaleString('th-TH')
}

function Dashboard() {
  const [projects, setProjects] = useState<Project[] | null>(null)
  const [selected, setSelected] = useState<string | null>(null)
  const [summary, setSummary] = useState<Summary | null>(null)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    apiFetch<Project[]>('/projects')
      .then((list) => {
        setProjects(list)
        if (list.length > 0) setSelected(list[0].name)
      })
      .catch((err) => setError(errorMessage(err)))
  }, [])

  useEffect(() => {
    if (selected === null) return
    // ถ้าสลับโปรเจกต์เร็ว ๆ คำตอบเก่าอาจมาถึงทีหลัง ต้องทิ้งคำตอบนั้น
    let ignore = false
    apiFetch<Summary>(`/projects/${encodeURIComponent(selected)}/summary`)
      .then((data) => {
        if (!ignore) setSummary(data)
      })
      .catch((err) => {
        if (!ignore) setError(errorMessage(err))
      })
    return () => {
      ignore = true
    }
  }, [selected])

  if (error) return <p className="error">โหลดข้อมูลไม่ได้: {error}</p>
  if (projects === null) return <p className="muted">กำลังโหลดโปรเจกต์...</p>
  if (projects.length === 0) return <p className="muted">ยังไม่มีโปรเจกต์ ให้รันสแกนก่อน</p>

  return (
    <>
      <div className="toolbar">
        <h2>Dashboard</h2>
        <label>
          โปรเจกต์
          <select value={selected ?? ''} onChange={(e) => setSelected(e.target.value)}>
            {projects.map((p) => (
              <option key={p.id} value={p.name}>
                {p.name} ({p.open_findings})
              </option>
            ))}
          </select>
        </label>
      </div>

      {summary === null || summary.project !== selected ? (
        <p className="muted">กำลังโหลดสรุป...</p>
      ) : (
        <>
          <div className="cards">
            {SEVERITIES.map((severity) => (
              <div key={severity} className={`card severity-${severity}`}>
                <span className="card-label">{SEVERITY_LABELS[severity]}</span>
                <span className="card-value">{summary.by_severity[severity]}</span>
              </div>
            ))}
          </div>
          <p className="muted">
            ช่องโหว่ที่ยังเปิดอยู่ {summary.open_total} รายการ ·{' '}
            {summary.last_scan
              ? `สแกนล่าสุด #${summary.last_scan.id} (${summary.last_scan.status}) โดย ${summary.last_scan.triggered_by} เมื่อ ${formatDate(summary.last_scan.created_at)}`
              : 'ยังไม่เคยสแกน'}
          </p>
          <ToolChart byTool={summary.by_tool} />
        </>
      )}
    </>
  )
}

export default Dashboard