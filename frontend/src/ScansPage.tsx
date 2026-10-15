import { useEffect, useState } from 'react'
import { apiFetch } from './api'
import { errorMessage, formatDate } from './format'
import type { Project, ScanJobSummary } from './types'

// มีทั้งไอคอนและคำ ไม่ใช้สีอย่างเดียวในการบอกสถานะ
const STATUS_LABELS: Record<string, string> = {
  queued: '⏳ รอคิว',
  running: '⟳ กำลังสแกน',
  completed: '✓ เสร็จ',
  partial: '⚠ เสร็จบางส่วน',
  failed: '✕ ล้มเหลว',
}

function ScansPage() {
  const [projects, setProjects] = useState<Project[] | null>(null)
  const [selected, setSelected] = useState<string | null>(null)
  const [jobs, setJobs] = useState<{ project: string; items: ScanJobSummary[] } | null>(null)
  const [refreshCount, setRefreshCount] = useState(0)
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
    let ignore = false
    apiFetch<ScanJobSummary[]>(`/projects/${encodeURIComponent(selected)}/scan-jobs`)
      .then((items) => {
        if (!ignore) setJobs({ project: selected, items })
      })
      .catch((err) => {
        if (!ignore) setError(errorMessage(err))
      })
    return () => {
      ignore = true
    }
  }, [selected, refreshCount])

  if (error) return <p className="error">โหลดข้อมูลไม่ได้: {error}</p>
  if (projects === null) return <p className="muted">กำลังโหลดโปรเจกต์...</p>
  if (projects.length === 0) return <p className="muted">ยังไม่มีโปรเจกต์</p>

  return (
    <>
      <div className="toolbar">
        <h2>การสแกน</h2>
        <label>
          โปรเจกต์
          <select value={selected ?? ''} onChange={(e) => setSelected(e.target.value)}>
            {projects.map((p) => (
              <option key={p.id} value={p.name}>
                {p.name}
              </option>
            ))}
          </select>
        </label>
        <button className="secondary" onClick={() => setRefreshCount(refreshCount + 1)}>
          รีเฟรช
        </button>
      </div>

      <section className="panel">
        <h3>ประวัติการสแกน</h3>
        {jobs === null || jobs.project !== selected ? (
          <p className="muted">กำลังโหลด...</p>
        ) : jobs.items.length === 0 ? (
          <p className="muted">โปรเจกต์นี้ยังไม่เคยสแกน</p>
        ) : (
          <div className="table-wrap">
            <table className="findings">
              <thead>
                <tr>
                  <th className="num">#</th>
                  <th>สถานะ</th>
                  <th>การสแกน</th>
                  <th>สั่งโดย</th>
                  <th>เวลา</th>
                  <th>report</th>
                </tr>
              </thead>
              <tbody>
                {jobs.items.map((job) => (
                  <tr key={job.id}>
                    <td className="num">{job.id}</td>
                    <td>
                      <span className={`badge status-${job.status}`}>{STATUS_LABELS[job.status] ?? job.status}</span>
                    </td>
                    <td>{job.requested_scans.join(', ')}</td>
                    <td>{job.triggered_by}</td>
                    <td>{formatDate(job.created_at)}</td>
                    <td>{job.has_report ? 'มี' : '-'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </>
  )
}

export default ScansPage