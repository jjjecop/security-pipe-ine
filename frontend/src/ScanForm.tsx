import { useEffect, useState } from 'react'
import type { FormEvent } from 'react'
import { apiFetch } from './api'
import { errorMessage } from './format'
import { SCAN_TYPES, STATUS_LABELS } from './types'
import type { Project, ScanJobDetail, ScanType } from './types'

const SCAN_LABELS: Record<ScanType, string> = {
  sast: 'SAST (Semgrep) อ่านซอร์สโค้ด',
  dependency: 'Dependency (Trivy) ไลบรารีที่ใช้',
  container: 'Container (Trivy) Docker image',
  dast: 'DAST (ZAP) ทดสอบเว็บที่รันอยู่',
}

const FINISHED = ['completed', 'partial', 'failed']
const POLL_MS = 2000

type Props = {
  project: Project
  onFinished: () => void
}

function ScanForm({ project, onFinished }: Props) {
  const [scans, setScans] = useState<Record<ScanType, boolean>>({
    sast: true,
    dependency: true,
    container: false,
    dast: false,
  })
  const [repoPath, setRepoPath] = useState(project.repo_url ?? '')
  const [image, setImage] = useState('')
  const [targetUrl, setTargetUrl] = useState(project.target_url ?? '')
  const [jobId, setJobId] = useState<number | null>(null)
  const [job, setJob] = useState<ScanJobDetail | null>(null)
  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const needsRepo = scans.sast || scans.dependency
  // ถ้า polling error ให้ปลดล็อกฟอร์ม ไม่อย่างนั้นจะกดสแกนใหม่ไม่ได้อีกเลย
  const running = jobId !== null && error === null && (job === null || !FINISHED.includes(job.status))

  // polling: ถามสถานะทุก 2 วินาทีจนกว่างานจะจบ
  useEffect(() => {
    if (jobId === null) return
    let ignore = false
    let timer: number | undefined

    async function poll() {
      try {
        const data = await apiFetch<ScanJobDetail>(`/scan-jobs/${jobId}`)
        if (ignore) return
        setJob(data)
        if (FINISHED.includes(data.status)) {
          onFinished()
          return
        }
      } catch (err) {
        if (!ignore) setError(errorMessage(err))
        return
      }
      // ใช้ setTimeout ต่อกันแทน setInterval: รอบใหม่เริ่มหลังรอบเก่าได้คำตอบแล้วเท่านั้น
      timer = window.setTimeout(poll, POLL_MS)
    }

    poll()
    return () => {
      ignore = true
      window.clearTimeout(timer)
    }
  }, [jobId, onFinished])

  async function handleSubmit(event: FormEvent) {
    event.preventDefault()
    setSubmitting(true)
    setError(null)
    // ล้างงานเก่าออกก่อน ถ้าส่งไม่ผ่านจะได้ไม่เหลือ "งาน #เก่า: กำลังตรวจสถานะ..." ค้างบนจอ
    setJobId(null)
    setJob(null)
    try {
      const chosen = SCAN_TYPES.filter((type) => scans[type])
      const result = await apiFetch<{ scan_job_id: number }>('/scans', {
        method: 'POST',
        body: JSON.stringify({
          project: project.name,
          scans: chosen,
          repo_path: needsRepo ? repoPath : null,
          image: scans.container ? image : null,
          target_url: scans.dast ? targetUrl : null,
        }),
      })
      setJobId(result.scan_job_id)
    } catch (err) {
      setError(errorMessage(err))
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <section className="panel">
      <h3>สั่งสแกน {project.name}</h3>
      <form className="scan-form" onSubmit={handleSubmit}>
        <fieldset disabled={running || submitting}>
          <div className="scan-types">
            {SCAN_TYPES.map((type) => (
              <label key={type}>
                <input
                  type="checkbox"
                  checked={scans[type]}
                  onChange={(e) => setScans({ ...scans, [type]: e.target.checked })}
                />
                {SCAN_LABELS[type]}
              </label>
            ))}
          </div>

          {needsRepo && (
            <label>
              โฟลเดอร์ซอร์สโค้ด
              <input value={repoPath} onChange={(e) => setRepoPath(e.target.value)} required />
            </label>
          )}
          {scans.container && (
            <label>
              Docker image
              <input value={image} onChange={(e) => setImage(e.target.value)} placeholder="nodegoat:latest" required />
            </label>
          )}
          {scans.dast && (
            <label>
              URL ของเว็บ
              <input type="url" value={targetUrl} onChange={(e) => setTargetUrl(e.target.value)} required />
            </label>
          )}

          <button type="submit" disabled={SCAN_TYPES.every((type) => !scans[type])}>
            {submitting ? 'กำลังส่ง...' : running ? 'กำลังสแกน...' : 'เริ่มสแกน'}
          </button>
        </fieldset>
      </form>

      {error && (
        <p className="error" role="alert">
          {error}
        </p>
      )}

      {jobId !== null && (
        <div className="scan-progress" aria-live="polite">
          <p>
            งาน #{jobId}:{' '}
            {job ? (
              <span className={`badge status-${job.status}`}>{STATUS_LABELS[job.status] ?? job.status}</span>
            ) : (
              'กำลังตรวจสถานะ...'
            )}
          </p>
          {job?.status === 'queued' && (
            <p className="muted">ถ้าค้างที่ "รอคิว" นาน ให้เช็กว่ารัน python worker.py อยู่หรือไม่</p>
          )}
          {job && job.runs.length > 0 && (
            <ul>
              {job.runs.map((run) => (
                <li key={run.tool}>
                  {run.tool}{' '}
                  <span className={`badge status-${run.status}`}>{STATUS_LABELS[run.status] ?? run.status}</span>
                  {run.error_message && <span className="error"> {run.error_message}</span>}
                </li>
              ))}
            </ul>
          )}
        </div>
      )}
    </section>
  )
}

export default ScanForm
