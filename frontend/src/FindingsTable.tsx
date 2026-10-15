import { useEffect, useState } from 'react'
import { apiFetch } from './api'
import { SEVERITIES, SEVERITY_LABELS } from './types'
import type { FindingLocation, FindingPage } from './types'

const PAGE_SIZE = 20

type Props = {
  project: string
  tools: string[]
}

function describeLocation(location: FindingLocation): string {
  switch (location.type) {
    case 'code': {
      const c = location.code
      return c.line_start ? `${c.file_path}:${c.line_start}` : c.file_path
    }
    case 'dependency': {
      const d = location.dependency
      return `${d.package_name} ${d.installed_version}${d.fixed_version ? ` → ${d.fixed_version}` : ''}`
    }
    case 'container_image': {
      const c = location.container_image
      return `${c.os_package} ${c.installed_version}${c.fixed_version ? ` → ${c.fixed_version}` : ''} (${c.image_ref})`
    }
    case 'http_endpoint': {
      const h = location.http_endpoint
      return `${h.method} ${h.url}${h.parameter ? ` [${h.parameter}]` : ''}`
    }
    default:
      return ''
  }
}

function FindingsTable({ project, tools }: Props) {
  const [search, setSearch] = useState('')
  const [q, setQ] = useState('')
  const [severity, setSeverity] = useState('')
  const [tool, setTool] = useState('')
  const [page, setPage] = useState(0)
  const [result, setResult] = useState<{ key: string; data: FindingPage } | null>(null)
  const [error, setError] = useState<string | null>(null)

  // debounce: รอให้หยุดพิมพ์ 300ms ก่อนค่อยค้นหา ไม่ยิง API ทุกครั้งที่กดแป้น
  useEffect(() => {
    const timer = setTimeout(() => {
      setQ(search.trim())
      setPage(0)
    }, 300)
    return () => clearTimeout(timer)
  }, [search])

  const params = new URLSearchParams({ limit: String(PAGE_SIZE), offset: String(page * PAGE_SIZE) })
  if (q) params.set('q', q)
  if (severity) params.set('severity', severity)
  if (tool) params.set('tool', tool)
  const requestKey = `/projects/${encodeURIComponent(project)}/findings?${params}`

  useEffect(() => {
    let ignore = false
    apiFetch<FindingPage>(requestKey)
      .then((data) => {
        if (ignore) return
        setResult({ key: requestKey, data })
        setError(null)
      })
      .catch((err) => {
        if (!ignore) setError(err instanceof Error ? err.message : String(err))
      })
    return () => {
      ignore = true
    }
  }, [requestKey])

  const data = result?.data
  const loading = result?.key !== requestKey
  const totalPages = data ? Math.max(1, Math.ceil(data.total / PAGE_SIZE)) : 1

  return (
    <section className="panel">
      <h3>รายการช่องโหว่</h3>
      <div className="filters">
        <input
          type="search"
          placeholder="ค้นหาชื่อ, CVE, CWE, ไฟล์ หรือ URL"
          aria-label="ค้นหา"
          maxLength={100}
          value={search}
          onChange={(e) => setSearch(e.target.value)}
        />
        <select
          aria-label="ความรุนแรง"
          value={severity}
          onChange={(e) => {
            setSeverity(e.target.value)
            setPage(0)
          }}
        >
          <option value="">ทุกความรุนแรง</option>
          {SEVERITIES.map((s) => (
            <option key={s} value={s}>
              {SEVERITY_LABELS[s]}
            </option>
          ))}
        </select>
        <select
          aria-label="เครื่องมือ"
          value={tool}
          onChange={(e) => {
            setTool(e.target.value)
            setPage(0)
          }}
        >
          <option value="">ทุกเครื่องมือ</option>
          {tools.map((t) => (
            <option key={t} value={t}>
              {t}
            </option>
          ))}
        </select>
      </div>

      {error && <p className="error">โหลดรายการไม่ได้: {error}</p>}
      {!data && !error && <p className="muted">กำลังโหลด...</p>}

      {data && (
        <>
          <div className={loading ? 'table-wrap loading' : 'table-wrap'}>
            <table className="findings">
              <thead>
                <tr>
                  <th className="num">risk</th>
                  <th className="num">EPSS</th>
                  <th>ความรุนแรง</th>
                  <th>ช่องโหว่</th>
                  <th>เครื่องมือ</th>
                  <th>CWE</th>
                </tr>
              </thead>
              <tbody>
                {data.items.map((f) => (
                  <tr key={f.id}>
                    <td className="num">{f.risk_score === null ? '-' : f.risk_score.toFixed(1)}</td>
                    <td className="num">{f.epss_score === null ? '-' : `${(f.epss_score * 100).toFixed(1)}%`}</td>
                    <td>
                      <span className={`badge severity-${f.severity}`}>{SEVERITY_LABELS[f.severity]}</span>
                    </td>
                    <td>
                      <div>{f.title}</div>
                      <div className="muted location">{describeLocation(f.location)}</div>
                    </td>
                    <td>{f.tool}</td>
                    <td>{f.cwe_id ?? '-'}</td>
                  </tr>
                ))}
                {data.items.length === 0 && (
                  <tr>
                    <td colSpan={6} className="muted">
                      ไม่พบช่องโหว่ที่ตรงกับเงื่อนไข
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>

          <div className="pager">
            <span className="muted">ทั้งหมด {data.total} รายการ</span>
            <button className="secondary" disabled={page === 0} onClick={() => setPage(page - 1)}>
              ◀
            </button>
            <span>
              หน้า {page + 1} / {totalPages}
            </span>
            <button className="secondary" disabled={page + 1 >= totalPages} onClick={() => setPage(page + 1)}>
              ▶
            </button>
          </div>
        </>
      )}
    </section>
  )
}

export default FindingsTable