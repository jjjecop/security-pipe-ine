import { useEffect, useState } from 'react'
import { NavLink, Route, Routes } from 'react-router'
import { ApiError, apiFetch } from './api'
import Dashboard from './Dashboard'
import LoginPage from './LoginPage'
import ScansPage from './ScansPage'
import './App.css'

function App() {
  // undefined = กำลังเช็ก, null = ยังไม่ login, string = login แล้ว
  const [username, setUsername] = useState<string | null | undefined>(undefined)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    apiFetch<{ username: string }>('/auth/me')
      .then((user) => setUsername(user.username))
      .catch((err) => {
        if (err instanceof ApiError && err.status === 401) setUsername(null)
        else setError(err instanceof Error ? err.message : String(err))
      })
  }, [])

  async function handleLogout() {
    await apiFetch('/auth/logout', { method: 'POST' })
    setUsername(null)
  }

  if (error) return <p className="error page-message">ต่อ API ไม่ได้: {error}</p>
  if (username === undefined) return <p className="muted page-message">กำลังโหลด...</p>
  if (username === null) return <LoginPage onLogin={setUsername} />

  return (
    <div className="app">
      <header className="topbar">
        <span className="brand">VulnCompass</span>
        <nav className="nav">
          <NavLink to="/" end>
            Dashboard
          </NavLink>
          <NavLink to="/scans">การสแกน</NavLink>
        </nav>
        <span className="muted">{username}</span>
        <button className="secondary" onClick={handleLogout}>
          ออกจากระบบ
        </button>
      </header>
      <main className="content">
        <Routes>
          <Route path="/" element={<Dashboard />} />
          <Route path="/scans" element={<ScansPage />} />
          <Route path="*" element={<p className="muted">ไม่พบหน้านี้</p>} />
        </Routes>
      </main>
    </div>
  )
}

export default App