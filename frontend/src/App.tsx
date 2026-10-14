import { useEffect, useState } from 'react'
import { ApiError, apiFetch } from './api'
import LoginPage from './LoginPage'
import Dashboard from './Dashboard'
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
        <span className="muted">{username}</span>
        <button className="secondary" onClick={handleLogout}>
          ออกจากระบบ
        </button>
      </header>
      <main className="content">
         <Dashboard />
        
      </main>
    </div>
  )
}

export default App
