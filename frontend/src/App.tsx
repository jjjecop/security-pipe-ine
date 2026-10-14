import { useEffect, useState } from 'react'

type Health = {
  status: string
  database: string
}

function App() {
  const [health, setHealth] = useState<Health | null>(null)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    fetch('/api/health')
      .then((response) => {
        if (!response.ok) throw new Error(`HTTP ${response.status}`)
        return response.json()
      })
      .then(setHealth)
      .catch((err) => setError(String(err)))
  }, [])

  return (
    <main style={{ fontFamily: 'sans-serif', padding: 32 }}>
      <h1>VulnCompass</h1>
      {error && <p style={{ color: 'crimson' }}>ต่อ API ไม่ได้: {error}</p>}
      {!health && !error && <p>กำลังเช็กการเชื่อมต่อ...</p>}
      {health && <p>API: {health.status} · Database: {health.database}</p>}
    </main>
  )
}

export default App