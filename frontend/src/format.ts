export function errorMessage(err: unknown): string {
  return err instanceof Error ? err.message : String(err)
}

export function formatDate(value: string | null): string {
  if (value === null) return '-'
  // API เก็บเวลาเป็น UTC แต่ไม่มี Z ต่อท้าย ต้องเติมเองก่อนแปลงเป็นเวลาไทย
  return new Date(value + 'Z').toLocaleString('th-TH')
}