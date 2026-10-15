import { Bar, BarChart, CartesianGrid, LabelList, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'

type Props = {
  byTool: Record<string, number>
}

function ToolChart({ byTool }: Props) {
  // แปลง {"semgrep": 35, ...} เป็น [{tool: "semgrep", count: 35}, ...] แล้วเรียงจากมากไปน้อย
  const data = Object.entries(byTool)
    .map(([tool, count]) => ({ tool, count }))
    .sort((a, b) => b.count - a.count)

  if (data.length === 0) return null

  return (
    <section className="panel">
      <h3>ช่องโหว่ที่เปิดอยู่ แยกตามเครื่องมือ</h3>
      <ResponsiveContainer width="100%" height={data.length * 48 + 40}>
        <BarChart data={data} layout="vertical" margin={{ top: 0, right: 48, bottom: 0, left: 8 }}>
          <CartesianGrid horizontal={false} stroke="#e5e7eb" />
          <XAxis
            type="number"
            allowDecimals={false}
            axisLine={false}
            tickLine={false}
            tick={{ fill: '#6b7280', fontSize: 12 }}
          />
          <YAxis
            type="category"
            dataKey="tool"
            width={130}
            axisLine={false}
            tickLine={false}
            tick={{ fill: '#374151', fontSize: 13 }}
          />
          <Tooltip cursor={{ fill: '#f3f4f6' }} formatter={(value) => [`${value} รายการ`, 'จำนวน']} />
          <Bar dataKey="count" fill="#1d4ed8" radius={[0, 4, 4, 0]} barSize={24}>
            <LabelList dataKey="count" position="right" fill="#374151" fontSize={13} />
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </section>
  )
}

export default ToolChart