import { useState, useEffect } from 'react'
import axios from 'axios'
import { ShieldAlert, AlertTriangle, Info, CheckCircle2, FileText, Download, Activity, BarChart3 } from 'lucide-react'
import { jsPDF } from "jspdf"

const API = import.meta.env.DEV ? 'http://localhost:3000' : ''

const SEVERITY_STYLES = {
  CRITICAL: { icon: ShieldAlert, color: 'text-rose-400', bg: 'bg-rose-500/8', border: 'border-rose-500/20', bar: 'bg-rose-500' },
  HIGH:     { icon: AlertTriangle, color: 'text-orange-400', bg: 'bg-orange-500/8', border: 'border-orange-500/20', bar: 'bg-orange-500' },
  MEDIUM:   { icon: Info, color: 'text-amber-400', bg: 'bg-amber-500/8', border: 'border-amber-500/20', bar: 'bg-amber-400' },
  LOW:      { icon: CheckCircle2, color: 'text-emerald-400', bg: 'bg-emerald-500/8', border: 'border-emerald-500/20', bar: 'bg-emerald-500' },
  UNKNOWN:  { icon: Activity, color: 'text-zinc-400', bg: 'bg-zinc-800/50', border: 'border-zinc-700', bar: 'bg-zinc-500' },
}

export default function ThreatFeed() {
  const [events, setEvents] = useState([])
  const [stats, setStats] = useState(null)
  const [report, setReport] = useState(null)
  const [loading, setLoading] = useState(false)

  const fetchData = async () => {
    try {
      const [eventsRes, statsRes] = await Promise.all([
        axios.get(`${API}/api/events?hours=24`),
        axios.get(`${API}/api/stats`)
      ])
      setEvents(eventsRes.data.events || [])
      setStats(statsRes.data)
    } catch (error) {
      console.error('Failed to fetch feed data', error)
    }
  }

  useEffect(() => {
    fetchData()
    const interval = setInterval(fetchData, 10000)
    return () => clearInterval(interval)
  }, [])

  const generateReport = async () => {
    setLoading(true)
    try {
      const res = await axios.get(`${API}/api/report`)
      setReport(res.data.report)
    } catch (e) {
      console.error('Failed to generate report', e)
    }
    setLoading(false)
  }

  const downloadReport = () => {
    if (!report) return
    const doc = new jsPDF()
    doc.setFont('helvetica', 'normal')
    doc.setFontSize(10)
    const splitText = doc.splitTextToSize(report, 180)
    let y = 15
    for (let i = 0; i < splitText.length; i++) {
      if (y > 280) { doc.addPage(); y = 15 }
      doc.text(splitText[i], 15, y)
      y += 5
    }
    doc.save(`contextguard-report-${new Date().toISOString().slice(0,10)}.pdf`)
  }

  return (
    <div className="space-y-6">
      {/* Stats */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {[
          { label: 'OAuth Apps Monitored', value: stats?.total_apps || 0, color: 'text-blue-400', desc: 'Active integrations' },
          { label: 'Critical / High Threats', value: (stats?.critical_apps || 0) + (stats?.high_risk_apps || 0), color: 'text-rose-400', desc: 'Require attention' },
          { label: 'Events Intercepted (24h)', value: stats?.total_events_24h || 0, color: 'text-emerald-400', desc: 'Last 24 hours' },
        ].map(stat => (
          <div key={stat.label} className="p-5 rounded-xl border border-zinc-800 bg-zinc-900/40 hover:border-zinc-700 transition-colors">
            <div className={`text-3xl font-bold mb-1 ${stat.color}`}>{stat.value}</div>
            <div className="text-sm font-medium text-zinc-300">{stat.label}</div>
            <div className="text-xs text-zinc-600 mt-0.5">{stat.desc}</div>
          </div>
        ))}
      </div>

      {/* Report */}
      <div className="bg-zinc-900/40 border border-zinc-800 rounded-xl p-5">
        <div className="flex items-center justify-between mb-1">
          <div>
            <h3 className="text-sm font-semibold text-zinc-200">Compliance & Audit Report</h3>
            <p className="text-xs text-zinc-500 mt-0.5">Generate a SOC2/HIPAA-ready PDF summary of the last 24 hours</p>
          </div>
          <button
            onClick={generateReport}
            disabled={loading}
            className="flex items-center gap-2 bg-zinc-800 hover:bg-zinc-700 disabled:opacity-50 border border-zinc-700 px-4 py-2 rounded-lg text-xs font-medium transition-colors text-zinc-200"
          >
            {loading ? (
              <><div className="w-3.5 h-3.5 border-2 border-zinc-500 border-t-zinc-200 rounded-full animate-spin" /><span>Analyzing...</span></>
            ) : (
              <><FileText className="w-3.5 h-3.5" /><span>Generate Report</span></>
            )}
          </button>
        </div>

        {report && (
          <div className="mt-4 bg-[#09090b] border border-zinc-800 rounded-lg p-4 relative group">
            <button
              onClick={downloadReport}
              className="absolute top-3 right-3 p-1.5 text-zinc-500 hover:text-zinc-200 bg-zinc-800 hover:bg-zinc-700 rounded-md transition-colors opacity-0 group-hover:opacity-100"
              title="Download report"
            >
              <Download className="w-3.5 h-3.5" />
            </button>
            <div className="flex items-center gap-2 mb-3">
              <div className="w-1.5 h-1.5 rounded-full bg-blue-500" />
              <span className="text-xs font-medium text-zinc-400 uppercase tracking-wider">Gemini Intelligence Summary</span>
            </div>
            <p className="text-zinc-400 text-xs leading-relaxed whitespace-pre-wrap font-mono">{report}</p>
          </div>
        )}
      </div>

      {/* Events */}
      <div>
        <div className="flex items-center gap-2 mb-4">
          <Activity className="w-4 h-4 text-zinc-500" />
          <h2 className="text-sm font-semibold text-zinc-300">Live DPI Interceptions</h2>
          {events.length > 0 && (
            <span className="ml-auto text-xs text-zinc-600">{events.length} events</span>
          )}
        </div>

        {events.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-16 border border-zinc-800 border-dashed rounded-xl">
            <ShieldAlert className="w-8 h-8 text-zinc-700 mb-3" />
            <p className="text-zinc-500 text-sm font-medium">No malicious traffic detected</p>
            <p className="text-xs text-zinc-600 mt-1">DPI is actively monitoring all AI agent traffic</p>
          </div>
        ) : (
          <div className="space-y-2">
            {events.map((event, idx) => {
              const style = SEVERITY_STYLES[event.severity] || SEVERITY_STYLES.UNKNOWN
              const Icon = style.icon
              return (
                <div key={idx} className={`rounded-xl border ${style.border} bg-zinc-900/40 hover:bg-zinc-900/70 transition-colors overflow-hidden`}>
                  <div className={`h-0.5 w-full ${style.bar}`} />
                  <div className="p-4">
                    <div className="flex justify-between items-start mb-2">
                      <div className="flex items-center gap-3">
                        <div className={`p-2 rounded-lg ${style.bg}`}>
                          <Icon className={`w-4 h-4 ${style.color}`} />
                        </div>
                        <div>
                          <h4 className="text-sm font-semibold text-zinc-200">{event.policy_triggered}</h4>
                          <span className="text-xs text-zinc-600">{new Date(event.timestamp).toLocaleString()}</span>
                        </div>
                      </div>
                      <span className={`text-xs font-semibold px-2 py-1 rounded-md ${style.bg} ${style.color} border ${style.border}`}>
                        {event.severity}
                      </span>
                    </div>
                    <div className="mt-3 bg-[#09090b] rounded-lg p-3 border border-zinc-800/80">
                      <p className="text-xs text-zinc-400 leading-relaxed">
                        <span className="text-blue-500 font-medium mr-2">[AI]</span>
                        {event.alert_message}
                      </p>
                    </div>
                  </div>
                </div>
              )
            })}
          </div>
        )}
      </div>
    </div>
  )
}
