import { useState, useEffect } from 'react'
import axios from 'axios'
import { FileKey, RefreshCw, CheckCircle2, Key, ShieldAlert, Plus, X, Scan, AlertTriangle, Lock } from 'lucide-react'

const API = import.meta.env.DEV ? 'http://localhost:3000' : ''

const CLASS_STYLE = {
  SENSITIVE: 'bg-rose-500/10 text-rose-400 border-rose-500/20',
  MISCLASSIFIED: 'bg-amber-500/10 text-amber-400 border-amber-500/20',
  'NON-SENSITIVE': 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20',
}

export default function EnvGuardian() {
  const [variables, setVariables] = useState([])
  const [alerts, setAlerts] = useState([])
  const [loadingVar, setLoadingVar] = useState(null)
  const [showAddForm, setShowAddForm] = useState(false)
  const [newVarName, setNewVarName] = useState('')
  const [newVarHint, setNewVarHint] = useState('')
  const [classifying, setClassifying] = useState(false)
  const [scanning, setScanning] = useState(false)
  const [scanResult, setScanResult] = useState(null)
  const [expandedVar, setExpandedVar] = useState(null)

  const fetchData = async () => {
    try {
      const [envRes, alertRes] = await Promise.all([
        axios.get(`${API}/api/env`),
        axios.get(`${API}/api/env/alerts?unacknowledged_only=false`)
      ])
      setVariables(envRes.data.variables || [])
      setAlerts(alertRes.data.alerts || [])
    } catch (e) { console.error(e) }
  }

  useEffect(() => {
    fetchData()
    const interval = setInterval(fetchData, 5000)
    return () => clearInterval(interval)
  }, [])

  const rotateKey = async (varName) => {
    setLoadingVar(varName)
    try {
      await axios.post(`${API}/api/env/${varName}/rotate`)
      await fetchData()
    } catch (e) { console.error(e) }
    setLoadingVar(null)
  }

  const classifyVar = async (e) => {
    e.preventDefault()
    if (!newVarName.trim()) return
    setClassifying(true)
    try {
      await axios.post(`${API}/api/env/classify`, { var_name: newVarName.trim(), value_hint: newVarHint.trim() || null })
      setNewVarName('')
      setNewVarHint('')
      setShowAddForm(false)
      await fetchData()
    } catch (e) { console.error(e) }
    setClassifying(false)
  }

  const scanRealEnv = async () => {
    setScanning(true)
    setScanResult(null)
    try {
      const res = await axios.post(`${API}/api/env/scan`)
      setScanResult(res.data)
      await fetchData()
    } catch (e) { console.error(e) }
    setScanning(false)
  }

  const sensitiveCount = variables.filter(v => v.classification === 'SENSITIVE').length
  const misclassifiedCount = variables.filter(v => v.classification === 'MISCLASSIFIED').length

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row justify-between bg-zinc-900/40 p-6 rounded-2xl border border-zinc-800 backdrop-blur-md">
        <div>
          <h2 className="text-2xl font-black text-zinc-200 flex items-center">
            <FileKey className="w-6 h-6 mr-3" /> Environment Guardian
          </h2>
          <p className="text-sm text-zinc-400 mt-1">Classify and monitor all sensitive credentials. Detect AI agents accessing secrets in real-time.</p>
        </div>
        <div className="mt-4 sm:mt-0 flex flex-wrap gap-2 self-start">
          <button onClick={scanRealEnv} disabled={scanning} className="flex items-center space-x-2 bg-zinc-700 hover:bg-zinc-600 disabled:opacity-50 text-white px-4 py-2 rounded-xl text-sm font-bold transition border border-emerald-500">
            {scanning ? <div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin"></div> : <Scan className="w-4 h-4" />}
            <span>{scanning ? 'Scanning...' : 'Scan System Env Vars'}</span>
          </button>
          <button onClick={() => setShowAddForm(v => !v)} className="flex items-center space-x-2 bg-zinc-700 hover:bg-slate-600 border border-zinc-700 text-zinc-200 px-4 py-2 rounded-xl text-sm font-bold transition">
            <Plus className="w-4 h-4" /><span>Classify Variable</span>
          </button>
        </div>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        <div className="p-5 rounded-xl border border-zinc-800 bg-zinc-900/40">
          <p className="text-zinc-400 text-xs font-bold uppercase tracking-wider mb-2">Total Monitored</p>
          <p className="text-3xl font-black text-zinc-200">{variables.length}</p>
        </div>
        <div className="bg-rose-500/5 border border-rose-500/20 rounded-xl p-5">
          <p className="text-rose-400 text-xs font-bold uppercase tracking-wider mb-2">Sensitive Secrets</p>
          <p className="text-3xl font-black text-rose-400">{sensitiveCount}</p>
        </div>
        <div className="bg-amber-500/5 border border-amber-500/20 rounded-xl p-5">
          <p className="text-amber-400 text-xs font-bold uppercase tracking-wider mb-2">Misclassified (Risk)</p>
          <p className="text-3xl font-black text-amber-400">{misclassifiedCount}</p>
        </div>
      </div>

      {/* Scan result banner */}
      {scanResult && (
        <div className="bg-emerald-500/5 border border-emerald-500/30 rounded-xl p-4 flex items-center justify-between animate-in slide-in-from-top-4 fade-in duration-300">
          <div>
            <p className="text-emerald-400 font-bold text-sm">System Scan Complete</p>
            <p className="text-zinc-400 text-xs mt-0.5">Scanned {scanResult.total_scanned} environment variables — found <strong className="text-rose-400">{scanResult.sensitive_found} sensitive</strong> credentials.</p>
          </div>
          <button onClick={() => setScanResult(null)} className="text-zinc-500 hover:text-zinc-300"><X className="w-4 h-4" /></button>
        </div>
      )}

      {/* Add Variable Form */}
      {showAddForm && (
        <div className="bg-zinc-900/40 border border-emerald-500/30 rounded-2xl p-6 animate-in slide-in-from-top-4 fade-in duration-200">
          <div className="flex justify-between items-center mb-4">
            <div>
              <h3 className="font-bold text-emerald-400">Classify an Environment Variable</h3>
              <p className="text-xs text-zinc-500 mt-0.5">Gemini AI will classify it. Value hint is never stored — only used for pattern matching.</p>
            </div>
            <button onClick={() => setShowAddForm(false)} className="text-zinc-400 hover:text-white"><X className="w-4 h-4" /></button>
          </div>
          <form onSubmit={classifyVar} className="flex flex-col sm:flex-row gap-3">
            <input type="text" placeholder="Variable name (e.g. OPENAI_API_KEY)" value={newVarName} onChange={e => setNewVarName(e.target.value)} className="flex-1 bg-[#09090b] border border-zinc-700 rounded-lg px-4 py-2 text-white text-sm outline-none focus:border-emerald-500 font-mono" required />
            <input type="text" placeholder="Value hint — optional (e.g. sk-...)" value={newVarHint} onChange={e => setNewVarHint(e.target.value)} className="flex-1 bg-[#09090b] border border-zinc-700 rounded-lg px-4 py-2 text-white text-sm outline-none focus:border-emerald-500 font-mono" />
            <button type="submit" disabled={classifying || !newVarName.trim()} className="bg-zinc-700 hover:bg-zinc-600 disabled:opacity-50 text-white font-bold px-6 py-2 rounded-lg text-sm transition flex items-center space-x-2">
              {classifying ? <div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin"></div> : <CheckCircle2 className="w-4 h-4" />}
              <span>{classifying ? 'Classifying...' : 'Classify'}</span>
            </button>
          </form>
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Variables List */}
        <div className="lg:col-span-2 space-y-3">
          <h3 className="text-sm font-bold text-zinc-400 uppercase tracking-wider">Monitored Secrets</h3>
          {variables.length === 0 ? (
            <div className="bg-zinc-900/40 border border-zinc-800 border-dashed rounded-2xl p-12 text-center">
              <Key className="w-12 h-12 text-zinc-600 mx-auto mb-3" />
              <p className="text-zinc-400 font-medium">No variables classified yet.</p>
              <p className="text-sm text-zinc-500 mt-1">Click <strong>"Scan System Env Vars"</strong> to auto-discover sensitive credentials in your environment.</p>
            </div>
          ) : variables.map((v) => (
            <div key={v.var_name} className="bg-zinc-900/40 border border-zinc-700 rounded-xl overflow-hidden hover:border-zinc-700 transition-all">
              <div className="flex items-center justify-between p-4 cursor-pointer" onClick={() => setExpandedVar(expandedVar === v.var_name ? null : v.var_name)}>
                <div className="flex items-center space-x-4">
                  <div className={`p-2.5 rounded-xl border ${CLASS_STYLE[v.classification] || 'bg-zinc-700'}`}>
                    <Key className="w-4 h-4" />
                  </div>
                  <div>
                    <h4 className="font-bold text-zinc-200 font-mono text-sm">{v.var_name}</h4>
                    <div className="flex items-center space-x-3 mt-1">
                      <span className={`text-[10px] font-black px-2 py-0.5 rounded border uppercase ${CLASS_STYLE[v.classification] || 'bg-zinc-700 text-zinc-400'}`}>{v.classification}</span>
                      {v.rotation_status?.days != null ? (
                        <span className={`text-xs ${v.rotation_status.status === 'overdue' ? 'text-rose-400 font-bold' : 'text-zinc-500'}`}>
                          {v.rotation_status.status === 'overdue' ? 'OVERDUE: ' : ''}{v.rotation_status.display}
                        </span>
                      ) : (
                        <span className="text-xs text-zinc-600">Never rotated</span>
                      )}
                    </div>
                  </div>
                </div>
                <div className="flex items-center space-x-2">
                  <button onClick={e => { e.stopPropagation(); rotateKey(v.var_name) }} disabled={loadingVar === v.var_name} className="flex items-center px-3 py-1.5 bg-zinc-800 hover:bg-zinc-700 text-zinc-300 text-xs font-bold rounded-lg transition border border-zinc-700 disabled:opacity-50">
                    <RefreshCw className={`w-3.5 h-3.5 mr-1.5 ${loadingVar === v.var_name ? 'animate-spin' : ''}`} />
                    {loadingVar === v.var_name ? 'Saving...' : 'Mark Rotated'}
                  </button>
                </div>
              </div>

              {expandedVar === v.var_name && (
                <div className="border-t border-slate-800 bg-zinc-950/60 p-4 animate-in slide-in-from-top-2 fade-in duration-150">
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 text-xs">
                    <div>
                      <p className="text-zinc-500 uppercase font-bold tracking-wider mb-1">Classification</p>
                      <p className={`font-bold ${CLASS_STYLE[v.classification]?.split(' ')[1] || 'text-zinc-300'}`}>{v.classification}</p>
                    </div>
                    <div>
                      <p className="text-zinc-500 uppercase font-bold tracking-wider mb-1">Last Accessed</p>
                      <p className="text-zinc-300">{v.last_accessed ? new Date(v.last_accessed).toLocaleString() : 'Never'}</p>
                    </div>
                    <div>
                      <p className="text-zinc-500 uppercase font-bold tracking-wider mb-1">Value Hash (SHA-256)</p>
                      <p className="text-zinc-400 font-mono truncate">{v.value_hash || '—'}</p>
                    </div>
                    <div>
                      <p className="text-zinc-500 uppercase font-bold tracking-wider mb-1">Rotation Status</p>
                      <p className={v.rotation_status?.status === 'overdue' ? 'text-rose-400 font-bold' : 'text-zinc-300'}>{v.rotation_status?.display || 'Unknown'}</p>
                    </div>
                    {v.gemini_explanation && (
                      <div className="sm:col-span-2">
                        <p className="text-zinc-500 uppercase font-bold tracking-wider mb-1">Gemini Explanation</p>
                        <p className="text-zinc-300 leading-relaxed">{v.gemini_explanation}</p>
                      </div>
                    )}
                  </div>
                </div>
              )}
            </div>
          ))}
        </div>

        {/* Alerts Sidebar */}
        <div className="space-y-3">
          <h3 className="text-sm font-bold text-zinc-400 uppercase tracking-wider">Live Access Alerts</h3>
          <div className="bg-zinc-900/40 border border-zinc-800 rounded-2xl p-4 max-h-[600px] overflow-y-auto">
            {alerts.length === 0 ? (
              <div className="text-center text-zinc-500 py-10">
                <Lock className="w-8 h-8 mx-auto mb-2 opacity-40" />
                <p className="text-sm font-medium">No alerts.</p>
                <p className="text-xs mt-1 text-zinc-600">Alerts appear when an AI agent accesses sensitive variables via Lobster Trap.</p>
              </div>
            ) : alerts.map((alert, i) => (
              <div key={i} className="mb-4 pb-4 border-b border-slate-800 last:border-0 last:mb-0 last:pb-0">
                <div className={`flex items-center mb-2 ${alert.severity === 'CRITICAL' ? 'text-rose-400' : 'text-amber-400'}`}>
                  {alert.severity === 'CRITICAL' ? <ShieldAlert className="w-3.5 h-3.5 mr-2" /> : <AlertTriangle className="w-3.5 h-3.5 mr-2" />}
                  <span className="text-xs font-black uppercase">{alert.severity} ALERT</span>
                </div>
                <p className="text-sm text-zinc-300 font-medium leading-snug">{alert.message}</p>
                <div className="flex justify-between mt-2 text-xs text-zinc-500">
                  <span className="font-mono bg-zinc-800 px-1.5 py-0.5 rounded">{alert.var_name}</span>
                  <span>{new Date(alert.created_at).toLocaleTimeString()}</span>
                </div>
              </div>
            ))}
          </div>

          {/* How it works */}
          <div className="bg-zinc-900/20 border border-zinc-800 rounded-xl p-4">
            <h4 className="text-xs font-bold text-zinc-400 uppercase tracking-wider mb-3">How It Works</h4>
            <div className="space-y-2">
              {[
                { step: '1', text: 'Scan your system env vars to find secrets' },
                { step: '2', text: 'Gemini AI classifies each as SENSITIVE or SAFE' },
                { step: '3', text: 'Lobster Trap fires alert if any AI agent accesses them' },
                { step: '4', text: 'Mark rotated after you update the credential' },
              ].map(item => (
                <div key={item.step} className="flex items-start space-x-2">
                  <span className="w-5 h-5 rounded-full bg-emerald-600/30 text-emerald-400 text-[10px] font-black flex items-center justify-center flex-shrink-0 mt-0.5">{item.step}</span>
                  <p className="text-xs text-zinc-400">{item.text}</p>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}
