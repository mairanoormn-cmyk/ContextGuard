import { useState, useEffect } from 'react'
import axios from 'axios'
import { ShieldAlert, AlertOctagon, CheckCircle2, ChevronRight, Key } from 'lucide-react'

const API = import.meta.env.DEV ? 'http://localhost:3000' : ''

export default function IncidentResponse() {
  const [incidents, setIncidents] = useState([])
  const [selectedInc, setSelectedInc] = useState(null)
  const [actionLoading, setActionLoading] = useState(false)

  const fetchIncidents = async () => {
    try {
      const res = await axios.get(`${API}/api/incidents`)
      setIncidents(res.data.incidents || [])
    } catch (e) { console.error(e) }
  }

  useEffect(() => {
    fetchIncidents()
    const int = setInterval(fetchIncidents, 10000)
    return () => clearInterval(int)
  }, [])

  const advanceStep = async (incId, stepId) => {
    setActionLoading(true)
    try {
      await axios.post(`${API}/api/incidents/${incId}/advance`, { step_id: stepId })
      await fetchIncidents()
      if (selectedInc?.id === incId) {
        const updated = await axios.get(`${API}/api/incidents/${incId}`)
        setSelectedInc(updated.data)
      }
    } catch (e) { console.error(e) }
    setActionLoading(false)
  }

  const rotateCredentials = async (incId) => {
    setActionLoading(true)
    try {
      await axios.post(`${API}/api/incidents/${incId}/rotate`)
      await fetchIncidents()
      if (selectedInc?.id === incId) {
        const updated = await axios.get(`${API}/api/incidents/${incId}`)
        setSelectedInc(updated.data)
      }
    } catch (e) { console.error(e) }
    setActionLoading(false)
  }

  return (
    <div className="flex h-[calc(100vh-8rem)] gap-4">
      {/* Incident List */}
      <div className="w-72 flex-shrink-0 border border-zinc-800 rounded-xl flex flex-col overflow-hidden bg-zinc-900/40">
        <div className="px-4 py-3 border-b border-zinc-800">
          <h2 className="text-sm font-semibold text-zinc-200 flex items-center gap-2">
            <AlertOctagon className="w-4 h-4 text-rose-400" />
            Active Incidents
          </h2>
        </div>
        <div className="flex-1 overflow-y-auto p-2 space-y-1">
          {incidents.length === 0 ? (
            <p className="text-center text-zinc-600 mt-10 text-xs">No incidents reported.</p>
          ) : incidents.map(inc => (
            <button
              key={inc.id}
              onClick={() => setSelectedInc(inc)}
              className={`w-full text-left p-3 rounded-lg border transition-colors ${
                selectedInc?.id === inc.id
                  ? 'bg-zinc-800 border-zinc-700 text-zinc-100'
                  : 'bg-transparent border-transparent text-zinc-400 hover:border-zinc-800 hover:bg-zinc-900/60 hover:text-zinc-300'
              }`}
            >
              <div className="flex justify-between items-center mb-1.5">
                <span className={`text-[10px] font-semibold px-1.5 py-0.5 rounded uppercase ${
                  inc.severity === 'CRITICAL' ? 'bg-rose-500/15 text-rose-400' : 'bg-orange-500/15 text-orange-400'
                }`}>{inc.severity}</span>
                <span className={`text-[10px] font-semibold px-1.5 py-0.5 rounded uppercase ${
                  inc.status === 'resolved' ? 'bg-emerald-500/15 text-emerald-400' : 'bg-zinc-800 text-zinc-500'
                }`}>{inc.status}</span>
              </div>
              <h4 className="font-medium text-xs line-clamp-2 leading-relaxed">{inc.title}</h4>
              <p className="text-[10px] text-zinc-600 mt-1.5">{new Date(inc.created_at).toLocaleString()}</p>
            </button>
          ))}
        </div>
      </div>

      {/* Details */}
      <div className="flex-1 border border-zinc-800 rounded-xl overflow-y-auto bg-zinc-900/40 p-6">
        {selectedInc ? (
          <div>
            <div className="flex justify-between items-start border-b border-zinc-800 pb-5 mb-6">
              <div>
                <h2 className="text-lg font-bold text-zinc-100">{selectedInc.title}</h2>
                <div className="flex gap-4 mt-2 text-xs text-zinc-500">
                  <span>INC-{selectedInc.id.toString().padStart(4, '0')}</span>
                  <span>Event: {selectedInc.event_id}</span>
                </div>
              </div>
              {selectedInc.status === 'resolved' && (
                <div className="bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 px-3 py-1.5 rounded-lg flex items-center gap-1.5 text-xs font-semibold">
                  <CheckCircle2 className="w-3.5 h-3.5" /> Resolved
                </div>
              )}
            </div>

            <div className="mb-6">
              <h3 className="text-xs font-semibold text-zinc-500 uppercase tracking-widest mb-3">AI Event Summary</h3>
              <div className="bg-[#09090b] p-4 rounded-lg border border-zinc-800 text-xs text-zinc-400 leading-relaxed font-mono">
                {JSON.stringify(selectedInc.event_summary, null, 2)}
              </div>
            </div>

            <div>
              <h3 className="text-xs font-semibold text-zinc-500 uppercase tracking-widest mb-3">Remediation Playbook</h3>
              <div className="space-y-3">
                {selectedInc.steps?.map((step, idx) => {
                  const isCompleted = step.status === 'completed'
                  const isCurrent = idx + 1 === selectedInc.current_step && selectedInc.status !== 'resolved'
                  return (
                    <div key={step.id} className={`p-4 rounded-lg border transition-colors ${
                      isCompleted ? 'border-emerald-900/40 bg-emerald-500/5' :
                      isCurrent ? 'border-blue-800/40 bg-blue-600/5' :
                      'border-zinc-800 bg-transparent opacity-40'
                    }`}>
                      <div className="flex items-start gap-3">
                        <div className={`w-6 h-6 rounded-full flex items-center justify-center text-xs font-bold flex-shrink-0 mt-0.5 ${
                          isCompleted ? 'bg-emerald-500 text-white' :
                          isCurrent ? 'bg-blue-500 text-white' :
                          'bg-zinc-800 text-zinc-500'
                        }`}>
                          {isCompleted ? <CheckCircle2 className="w-3.5 h-3.5" /> : idx + 1}
                        </div>
                        <div className="flex-1">
                          <h4 className={`font-semibold text-sm ${isCurrent ? 'text-zinc-100' : 'text-zinc-300'}`}>{step.title}</h4>
                          <p className="text-xs text-zinc-500 mt-0.5 leading-relaxed">{step.description}</p>
                          {isCurrent && (
                            <div className="mt-3 flex gap-2">
                              {step.action_type === 'rotate_credentials' && (
                                <button
                                  onClick={() => rotateCredentials(selectedInc.id)}
                                  disabled={actionLoading}
                                  className="flex items-center gap-1.5 bg-rose-600 hover:bg-rose-500 text-white px-3 py-1.5 rounded-md text-xs font-semibold transition-colors disabled:opacity-50"
                                >
                                  <Key className="w-3 h-3" /> 1-Click Rotate Keys
                                </button>
                              )}
                              <button
                                onClick={() => advanceStep(selectedInc.id, step.id)}
                                disabled={actionLoading}
                                className="flex items-center gap-1.5 bg-blue-600 hover:bg-blue-500 text-white px-3 py-1.5 rounded-md text-xs font-semibold transition-colors disabled:opacity-50"
                              >
                                Mark Complete <ChevronRight className="w-3 h-3" />
                              </button>
                            </div>
                          )}
                        </div>
                      </div>
                    </div>
                  )
                })}
              </div>
            </div>
          </div>
        ) : (
          <div className="h-full flex flex-col items-center justify-center text-zinc-600">
            <ShieldAlert className="w-10 h-10 mb-3 opacity-30" />
            <p className="text-sm">Select an incident to view details</p>
          </div>
        )}
      </div>
    </div>
  )
}
