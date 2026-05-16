// OAuthApps.jsx
import { useState, useEffect } from 'react'
import axios from 'axios'
import { LineChart, Line, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid } from 'recharts'
import { Search, Shield, AlertOctagon, CheckCircle2, Settings, X, LogOut } from 'lucide-react'

const API = import.meta.env.DEV ? 'http://localhost:3000' : ''

export default function OAuthApps() {
  const [apps, setApps] = useState([])
  const [scanning, setScanning] = useState(false)
  const [chartData, setChartData] = useState([])
  
  const [systemStatus, setSystemStatus] = useState(null)
  
  const [showConnectModal, setShowConnectModal] = useState(false)
  const [adminEmail, setAdminEmail] = useState('')
  const [credsFile, setCredsFile] = useState(null)
  const [connecting, setConnecting] = useState(false)

  const handleConnect = async (e) => {
    e.preventDefault();
    if (!adminEmail || !credsFile) return;
    setConnecting(true);
    
    const reader = new FileReader();
    reader.onload = async (event) => {
      const creds_json = event.target.result;
      try {
        await axios.post(`${API}/api/workspace/connect`, {
          admin_email: adminEmail,
          creds_json
        });
      } catch (err) {
        // Uvicorn reload drops the connection, this is expected
        console.log("Server reload expected", err);
      }
      
      setShowConnectModal(false);
      setAdminEmail('');
      setCredsFile(null);
      
      // Wait for server to restart, then fetch apps and trigger scan
      setTimeout(async () => {
        await axios.post(`${API}/api/scan`).catch(console.error);
        await fetchApps();
        setConnecting(false);
      }, 2500);
    };
    reader.onerror = () => setConnecting(false);
    reader.readAsText(credsFile);
  }

  const fetchApps = async () => {
    try {
      const res = await axios.get(`${API}/api/apps`)
      setApps(res.data.apps || [])
    } catch (e) {
      console.error(e)
    }
    
    try {
      const statusRes = await axios.get(`${API}/api/status`)
      setSystemStatus(statusRes.data)
    } catch (e) {
      console.error(e)
    }
  }

  useEffect(() => {
    fetchApps()
    const interval = setInterval(fetchApps, 10000)
    return () => clearInterval(interval)
  }, [])

  const triggerScan = async () => {
    setScanning(true)
    try {
      await axios.post(`${API}/api/scan`)
      await fetchApps()
    } catch (e) {
      console.error(e)
    }
    setScanning(false)
  }

  const handleDisconnect = async () => {
    try {
      await axios.post(`${API}/api/workspace/disconnect`)
      await fetchApps()
    } catch (e) {
      console.error(e)
    }
  }

  const getRiskStyle = (category) => {
    switch(category) {
      case 'CRITICAL': return 'bg-rose-500/10 border-rose-500/40 text-rose-500 shadow-[0_0_15px_rgba(244,63,94,0.1)]'
      case 'HIGH': return 'bg-orange-500/10 border-orange-500/40 text-orange-500 shadow-[0_0_15px_rgba(249,115,22,0.1)]'
      case 'MEDIUM': return 'bg-amber-400/10 border-amber-400/40 text-amber-400'
      default: return 'bg-emerald-500/10 border-emerald-500/40 text-emerald-500'
    }
  }

  return (
    <div className="space-y-8">
      {/* Header & Actions */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between bg-gradient-to-r from-zinc-900 to-zinc-900/20 p-6 rounded-2xl border border-zinc-800 backdrop-blur-md shadow-lg">
        <div className="mb-4 sm:mb-0">
          <h2 className="text-2xl font-black text-zinc-100 tracking-tight">OAuth Attack Surface</h2>
          <p className="text-sm text-zinc-400 mt-1">Continuous monitoring of third-party connected applications in Google Workspace.</p>
        </div>
        <div className="flex flex-col sm:flex-row space-y-3 sm:space-y-0 sm:space-x-3">
          <button
            onClick={() => setShowConnectModal(true)}
            className="flex items-center justify-center space-x-2 bg-zinc-800 hover:bg-zinc-700 px-6 py-3 rounded-xl text-sm font-bold transition-all border border-zinc-700 text-white"
          >
            <Settings className="w-5 h-5" /><span>Connect Workspace</span>
          </button>
          {systemStatus?.workspace?.connected && (
            <button
              onClick={handleDisconnect}
              className="flex items-center justify-center space-x-2 bg-zinc-800 hover:bg-rose-900/50 px-4 py-3 rounded-xl text-sm font-bold transition-all border border-zinc-700 hover:border-rose-500/50 hover:text-rose-400 text-zinc-300"
              title="Disconnect and return to demo mode"
            >
              <LogOut className="w-5 h-5" />
            </button>
          )}
          <button
            onClick={triggerScan}
            disabled={scanning}
            className="flex items-center justify-center space-x-2 bg-blue-600 hover:bg-blue-500 disabled:opacity-50 px-6 py-3 rounded-xl text-sm font-bold transition-all shadow-[0_0_20px_rgba(37,99,235,0.4)] hover:shadow-[0_0_25px_rgba(37,99,235,0.6)] text-white"
          >
            {scanning ? (
              <><div className="w-5 h-5 border-2 border-white/30 border-t-white rounded-full animate-spin"></div><span>Running Deep Scan...</span></>
            ) : (
              <><Search className="w-5 h-5" /><span>Scan Environment</span></>
            )}
          </button>
        </div>
      </div>

      {/* Connect Modal */}
      {showConnectModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
          <div className="bg-zinc-900 border border-zinc-700 p-6 rounded-2xl shadow-2xl w-full max-w-md">
            <div className="flex justify-between items-center mb-6">
              <h3 className="text-xl font-bold text-white">Connect Workspace</h3>
              <button onClick={() => setShowConnectModal(false)} className="text-zinc-400 hover:text-white">
                <X className="w-5 h-5" />
              </button>
            </div>
            <form onSubmit={handleConnect} className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-zinc-300 mb-1">Google Admin Email</label>
                <input 
                  type="email" 
                  value={adminEmail}
                  onChange={(e) => setAdminEmail(e.target.value)}
                  className="w-full bg-[#1e293b] border border-zinc-700 rounded-lg px-4 py-2 text-white outline-none focus:border-blue-500"
                  placeholder="admin@yourdomain.com"
                  required
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-zinc-300 mb-1">Service Account JSON</label>
                <input 
                  type="file" 
                  accept=".json"
                  onChange={(e) => setCredsFile(e.target.files[0])}
                  className="w-full bg-[#1e293b] border border-zinc-700 rounded-lg px-4 py-2 text-white outline-none focus:border-blue-500 file:mr-4 file:py-1 file:px-3 file:rounded-md file:border-0 file:text-sm file:font-semibold file:bg-blue-600 file:text-white hover:file:bg-blue-500 cursor-pointer"
                  required
                />
              </div>
              <button 
                type="submit" 
                disabled={connecting || !adminEmail || !credsFile}
                className="w-full bg-blue-600 hover:bg-blue-500 disabled:opacity-50 text-white font-bold py-2 px-4 rounded-lg flex justify-center items-center mt-6 transition-colors"
              >
                {connecting ? 'Connecting...' : 'Connect & Scan'}
              </button>
            </form>
          </div>
        </div>
      )}


      {/* App Grid */}
      <div className="grid grid-cols-1 xl:grid-cols-2 gap-6">
        {apps.length === 0 ? (
          <div className="col-span-full py-16 text-center text-zinc-500 border border-zinc-800 border-dashed rounded-2xl bg-zinc-900/20">
            <Shield className="w-16 h-16 mx-auto mb-4 opacity-20" />
            <p className="text-lg font-medium">No applications discovered yet.</p>
            <p className="text-sm mt-1">Click "Scan Environment" to pull data from Google Workspace.</p>
          </div>
        ) : (
          apps.map(app => {
            const style = getRiskStyle(app.risk_category)
            return (
              <div key={app.app_id} className="bg-zinc-900/50 border border-zinc-800 rounded-2xl p-6 hover:border-zinc-700 transition-all backdrop-blur-md relative overflow-hidden group hover:-translate-y-1 duration-300">
                {app.is_ioc && (
                  <div className="absolute top-0 right-0 bg-rose-500 text-white text-[10px] font-black px-4 py-1.5 rounded-bl-xl flex items-center shadow-md">
                    <AlertOctagon className="w-3.5 h-3.5 mr-1.5" />
                    KNOWN IOC
                  </div>
                )}
                
                <div className="flex justify-between items-start">
                  <div className="pr-16">
                    <h4 className="text-xl font-bold text-zinc-100 truncate" title={app.name}>{app.name}</h4>
                    <p className="text-sm text-zinc-400 mt-1">{app.publisher}</p>
                    <div className="flex flex-wrap gap-2 mt-4">
                      {(app.scopes || []).slice(0,3).map((scope, idx) => (
                        <span key={idx} className="bg-zinc-900 border border-zinc-700 text-zinc-300 text-[10px] font-semibold px-2.5 py-1 rounded-full truncate max-w-[150px]" title={scope}>
                          {scope.split('/').pop()}
                        </span>
                      ))}
                      {(app.scopes?.length > 3) && <span className="bg-zinc-900 border border-zinc-700 text-zinc-400 text-[10px] font-bold px-2.5 py-1 rounded-full">+{app.scopes.length - 3}</span>}
                    </div>
                  </div>
                  <div className="flex flex-col items-end flex-shrink-0">
                    <div className={`text-4xl font-black ${style.split(' ')[2]}`}>
                      {app.risk_score}
                    </div>
                    <div className={`text-[10px] font-black mt-2 px-3 py-1 rounded-md uppercase tracking-widest border ${style}`}>
                      {app.risk_category}
                    </div>
                  </div>
                </div>
                
                <div className="mt-6 pt-5 border-t border-zinc-800/80">
                  <p className="text-sm text-zinc-300 leading-relaxed">
                    <span className="text-indigo-400 font-black mr-2 uppercase tracking-wide text-xs">[Gemini Insight]</span>
                    {app.explanation || "No explanation provided."}
                  </p>
                </div>
              </div>
            )
          })
        )}
      </div>
    </div>
  )
}
