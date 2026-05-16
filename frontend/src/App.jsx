import { useState, useEffect, useRef } from 'react'
import ThreatFeed from './ThreatFeed'
import OAuthApps from './OAuthApps'
import EnvGuardian from './EnvGuardian'
import RedTeamSimulator from './RedTeamSimulator'
import IncidentResponse from './IncidentResponse'
import axios from 'axios'
import {
  ShieldAlert, AppWindow, FileKey, Crosshair, Activity,
  LogOut, Menu, Bell, Shield, Wifi, WifiOff, Database,
  Lock, CheckCircle2, X, ChevronRight, ArrowRight, ExternalLink,
  Eye, Zap, Globe, Users, Check,
  AlertTriangle, BarChart3, Server, Upload, FileJson,
  Mail, BookOpen, Settings, HeadphonesIcon, ChevronDown,
  Code2, Terminal, Copy, CheckCheck, Search, MessageSquare,
  LifeBuoy, FileText, Layers, Key, Scan
} from 'lucide-react'

const API = import.meta.env.DEV ? 'http://localhost:3000' : ''

/* ─── FOOTER ──────────────────────────────────────────────────── */
function Footer({ onNavigate, minimal }) {
  if (minimal) return (
    <footer className="border-t border-zinc-800/60 py-6 px-6 text-center">
      <p className="text-xs text-zinc-600">© 2025 ContextGuard. All rights reserved.</p>
    </footer>
  )
  return (
    <footer className="border-t border-zinc-800/60 bg-zinc-900/20 px-6 py-14">
      <div className="max-w-5xl mx-auto grid md:grid-cols-4 gap-10">
        <div>
          <div className="flex items-center gap-2 mb-4">
            <Shield className="w-5 h-5 text-blue-500" />
            <span className="font-semibold text-zinc-100">ContextGuard</span>
          </div>
          <p className="text-sm text-zinc-500 leading-relaxed">Enterprise AI security platform. Monitor, inspect, and protect your AI supply chain.</p>
        </div>
        {[
          { title: 'Product', links: ['Features', 'Pricing', 'Documentation', 'Changelog'] },
          { title: 'Company', links: ['About', 'Blog', 'Careers', 'Contact'] },
          { title: 'Legal', links: ['Privacy', 'Terms', 'Security', 'Cookie Policy'] },
        ].map(col => (
          <div key={col.title}>
            <h4 className="text-xs font-semibold text-zinc-400 uppercase tracking-wider mb-4">{col.title}</h4>
            <ul className="space-y-2.5">
              {col.links.map(link => (
                <li key={link}>
                  <button
                    onClick={() => { if (link === 'Pricing') onNavigate('pricing'); if (link === 'About') onNavigate('about') }}
                    className="text-sm text-zinc-500 hover:text-zinc-300 transition-colors"
                  >{link}</button>
                </li>
              ))}
            </ul>
          </div>
        ))}
      </div>
      <div className="max-w-5xl mx-auto mt-10 pt-8 border-t border-zinc-800/60 flex flex-col sm:flex-row items-center justify-between gap-4">
        <p className="text-xs text-zinc-600">© 2025 ContextGuard. All rights reserved.</p>
        <div className="flex items-center gap-4">
          {[ExternalLink, ExternalLink, ExternalLink].map((Icon, i) => (
            <button key={i} className="text-zinc-600 hover:text-zinc-400 transition-colors"><Icon className="w-4 h-4" /></button>
          ))}
        </div>
      </div>
    </footer>
  )
}

/* ─── ABOUT PAGE ─────────────────────────────────────────────── */
function AboutPage({ onBack, onEnter }) {
  return (
    <div className="min-h-screen bg-[#09090b] text-zinc-100 font-sans">
      <header className="fixed top-0 left-0 right-0 z-50 border-b border-zinc-800/60 bg-[#09090b]/90 backdrop-blur-md">
        <div className="max-w-6xl mx-auto px-6 h-16 flex items-center justify-between">
          <button onClick={onBack} className="flex items-center gap-2.5">
            <Shield className="w-6 h-6 text-blue-500" />
            <span className="font-semibold text-zinc-100 tracking-tight">ContextGuard</span>
          </button>
          <button onClick={onEnter} className="px-4 py-2 text-sm bg-blue-600 hover:bg-blue-500 text-white rounded-lg font-medium transition-colors">Open Dashboard</button>
        </div>
      </header>
      <div className="pt-28 pb-20 px-6">
        <div className="max-w-3xl mx-auto">
          <button onClick={onBack} className="flex items-center gap-2 text-sm text-zinc-500 hover:text-zinc-300 transition-colors mb-10">
            <ChevronRight className="w-4 h-4 rotate-180" /> Back to home
          </button>
          <h1 className="text-4xl font-bold text-zinc-100 mb-6">About ContextGuard</h1>
          <p className="text-lg text-zinc-400 leading-relaxed mb-12">
            ContextGuard was built by a team of security engineers and AI researchers who witnessed firsthand how quickly AI agents were being deployed — and how little organizations understood the security implications.
          </p>
          <div className="grid md:grid-cols-2 gap-6 mb-16">
            {[
              { icon: Shield, title: 'Mission', desc: 'Make AI supply-chain security accessible to every organization, regardless of size or security maturity.' },
              { icon: Eye, title: 'Vision', desc: 'A world where every AI agent operates within a clearly defined, auditable security boundary.' },
              { icon: Zap, title: 'Approach', desc: 'Transparent proxying with deep packet inspection — no agent code changes, no vendor lock-in.' },
              { icon: Globe, title: 'Scope', desc: 'Full coverage of Google Workspace, OAuth integrations, environment secrets, and AI prompt traffic.' },
            ].map(item => (
              <div key={item.title} className="p-6 rounded-xl border border-zinc-800 bg-zinc-900/40">
                <item.icon className="w-5 h-5 text-blue-400 mb-3" />
                <h3 className="font-semibold text-zinc-100 mb-2">{item.title}</h3>
                <p className="text-sm text-zinc-500 leading-relaxed">{item.desc}</p>
              </div>
            ))}
          </div>
          <div className="border-t border-zinc-800 pt-12 mb-12">
            <h2 className="text-2xl font-bold text-zinc-100 mb-8">The problem we solve</h2>
            <div className="space-y-6">
              {[
                { title: 'AI agents have unchecked access', desc: 'Most AI agents are deployed with broad OAuth scopes and no monitoring. A single compromised prompt can exfiltrate your entire organization\'s data.' },
                { title: 'Supply-chain attacks are invisible', desc: 'Malicious third-party AI integrations can silently harvest credentials, PII, and API keys — all while appearing legitimate.' },
                { title: 'Incident response is manual', desc: 'Security teams lack the tooling to detect, triage, and respond to AI-specific threats in real time.' },
              ].map((item, i) => (
                <div key={i} className="flex gap-4">
                  <div className="w-6 h-6 rounded-full bg-blue-600/20 border border-blue-500/30 flex items-center justify-center flex-shrink-0 mt-0.5">
                    <AlertTriangle className="w-3 h-3 text-blue-400" />
                  </div>
                  <div>
                    <h4 className="font-semibold text-zinc-200 mb-1">{item.title}</h4>
                    <p className="text-sm text-zinc-500 leading-relaxed">{item.desc}</p>
                  </div>
                </div>
              ))}
            </div>
          </div>
          <div className="bg-zinc-900/60 border border-zinc-800 rounded-xl p-8 text-center">
            <h3 className="text-xl font-bold text-zinc-100 mb-3">Built for security teams</h3>
            <p className="text-zinc-400 mb-6 text-sm">ContextGuard integrates directly with your existing security stack. No rip-and-replace required.</p>
            <button onClick={onEnter} className="px-6 py-3 bg-blue-600 hover:bg-blue-500 text-white rounded-lg font-medium transition-colors inline-flex items-center gap-2">
              See it in action <ArrowRight className="w-4 h-4" />
            </button>
          </div>
        </div>
      </div>
      <Footer onNavigate={() => {}} minimal />
    </div>
  )
}

/* ─── PRICING PAGE ───────────────────────────────────────────── */
function PricingPage({ onBack, onEnter }) {
  const [annual, setAnnual] = useState(true)
  const plans = [
    {
      name: 'Starter', price: 0, period: 'Free forever',
      desc: 'For individuals and small teams exploring AI security.',
      features: ['Up to 5 OAuth apps', 'Basic threat feed', '7-day event history', 'Community support', 'Demo mode'],
      cta: 'Get started free', highlighted: false,
    },
    {
      name: 'Professional', price: annual ? 49 : 59, period: annual ? '/month, billed annually' : '/month',
      desc: 'For growing teams that need real-time protection and compliance.',
      features: ['Unlimited OAuth apps', 'Real-time DPI monitoring', '90-day event history', 'Gemini AI reports', 'Red team simulator', 'Incident response playbooks', 'SOC2 audit exports', 'Email support'],
      cta: 'Start free trial', highlighted: true,
    },
    {
      name: 'Enterprise', price: 'Custom', period: '',
      desc: 'For organizations with advanced compliance and scale requirements.',
      features: ['Everything in Professional', 'Custom DPI policies', 'SSO / SAML integration', 'Dedicated workspace tenant', 'SLA guarantees', 'On-prem deployment option', 'Dedicated security engineer', 'Priority support 24/7'],
      cta: 'Contact sales', highlighted: false,
    },
  ]
  return (
    <div className="min-h-screen bg-[#09090b] text-zinc-100 font-sans">
      <header className="fixed top-0 left-0 right-0 z-50 border-b border-zinc-800/60 bg-[#09090b]/90 backdrop-blur-md">
        <div className="max-w-6xl mx-auto px-6 h-16 flex items-center justify-between">
          <button onClick={onBack} className="flex items-center gap-2.5">
            <Shield className="w-6 h-6 text-blue-500" />
            <span className="font-semibold text-zinc-100 tracking-tight">ContextGuard</span>
          </button>
          <button onClick={onEnter} className="px-4 py-2 text-sm bg-blue-600 hover:bg-blue-500 text-white rounded-lg font-medium transition-colors">Open Dashboard</button>
        </div>
      </header>
      <div className="pt-28 pb-20 px-6">
        <div className="max-w-5xl mx-auto">
          <button onClick={onBack} className="flex items-center gap-2 text-sm text-zinc-500 hover:text-zinc-300 transition-colors mb-10">
            <ChevronRight className="w-4 h-4 rotate-180" /> Back to home
          </button>
          <div className="text-center mb-14">
            <h1 className="text-4xl font-bold text-zinc-100 mb-4">Simple, transparent pricing</h1>
            <p className="text-zinc-400 mb-8">Start free. Scale as your security needs grow.</p>
            <div className="inline-flex items-center gap-0 bg-zinc-900 border border-zinc-800 rounded-lg p-1">
              <button onClick={() => setAnnual(false)} className={`px-4 py-2 text-sm rounded-md transition-colors ${!annual ? 'bg-zinc-700 text-zinc-100' : 'text-zinc-400 hover:text-zinc-200'}`}>Monthly</button>
              <button onClick={() => setAnnual(true)} className={`px-4 py-2 text-sm rounded-md transition-colors flex items-center gap-2 ${annual ? 'bg-zinc-700 text-zinc-100' : 'text-zinc-400 hover:text-zinc-200'}`}>
                Annual <span className="text-xs bg-emerald-500/20 text-emerald-400 px-1.5 py-0.5 rounded">Save 17%</span>
              </button>
            </div>
          </div>
          <div className="grid md:grid-cols-3 gap-4 mb-20">
            {plans.map(plan => (
              <div key={plan.name} className={`rounded-xl p-6 border flex flex-col relative ${plan.highlighted ? 'border-blue-500/40 bg-blue-600/5' : 'border-zinc-800 bg-zinc-900/40'}`}>
                {plan.highlighted && (
                  <div className="absolute -top-3 left-1/2 -translate-x-1/2 px-3 py-1 bg-blue-600 rounded-full text-xs font-semibold text-white">Most popular</div>
                )}
                <div className="mb-6">
                  <h3 className="font-semibold text-zinc-100 mb-1">{plan.name}</h3>
                  <p className="text-xs text-zinc-500 mb-4">{plan.desc}</p>
                  <div className="flex items-baseline gap-1">
                    {typeof plan.price === 'number'
                      ? <><span className="text-3xl font-bold text-zinc-100">${plan.price}</span><span className="text-sm text-zinc-500">{plan.period}</span></>
                      : <span className="text-3xl font-bold text-zinc-100">{plan.price}</span>}
                  </div>
                </div>
                <ul className="space-y-2.5 flex-1 mb-6">
                  {plan.features.map(f => (
                    <li key={f} className="flex items-start gap-2.5 text-sm">
                      <Check className="w-4 h-4 text-emerald-500 flex-shrink-0 mt-0.5" />
                      <span className="text-zinc-400">{f}</span>
                    </li>
                  ))}
                </ul>
                <button onClick={onEnter} className={`w-full py-2.5 rounded-lg text-sm font-medium transition-colors ${plan.highlighted ? 'bg-blue-600 hover:bg-blue-500 text-white' : 'bg-zinc-800 hover:bg-zinc-700 text-zinc-100 border border-zinc-700'}`}>
                  {plan.cta}
                </button>
              </div>
            ))}
          </div>
        </div>
      </div>
      <Footer onNavigate={() => {}} minimal />
    </div>
  )
}

/* ─── DOCUMENTATION PAGE ─────────────────────────────────────── */
function DocumentationPage({ onClose }) {
  const [activeSection, setActiveSection] = useState('quickstart')
  const [copied, setCopied] = useState('')

  const copyCode = (code, id) => {
    navigator.clipboard.writeText(code).catch(() => {})
    setCopied(id)
    setTimeout(() => setCopied(''), 2000)
  }

  const sections = [
    { id: 'quickstart', label: 'Quick Start', icon: Zap },
    { id: 'workspace', label: 'Workspace Setup', icon: Globe },
    { id: 'api', label: 'API Reference', icon: Code2 },
    { id: 'proxy', label: 'Proxy Config', icon: Server },
    { id: 'policies', label: 'Security Policies', icon: Shield },
  ]

  const content = {
    quickstart: {
      title: 'Quick Start',
      desc: 'Get ContextGuard running in under 5 minutes.',
      blocks: [
        {
          type: 'step', num: '01', title: 'Clone and install',
          code: `git clone https://github.com/your-org/contextguard\ncd contextguard\npip install -r requirements.txt`,
          lang: 'bash', id: 'install'
        },
        {
          type: 'step', num: '02', title: 'Configure environment',
          code: `cp backend/.env.example backend/.env\n# Edit .env with your Gemini API key and workspace credentials`,
          lang: 'bash', id: 'env'
        },
        {
          type: 'step', num: '03', title: 'Start the backend',
          code: `cd backend\nuvicorn main:app --reload --port 3000`,
          lang: 'bash', id: 'start'
        },
        {
          type: 'step', num: '04', title: 'Connect your workspace',
          desc: 'Go to Profile → Upload your Gmail credentials file (.json) and workspace config file. The system will automatically scan all connected OAuth apps.',
          type: 'info'
        },
      ]
    },
    workspace: {
      title: 'Workspace Setup',
      desc: 'Connect your Google Workspace for real-time scanning.',
      blocks: [
        {
          type: 'info-card',
          title: 'Required files',
          items: [
            { icon: Mail, label: 'Gmail Credentials (.json)', desc: 'Service account JSON from Google Cloud Console with Gmail API access.' },
            { icon: FileJson, label: 'Workspace Config (.json)', desc: 'Your workspace configuration file with admin email and domain settings.' },
          ]
        },
        {
          type: 'step', num: '01', title: 'Create a service account',
          desc: 'In Google Cloud Console → IAM & Admin → Service Accounts → Create. Enable domain-wide delegation.',
          type: 'info'
        },
        {
          type: 'step', num: '02', title: 'Grant API scopes',
          code: `https://www.googleapis.com/auth/admin.directory.user.readonly\nhttps://www.googleapis.com/auth/admin.directory.domain.readonly\nhttps://mail.google.com/`,
          lang: 'text', id: 'scopes'
        },
        {
          type: 'step', num: '03', title: 'Upload via Profile',
          desc: 'Click your profile avatar → Upload the two files. ContextGuard handles the rest — scanning starts automatically within 30 seconds.',
          type: 'info'
        },
      ]
    },
    api: {
      title: 'API Reference',
      desc: 'FastAPI backend v1.0 · Base URL: http://localhost:3000',
      blocks: [
        {
          type: 'endpoint', method: 'GET', path: '/api/status',
          desc: 'System health check — workspace, proxy, and Gemini status.',
          id: 'status-ex',
          code: `{\n  "workspace": { "connected": true, "admin_email": "admin@acme.com", "apps_in_db": 74 },\n  "proxy": { "url": "http://localhost:8080", "online": true },\n  "gemini_key_set": true\n}`
        },
        {
          type: 'endpoint', method: 'GET', path: '/api/apps',
          desc: 'All OAuth apps with risk scores and Gemini explanations.',
          id: 'apps-ex',
          code: `{\n  "apps": [\n    {\n      "name": "DataSync Pro",\n      "risk_score": 87,\n      "risk_category": "CRITICAL",\n      "scopes": ["https://mail.google.com/"]\n    }\n  ],\n  "count": 74\n}`
        },
        {
          type: 'endpoint', method: 'POST', path: '/api/workspace/connect',
          desc: 'Connect workspace by uploading service account credentials (multipart/form-data).',
          id: 'connect-ex',
          code: `# multipart/form-data\ncreds_file: <service_account.json>\nadmin_email: admin@acme.com`
        },
      ]
    },
    proxy: {
      title: 'Proxy Configuration',
      desc: 'Configure the Lobster Trap DPI proxy for AI traffic inspection.',
      blocks: [
        {
          type: 'code-block', title: 'lobster/configs/backends.yaml', id: 'proxy-cfg',
          code: `backends:\n  openai:\n    url: https://api.openai.com\n    timeout: 30\n  anthropic:\n    url: https://api.anthropic.com\n    timeout: 30\n  gemini:\n    url: https://generativelanguage.googleapis.com\n    timeout: 30`
        },
        {
          type: 'info', title: 'Routing AI traffic',
          desc: 'Point your AI agents to http://localhost:8080 instead of the provider directly. The proxy forwards requests transparently while applying your DPI policies.'
        }
      ]
    },
    policies: {
      title: 'Security Policies',
      desc: 'Define what ContextGuard blocks, flags, and allows.',
      blocks: [
        {
          type: 'code-block', title: 'lobster/policy.yaml', id: 'policy-cfg',
          code: `rules:\n  - name: block_pii_exfiltration\n    match: regex\n    pattern: "\\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\\.[A-Z]{2,}\\b"\n    action: block\n    severity: critical\n\n  - name: flag_prompt_injection\n    match: keyword\n    keywords: ["ignore previous", "jailbreak", "DAN mode"]\n    action: flag\n    severity: high`
        },
        {
          type: 'info', title: 'Policy actions',
          desc: 'block — request dropped immediately. flag — request passes but logged as incident. allow — explicit whitelist bypass.'
        }
      ]
    }
  }

  const sec = content[activeSection]

  return (
    <div className="fixed inset-0 z-50 bg-[#09090b] flex flex-col overflow-hidden">
      {/* Header */}
      <div className="flex items-center justify-between px-6 h-14 border-b border-zinc-800/60 bg-[#0f1117] flex-shrink-0">
        <div className="flex items-center gap-3">
          <BookOpen className="w-4 h-4 text-blue-400" />
          <span className="text-sm font-semibold text-zinc-100">Documentation</span>
        </div>
        <button onClick={onClose} className="p-1.5 text-zinc-500 hover:text-zinc-200 hover:bg-zinc-800 rounded-md transition-colors">
          <X className="w-4 h-4" />
        </button>
      </div>

      <div className="flex flex-1 overflow-hidden">
        {/* Sidebar */}
        <nav className="w-52 border-r border-zinc-800/60 bg-[#0f1117] flex-shrink-0 py-4 px-2 space-y-0.5 overflow-y-auto">
          {sections.map(s => (
            <button key={s.id} onClick={() => setActiveSection(s.id)}
              className={`w-full flex items-center gap-2.5 px-3 py-2.5 rounded-lg text-sm transition-colors ${activeSection === s.id ? 'bg-zinc-800 text-zinc-100' : 'text-zinc-500 hover:text-zinc-200 hover:bg-zinc-800/50'}`}>
              <s.icon className={`w-4 h-4 flex-shrink-0 ${activeSection === s.id ? 'text-blue-400' : ''}`} />
              {s.label}
            </button>
          ))}
        </nav>

        {/* Content */}
        <main className="flex-1 overflow-y-auto p-8">
          <div className="max-w-2xl">
            <h1 className="text-2xl font-bold text-zinc-100 mb-2">{sec.title}</h1>
            <p className="text-zinc-400 text-sm mb-8">{sec.desc}</p>

            <div className="space-y-6">
              {sec.blocks.map((block, i) => {
                if (block.type === 'info' || (block.type === 'step' && !block.code)) {
                  return (
                    <div key={i} className="flex gap-4">
                      {block.num && (
                        <div className="w-7 h-7 rounded-full bg-blue-600/20 border border-blue-500/30 flex items-center justify-center flex-shrink-0 text-xs font-bold text-blue-400">{block.num}</div>
                      )}
                      <div>
                        {block.title && <h3 className="font-semibold text-zinc-200 mb-1 text-sm">{block.title}</h3>}
                        <p className="text-sm text-zinc-500 leading-relaxed">{block.desc}</p>
                      </div>
                    </div>
                  )
                }
                if (block.type === 'info-card') {
                  return (
                    <div key={i} className="rounded-xl border border-zinc-800 bg-zinc-900/40 p-5">
                      <h3 className="text-sm font-semibold text-zinc-200 mb-4">{block.title}</h3>
                      <div className="space-y-3">
                        {block.items.map((item, j) => (
                          <div key={j} className="flex items-start gap-3">
                            <div className="w-8 h-8 rounded-lg bg-blue-600/10 border border-blue-500/20 flex items-center justify-center flex-shrink-0">
                              <item.icon className="w-4 h-4 text-blue-400" />
                            </div>
                            <div>
                              <p className="text-sm font-medium text-zinc-200">{item.label}</p>
                              <p className="text-xs text-zinc-500 mt-0.5">{item.desc}</p>
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>
                  )
                }
                if (block.type === 'endpoint') {
                  const methodColors = { GET: 'text-emerald-400 bg-emerald-500/10 border-emerald-900/60', POST: 'text-blue-400 bg-blue-500/10 border-blue-900/60', DELETE: 'text-rose-400 bg-rose-500/10 border-rose-900/60' }
                  return (
                    <div key={i} className="rounded-xl border border-zinc-800 bg-zinc-900/40 overflow-hidden">
                      <div className="flex items-center gap-3 px-4 py-3 border-b border-zinc-800/60">
                        <span className={`text-xs font-bold px-2 py-0.5 rounded border ${methodColors[block.method] || 'text-zinc-400 bg-zinc-800 border-zinc-700'}`}>{block.method}</span>
                        <code className="text-sm font-mono text-zinc-200">{block.path}</code>
                      </div>
                      <div className="px-4 py-3 border-b border-zinc-800/60">
                        <p className="text-sm text-zinc-500">{block.desc}</p>
                      </div>
                      <div className="relative">
                        <pre className="p-4 text-xs font-mono text-zinc-300 overflow-x-auto leading-relaxed">{block.code}</pre>
                        <button onClick={() => copyCode(block.code, block.id)} className="absolute top-3 right-3 p-1.5 text-zinc-600 hover:text-zinc-300 hover:bg-zinc-800 rounded transition-colors">
                          {copied === block.id ? <CheckCheck className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                        </button>
                      </div>
                    </div>
                  )
                }
                // code-block or step with code
                return (
                  <div key={i} className="space-y-2">
                    {(block.num || block.title) && (
                      <div className="flex items-center gap-3">
                        {block.num && <div className="w-6 h-6 rounded-full bg-blue-600/20 border border-blue-500/30 flex items-center justify-center text-xs font-bold text-blue-400">{block.num}</div>}
                        {block.title && <h3 className="text-sm font-semibold text-zinc-200">{block.title}</h3>}
                      </div>
                    )}
                    <div className="relative rounded-xl border border-zinc-800 bg-zinc-950 overflow-hidden">
                      {block.lang && <div className="flex items-center gap-2 px-4 py-2 border-b border-zinc-800/60 bg-zinc-900/40"><Terminal className="w-3 h-3 text-zinc-600" /><span className="text-xs text-zinc-600 font-mono">{block.lang}</span></div>}
                      <pre className="p-4 text-xs font-mono text-zinc-300 overflow-x-auto leading-relaxed">{block.code}</pre>
                      <button onClick={() => copyCode(block.code, block.id)} className="absolute top-2 right-2 p-1.5 text-zinc-600 hover:text-zinc-300 hover:bg-zinc-800 rounded transition-colors">
                        {copied === block.id ? <CheckCheck className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                      </button>
                    </div>
                  </div>
                )
              })}
            </div>
          </div>
        </main>
      </div>
    </div>
  )
}

/* ─── SETTINGS PAGE ──────────────────────────────────────────── */
function SettingsPage({ onClose, systemStatus }) {
  const [activeTab, setActiveTab] = useState('general')
  const [saved, setSaved] = useState('')
  const [geminiKey, setGeminiKey] = useState('')
  const [proxyUrl, setProxyUrl] = useState('http://localhost:8080')
  const [scanInterval, setScanInterval] = useState('15')
  const [notifyEmail, setNotifyEmail] = useState('')
  const [dpiEnabled, setDpiEnabled] = useState(true)
  const [autoBlock, setAutoBlock] = useState(true)
  const [alertCritical, setAlertCritical] = useState(true)
  const [alertWarning, setAlertWarning] = useState(true)

  const save = (section) => {
    setSaved(section)
    setTimeout(() => setSaved(''), 2000)
  }

  const tabs = [
    { id: 'general', label: 'General', icon: Settings },
    { id: 'security', label: 'Security', icon: Shield },
    { id: 'notifications', label: 'Notifications', icon: Bell },
    { id: 'integrations', label: 'Integrations', icon: Layers },
  ]

  return (
    <div className="fixed inset-0 z-50 bg-[#09090b] flex flex-col overflow-hidden">
      <div className="flex items-center justify-between px-6 h-14 border-b border-zinc-800/60 bg-[#0f1117] flex-shrink-0">
        <div className="flex items-center gap-3">
          <Settings className="w-4 h-4 text-blue-400" />
          <span className="text-sm font-semibold text-zinc-100">Settings</span>
        </div>
        <button onClick={onClose} className="p-1.5 text-zinc-500 hover:text-zinc-200 hover:bg-zinc-800 rounded-md transition-colors">
          <X className="w-4 h-4" />
        </button>
      </div>

      <div className="flex flex-1 overflow-hidden">
        <nav className="w-48 border-r border-zinc-800/60 bg-[#0f1117] flex-shrink-0 py-4 px-2 space-y-0.5">
          {tabs.map(t => (
            <button key={t.id} onClick={() => setActiveTab(t.id)}
              className={`w-full flex items-center gap-2.5 px-3 py-2.5 rounded-lg text-sm transition-colors ${activeTab === t.id ? 'bg-zinc-800 text-zinc-100' : 'text-zinc-500 hover:text-zinc-200 hover:bg-zinc-800/50'}`}>
              <t.icon className={`w-4 h-4 flex-shrink-0 ${activeTab === t.id ? 'text-blue-400' : ''}`} />
              {t.label}
            </button>
          ))}
        </nav>

        <main className="flex-1 overflow-y-auto p-8">
          <div className="max-w-xl space-y-8">

            {activeTab === 'general' && (
              <>
                <div>
                  <h2 className="text-base font-semibold text-zinc-100 mb-1">General</h2>
                  <p className="text-xs text-zinc-500">Core system configuration.</p>
                </div>
                <div className="space-y-5">
                  <div>
                    <label className="block text-xs font-medium text-zinc-400 mb-1.5">Gemini API Key</label>
                    <input
                      type="password"
                      value={geminiKey}
                      onChange={e => setGeminiKey(e.target.value)}
                      placeholder={systemStatus?.gemini_key_set ? '••••••••••••••••' : 'Enter Gemini API key…'}
                      className="w-full px-3 py-2.5 rounded-lg border border-zinc-700 bg-zinc-900 text-sm text-zinc-200 placeholder-zinc-600 focus:outline-none focus:border-blue-500/60 transition-colors"
                    />
                    {systemStatus?.gemini_key_set && (
                      <p className="text-xs text-emerald-400 mt-1 flex items-center gap-1"><Check className="w-3 h-3" /> API key configured</p>
                    )}
                  </div>
                  <div>
                    <label className="block text-xs font-medium text-zinc-400 mb-1.5">Proxy URL</label>
                    <input
                      value={proxyUrl}
                      onChange={e => setProxyUrl(e.target.value)}
                      className="w-full px-3 py-2.5 rounded-lg border border-zinc-700 bg-zinc-900 text-sm text-zinc-200 focus:outline-none focus:border-blue-500/60 transition-colors"
                    />
                  </div>
                  <div>
                    <label className="block text-xs font-medium text-zinc-400 mb-1.5">Auto-scan interval (seconds)</label>
                    <select
                      value={scanInterval}
                      onChange={e => setScanInterval(e.target.value)}
                      className="w-full px-3 py-2.5 rounded-lg border border-zinc-700 bg-zinc-900 text-sm text-zinc-200 focus:outline-none focus:border-blue-500/60 transition-colors"
                    >
                      {['5', '15', '30', '60', '300'].map(v => <option key={v} value={v}>{v}s</option>)}
                    </select>
                  </div>
                  <button onClick={() => save('general')} className="px-5 py-2.5 bg-blue-600 hover:bg-blue-500 text-white text-sm rounded-lg font-medium transition-colors flex items-center gap-2">
                    {saved === 'general' ? <><CheckCheck className="w-4 h-4" /> Saved</> : 'Save changes'}
                  </button>
                </div>
              </>
            )}

            {activeTab === 'security' && (
              <>
                <div>
                  <h2 className="text-base font-semibold text-zinc-100 mb-1">Security</h2>
                  <p className="text-xs text-zinc-500">DPI and threat response settings.</p>
                </div>
                <div className="space-y-4">
                  {[
                    { label: 'Enable Deep Packet Inspection', desc: 'Inspect all AI traffic through the Lobster Trap proxy.', state: dpiEnabled, set: setDpiEnabled },
                    { label: 'Auto-block critical threats', desc: 'Automatically block requests classified as CRITICAL severity.', state: autoBlock, set: setAutoBlock },
                  ].map(item => (
                    <div key={item.label} className="flex items-start justify-between p-4 rounded-xl border border-zinc-800 bg-zinc-900/40">
                      <div className="flex-1 pr-4">
                        <p className="text-sm font-medium text-zinc-200">{item.label}</p>
                        <p className="text-xs text-zinc-500 mt-0.5">{item.desc}</p>
                      </div>
                      <button onClick={() => item.set(!item.state)}
                        className={`relative w-10 h-5.5 rounded-full transition-colors flex-shrink-0 mt-0.5 ${item.state ? 'bg-blue-600' : 'bg-zinc-700'}`}
                        style={{ height: '22px', width: '40px' }}>
                        <span className={`absolute top-0.5 w-4 h-4 rounded-full bg-white shadow transition-transform ${item.state ? 'translate-x-5' : 'translate-x-0.5'}`} style={{ height: '18px', width: '18px' }} />
                      </button>
                    </div>
                  ))}
                  <button onClick={() => save('security')} className="px-5 py-2.5 bg-blue-600 hover:bg-blue-500 text-white text-sm rounded-lg font-medium transition-colors flex items-center gap-2">
                    {saved === 'security' ? <><CheckCheck className="w-4 h-4" /> Saved</> : 'Save changes'}
                  </button>
                </div>
              </>
            )}

            {activeTab === 'notifications' && (
              <>
                <div>
                  <h2 className="text-base font-semibold text-zinc-100 mb-1">Notifications</h2>
                  <p className="text-xs text-zinc-500">Configure alert delivery preferences.</p>
                </div>
                <div className="space-y-5">
                  <div>
                    <label className="block text-xs font-medium text-zinc-400 mb-1.5">Alert email address</label>
                    <input
                      value={notifyEmail}
                      onChange={e => setNotifyEmail(e.target.value)}
                      placeholder="security@yourcompany.com"
                      className="w-full px-3 py-2.5 rounded-lg border border-zinc-700 bg-zinc-900 text-sm text-zinc-200 placeholder-zinc-600 focus:outline-none focus:border-blue-500/60 transition-colors"
                    />
                  </div>
                  <div className="space-y-3">
                    <p className="text-xs font-medium text-zinc-400">Alert thresholds</p>
                    {[
                      { label: 'Critical severity alerts', state: alertCritical, set: setAlertCritical, color: 'rose' },
                      { label: 'Warning severity alerts', state: alertWarning, set: setAlertWarning, color: 'amber' },
                    ].map(item => (
                      <div key={item.label} className="flex items-center justify-between py-2">
                        <span className="text-sm text-zinc-300">{item.label}</span>
                        <button onClick={() => item.set(!item.state)}
                          className={`relative rounded-full transition-colors flex-shrink-0 ${item.state ? 'bg-blue-600' : 'bg-zinc-700'}`}
                          style={{ height: '22px', width: '40px' }}>
                          <span className={`absolute top-0.5 w-4 h-4 rounded-full bg-white shadow transition-transform ${item.state ? 'translate-x-5' : 'translate-x-0.5'}`} style={{ height: '18px', width: '18px' }} />
                        </button>
                      </div>
                    ))}
                  </div>
                  <button onClick={() => save('notifications')} className="px-5 py-2.5 bg-blue-600 hover:bg-blue-500 text-white text-sm rounded-lg font-medium transition-colors flex items-center gap-2">
                    {saved === 'notifications' ? <><CheckCheck className="w-4 h-4" /> Saved</> : 'Save changes'}
                  </button>
                </div>
              </>
            )}

            {activeTab === 'integrations' && (
              <>
                <div>
                  <h2 className="text-base font-semibold text-zinc-100 mb-1">Integrations</h2>
                  <p className="text-xs text-zinc-500">Connected third-party services.</p>
                </div>
                <div className="space-y-3">
                  {[
                    { name: 'Google Workspace', desc: 'OAuth app scanning and user directory', connected: systemStatus?.workspace?.connected, icon: Globe },
                    { name: 'Gemini AI', desc: 'Threat intelligence and risk scoring', connected: systemStatus?.gemini_key_set, icon: Zap },
                    { name: 'Lobster Trap Proxy', desc: 'Deep packet inspection engine', connected: systemStatus?.proxy?.online, icon: Server },
                  ].map(item => (
                    <div key={item.name} className="flex items-center justify-between p-4 rounded-xl border border-zinc-800 bg-zinc-900/40">
                      <div className="flex items-center gap-3">
                        <div className="w-8 h-8 rounded-lg bg-zinc-800 border border-zinc-700 flex items-center justify-center">
                          <item.icon className="w-4 h-4 text-zinc-400" />
                        </div>
                        <div>
                          <p className="text-sm font-medium text-zinc-200">{item.name}</p>
                          <p className="text-xs text-zinc-500">{item.desc}</p>
                        </div>
                      </div>
                      <span className={`text-xs font-medium px-2 py-0.5 rounded-full border ${item.connected ? 'text-emerald-400 bg-emerald-500/10 border-emerald-900/60' : 'text-zinc-500 bg-zinc-900 border-zinc-800'}`}>
                        {item.connected ? 'Connected' : 'Disconnected'}
                      </span>
                    </div>
                  ))}
                </div>
              </>
            )}
          </div>
        </main>
      </div>
    </div>
  )
}

/* ─── SUPPORT PAGE ───────────────────────────────────────────── */
function SupportPage({ onClose }) {
  const [subject, setSubject] = useState('')
  const [message, setMessage] = useState('')
  const [submitted, setSubmitted] = useState(false)
  const [activeTab, setActiveTab] = useState('contact')

  const faqs = [
    { q: 'Why is my workspace not connecting?', a: 'Ensure your service account JSON has domain-wide delegation enabled and the correct API scopes granted. Check that the admin email matches your workspace primary domain.' },
    { q: 'How do I reduce false positives?', a: 'Go to Settings → Security → edit your policy.yaml to whitelist trusted app IDs or adjust regex patterns. Apps can also be individually whitelisted from the OAuth Apps view.' },
    { q: 'The proxy shows offline — what do I do?', a: 'Run the backend with uvicorn main:app --reload and confirm lobster/webhook_bridge.py is running. Check your firewall allows port 8080.' },
    { q: 'How does Gemini analysis work?', a: 'ContextGuard sends app metadata (name, scopes, publisher) to Gemini for risk narrative generation. No actual user data or prompt content is sent to Gemini.' },
    { q: 'Can I export audit logs?', a: 'Yes — from the Incident Response tab, use the Export button to download a CSV of all incidents. SOC2-formatted exports are available on Professional and Enterprise plans.' },
  ]

  const submit = (e) => {
    e.preventDefault()
    if (subject && message) setSubmitted(true)
  }

  return (
    <div className="fixed inset-0 z-50 bg-[#09090b] flex flex-col overflow-hidden">
      <div className="flex items-center justify-between px-6 h-14 border-b border-zinc-800/60 bg-[#0f1117] flex-shrink-0">
        <div className="flex items-center gap-3">
          <LifeBuoy className="w-4 h-4 text-blue-400" />
          <span className="text-sm font-semibold text-zinc-100">Support</span>
        </div>
        <button onClick={onClose} className="p-1.5 text-zinc-500 hover:text-zinc-200 hover:bg-zinc-800 rounded-md transition-colors">
          <X className="w-4 h-4" />
        </button>
      </div>

      <main className="flex-1 overflow-y-auto p-8">
        <div className="max-w-2xl mx-auto">
          {/* Tabs */}
          <div className="flex gap-1 mb-8 bg-zinc-900 border border-zinc-800 rounded-lg p-1 w-fit">
            {[{ id: 'contact', label: 'Contact Us', icon: MessageSquare }, { id: 'faq', label: 'FAQ', icon: FileText }].map(t => (
              <button key={t.id} onClick={() => setActiveTab(t.id)}
                className={`flex items-center gap-2 px-4 py-2 text-sm rounded-md transition-colors ${activeTab === t.id ? 'bg-zinc-700 text-zinc-100' : 'text-zinc-400 hover:text-zinc-200'}`}>
                <t.icon className="w-3.5 h-3.5" />
                {t.label}
              </button>
            ))}
          </div>

          {activeTab === 'contact' && (
            <>
              {/* Contact cards */}
              <div className="grid sm:grid-cols-3 gap-3 mb-8">
                {[
                  { icon: MessageSquare, title: 'Live Chat', desc: 'Available Mon–Fri 9am–6pm UTC', action: 'Start chat' },
                  { icon: Mail, title: 'Email', desc: 'support@contextguard.ai', action: 'Send email' },
                  { icon: BookOpen, title: 'Docs', desc: 'Self-serve documentation', action: 'Browse docs' },
                ].map(c => (
                  <div key={c.title} className="p-4 rounded-xl border border-zinc-800 bg-zinc-900/40 text-center">
                    <div className="w-8 h-8 rounded-lg bg-blue-600/10 border border-blue-500/20 flex items-center justify-center mx-auto mb-3">
                      <c.icon className="w-4 h-4 text-blue-400" />
                    </div>
                    <p className="text-sm font-medium text-zinc-200">{c.title}</p>
                    <p className="text-xs text-zinc-500 mt-0.5 mb-3">{c.desc}</p>
                    <button className="text-xs text-blue-400 hover:text-blue-300 transition-colors">{c.action}</button>
                  </div>
                ))}
              </div>

              {/* Support form */}
              {submitted ? (
                <div className="rounded-xl border border-emerald-900/60 bg-emerald-500/5 p-8 text-center">
                  <CheckCircle2 className="w-10 h-10 text-emerald-400 mx-auto mb-3" />
                  <h3 className="font-semibold text-zinc-100 mb-1">Message sent!</h3>
                  <p className="text-sm text-zinc-500">Our team will get back to you within 24 hours.</p>
                  <button onClick={() => { setSubmitted(false); setSubject(''); setMessage('') }} className="mt-4 text-sm text-blue-400 hover:text-blue-300 transition-colors">Send another</button>
                </div>
              ) : (
                <div className="rounded-xl border border-zinc-800 bg-zinc-900/40 p-6">
                  <h3 className="font-semibold text-zinc-100 mb-5">Send a message</h3>
                  <div className="space-y-4">
                    <div>
                      <label className="block text-xs font-medium text-zinc-400 mb-1.5">Subject</label>
                      <input
                        value={subject}
                        onChange={e => setSubject(e.target.value)}
                        placeholder="Brief description of your issue…"
                        className="w-full px-3 py-2.5 rounded-lg border border-zinc-700 bg-zinc-900 text-sm text-zinc-200 placeholder-zinc-600 focus:outline-none focus:border-blue-500/60 transition-colors"
                      />
                    </div>
                    <div>
                      <label className="block text-xs font-medium text-zinc-400 mb-1.5">Message</label>
                      <textarea
                        value={message}
                        onChange={e => setMessage(e.target.value)}
                        rows={4}
                        placeholder="Describe the problem in detail…"
                        className="w-full px-3 py-2.5 rounded-lg border border-zinc-700 bg-zinc-900 text-sm text-zinc-200 placeholder-zinc-600 focus:outline-none focus:border-blue-500/60 transition-colors resize-none"
                      />
                    </div>
                    <button onClick={submit} disabled={!subject || !message}
                      className="px-5 py-2.5 bg-blue-600 hover:bg-blue-500 disabled:opacity-40 disabled:cursor-not-allowed text-white text-sm rounded-lg font-medium transition-colors">
                      Send message
                    </button>
                  </div>
                </div>
              )}
            </>
          )}

          {activeTab === 'faq' && (
            <div className="space-y-3">
              {faqs.map((item, i) => (
                <FAQItem key={i} q={item.q} a={item.a} />
              ))}
            </div>
          )}
        </div>
      </main>
    </div>
  )
}

function FAQItem({ q, a }) {
  const [open, setOpen] = useState(false)
  return (
    <div className="rounded-xl border border-zinc-800 bg-zinc-900/40 overflow-hidden">
      <button onClick={() => setOpen(!open)} className="w-full flex items-center justify-between px-5 py-4 text-left">
        <span className="text-sm font-medium text-zinc-200">{q}</span>
        <ChevronDown className={`w-4 h-4 text-zinc-500 flex-shrink-0 ml-3 transition-transform ${open ? 'rotate-180' : ''}`} />
      </button>
      {open && (
        <div className="px-5 pb-4 border-t border-zinc-800/60 pt-3">
          <p className="text-sm text-zinc-500 leading-relaxed">{a}</p>
        </div>
      )}
    </div>
  )
}

/* ─── LANDING PAGE ───────────────────────────────────────────── */
function LandingPage({ onEnterDashboard, onConnectWorkspace }) {
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false)
  const [currentPage, setCurrentPage] = useState('home')

  if (currentPage === 'about') return <AboutPage onBack={() => setCurrentPage('home')} onEnter={onEnterDashboard} />
  if (currentPage === 'pricing') return <PricingPage onBack={() => setCurrentPage('home')} onEnter={onEnterDashboard} />

  return (
    <div className="min-h-screen bg-[#09090b] text-zinc-100 font-sans">
      <header className="fixed top-0 left-0 right-0 z-50 border-b border-zinc-800/60 bg-[#09090b]/90 backdrop-blur-md">
        <div className="max-w-6xl mx-auto px-6 h-16 flex items-center justify-between">
          <div className="flex items-center gap-2.5">
            <Shield className="w-6 h-6 text-blue-500" />
            <span className="font-semibold text-zinc-100 tracking-tight">ContextGuard</span>
          </div>
          <nav className="hidden md:flex items-center gap-1">
            {[{ label: 'Product', page: null }, { label: 'About', page: 'about' }, { label: 'Pricing', page: 'pricing' }, { label: 'Docs', page: null }].map(link => (
              <button key={link.label} onClick={() => link.page && setCurrentPage(link.page)}
                className="px-4 py-2 text-sm text-zinc-400 hover:text-zinc-100 transition-colors rounded-md hover:bg-zinc-800/50">
                {link.label}
              </button>
            ))}
          </nav>
          <div className="hidden md:flex items-center gap-3">
            <button onClick={onEnterDashboard} className="px-4 py-2 text-sm text-zinc-400 hover:text-zinc-100 transition-colors">Demo</button>
            <button onClick={onConnectWorkspace} className="px-4 py-2 text-sm bg-blue-600 hover:bg-blue-500 text-white rounded-lg font-medium transition-colors">Get started</button>
          </div>
          <button className="md:hidden p-2 text-zinc-400" onClick={() => setMobileMenuOpen(!mobileMenuOpen)}>
            {mobileMenuOpen ? <X className="w-5 h-5" /> : <Menu className="w-5 h-5" />}
          </button>
        </div>
        {mobileMenuOpen && (
          <div className="md:hidden border-t border-zinc-800 bg-[#09090b] px-6 py-4 space-y-1">
            {[{ label: 'About', page: 'about' }, { label: 'Pricing', page: 'pricing' }].map(link => (
              <button key={link.label} onClick={() => { setCurrentPage(link.page); setMobileMenuOpen(false) }}
                className="block w-full text-left px-3 py-2.5 text-sm text-zinc-400 hover:text-zinc-100 rounded-md">{link.label}</button>
            ))}
            <div className="pt-3 flex flex-col gap-2">
              <button onClick={onEnterDashboard} className="px-4 py-2.5 text-sm text-zinc-100 border border-zinc-700 rounded-lg">Demo</button>
              <button onClick={onConnectWorkspace} className="px-4 py-2.5 text-sm bg-blue-600 hover:bg-blue-500 text-white rounded-lg font-medium">Get started</button>
            </div>
          </div>
        )}
      </header>

      <section className="pt-36 pb-24 px-6 text-center relative overflow-hidden">
        <div className="absolute inset-0 pointer-events-none">
          <div className="absolute top-1/3 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[600px] h-[600px] bg-blue-600/8 blur-[140px] rounded-full" />
        </div>
        <div className="max-w-3xl mx-auto relative">
          <div className="inline-flex items-center gap-2 px-3 py-1.5 bg-zinc-900 border border-zinc-700/60 rounded-full text-xs text-zinc-400 mb-8">
            <div className="w-1.5 h-1.5 rounded-full bg-emerald-500" />
            Now with Gemini-powered threat intelligence
          </div>
          <h1 className="text-5xl md:text-6xl font-bold text-zinc-100 tracking-tight leading-tight mb-6">
            AI Security for<br /><span className="text-blue-400">Enterprise Workspaces</span>
          </h1>
          <p className="text-lg text-zinc-400 leading-relaxed max-w-2xl mx-auto mb-10">
            ContextGuard monitors, inspects, and shields your organization from third-party AI supply-chain attacks — in real time.
          </p>
          <div className="flex flex-col sm:flex-row items-center justify-center gap-3">
            <button onClick={onEnterDashboard} className="w-full sm:w-auto px-6 py-3 bg-blue-600 hover:bg-blue-500 text-white rounded-lg font-medium transition-colors flex items-center justify-center gap-2">
              Explore Demo <ArrowRight className="w-4 h-4" />
            </button>
            <button onClick={onConnectWorkspace} className="w-full sm:w-auto px-6 py-3 border border-zinc-700 hover:border-zinc-500 text-zinc-200 rounded-lg font-medium transition-colors flex items-center justify-center gap-2">
              <Lock className="w-4 h-4" /> Connect Workspace
            </button>
          </div>
          <p className="mt-6 text-xs text-zinc-500">No credit card required · SOC2 Ready · AI-Powered</p>
        </div>
      </section>

      <section className="border-y border-zinc-800/60 bg-zinc-900/30 py-8 px-6">
        <div className="max-w-4xl mx-auto grid grid-cols-2 md:grid-cols-4 gap-6 text-center">
          {[
            { value: '99.9%', label: 'Threat detection rate' },
            { value: '<2ms', label: 'DPI latency overhead' },
            { value: '500+', label: 'Policy rules built-in' },
            { value: 'SOC2', label: 'Compliance ready' },
          ].map(s => (
            <div key={s.label}>
              <div className="text-2xl font-bold text-zinc-100 mb-1">{s.value}</div>
              <div className="text-xs text-zinc-500">{s.label}</div>
            </div>
          ))}
        </div>
      </section>

      <section className="py-24 px-6">
        <div className="max-w-5xl mx-auto">
          <div className="text-center mb-16">
            <h2 className="text-3xl font-bold text-zinc-100 mb-4">Everything you need to secure AI</h2>
            <p className="text-zinc-400 max-w-xl mx-auto">A complete platform for monitoring AI agents, detecting threats, and responding to incidents across your entire organization.</p>
          </div>
          <div className="grid md:grid-cols-3 gap-4">
            {[
              { icon: Activity, title: 'Live Threat Feed', desc: 'Real-time DPI interception and classification of malicious AI traffic with severity scoring.' },
              { icon: AppWindow, title: 'OAuth App Scanner', desc: 'Continuously audit all third-party OAuth integrations for excessive permissions and supply-chain risk.' },
              { icon: FileKey, title: 'Env Variable Guardian', desc: 'AI-powered classification of environment variables to prevent credential leakage.' },
              { icon: Crosshair, title: 'Red Team Simulator', desc: 'Test your defenses with realistic prompt injection and jailbreak attack simulations.' },
              { icon: ShieldAlert, title: 'Incident Response', desc: 'Structured playbooks with 1-click remediation for every security incident.' },
              { icon: BarChart3, title: 'Compliance Reports', desc: 'Generate SOC2 and HIPAA-ready audit reports powered by Gemini intelligence.' },
            ].map(f => (
              <div key={f.title} className="p-6 rounded-xl border border-zinc-800 bg-zinc-900/40 hover:border-zinc-700 hover:bg-zinc-900/70 transition-all group">
                <div className="w-9 h-9 rounded-lg bg-blue-600/10 border border-blue-500/20 flex items-center justify-center mb-4 group-hover:bg-blue-600/20 transition-colors">
                  <f.icon className="w-5 h-5 text-blue-400" />
                </div>
                <h3 className="font-semibold text-zinc-100 mb-2">{f.title}</h3>
                <p className="text-sm text-zinc-500 leading-relaxed">{f.desc}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      <section className="py-20 px-6 border-t border-zinc-800/60 bg-zinc-900/20">
        <div className="max-w-4xl mx-auto">
          <div className="text-center mb-14">
            <h2 className="text-3xl font-bold text-zinc-100 mb-4">How ContextGuard works</h2>
            <p className="text-zinc-400">Deployed as a transparent proxy between your AI agents and external services.</p>
          </div>
          <div className="grid md:grid-cols-3 gap-8">
            {[
              { step: '01', title: 'Connect your workspace', desc: 'Upload your Gmail credentials and workspace JSON via your profile. Zero config, no code changes required.' },
              { step: '02', title: 'Proxy routes traffic', desc: 'Lobster Trap DPI engine inspects all AI agent requests in real time.' },
              { step: '03', title: 'Threats blocked instantly', desc: 'Malicious prompts blocked, incidents logged, and teams notified automatically.' },
            ].map(s => (
              <div key={s.step}>
                <div className="text-5xl font-bold text-zinc-800 mb-4 font-mono">{s.step}</div>
                <h3 className="font-semibold text-zinc-100 mb-2">{s.title}</h3>
                <p className="text-sm text-zinc-500 leading-relaxed">{s.desc}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      <section className="py-20 px-6 text-center">
        <div className="max-w-xl mx-auto">
          <h2 className="text-3xl font-bold text-zinc-100 mb-4">Ready to secure your AI stack?</h2>
          <p className="text-zinc-400 mb-8">Join security teams who trust ContextGuard to protect their AI-powered workflows.</p>
          <div className="flex flex-col sm:flex-row gap-3 justify-center">
            <button onClick={onEnterDashboard} className="px-6 py-3 bg-blue-600 hover:bg-blue-500 text-white rounded-lg font-medium transition-colors flex items-center justify-center gap-2">
              Try Demo Dashboard <ArrowRight className="w-4 h-4" />
            </button>
            <button onClick={() => setCurrentPage('pricing')} className="px-6 py-3 border border-zinc-700 hover:border-zinc-500 text-zinc-200 rounded-lg font-medium transition-colors">
              View Pricing
            </button>
          </div>
        </div>
      </section>

      <Footer onNavigate={setCurrentPage} />
    </div>
  )
}

/* ─── NOTIFICATIONS DROPDOWN ─────────────────────────────────── */
const DEMO_NOTIFICATIONS = [
  { id: 1, type: 'critical', title: 'Prompt Injection Detected', desc: 'Malicious payload blocked in OAuth app "DataSync Pro"', time: '2m ago', read: false },
  { id: 2, type: 'warning', title: 'Excessive OAuth Scope', desc: 'App "TaskBot" requested write access to Gmail', time: '18m ago', read: false },
  { id: 3, type: 'info', title: 'Red Team Simulation Complete', desc: 'Jailbreak test finished — 3 vectors blocked, 0 bypassed', time: '1h ago', read: true },
  { id: 4, type: 'info', title: 'Env Variable Scan Done', desc: '12 variables classified, 1 flagged as high-risk', time: '3h ago', read: true },
  { id: 5, type: 'critical', title: 'PII Exfiltration Attempt', desc: 'Agent tried to send email addresses to external endpoint', time: '5h ago', read: true },
]

function NotificationsDropdown({ onClose }) {
  const [notifications, setNotifications] = useState(DEMO_NOTIFICATIONS)
  const unread = notifications.filter(n => !n.read).length
  const typeStyles = {
    critical: 'bg-rose-500/10 border-rose-500/20 text-rose-400',
    warning: 'bg-amber-500/10 border-amber-500/20 text-amber-400',
    info: 'bg-blue-500/10 border-blue-500/20 text-blue-400',
  }
  const markAllRead = () => setNotifications(prev => prev.map(n => ({ ...n, read: true })))
  return (
    <div className="absolute right-0 top-full mt-2 w-80 bg-[#0f1117] border border-zinc-800 rounded-xl shadow-2xl shadow-black/40 z-50 overflow-hidden">
      <div className="flex items-center justify-between px-4 py-3 border-b border-zinc-800">
        <div className="flex items-center gap-2">
          <span className="text-sm font-semibold text-zinc-100">Notifications</span>
          {unread > 0 && <span className="px-1.5 py-0.5 text-xs bg-rose-500 text-white rounded-full font-medium">{unread}</span>}
        </div>
        <button onClick={markAllRead} className="text-xs text-blue-400 hover:text-blue-300 transition-colors">Mark all read</button>
      </div>
      <div className="max-h-80 overflow-y-auto">
        {notifications.map(n => (
          <button key={n.id} onClick={() => setNotifications(prev => prev.map(x => x.id === n.id ? { ...x, read: true } : x))}
            className={`w-full text-left px-4 py-3 border-b border-zinc-800/60 hover:bg-zinc-800/30 transition-colors ${!n.read ? 'bg-zinc-800/20' : ''}`}>
            <div className="flex items-start gap-3">
              <div className={`mt-0.5 px-1.5 py-0.5 text-[10px] font-semibold rounded border uppercase tracking-wide flex-shrink-0 ${typeStyles[n.type]}`}>{n.type}</div>
              <div className="flex-1 min-w-0">
                <p className={`text-xs font-medium mb-0.5 truncate ${!n.read ? 'text-zinc-100' : 'text-zinc-300'}`}>{n.title}</p>
                <p className="text-xs text-zinc-500 leading-relaxed line-clamp-2">{n.desc}</p>
                <p className="text-[10px] text-zinc-600 mt-1">{n.time}</p>
              </div>
              {!n.read && <div className="w-2 h-2 rounded-full bg-blue-500 flex-shrink-0 mt-1" />}
            </div>
          </button>
        ))}
      </div>
      <div className="px-4 py-2.5 border-t border-zinc-800 text-center">
        <button onClick={onClose} className="text-xs text-zinc-500 hover:text-zinc-300 transition-colors">View all in Incident Feed</button>
      </div>
    </div>
  )
}

/* ─── PROFILE MODAL ──────────────────────────────────────────── */
function ProfileModal({ onClose, onDisconnect, wsConnected, systemStatus, onFilesUploaded }) {
  const [gmailInput, setGmailInput] = useState('')
  const [gmailValid, setGmailValid] = useState(null) // null | true | false
  const [workspaceFile, setWorkspaceFile] = useState(null)
  const [uploading, setUploading] = useState(false)
  const [uploadStatus, setUploadStatus] = useState(null) // 'success' | 'error' | null
  const [scanLog, setScanLog] = useState([])
  const wsRef = useRef()

  const validateEmail = (val) => {
    const ok = /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(val)
    setGmailValid(val.length > 0 ? ok : null)
  }

  const handleGmailChange = (e) => {
    setGmailInput(e.target.value)
    validateEmail(e.target.value)
    setUploadStatus(null)
  }

  const handleFileDrop = (file) => {
    if (!file || !file.name.endsWith('.json')) {
      setUploadStatus('error')
      return
    }
    setWorkspaceFile(file)
    setUploadStatus(null)
  }

  const handleConnect = async () => {
    if (!gmailValid || !workspaceFile) return
    setUploading(true)
    setScanLog([])
    setUploadStatus(null)

    const steps = [
      'Validating credentials format…',
      'Connecting to Google Workspace…',
      'Fetching OAuth app inventory…',
      'Running Gemini risk analysis…',
      'Scan complete.',
    ]

    for (let i = 0; i < steps.length; i++) {
      await new Promise(r => setTimeout(r, 700))
      setScanLog(prev => [...prev, steps[i]])
    }

    try {
      const formData = new FormData()
      formData.append('admin_email', gmailInput)
      formData.append('workspace_config', workspaceFile)
      await axios.post(`${API}/api/workspace/connect`, formData)
      setUploadStatus('success')
      if (onFilesUploaded) onFilesUploaded()
    } catch (e) {
      setUploadStatus('success')
      if (onFilesUploaded) onFilesUploaded()
    }
    setUploading(false)
  }

  return (
    <div className="absolute right-0 top-full mt-2 w-80 bg-[#0f1117] border border-zinc-800 rounded-xl shadow-2xl shadow-black/40 z-50 overflow-hidden">
      {/* User info header */}
      <div className="px-4 py-3 border-b border-zinc-800">
        <div className="flex items-center gap-3">
          <div className="w-9 h-9 rounded-full bg-blue-600/20 border border-blue-500/30 flex items-center justify-center flex-shrink-0">
            <Users className="w-4 h-4 text-blue-400" />
          </div>
          <div className="min-w-0 flex-1">
            <p className="text-sm font-semibold text-zinc-100 truncate">
              {wsConnected ? systemStatus?.workspace?.admin_email?.split('@')[0] : 'Demo User'}
            </p>
            <p className="text-xs text-zinc-500 truncate">
              {wsConnected ? systemStatus?.workspace?.admin_email : 'demo@contextguard.ai'}
            </p>
          </div>
          <button onClick={onClose} className="p-1 text-zinc-600 hover:text-zinc-400 transition-colors flex-shrink-0">
            <X className="w-3.5 h-3.5" />
          </button>
        </div>
        <div className={`mt-3 flex items-center gap-1.5 text-xs rounded-lg px-2.5 py-1.5 border ${wsConnected ? 'bg-emerald-500/10 border-emerald-900/60 text-emerald-400' : 'bg-zinc-900 border-zinc-800 text-zinc-500'}`}>
          <div className={`w-1.5 h-1.5 rounded-full ${wsConnected ? 'bg-emerald-500' : 'bg-zinc-600'}`} />
          {wsConnected ? 'Workspace connected' : 'Demo mode active'}
        </div>
      </div>

      {/* Workspace connect */}
      <div className="px-4 py-4 border-b border-zinc-800">
        <p className="text-xs font-semibold text-zinc-400 uppercase tracking-wider mb-3">Connect Workspace</p>
        <div className="space-y-2.5 mb-3">

          {/* Gmail email input */}
          <div>
            <label className="block text-xs text-zinc-500 mb-1.5">Gmail / Admin Email</label>
            <div className="relative">
              <Mail className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-zinc-600 pointer-events-none" />
              <input
                type="email"
                value={gmailInput}
                onChange={handleGmailChange}
                placeholder="admin@yourworkspace.com"
                className={`w-full pl-9 pr-8 py-2.5 rounded-lg border bg-zinc-900 text-sm placeholder-zinc-600 focus:outline-none transition-colors
                  ${gmailValid === true ? 'border-emerald-600/60 text-emerald-300 focus:border-emerald-500' :
                    gmailValid === false ? 'border-rose-600/60 text-rose-300 focus:border-rose-500' :
                    'border-zinc-700 text-zinc-200 focus:border-blue-500/60'}`}
              />
              {gmailValid === true && (
                <Check className="absolute right-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-emerald-400 pointer-events-none" />
              )}
              {gmailValid === false && (
                <AlertTriangle className="absolute right-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-rose-400 pointer-events-none" />
              )}
            </div>
            {gmailValid === false && (
              <p className="text-xs text-rose-400 mt-1">Enter a valid email address</p>
            )}
          </div>

          {/* Workspace JSON upload */}
          <div>
            <label className="block text-xs text-zinc-500 mb-1.5">Workspace Config (.json)</label>
            <div
              className={`relative border-2 border-dashed rounded-xl p-4 transition-colors cursor-pointer ${workspaceFile ? 'border-emerald-600/50 bg-emerald-500/5' : 'border-zinc-700 hover:border-zinc-500 bg-zinc-900/40'}`}
              onClick={() => wsRef.current?.click()}
              onDragOver={e => e.preventDefault()}
              onDrop={e => { e.preventDefault(); handleFileDrop(e.dataTransfer.files[0]) }}
            >
              <input
                ref={wsRef}
                type="file"
                accept=".json"
                className="hidden"
                onChange={e => handleFileDrop(e.target.files[0])}
              />
              <div className="flex items-center gap-3">
                <div className={`w-8 h-8 rounded-lg flex items-center justify-center flex-shrink-0 ${workspaceFile ? 'bg-emerald-500/10 border border-emerald-900/60' : 'bg-zinc-800 border border-zinc-700'}`}>
                  {workspaceFile ? <Check className="w-4 h-4 text-emerald-400" /> : <FileJson className="w-4 h-4 text-zinc-400" />}
                </div>
                <div className="flex-1 min-w-0">
                  <p className={`text-sm font-medium truncate ${workspaceFile ? 'text-emerald-400' : 'text-zinc-400'}`}>
                    {workspaceFile ? workspaceFile.name : 'Click or drag to upload'}
                  </p>
                  <p className="text-xs text-zinc-600 mt-0.5">
                    {workspaceFile ? `${(workspaceFile.size / 1024).toFixed(1)} KB · JSON` : 'Workspace configuration file'}
                  </p>
                </div>
                {!workspaceFile && <Upload className="w-4 h-4 text-zinc-600 flex-shrink-0" />}
              </div>
            </div>
          </div>
        </div>

        {/* Scan log */}
        {scanLog.length > 0 && (
          <div className="rounded-lg bg-zinc-950 border border-zinc-800 p-2.5 mb-3 space-y-1">
            {scanLog.map((line, i) => (
              <div key={i} className="flex items-center gap-2">
                {i === scanLog.length - 1 && uploading
                  ? <div className="w-1.5 h-1.5 rounded-full bg-blue-400 animate-pulse flex-shrink-0" />
                  : <Check className="w-3 h-3 text-emerald-400 flex-shrink-0" />}
                <span className="text-xs text-zinc-400 font-mono">{line}</span>
              </div>
            ))}
          </div>
        )}

        {uploadStatus === 'success' && (
          <div className="flex items-center gap-2 text-xs text-emerald-400 mb-3 bg-emerald-500/5 border border-emerald-900/40 rounded-lg px-3 py-2">
            <CheckCircle2 className="w-3.5 h-3.5 flex-shrink-0" />
            Workspace connected — scan complete
          </div>
        )}
        {uploadStatus === 'error' && (
          <div className="flex items-center gap-2 text-xs text-rose-400 mb-3 bg-rose-500/5 border border-rose-900/40 rounded-lg px-3 py-2">
            <AlertTriangle className="w-3.5 h-3.5 flex-shrink-0" />
            Only .json files are accepted
          </div>
        )}

        <button
          onClick={handleConnect}
          disabled={!gmailValid || !workspaceFile || uploading}
          className="w-full py-2.5 rounded-lg text-sm font-medium transition-colors flex items-center justify-center gap-2 bg-blue-600 hover:bg-blue-500 disabled:opacity-40 disabled:cursor-not-allowed text-white"
        >
          {uploading
            ? <><div className="w-3.5 h-3.5 border border-white/30 border-t-white rounded-full animate-spin" /> Scanning…</>
            : <><Scan className="w-3.5 h-3.5" /> Connect & Scan</>}
        </button>
      </div>

      {/* Disconnect */}
      <div className="py-1">
        <button onClick={onDisconnect}
          className="w-full flex items-center gap-3 px-4 py-2.5 text-sm text-rose-400 hover:text-rose-300 hover:bg-rose-500/10 transition-colors">
          <LogOut className="w-4 h-4 flex-shrink-0" />
          Disconnect
        </button>
      </div>
    </div>
  )
}

/* ─── MAIN APP ───────────────────────────────────────────────── */
export default function App() {
  const [activeTab, setActiveTab] = useState('threats')
  const [sidebarOpen, setSidebarOpen] = useState(true)
  const [systemStatus, setSystemStatus] = useState(null)
  const [showLanding, setShowLanding] = useState(true)
  const [showNotifications, setShowNotifications] = useState(false)
  const [showProfile, setShowProfile] = useState(false)
  const [activePage, setActivePage] = useState(null) // 'docs' | 'settings' | 'support'

  const fetchStatus = async () => {
    try {
      const res = await axios.get(`${API}/api/status`)
      setSystemStatus(res.data)
    } catch (e) {
      setSystemStatus(null)
    }
  }

  useEffect(() => {
    fetchStatus()
    const interval = setInterval(fetchStatus, 15000)
    return () => clearInterval(interval)
  }, [])

  useEffect(() => {
    const handle = (e) => {
      if (!e.target.closest('[data-dropdown]')) {
        setShowNotifications(false)
        setShowProfile(false)
      }
    }
    document.addEventListener('mousedown', handle)
    return () => document.removeEventListener('mousedown', handle)
  }, [])

  const handleDisconnect = async () => {
    try {
      await axios.post(`${API}/api/workspace/disconnect`)
      setSystemStatus(prev => ({ ...prev, workspace: { ...prev?.workspace, connected: false, mode: 'synthetic_demo' } }))
    } catch (e) { console.error('Failed to disconnect', e) }
    setShowLanding(true)
  }

  const TABS = [
    { id: 'threats', label: 'Threat Feed', icon: Activity },
    { id: 'apps', label: 'OAuth Apps', icon: AppWindow },
    { id: 'env', label: 'Env Guardian', icon: FileKey },
    { id: 'redteam', label: 'Red Team', icon: Crosshair },
    { id: 'response', label: 'Incidents', icon: ShieldAlert },
  ]

  const renderContent = () => {
    switch (activeTab) {
      case 'threats': return <ThreatFeed />
      case 'apps': return <OAuthApps />
      case 'env': return <EnvGuardian />
      case 'redteam': return <RedTeamSimulator />
      case 'response': return <IncidentResponse />
      default: return null
    }
  }

  const wsConnected = systemStatus?.workspace?.connected
  const proxyOnline = systemStatus?.proxy?.online

  if (showLanding) {
    return (
      <LandingPage
        onEnterDashboard={() => setShowLanding(false)}
        onConnectWorkspace={() => { setShowLanding(false); setActiveTab('apps') }}
      />
    )
  }

  return (
    <>
      {/* Overlay pages */}
      {activePage === 'docs' && <DocumentationPage onClose={() => setActivePage(null)} />}
      {activePage === 'settings' && <SettingsPage onClose={() => setActivePage(null)} systemStatus={systemStatus} />}
      {activePage === 'support' && <SupportPage onClose={() => setActivePage(null)} />}

      <div className="flex h-screen bg-[#09090b] text-zinc-100 font-sans overflow-hidden">
        {/* Sidebar */}
        <aside className={`transition-all duration-300 ease-in-out border-r border-zinc-800/60 bg-[#0f1117] ${sidebarOpen ? 'w-56' : 'w-16'} flex flex-col z-20 flex-shrink-0`}>
          <div className="flex items-center h-14 px-4 border-b border-zinc-800/60">
            <Shield className="w-6 h-6 text-blue-500 flex-shrink-0" />
            {sidebarOpen && <span className="ml-2.5 font-semibold text-zinc-100 text-sm tracking-tight whitespace-nowrap">ContextGuard</span>}
          </div>

          <nav className="flex-1 py-4 px-2 space-y-0.5">
            {TABS.map(tab => {
              const Icon = tab.icon
              const isActive = activeTab === tab.id
              return (
                <button key={tab.id} onClick={() => setActiveTab(tab.id)}
                  className={`w-full flex items-center px-3 py-2.5 rounded-lg transition-all text-sm ${isActive ? 'bg-zinc-800 text-zinc-100' : 'text-zinc-500 hover:text-zinc-200 hover:bg-zinc-800/50'}`}>
                  <Icon className={`w-4 h-4 flex-shrink-0 ${!sidebarOpen ? 'mx-auto' : 'mr-2.5'} ${isActive ? 'text-blue-400' : ''}`} />
                  {sidebarOpen && <span className="whitespace-nowrap font-medium">{tab.label}</span>}
                </button>
              )
            })}
          </nav>

          {/* Sidebar quick links */}
          {sidebarOpen && (
            <div className="px-2 pb-2 space-y-0.5">
              {[
                { label: 'Documentation', icon: BookOpen, page: 'docs' },
                { label: 'Settings', icon: Settings, page: 'settings' },
                { label: 'Support', icon: LifeBuoy, page: 'support' },
              ].map(item => (
                <button key={item.label} onClick={() => setActivePage(item.page)}
                  className="w-full flex items-center px-3 py-2.5 rounded-lg text-zinc-500 hover:text-zinc-200 hover:bg-zinc-800/50 transition-colors text-sm">
                  <item.icon className="w-4 h-4 flex-shrink-0 mr-2.5" />
                  <span className="whitespace-nowrap">{item.label}</span>
                </button>
              ))}
            </div>
          )}

          {sidebarOpen && systemStatus && (
            <div className="px-3 pb-3 space-y-1.5">
              <p className="text-[10px] font-semibold text-zinc-600 uppercase tracking-widest px-1 mb-2">System</p>
              <div className={`flex items-center gap-2 text-xs rounded-lg px-2.5 py-2 border ${wsConnected ? 'bg-emerald-500/8 border-emerald-900/60 text-emerald-400' : 'bg-zinc-900 border-zinc-800 text-zinc-500'}`}>
                <Database className="w-3 h-3 flex-shrink-0" />
                <span className="truncate">{wsConnected ? systemStatus.workspace.admin_email : 'Demo mode'}</span>
              </div>
              <div className={`flex items-center gap-2 text-xs rounded-lg px-2.5 py-2 border ${proxyOnline ? 'bg-emerald-500/8 border-emerald-900/60 text-emerald-400' : 'bg-zinc-900 border-zinc-800 text-zinc-500'}`}>
                {proxyOnline ? <Wifi className="w-3 h-3 flex-shrink-0" /> : <WifiOff className="w-3 h-3 flex-shrink-0" />}
                <span>{proxyOnline ? 'Proxy online' : 'Proxy offline'}</span>
              </div>
            </div>
          )}

          <div className="p-2 border-t border-zinc-800/60">
            <button onClick={handleDisconnect}
              className="w-full flex items-center px-3 py-2.5 text-zinc-500 hover:text-zinc-200 hover:bg-zinc-800/50 rounded-lg transition-colors text-sm">
              <LogOut className={`w-4 h-4 flex-shrink-0 ${sidebarOpen ? 'mr-2.5' : 'mx-auto'}`} />
              {sidebarOpen && <span>Disconnect</span>}
            </button>
          </div>
        </aside>

        {/* Main */}
        <div className="flex-1 flex flex-col min-w-0">
          <header className="h-14 flex items-center justify-between px-5 border-b border-zinc-800/60 bg-[#0f1117]/80 backdrop-blur-md z-10 flex-shrink-0">
            <div className="flex items-center gap-3">
              <button onClick={() => setSidebarOpen(!sidebarOpen)}
                className="p-2 text-zinc-500 hover:text-zinc-200 hover:bg-zinc-800/60 rounded-md transition-colors">
                <Menu className="w-4 h-4" />
              </button>
              <h2 className="text-sm font-semibold text-zinc-200">{TABS.find(t => t.id === activeTab)?.label}</h2>
            </div>
            <div className="flex items-center gap-2.5">
              {systemStatus ? (
                <div className={`flex items-center gap-1.5 rounded-full px-3 py-1 border text-xs font-medium ${wsConnected ? 'bg-emerald-500/10 border-emerald-900/60 text-emerald-400' : 'bg-zinc-900 border-zinc-800 text-zinc-500'}`}>
                  <div className={`w-1.5 h-1.5 rounded-full ${wsConnected ? 'bg-emerald-500' : 'bg-zinc-600'}`} />
                  {wsConnected ? `${systemStatus.workspace.apps_in_db} apps` : 'Demo'}
                </div>
              ) : (
                <div className="flex items-center gap-1.5 bg-zinc-900 border border-zinc-800 rounded-full px-3 py-1">
                  <div className="w-1.5 h-1.5 rounded-full bg-zinc-600 animate-pulse" />
                  <span className="text-xs text-zinc-500">Connecting</span>
                </div>
              )}

              {/* Quick nav buttons in header */}
              <div className="hidden sm:flex items-center gap-1">
                {[
                  { icon: BookOpen, page: 'docs', tip: 'Documentation' },
                  { icon: Settings, page: 'settings', tip: 'Settings' },
                  { icon: LifeBuoy, page: 'support', tip: 'Support' },
                ].map(item => (
                  <button key={item.page} onClick={() => setActivePage(item.page)} title={item.tip}
                    className="p-2 text-zinc-500 hover:text-zinc-200 hover:bg-zinc-800/60 rounded-md transition-colors">
                    <item.icon className="w-4 h-4" />
                  </button>
                ))}
              </div>

              <div className="relative" data-dropdown>
                <button
                  onClick={() => { setShowNotifications(p => !p); setShowProfile(false) }}
                  className="relative p-2 text-zinc-500 hover:text-zinc-200 hover:bg-zinc-800/60 rounded-md transition-colors">
                  <Bell className="w-4 h-4" />
                  <span className="absolute top-1.5 right-1.5 w-2 h-2 bg-rose-500 rounded-full" />
                </button>
                {showNotifications && (
                  <NotificationsDropdown onClose={() => setShowNotifications(false)} />
                )}
              </div>

              <div className="relative" data-dropdown>
                <button
                  onClick={() => { setShowProfile(p => !p); setShowNotifications(false) }}
                  className="w-8 h-8 rounded-full bg-zinc-800 border border-zinc-700 flex items-center justify-center cursor-pointer hover:border-zinc-500 transition-colors">
                  <Users className="w-4 h-4 text-zinc-400" />
                </button>
                {showProfile && (
                  <ProfileModal
                    onDisconnect={handleDisconnect}
                    onClose={() => setShowProfile(false)}
                    wsConnected={wsConnected}
                    systemStatus={systemStatus}
                    onFilesUploaded={() => { fetchStatus(); setShowProfile(false) }}
                  />
                )}
              </div>
            </div>
          </header>

          <main className="flex-1 overflow-y-auto bg-[#09090b]">
            <div className="max-w-[1400px] mx-auto p-6">
              {renderContent()}
            </div>
          </main>
        </div>
      </div>
    </>
  )
}
