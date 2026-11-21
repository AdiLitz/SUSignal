import React from 'react';
import { Shield, Radio, Activity, Terminal } from 'lucide-react';

export default function Navbar({ backendStatus }) {
  return (
    <header className="border-b border-navy-800 bg-navy-900/80 backdrop-blur-md sticky top-0 z-50">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between">
        {/* Brand */}
        <div className="flex items-center space-x-3">
          <div className="w-10 h-10 rounded-lg bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center text-cyan-400 shadow-[0_0_15px_rgba(6,182,212,0.2)]">
            <Shield className="w-5 h-5" />
          </div>
          <div>
            <div className="flex items-center space-x-2">
              <span className="font-bold text-lg tracking-tight text-white">5G SENTINEL</span>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-cyan-950 text-cyan-400 border border-cyan-800/60 font-semibold tracking-wider">
                CORE AUDITOR
              </span>
            </div>
            <p className="text-xs text-slate-400">Intelligent 5G Network Misconfiguration Scanner</p>
          </div>
        </div>

        {/* Right Status Indicators */}
        <div className="flex items-center space-x-4">
          <div className="hidden sm:flex items-center space-x-2 text-xs font-mono text-slate-400 bg-navy-950 px-3 py-1.5 rounded-md border border-navy-800">
            <Radio className="w-3.5 h-3.5 text-cyan-400 animate-pulse" />
            <span>NFs: AMF · SMF · UPF · NRF · AUSF · UDM</span>
          </div>

          {/* Backend Connection Status Pill */}
          <div className="flex items-center space-x-2 text-xs px-3 py-1.5 rounded-md bg-navy-850 border border-navy-750">
            <span
              className={`w-2 h-2 rounded-full ${
                backendStatus === 'online'
                  ? 'bg-emerald-400 shadow-[0_0_8px_rgba(52,211,153,0.6)]'
                  : backendStatus === 'offline'
                  ? 'bg-rose-500'
                  : 'bg-amber-400 animate-pulse'
              }`}
            />
            <span className="text-slate-300 font-mono text-[11px]">
              API: {backendStatus === 'online' ? 'CONNECTED' : backendStatus === 'offline' ? 'OFFLINE' : 'CHECKING...'}
            </span>
          </div>
        </div>
      </div>
    </header>
  );
}
