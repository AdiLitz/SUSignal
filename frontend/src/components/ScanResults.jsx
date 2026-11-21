import React, { useState } from 'react';
import { ShieldCheck, ChevronDown, ChevronRight, Wrench, FileText, CheckCircle2 } from 'lucide-react';

export default function ScanResults({ findings, filename }) {
  const [expandedIndex, setExpandedIndex] = useState(0);

  if (!findings) {
    return (
      <div className="bg-navy-900 border border-navy-800 rounded-xl p-6 shadow-xl">
        <div className="flex items-center space-x-2 pb-4 mb-4 border-b border-navy-800">
          <FileText className="w-5 h-5 text-cyan-400" />
          <h2 className="text-lg font-semibold text-white">Security Findings & Recommendations</h2>
        </div>
        <div className="text-center py-12 text-slate-500">
          <p className="text-sm">Scan results will appear here after configuration analysis.</p>
        </div>
      </div>
    );
  }

  if (findings.length === 0) {
    return (
      <div className="bg-navy-900 border border-navy-800 rounded-xl p-6 shadow-xl">
        <div className="flex items-center space-x-2 pb-4 mb-4 border-b border-navy-800">
          <FileText className="w-5 h-5 text-cyan-400" />
          <h2 className="text-lg font-semibold text-white">Security Findings & Recommendations</h2>
        </div>
        <div className="text-center py-12">
          <div className="w-12 h-12 rounded-full bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 flex items-center justify-center mx-auto mb-3">
            <CheckCircle2 className="w-6 h-6" />
          </div>
          <h3 className="text-base font-semibold text-white">No Misconfigurations Detected</h3>
          <p className="text-xs text-slate-400 mt-1 max-w-md mx-auto">
            The configuration for <span className="font-mono text-cyan-300">{filename}</span> passed all active security checks and adheres to basic 3GPP hardening rules.
          </p>
        </div>
      </div>
    );
  }

  const getSeverityBadge = (severity) => {
    switch (severity?.toUpperCase()) {
      case 'CRITICAL':
        return <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-red-950 text-red-400 border border-red-800/80">CRITICAL</span>;
      case 'HIGH':
        return <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-orange-950 text-orange-400 border border-orange-800/80">HIGH</span>;
      case 'MEDIUM':
        return <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-yellow-950 text-yellow-400 border border-yellow-800/80">MEDIUM</span>;
      case 'LOW':
        return <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-cyan-950 text-cyan-400 border border-cyan-800/80">LOW</span>;
      default:
        return <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-slate-800 text-slate-400">INFO</span>;
    }
  };

  return (
    <div className="bg-navy-900 border border-navy-800 rounded-xl p-6 shadow-xl space-y-4">
      <div className="flex items-center justify-between pb-4 border-b border-navy-800">
        <div className="flex items-center space-x-2">
          <FileText className="w-5 h-5 text-cyan-400" />
          <h2 className="text-lg font-semibold text-white">Security Findings & Recommendations</h2>
        </div>
        <span className="text-xs font-mono text-slate-400">
          Showing {findings.length} misconfiguration{findings.length > 1 ? 's' : ''}
        </span>
      </div>

      <div className="space-y-3">
        {findings.map((finding, idx) => {
          const isExpanded = expandedIndex === idx;

          return (
            <div
              key={finding.rule_id || idx}
              className={`border rounded-lg transition-all ${
                isExpanded ? 'border-navy-700 bg-navy-850' : 'border-navy-800 bg-navy-950 hover:border-navy-750'
              }`}
            >
              {/* Card Header Accordion */}
              <button
                onClick={() => setExpandedIndex(isExpanded ? null : idx)}
                className="w-full text-left p-4 flex items-center justify-between gap-4"
              >
                <div className="flex items-center space-x-3 min-w-0">
                  {getSeverityBadge(finding.severity)}
                  <span className="text-xs font-mono text-cyan-400/80">{finding.rule_id}</span>
                  <span className="text-sm font-medium text-slate-200 truncate">{finding.title}</span>
                </div>

                <div className="flex items-center space-x-3 shrink-0">
                  <span className="hidden sm:inline-block text-[11px] font-mono text-slate-500 bg-navy-900 px-2 py-0.5 rounded border border-navy-800">
                    {finding.category || 'Hardening'}
                  </span>
                  {isExpanded ? (
                    <ChevronDown className="w-4 h-4 text-slate-400" />
                  ) : (
                    <ChevronRight className="w-4 h-4 text-slate-400" />
                  )}
                </div>
              </button>

              {/* Expanded Details Body */}
              {isExpanded && (
                <div className="px-4 pb-4 pt-1 border-t border-navy-800/60 space-y-3 text-xs">
                  <div>
                    <h4 className="font-mono text-slate-400 uppercase text-[10px] mb-1">Impact & Description</h4>
                    <p className="text-slate-300 leading-relaxed bg-navy-900/60 p-3 rounded border border-navy-800">
                      {finding.description}
                    </p>
                  </div>

                  <div>
                    <h4 className="font-mono text-emerald-400 uppercase text-[10px] mb-1 flex items-center gap-1.5">
                      <Wrench className="w-3.5 h-3.5" />
                      Remediation Steps
                    </h4>
                    <p className="text-emerald-300/90 leading-relaxed bg-emerald-950/20 p-3 rounded border border-emerald-900/40 font-mono">
                      {finding.remediation}
                    </p>
                  </div>
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}
