import React, { useState, useEffect } from 'react';
import Navbar from '../components/Navbar';
import UploadSection from '../components/UploadSection';
import VulnerabilityStats from '../components/VulnerabilityStats';
import ScanResults from '../components/ScanResults';
import { checkBackendHealth, uploadConfiguration } from '../services/api';
import { Shield, AlertTriangle, Layers, GitBranch, Terminal } from 'lucide-react';

export default function Dashboard() {
  const [backendStatus, setBackendStatus] = useState('checking');
  const [isScanning, setIsScanning] = useState(false);
  const [scanData, setScanData] = useState(null);
  const [errorMessage, setErrorMessage] = useState(null);

  // Check backend health on initial load
  useEffect(() => {
    async function verifyHealth() {
      try {
        await checkBackendHealth();
        setBackendStatus('online');
      } catch (err) {
        setBackendStatus('offline');
      }
    }
    verifyHealth();
  }, []);

  const handleScanStart = async (file) => {
    setIsScanning(true);
    setErrorMessage(null);

    try {
      const result = await uploadConfiguration(file);
      setScanData(result);
    } catch (err) {
      setErrorMessage(err.message || 'An error occurred while scanning configuration.');
    } finally {
      setIsScanning(false);
    }
  };

  return (
    <div className="min-h-screen bg-navy-950 text-slate-100 flex flex-col">
      <Navbar backendStatus={backendStatus} />

      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-8 space-y-8">
        {/* Hero Section */}
        <div className="relative rounded-2xl bg-gradient-to-b from-navy-900 to-navy-950 p-6 sm:p-8 border border-navy-800 overflow-hidden shadow-2xl">
          <div className="absolute top-0 right-0 w-96 h-96 bg-cyan-500/5 rounded-full blur-3xl pointer-events-none" />

          <div className="relative z-10 max-w-3xl">
            <div className="inline-flex items-center space-x-2 px-3 py-1 rounded-full bg-cyan-950 border border-cyan-800/80 text-cyan-400 text-xs font-mono mb-4">
              <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 animate-ping" />
              <span>5G Core Security Baseline Verification (3GPP TS 33.501)</span>
            </div>

            <h1 className="text-2xl sm:text-4xl font-extrabold text-white tracking-tight">
              Automated Misconfiguration Scanner for <span className="text-cyan-400">5G Core Network Functions</span>
            </h1>

            <p className="mt-3 text-sm sm:text-base text-slate-400 leading-relaxed">
              Upload simulated or lab 5G configuration files (AMF, SMF, UPF, NRF, AUSF, UDM) to identify unencrypted communication channels, weak authentication parameters, and vulnerable interface bindings.
            </p>

            <div className="mt-6 flex flex-wrap gap-4 text-xs font-mono text-slate-400">
              <div className="flex items-center space-x-1.5 bg-navy-850 px-3 py-1.5 rounded border border-navy-750">
                <Layers className="w-3.5 h-3.5 text-cyan-400" />
                <span>Multi-NF Detection</span>
              </div>
              <div className="flex items-center space-x-1.5 bg-navy-850 px-3 py-1.5 rounded border border-navy-750">
                <Terminal className="w-3.5 h-3.5 text-cyan-400" />
                <span>YAML / JSON Parsers</span>
              </div>
              <div className="flex items-center space-x-1.5 bg-navy-850 px-3 py-1.5 rounded border border-navy-750">
                <GitBranch className="w-3.5 h-3.5 text-cyan-400" />
                <span>Ready for Open5GS / free5GC</span>
              </div>
            </div>
          </div>
        </div>

        {/* Global Error Banner */}
        {errorMessage && (
          <div className="p-4 rounded-xl bg-rose-950/40 border border-rose-800/80 text-rose-300 flex items-start space-x-3 text-sm">
            <AlertTriangle className="w-5 h-5 text-rose-400 shrink-0 mt-0.5" />
            <div className="flex-1">
              <span className="font-semibold">Scanner Alert: </span>
              <span>{errorMessage}</span>
            </div>
            <button
              onClick={() => setErrorMessage(null)}
              className="text-xs text-rose-400 hover:text-rose-200 underline"
            >
              Dismiss
            </button>
          </div>
        )}

        {/* Upload Section */}
        <UploadSection
          onScanStart={handleScanStart}
          onError={(err) => setErrorMessage(err)}
          isScanning={isScanning}
        />

        {/* Metrics & Posture Breakdown */}
        <VulnerabilityStats summary={scanData?.summary} />

        {/* Detailed Findings & Remediation */}
        <ScanResults
          findings={scanData?.findings}
          filename={scanData?.filename}
        />
      </main>

      {/* Footer */}
      <footer className="border-t border-navy-800 bg-navy-950 py-6 text-center text-xs text-slate-500 font-mono">
        <p>SUSignal · Cybersecurity Network Function Misconfiguration Engine</p>
      </footer>
    </div>
  );
}
