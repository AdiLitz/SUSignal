import React, { useState, useRef } from 'react';
import { Upload, FileCode2, CheckCircle2, AlertTriangle, ArrowRight, RefreshCw, Sparkles } from 'lucide-react';

export default function UploadSection({ onScanStart, onScanComplete, onError, isScanning }) {
  const [dragActive, setDragActive] = useState(false);
  const [selectedFile, setSelectedFile] = useState(null);
  const fileInputRef = useRef(null);

  const handleDrag = (e) => {
    e.preventDefault();
    e.stopPropagation();
    if (e.type === 'dragenter' || e.type === 'dragover') {
      setDragActive(true);
    } else if (e.type === 'dragleave') {
      setDragActive(false);
    }
  };

  const validateAndSetFile = (file) => {
    if (!file) return;
    const name = file.name.toLowerCase();
    if (!name.endsWith('.yaml') && !name.endsWith('.yml') && !name.endsWith('.json')) {
      onError('Invalid file format. Please upload a YAML (.yaml, .yml) or JSON (.json) configuration file.');
      return;
    }
    setSelectedFile(file);
    onError(null);
  };

  const handleDrop = (e) => {
    e.preventDefault();
    e.stopPropagation();
    setDragActive(false);
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      validateAndSetFile(e.dataTransfer.files[0]);
    }
  };

  const handleFileChange = (e) => {
    if (e.target.files && e.target.files[0]) {
      validateAndSetFile(e.target.files[0]);
    }
  };

  const handleTriggerScan = async () => {
    if (!selectedFile) {
      onError('Please select a file to scan.');
      return;
    }
    onScanStart(selectedFile);
  };

  const handleLoadSample = (sampleType) => {
    let content = '';
    let filename = '';
    
    if (sampleType === 'amf_vulnerable') {
      filename = 'amf_vulnerable.yaml';
      content = `amf:
  sbi:
    scheme: http
    addr: 0.0.0.0
    port: 7777
    tls:
      enabled: false
  ngap:
    addr: 0.0.0.0
  security:
    integrity_order: [NIA0, NIA2, NIA1]
    ciphering_order: [NEA0, NEA2, NEA1]`;
    } else if (sampleType === 'smf_sample') {
      filename = 'smf_sample.json';
      content = JSON.stringify({
        smf: {
          sbi: {
            scheme: "http",
            server: { addr: "0.0.0.0", port: 7777 }
          },
          pfcp: { server: { addr: "0.0.0.0" } }
        }
      }, null, 2);
    }

    const file = new File([content], filename, { type: filename.endsWith('.json') ? 'application/json' : 'text/yaml' });
    setSelectedFile(file);
    onError(null);
  };

  return (
    <div className="bg-navy-900 border border-navy-800 rounded-xl p-6 shadow-xl relative overflow-hidden">
      {/* Subtle top cyan glow */}
      <div className="absolute top-0 left-0 right-0 h-[2px] bg-gradient-to-r from-transparent via-cyan-500/60 to-transparent" />

      <div className="flex flex-col md:flex-row md:items-center justify-between pb-5 mb-5 border-b border-navy-800 gap-4">
        <div>
          <h2 className="text-lg font-semibold text-white flex items-center gap-2">
            <Upload className="w-5 h-5 text-cyan-400" />
            5G Core Configuration Upload
          </h2>
          <p className="text-xs text-slate-400 mt-1">
            Accepts AMF, SMF, UPF, NRF, AUSF, or UDM configuration in YAML or JSON format
          </p>
        </div>

        {/* Sample file buttons for quick testing */}
        <div className="flex items-center gap-2">
          <span className="text-[11px] text-slate-500 font-mono uppercase tracking-wider">Presets:</span>
          <button
            onClick={() => handleLoadSample('amf_vulnerable')}
            className="text-xs px-2.5 py-1 rounded bg-navy-800 hover:bg-navy-750 text-cyan-300 border border-navy-700 hover:border-cyan-500/40 transition-colors flex items-center gap-1.5"
          >
            <Sparkles className="w-3 h-3 text-cyan-400" />
            Sample AMF (YAML)
          </button>
          <button
            onClick={() => handleLoadSample('smf_sample')}
            className="text-xs px-2.5 py-1 rounded bg-navy-800 hover:bg-navy-750 text-cyan-300 border border-navy-700 hover:border-cyan-500/40 transition-colors"
          >
            Sample SMF (JSON)
          </button>
        </div>
      </div>

      {/* Dropzone Area */}
      <div
        onDragEnter={handleDrag}
        onDragLeave={handleDrag}
        onDragOver={handleDrag}
        onDrop={handleDrop}
        onClick={() => fileInputRef.current?.click()}
        className={`border-2 border-dashed rounded-lg p-8 text-center cursor-pointer transition-all ${
          dragActive
            ? 'border-cyan-400 bg-cyan-950/20 shadow-[0_0_20px_rgba(6,182,212,0.15)]'
            : selectedFile
            ? 'border-cyan-500/50 bg-navy-850/60'
            : 'border-navy-700 hover:border-navy-600 bg-navy-950/50'
        }`}
      >
        <input
          ref={fileInputRef}
          type="file"
          accept=".yaml,.yml,.json"
          onChange={handleFileChange}
          className="hidden"
        />

        <div className="flex flex-col items-center justify-center space-y-3">
          <div className="w-12 h-12 rounded-full bg-navy-800 border border-navy-700 flex items-center justify-center text-cyan-400 group-hover:scale-105 transition-transform">
            <FileCode2 className="w-6 h-6" />
          </div>

          {selectedFile ? (
            <div>
              <p className="text-sm font-medium text-white flex items-center justify-center gap-2">
                <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                {selectedFile.name}
              </p>
              <p className="text-xs text-slate-400 font-mono mt-1">
                {(selectedFile.size / 1024).toFixed(1)} KB · Ready for misconfiguration inspection
              </p>
            </div>
          ) : (
            <div>
              <p className="text-sm font-medium text-slate-200">
                Drag and drop your 5G configuration file here, or <span className="text-cyan-400 underline">browse</span>
              </p>
              <p className="text-xs text-slate-400 font-mono mt-1">
                Supported formats: .yaml, .yml, .json (Max 5MB)
              </p>
            </div>
          )}
        </div>
      </div>

      {/* Action Footer */}
      <div className="mt-4 flex items-center justify-between">
        <div className="text-xs text-slate-400">
          {selectedFile ? 'File attached. Click Start Security Scan to analyze.' : 'No file chosen.'}
        </div>

        <div className="flex items-center space-x-3">
          {selectedFile && (
            <button
              onClick={(e) => {
                e.stopPropagation();
                setSelectedFile(null);
                if (fileInputRef.current) fileInputRef.current.value = '';
              }}
              className="text-xs text-slate-400 hover:text-slate-200 px-3 py-2 rounded-lg transition-colors"
            >
              Clear
            </button>
          )}

          <button
            onClick={handleTriggerScan}
            disabled={!selectedFile || isScanning}
            className={`px-5 py-2.5 rounded-lg font-medium text-sm flex items-center space-x-2 transition-all ${
              !selectedFile || isScanning
                ? 'bg-navy-800 text-slate-500 cursor-not-allowed border border-navy-700'
                : 'bg-cyan-500 hover:bg-cyan-400 text-navy-950 shadow-[0_0_20px_rgba(6,182,212,0.3)]'
            }`}
          >
            {isScanning ? (
              <>
                <RefreshCw className="w-4 h-4 animate-spin text-navy-950" />
                <span>Auditing Rules...</span>
              </>
            ) : (
              <>
                <span>Start Security Scan</span>
                <ArrowRight className="w-4 h-4" />
              </>
            )}
          </button>
        </div>
      </div>
    </div>
  );
}
