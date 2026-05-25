import React, { useState, useEffect, useRef } from "react";
import { Terminal, ChevronDown, ChevronUp, Trash2, Shield } from "lucide-react";

export default function TerminalLogs() {
  const [logs, setLogs] = useState([
    { text: "System armed. Initializing SafeShare Cryptographic Shell v1.0.0...", type: "success", time: new Date().toLocaleTimeString() },
    { text: "Algorithms: SECP256R1 (ECC) + AES-256-GCM (AEAD) + ECDSA (Signatures) + HKDF-SHA256", type: "info", time: new Date().toLocaleTimeString() },
    { text: "Server Connection: ONLINE (Zero-Trust Session Active)", type: "success", time: new Date().toLocaleTimeString() }
  ]);
  const [isOpen, setIsOpen] = useState(true);
  const containerRef = useRef(null);

  useEffect(() => {
    // Mount a global function so any component can log cryptoprocessing in real-time
    window.addTerminalLog = (text, type = "info") => {
      setLogs((prev) => [
        ...prev,
        { text, type, time: new Date().toLocaleTimeString() }
      ]);
    };

    return () => {
      delete window.addTerminalLog;
    };
  }, []);

  useEffect(() => {
    if (containerRef.current) {
      containerRef.current.scrollTop = containerRef.current.scrollHeight;
    }
  }, [logs, isOpen]);

  const getLogColor = (type) => {
    switch (type) {
      case "success": return "text-[var(--color-neon-green)]";
      case "error": return "text-red-400 font-semibold text-glow-red";
      case "warning": return "text-amber-400 font-semibold";
      case "success-cyan": return "text-[var(--color-neon-blue)] text-glow-blue";
      case "debug": return "text-slate-500 font-mono";
      default: return "text-slate-300";
    }
  };

  const clearLogs = () => {
    setLogs([{ text: "Terminal logs flushed by security request. Ready.", type: "warning", time: new Date().toLocaleTimeString() }]);
  };

  return (
    <div className={`fixed bottom-0 left-0 right-0 z-40 transition-all duration-300 ${isOpen ? "h-64" : "h-10"} bg-slate-950/95 border-t border-slate-800 shadow-2xl flex flex-col font-mono text-xs select-text`}>
      {/* Header bar */}
      <div 
        onClick={() => setIsOpen(!isOpen)}
        className="h-10 bg-slate-900 border-b border-slate-800 px-4 flex items-center justify-between cursor-pointer hover:bg-slate-800/80 transition-colors"
      >
        <div className="flex items-center gap-2">
          <Terminal size={14} className="text-[var(--color-neon-blue)] animate-pulse" />
          <span className="font-semibold text-slate-200 tracking-wider">CRYPTOGRAPHIC OPERATIONS & CONSOLE LOGS</span>
          <span className="px-2 py-0.5 rounded bg-slate-950 text-[10px] text-[var(--color-neon-green)] border border-[var(--color-neon-green)]/20 font-bold flex items-center gap-1">
            <Shield size={10} /> ZERO-TRUST SECURE
          </span>
        </div>
        <div className="flex items-center gap-4" onClick={(e) => e.stopPropagation()}>
          <button 
            onClick={clearLogs}
            className="p-1.5 rounded hover:bg-slate-700 text-slate-400 hover:text-red-400 transition-colors"
            title="Clear Console"
          >
            <Trash2 size={13} />
          </button>
          <button 
            onClick={() => setIsOpen(!isOpen)}
            className="p-1 rounded hover:bg-slate-700 text-slate-400 hover:text-white transition-colors"
          >
            {isOpen ? <ChevronDown size={16} /> : <ChevronUp size={16} />}
          </button>
        </div>
      </div>

      {/* Terminal Output */}
      {isOpen && (
        <div 
          ref={containerRef}
          className="flex-1 p-4 overflow-y-auto bg-slate-950/40 bg-grid-cyber leading-relaxed scrollbar-thin"
        >
          {logs.map((log, index) => (
            <div key={index} className="flex gap-4 border-b border-white/[0.01] py-0.5 hover:bg-white/[0.02]">
              <span className="text-slate-600 select-none">[{log.time}]</span>
              <span className="text-[var(--color-neon-blue)] select-none font-bold">&gt;&gt;</span>
              <span className={`flex-1 break-all ${getLogColor(log.type)}`}>
                {log.text}
              </span>
            </div>
          ))}
          <div className="flex gap-4 py-0.5 select-none">
            <span className="text-slate-600">[{new Date().toLocaleTimeString()}]</span>
            <span className="text-[var(--color-neon-blue)] font-bold">&gt;&gt;</span>
            <span className="terminal-cursor text-slate-500">Listening for secure operations</span>
          </div>
        </div>
      )}
    </div>
  );
}
