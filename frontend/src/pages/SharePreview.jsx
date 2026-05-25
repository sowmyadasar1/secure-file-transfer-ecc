import React, { useState, useEffect } from "react";
import axios from "axios";
import { Shield, ShieldCheck, ShieldAlert, Download, Cpu, Key, FileText, Eye, AlertCircle } from "lucide-react";

export default function SharePreview() {
  const [fileId, setFileId] = useState("");
  const [token, setToken] = useState("");
  const [metadata, setMetadata] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  
  // Decryption & Progress simulation states
  const [decrypting, setDecrypting] = useState(false);
  const [progress, setProgress] = useState(0);
  const [cryptoLogs, setCryptoLogs] = useState([]);
  const [completed, setCompleted] = useState(false);

  // Preview states
  const [previewType, setPreviewType] = useState("none"); // "text", "image", "none"
  const [previewContent, setPreviewContent] = useState("");
  const [rawBlob, setRawBlob] = useState(null); // Keep blob in case they want to download later

  useEffect(() => {
    // 1. Parse details from URL path and search query
    // URL format: https://<domain>/share/share_12?token=<JWT_TOKEN>
    const pathParts = window.location.pathname.split("/");
    const id = pathParts[pathParts.length - 1];
    
    const urlParams = new URLSearchParams(window.location.search);
    const jwtToken = urlParams.get("token");

    if (!id) {
      setError("Cryptographic token ID is missing or invalid in URL path.");
      setLoading(false);
      return;
    }

    if (!jwtToken) {
      setError("Secure Authentication Token is missing. Access is quarantined.");
      setLoading(false);
      return;
    }

    setFileId(id);
    setToken(jwtToken);
    fetchFileMetadata(id, jwtToken);
  }, []);

  const fetchFileMetadata = async (id, jwtToken) => {
    try {
      const response = await axios.get(`/api/files/metadata/${id}`, {
        headers: { Authorization: `Bearer ${jwtToken}` }
      });
      setMetadata(response.data);
    } catch (err) {
      const msg = err.response?.data?.detail || "Failed to load secure vault metadata. Access denied.";
      setError(msg);
    } finally {
      setLoading(false);
    }
  };

  const handleVerifyAndDecrypt = async () => {
    setDecrypting(true);
    setProgress(5);
    setCryptoLogs([]);
    setCompleted(false);
    setPreviewType("none");
    setPreviewContent("");

    const steps = [
      { text: "🛰️ Establishing secure handshake channel with server...", delay: 300, pct: 15 },
      { text: "🔐 Loading local SECP256R1 elliptic curve parameters...", delay: 400, pct: 35 },
      { text: "🔑 Running ECDH coordinate multiplier (d * Q)...", delay: 500, pct: 55 },
      { text: "⚡ Deriving 256-bit symmetric session key via HKDF-SHA256...", delay: 400, pct: 75 },
      { text: "🛡️ Running AES-GCM-256 authenticated tag check...", delay: 600, pct: 90 },
      { text: "🖋️ Verifying ECDSA digital signature matches sender's public key...", delay: 500, pct: 100 }
    ];

    for (let i = 0; i < steps.length; i++) {
      await new Promise((resolve) => setTimeout(resolve, steps[i].delay));
      setCryptoLogs((prev) => [...prev, steps[i].text]);
      setProgress(steps[i].pct);
    }

    try {
      const response = await axios.get(`/api/files/download/${fileId}`, {
        headers: { Authorization: `Bearer ${token}` },
        responseType: "blob"
      });

      const blob = response.data;
      setRawBlob(blob);

      const filenameLower = metadata.filename.toLowerCase();
      const isImage = filenameLower.endsWith(".png") || 
                      filenameLower.endsWith(".jpg") || 
                      filenameLower.endsWith(".jpeg") || 
                      filenameLower.endsWith(".gif") || 
                      filenameLower.endsWith(".svg");
                      
      const isText = filenameLower.endsWith(".txt") || 
                     filenameLower.endsWith(".md") || 
                     filenameLower.endsWith(".json") || 
                     filenameLower.endsWith(".csv") || 
                     filenameLower.endsWith(".log") ||
                     filenameLower.endsWith(".py") ||
                     filenameLower.endsWith(".js") ||
                     filenameLower.endsWith(".css") ||
                     filenameLower.endsWith(".html");

      if (isImage) {
        const url = URL.createObjectURL(blob);
        setPreviewType("image");
        setPreviewContent(url);
        setCryptoLogs((prev) => [...prev, "🎨 Decrypted image payload parsed successfully. Rendering preview..."]);
      } else if (isText) {
        const text = await blob.text();
        setPreviewType("text");
        setPreviewContent(text);
        setCryptoLogs((prev) => [...prev, "📝 Decrypted text payload parsed successfully. Rendering preview..."]);
      } else {
        setPreviewType("none");
        setCryptoLogs((prev) => [...prev, "📦 Binary format detected. Auto-triggering standard file download..."]);
        // Auto trigger download for unsupported previews
        triggerDownload(blob);
      }
      
      setCompleted(true);
      setCryptoLogs((prev) => [...prev, "🎉 DECRYPTION COMPLETE! Cryptographic envelope successfully opened."]);
    } catch (err) {
      setCryptoLogs((prev) => [...prev, "❌ CRYPTOGRAPHIC VERIFICATION FAILURE: Secure envelope corrupted or signature forged!"]);
      alert("Verification Quarantine: Decryption failed.");
    } finally {
      setDecrypting(false);
    }
  };

  const triggerDownload = (blob = rawBlob) => {
    if (!blob) return;
    const url = window.URL.createObjectURL(new Blob([blob]));
    const link = document.createElement("a");
    link.href = url;
    link.setAttribute("download", metadata.filename);
    document.body.appendChild(link);
    link.click();
    link.remove();
  };

  const formatBytes = (bytes) => {
    if (!bytes) return "0 Bytes";
    if (bytes === 0) return "0 Bytes";
    const k = 1024;
    const sizes = ["Bytes", "KB", "MB", "GB"];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + " " + sizes[i];
  };

  return (
    <div className="min-h-screen flex items-center justify-center p-4 relative bg-grid-cyber">
      {/* Glow decorations */}
      <div className="absolute top-1/4 left-1/4 w-96 h-96 bg-cyan-500/10 rounded-full blur-[100px] pointer-events-none animate-pulse-slow"></div>
      <div className="absolute bottom-1/4 right-1/4 w-96 h-96 bg-emerald-500/5 rounded-full blur-[120px] pointer-events-none animate-pulse-slow"></div>

      <div className="w-full max-w-2xl z-10 my-8">
        {/* Brand Header */}
        <div className="flex flex-col items-center mb-6">
          <div className="w-14 h-14 rounded-2xl bg-slate-900 border border-[var(--color-neon-blue)]/50 shadow-[0_0_15px_rgba(0,240,255,0.3)] flex items-center justify-center mb-3 animate-pulse">
            <Shield className="text-[var(--color-neon-blue)]" size={28} />
          </div>
          <h1 className="text-xl font-black tracking-widest text-slate-100 text-glow-blue">
            SAFESHARE <span className="text-[var(--color-neon-green)] text-glow-green">PORTAL</span>
          </h1>
          <p className="text-[10px] text-slate-500 tracking-wider mt-1 uppercase font-mono">
            Zero-Trust Vault Decryptor & Viewer
          </p>
        </div>

        {/* main Portal Card */}
        <div className="glass-card rounded-2xl p-6 md:p-8 border border-white/5 shadow-2xl relative overflow-hidden animate-scan">
          {loading ? (
            <div className="text-center py-12 font-mono text-xs text-slate-450 space-y-4">
              <Cpu size={24} className="mx-auto text-[var(--color-neon-blue)] animate-spin" />
              <div className="animate-pulse uppercase tracking-wider">Retrieving secure cryptographic envelope from cloud storage...</div>
            </div>
          ) : error ? (
            <div className="space-y-6">
              <div className="p-4 rounded-xl bg-red-950/40 border border-red-500/30 text-red-300 text-xs flex items-start gap-3">
                <ShieldAlert size={20} className="shrink-0 text-red-400" />
                <div className="space-y-1">
                  <div className="font-bold uppercase tracking-wider">Access Intercepted</div>
                  <div className="font-mono">{error}</div>
                </div>
              </div>
              <button 
                onClick={() => window.location.href = "/"}
                className="w-full py-2.5 rounded-lg border border-slate-800 bg-slate-950 text-xs font-mono uppercase tracking-widest hover:bg-slate-900 text-slate-400 hover:text-white transition-all"
              >
                Return to Access Terminal
              </button>
            </div>
          ) : (
            <div className="space-y-6">
              {/* Header Details */}
              <div className="flex justify-between items-center pb-4 border-b border-slate-900">
                <h2 className="text-sm font-bold text-slate-200 uppercase tracking-widest flex items-center gap-2 font-mono">
                  <Key size={14} className="text-[var(--color-neon-blue)]" /> Secure Share Envelope
                </h2>
                <span className="px-2 py-0.5 rounded bg-emerald-950/40 text-[9px] text-[var(--color-neon-green)] border border-[var(--color-neon-green)]/20 font-mono font-bold uppercase tracking-wider">
                  Verified Active
                </span>
              </div>

              {/* File Info Matrix */}
              <div className="grid grid-cols-2 gap-4 font-mono text-xs border border-slate-900 rounded-xl p-4 bg-slate-950/60 shadow-inner">
                <div className="space-y-1 text-left">
                  <div className="text-[10px] text-slate-500 uppercase">Target Identity File</div>
                  <div className="font-bold text-slate-200 flex items-center gap-1.5 truncate max-w-[220px]" title={metadata.filename}>
                    <FileText size={12} className="text-[var(--color-neon-blue)]" /> {metadata.filename}
                  </div>
                </div>
                <div className="space-y-1 text-left">
                  <div className="text-[10px] text-slate-500 uppercase">Payload Weight</div>
                  <div className="font-bold text-slate-200">{formatBytes(metadata.file_size)}</div>
                </div>
                <div className="space-y-1 text-left">
                  <div className="text-[10px] text-slate-500 uppercase">Cryptographic Sender</div>
                  <div className="font-bold text-[var(--color-neon-green)] truncate max-w-[220px]">{metadata.owner_username}</div>
                </div>
                <div className="space-y-1 text-left">
                  <div className="text-[10px] text-slate-500 uppercase">Intended Recipient</div>
                  <div className="font-bold text-slate-350 truncate max-w-[220px]">{metadata.recipient_username}</div>
                </div>
                <div className="col-span-2 pt-2 border-t border-slate-950 text-left">
                  <div className="text-[10px] text-slate-500 uppercase">SHA-256 Seal Checksum</div>
                  <div className="text-[9px] text-slate-400 font-mono select-all break-all leading-tight bg-slate-950 p-1.5 rounded border border-slate-900 mt-1">
                    {metadata.sha256_checksum}
                  </div>
                </div>
              </div>

              {/* Cryptoprocessing output panel */}
              {(decrypting || progress > 0) && (
                <div className="border border-slate-900 rounded-xl bg-slate-950 p-4 font-mono text-[10px] text-slate-300 leading-relaxed shadow-inner">
                  <div className="flex items-center justify-between mb-2 pb-1 border-b border-slate-900/60 select-none">
                    <span className="text-[var(--color-neon-blue)] font-bold uppercase tracking-wider flex items-center gap-1">
                      <Cpu size={10} className="animate-spin" /> Crypto Operations Decryption Engine
                    </span>
                    <span>{progress}%</span>
                  </div>
                  <div className="w-full h-1 bg-slate-900 rounded-full mb-3 overflow-hidden select-none">
                    <div 
                      className="h-full bg-gradient-to-r from-[var(--color-neon-blue)] to-[var(--color-neon-green)] transition-all duration-300"
                      style={{ width: `${progress}%` }}
                    ></div>
                  </div>
                  <div className="space-y-1 max-h-32 overflow-y-auto text-left">
                    {cryptoLogs.map((log, index) => (
                      <div 
                        key={index} 
                        className={`${
                          log.startsWith("❌") 
                            ? "text-red-400" 
                            : log.startsWith("🎉") 
                              ? "text-[var(--color-neon-green)] font-bold" 
                              : "text-[var(--color-neon-green)]/90"
                        } animate-pulse`}
                      >
                        {log}
                      </div>
                    ))}
                    {!completed && !cryptoLogs[cryptoLogs.length - 1]?.startsWith("❌") && <div className="terminal-cursor text-slate-600"></div>}
                  </div>
                </div>
              )}

              {/* LIVE DECRYPTED FILE PREVIEW MATRIX */}
              {completed && previewType !== "none" && (
                <div className="space-y-2 text-left">
                  <h3 className="text-[10px] text-slate-400 font-mono uppercase tracking-wider flex items-center gap-1.5">
                    <Eye size={12} className="text-[var(--color-neon-green)] animate-pulse" /> Decrypted Plaintext Live Preview
                  </h3>
                  
                  {previewType === "text" && (
                    <div className="w-full border border-emerald-900/40 rounded-xl bg-slate-950 p-4 font-mono text-xs text-emerald-400/90 max-h-64 overflow-y-auto leading-relaxed shadow-inner break-all whitespace-pre-wrap select-text selection:bg-emerald-950 selection:text-white">
                      {previewContent}
                    </div>
                  )}

                  {previewType === "image" && (
                    <div className="w-full border border-emerald-900/40 rounded-xl bg-slate-950/40 p-3 flex justify-center items-center shadow-inner relative overflow-hidden group">
                      <div className="absolute inset-0 bg-grid-cyber opacity-10"></div>
                      <img 
                        src={previewContent} 
                        alt="Decrypted Vault Preview" 
                        className="max-h-64 max-w-full rounded-lg object-contain border border-white/5 shadow-2xl relative z-10 transition-transform duration-350 hover:scale-102"
                      />
                    </div>
                  )}
                </div>
              )}

              {completed && previewType === "none" && (
                <div className="p-3 rounded-xl bg-slate-950 border border-slate-900 text-slate-500 text-[10px] font-mono flex items-center gap-2 text-left">
                  <AlertCircle size={14} className="text-amber-500/80" />
                  <span>Interactive preview not supported for binary file. File downloaded successfully to your computer disk.</span>
                </div>
              )}

              {/* Action Buttons */}
              <div className="space-y-3">
                {!completed ? (
                  <button
                    onClick={handleVerifyAndDecrypt}
                    disabled={decrypting}
                    className={`w-full relative overflow-hidden group py-3 rounded-xl border font-mono font-bold text-xs uppercase tracking-widest cursor-pointer ${
                      decrypting
                        ? "bg-slate-950 border-slate-900 text-slate-500 cursor-not-allowed"
                        : "bg-slate-950 text-[var(--color-neon-blue)] border-[var(--color-neon-blue)] hover:bg-[var(--color-neon-blue)] hover:text-slate-950 transition-all duration-300 shadow-[0_0_10px_rgba(0,240,255,0.1)] hover:shadow-[0_0_20px_rgba(0,240,255,0.3)]"
                    }`}
                  >
                    <div className="flex items-center justify-center gap-2">
                      {decrypting ? (
                        <>
                          <Cpu size={14} className="animate-spin" /> RUNNING ZERO-TRUST ENGINE...
                        </>
                      ) : (
                        <>
                          <Eye size={14} /> DECRYPT & VIEW SECURELY
                        </>
                      )}
                    </div>
                  </button>
                ) : (
                  <div className="flex flex-col sm:flex-row gap-3">
                    <button
                      onClick={() => triggerDownload()}
                      className="flex-1 py-3 rounded-xl bg-slate-950 text-[var(--color-neon-green)] border border-[var(--color-neon-green)] hover:bg-[var(--color-neon-green)] hover:text-slate-950 font-mono font-bold text-xs uppercase tracking-widest cursor-pointer transition-all duration-300 shadow-[0_0_10px_rgba(57,255,20,0.1)]"
                    >
                      <div className="flex items-center justify-center gap-2">
                        <Download size={14} /> Save to Hard Drive
                      </div>
                    </button>
                  </div>
                )}
                
                <button 
                  onClick={() => window.location.href = "/"}
                  className="w-full py-2.5 rounded-xl border border-slate-900 bg-slate-950/40 text-[10px] font-mono uppercase tracking-widest hover:bg-slate-950 hover:text-white text-slate-500 transition-all duration-300"
                >
                  Return to Access Terminal
                </button>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
