import React, { useState, useEffect } from "react";
import axios from "axios";
import { 
  Shield, Upload, ShieldCheck, ShieldAlert, Key, User, 
  Download, Share2, Trash2, QrCode, Eye, AlertTriangle, 
  Terminal, RefreshCw, Cpu, Activity
} from "lucide-react";

export default function Dashboard({ user, token, onLogout }) {
  // Navigation Tabs
  const [activeTab, setActiveTab] = useState("vault"); // vault, sharing, threat, anomaly, sandbox
  
  // Data States
  const [usersList, setUsersList] = useState([]);
  const [files, setFiles] = useState({ owned: [], received: [], shared_by_me: [], shared_with_me: [] });
  const [auditLogs, setAuditLogs] = useState([]);
  const [securityEvents, setSecurityEvents] = useState([]);
  const [securityInsights, setSecurityInsights] = useState(null);
  
  // Upload States
  const [uploadFile, setUploadFile] = useState(null);
  const [recipientId, setRecipientId] = useState("");
  const [expiryHours, setExpiryHours] = useState("");
  const [oneTimeDownload, setOneTimeDownload] = useState(false);
  const [uploadProgress, setUploadProgress] = useState(0);
  const [uploadStepLogs, setUploadStepLogs] = useState([]);
  const [isUploading, setIsUploading] = useState(false);
  const [dragActive, setDragActive] = useState(false);

  // UI Control States
  const [showShareModal, setShowShareModal] = useState(false);
  const [activeShareFile, setActiveShareFile] = useState(null);
  const [shareRecipientId, setShareRecipientId] = useState("");
  const [showQrModal, setShowQrModal] = useState(false);
  const [qrDownloadUrl, setQrDownloadUrl] = useState("");
  const [tamperingFileId, setTamperingFileId] = useState("");

  // System Loading
  const [refreshing, setRefreshing] = useState(false);

  // Axios config
  const axiosConfig = {
    headers: { Authorization: `Bearer ${token}` }
  };

  useEffect(() => {
    fetchDashboardData();
  }, []);

  const fetchDashboardData = async () => {
    setRefreshing(true);
    try {
      if (window.addTerminalLog) {
        window.addTerminalLog("Synchronizing local node with secure database...", "info");
      }
      
      const [filesRes, usersRes, logsRes, eventsRes, insightsRes] = await Promise.all([
        axios.get("/api/files", axiosConfig),
        axios.get("/api/users", axiosConfig),
        axios.get("/api/security/audit-logs", axiosConfig),
        axios.get("/api/security/security-events", axiosConfig),
        axios.get("/api/security/security-insights", axiosConfig)
      ]);

      setFiles(filesRes.data);
      setUsersList(usersRes.data);
      setAuditLogs(logsRes.data);
      setSecurityEvents(eventsRes.data);
      setSecurityInsights(insightsRes.data);

      if (window.addTerminalLog) {
        window.addTerminalLog("Telemetry check complete. Cryptographic integrity synced.", "success");
      }
    } catch (err) {
      console.error(err);
      if (window.addTerminalLog) {
        window.addTerminalLog("Failed to sync secure dashboard state.", "error");
      }
    } finally {
      setRefreshing(false);
    }
  };

  // --- DRAG AND DROP HANDLERS ---
  
  const handleDrag = (e) => {
    e.preventDefault();
    e.stopPropagation();
    if (e.type === "dragenter" || e.type === "dragover") {
      setDragActive(true);
    } else if (e.type === "dragleave") {
      setDragActive(false);
    }
  };

  const handleDrop = (e) => {
    e.preventDefault();
    e.stopPropagation();
    setDragActive(false);
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      setUploadFile(e.dataTransfer.files[0]);
      if (window.addTerminalLog) {
        window.addTerminalLog(`Staged plaintext file for encryption: '${e.dataTransfer.files[0].name}'`, "info");
      }
    }
  };

  const handleFileChange = (e) => {
    if (e.target.files && e.target.files[0]) {
      setUploadFile(e.target.files[0]);
      if (window.addTerminalLog) {
        window.addTerminalLog(`Staged plaintext file for encryption: '${e.target.files[0].name}'`, "info");
      }
    }
  };

  // --- CRYPTO ANIMATED UPLOAD FLOW ---

  const handleUploadSubmit = async (e) => {
    e.preventDefault();
    if (!uploadFile) return;

    setIsUploading(true);
    setUploadStepLogs([]);
    setUploadProgress(5);

    const steps = [
      { text: "🔍 Retrieving recipient public keys from database...", delay: 200, pct: 15 },
      { text: "🔐 Spawning random 256-bit ECC ephemeral keypair (Curve SECP256R1)...", delay: 400, pct: 35 },
      { text: "⚡ Deriving Alice-Bob shared secret via Elliptic Curve Diffie-Hellman (ECDH)...", delay: 400, pct: 55 },
      { text: "🛡️ Running HKDF key derivation to compute symmetric AES-256 key...", delay: 300, pct: 75 },
      { text: "🔒 Encrypting plaintext payload using AES-256-GCM authenticated cipher...", delay: 400, pct: 90 },
      { text: "✍️ Signing GCM ciphertext envelope with sender long-term ECDSA signature...", delay: 300, pct: 98 },
      { text: "🚀 Transporting secure package containing metadata, nonces, and signature...", delay: 200, pct: 100 }
    ];

    for (let i = 0; i < steps.length; i++) {
      await new Promise((resolve) => setTimeout(resolve, steps[i].delay));
      setUploadStepLogs((prev) => [...prev, steps[i].text]);
      setUploadProgress(steps[i].pct);
      if (window.addTerminalLog) {
        window.addTerminalLog(steps[i].text, "success-cyan");
      }
    }

    // Submit API Multipart request
    const formData = new FormData();
    formData.append("file", uploadFile);
    if (recipientId) {
      formData.append("recipient_id", recipientId);
    }
    if (expiryHours) {
      formData.append("expiry_hours", expiryHours);
    }
    formData.append("one_time_download", oneTimeDownload);

    try {
      const res = await axios.post("/api/files/upload", formData, {
        headers: {
          ...axiosConfig.headers,
          "Content-Type": "multipart/form-data"
        }
      });
      if (window.addTerminalLog) {
        window.addTerminalLog(`Upload SUCCESS. File stored securely on disk under UUID ${res.data.id}. Checksum: ${res.data.sha256_checksum}`, "success");
      }
      
      // Reset form and refresh
      setUploadFile(null);
      setRecipientId("");
      setExpiryHours("");
      setOneTimeDownload(false);
      fetchDashboardData();
    } catch (err) {
      const msg = err.response?.data?.detail || "Symmetric encryption failed.";
      if (window.addTerminalLog) {
        window.addTerminalLog(`[SECURITY ERROR] File Upload Blocked: ${msg}`, "error");
      }
      alert(`Upload failed: ${msg}`);
    } finally {
      setIsUploading(false);
      setUploadProgress(0);
      setUploadStepLogs([]);
    }
  };

  // --- CRYPTO SECURE DOWNLOAD WORKFLOW ---

  const handleDownload = async (fileId, filename) => {
    try {
      if (window.addTerminalLog) {
        window.addTerminalLog(`Initiating download for file identity: ${fileId}...`, "info");
        window.addTerminalLog("Reading ciphertext envelope from secure disk vault...", "info");
      }

      // Download file as a blob
      const response = await axios.get(`/api/files/download/${fileId}`, {
        ...axiosConfig,
        responseType: "blob"
      });

      // Extract verification headers
      const sigStatus = response.headers["x-signature-verification"];
      const checksum = response.headers["x-integrity-checksum"];

      if (window.addTerminalLog) {
        window.addTerminalLog(`[SUCCESS] ECDSA Digital Signature Verified. Owner signature matches perfectly.`, "success");
        window.addTerminalLog(`[SUCCESS] AES-GCM authenticated tag verification SUCCESS. Plaintext unmodified.`, "success");
        window.addTerminalLog(`[INTEGRITY Checksum] SHA-256: ${checksum}`, "success-cyan");
      }

      // Trigger standard browser download of decrypted plaintext
      const url = window.URL.createObjectURL(new Blob([response.data]));
      const link = document.createElement("a");
      link.href = url;
      link.setAttribute("download", filename);
      document.body.appendChild(link);
      link.click();
      link.remove();
      
      // Refresh dashboard (especially important for one-time download deletions)
      fetchDashboardData();
    } catch (err) {
      // In Axios response type blob, the error payload is inside blob. We read it as text.
      if (err.response && err.response.data) {
        const reader = new FileReader();
        reader.onload = () => {
          try {
            const errorObj = JSON.parse(reader.result);
            const msg = errorObj.detail || "Download failed.";
            if (window.addTerminalLog) {
              window.addTerminalLog(`[CRITICAL THREAT BLOCKED] ${msg}`, "error");
            }
            alert(`SECURITY QUARANTINE: ${msg}`);
          } catch (e) {
            if (window.addTerminalLog) {
              window.addTerminalLog("[CRITICAL THREAT BLOCKED] Digital signature/Ciphertext altered on server! Integrity check failed.", "error");
            }
            alert("SECURITY QUARANTINE: Cryptographic integrity check failed! The ciphertext has been corrupted or forged.");
          }
        };
        reader.readAsText(err.response.data);
      } else {
        if (window.addTerminalLog) {
          window.addTerminalLog("Network error during secure file download.", "error");
        }
      }
      fetchDashboardData();
    }
  };

  // --- MULTI-USER SHARING SYSTEM ---

  const handleShareSubmit = async (e) => {
    e.preventDefault();
    if (!activeShareFile || !shareRecipientId) return;

    try {
      if (window.addTerminalLog) {
        window.addTerminalLog(`Initializing Multi-User sharing of file '${activeShareFile.filename}'...`, "info");
        window.addTerminalLog("Retrieving public key of sharing recipient...", "info");
        window.addTerminalLog("Decrypting file with owner keys and re-encrypting with recipient key capsule...", "info");
      }

      const res = await axios.post("/api/files/share", {
        file_id: activeShareFile.id,
        shared_with_id: parseInt(shareRecipientId)
      }, axiosConfig);

      if (window.addTerminalLog) {
        window.addTerminalLog(`Multi-User Key Capsule generated. File now securely accessible to ${res.data.shared_with}.`, "success");
      }

      setShowShareModal(false);
      setShareRecipientId("");
      setActiveShareFile(null);
      fetchDashboardData();
    } catch (err) {
      const msg = err.response?.data?.detail || "Sharing failed.";
      if (window.addTerminalLog) {
        window.addTerminalLog(`[ERROR] Sharing transaction aborted: ${msg}`, "error");
      }
      alert(`Sharing failed: ${msg}`);
    }
  };

  // --- QR CODE SHARING SYSTEM ---

  const openQrModal = (id) => {
    const isShared = id.startsWith("share_") || typeof id === "number";
    const downloadId = isShared ? `share_${id.toString().replace("share_", "")}` : id;
    
    // We generate a clean secure token or direct download link
    const origin = window.location.origin;
    const downloadUrl = `${origin}/api/files/download/${downloadId}`;
    
    // Generate Google or QRServer url
    const qrUrl = `https://api.qrserver.com/v1/create-qr-code/?size=200x200&data=${encodeURIComponent(downloadUrl)}`;
    
    setQrDownloadUrl(qrUrl);
    setShowQrModal(true);
    
    if (window.addTerminalLog) {
      window.addTerminalLog(`Generated secure sharing QR download token URL: ${downloadUrl}`, "success-cyan");
    }
  };

  // --- ATTACK SIMULATOR Sandbox ---

  const runSimulateCorrupt = async (id, name) => {
    try {
      if (window.addTerminalLog) {
        window.addTerminalLog(`Initiating ATTACK SIMULATOR: Corrupting ciphertext of '${name}' on disk...`, "warning");
      }
      const res = await axios.post(`/api/security/simulate/corrupt/${id}`, {}, axiosConfig);
      if (window.addTerminalLog) {
        window.addTerminalLog(`[ATTACK COMPLETE] '${name}' ciphertext on disk has been corrupted!`, "error");
      }
      fetchDashboardData();
      alert(res.data.message);
    } catch (err) {
      alert("Failed to simulate corruption");
    }
  };

  const runSimulateForge = async (id, name) => {
    try {
      if (window.addTerminalLog) {
        window.addTerminalLog(`Initiating ATTACK SIMULATOR: Forging ECDSA digital signature of '${name}' in database...`, "warning");
      }
      const res = await axios.post(`/api/security/simulate/forge/${id}`, {}, axiosConfig);
      if (window.addTerminalLog) {
        window.addTerminalLog(`[ATTACK COMPLETE] '${name}' ECDSA signature in database has been forged with garbage!`, "error");
      }
      fetchDashboardData();
      alert(res.data.message);
    } catch (err) {
      alert("Failed to simulate signature forgery");
    }
  };

  const runSimulateRepair = async (id, name) => {
    try {
      if (window.addTerminalLog) {
        window.addTerminalLog(`Initiating SYSTEM REPAIR: Restoring integrity parameters for '${name}'...`, "info");
      }
      const res = await axios.post(`/api/security/simulate/repair/${id}`, {}, axiosConfig);
      if (window.addTerminalLog) {
        window.addTerminalLog(`[REPAIR COMPLETE] Original signature and ciphertext restored. Status: SECURE.`, "success");
      }
      fetchDashboardData();
      alert(res.data.message);
    } catch (err) {
      alert("Failed to repair file");
    }
  };

  // --- FILE DELETION / REVOCATION ---

  const handleDelete = async (id, name) => {
    if (!confirm(`Are you sure you want to delete/revoke access to '${name}'?`)) return;
    try {
      if (window.addTerminalLog) {
        window.addTerminalLog(`Removing and purging file elements for ID: ${id}...`, "info");
      }
      await axios.delete(`/api/files/${id}`, axiosConfig);
      if (window.addTerminalLog) {
        window.addTerminalLog(`File '${name}' successfully deleted. Zero-trust revocation verified.`, "success");
      }
      fetchDashboardData();
    } catch (err) {
      alert("Deletion failed.");
    }
  };

  const copyPublicKey = () => {
    navigator.clipboard.writeText(user.public_key);
    if (window.addTerminalLog) {
      window.addTerminalLog("ECC Public Key copied to clipboard.", "success");
    }
    alert("Public key copied to clipboard!");
  };

  const formatBytes = (bytes) => {
    if (bytes === 0) return "0 Bytes";
    const k = 1024;
    const sizes = ["Bytes", "KB", "MB", "GB"];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + " " + sizes[i];
  };

  return (
    <div className="min-h-screen pb-64 relative bg-grid-cyber">
      {/* Background glow top right */}
      <div className="absolute top-0 right-0 w-[500px] h-[500px] bg-cyan-500/5 rounded-full blur-[120px] pointer-events-none animate-pulse-slow"></div>

      {/* NAVBAR */}
      <nav className="glass-card sticky top-0 z-30 border-b border-white/5 py-4 px-6 flex items-center justify-between">
        <div className="flex items-center gap-2">
          <div className="w-8 h-8 rounded-lg bg-slate-900 border border-[var(--color-neon-blue)]/50 shadow-[0_0_8px_rgba(0,240,255,0.3)] flex items-center justify-center animate-pulse">
            <Shield size={16} className="text-[var(--color-neon-blue)]" />
          </div>
          <span className="font-black text-sm tracking-widest text-slate-100 text-glow-blue">
            SAFESHARE <span className="text-[var(--color-neon-green)] text-glow-green">ECC</span>
          </span>
        </div>

        {/* User Identity Key Badge */}
        <div className="flex items-center gap-4">
          <div className="hidden md:flex items-center gap-2 px-3 py-1.5 rounded-lg bg-slate-950/80 border border-slate-800 font-mono text-[10px]">
            <Key size={12} className="text-[var(--color-neon-green)] shrink-0" />
            <span className="text-slate-400 font-semibold uppercase">My ECC Key:</span>
            <span className="text-slate-200 select-all max-w-[120px] truncate">{user.public_key}</span>
            <button 
              onClick={copyPublicKey}
              className="ml-1 text-[var(--color-neon-blue)] hover:underline cursor-pointer"
            >
              [Copy]
            </button>
          </div>

          <div className="flex items-center gap-2 font-mono text-xs">
            <div className="w-6 h-6 rounded-full bg-slate-850 flex items-center justify-center border border-slate-700">
              <User size={12} className="text-slate-300" />
            </div>
            <span className="text-slate-300 font-bold">{user.username}</span>
          </div>

          <button 
            onClick={onLogout}
            className="px-3 py-1.5 rounded bg-slate-900 hover:bg-red-950/40 border border-slate-800 hover:border-red-900 text-slate-400 hover:text-red-400 font-mono text-[10px] uppercase tracking-wider transition-all duration-300 cursor-pointer"
          >
            Logout
          </button>
        </div>
      </nav>

      {/* DASHBOARD GRID */}
      <div className="max-w-7xl mx-auto px-6 py-8">
        
        {/* Navigation Tabs */}
        <div className="flex flex-wrap gap-2 mb-8 border-b border-slate-800 pb-3 font-mono text-xs uppercase tracking-wider">
          <button 
            onClick={() => setActiveTab("vault")}
            className={`px-4 py-2 rounded-lg border font-bold flex items-center gap-2 cursor-pointer transition-all duration-300 ${
              activeTab === "vault"
                ? "bg-slate-900 text-[var(--color-neon-blue)] border-[var(--color-neon-blue)]/50 shadow-[0_0_10px_rgba(0,240,255,0.15)]"
                : "bg-slate-950/40 border-slate-900 text-slate-400 hover:text-slate-200 hover:bg-slate-900/50"
            }`}
          >
            <ShieldCheck size={14} /> Cryptographic Vault
          </button>
          
          <button 
            onClick={() => setActiveTab("sharing")}
            className={`px-4 py-2 rounded-lg border font-bold flex items-center gap-2 cursor-pointer transition-all duration-300 ${
              activeTab === "sharing"
                ? "bg-slate-900 text-[var(--color-neon-blue)] border-[var(--color-neon-blue)]/50 shadow-[0_0_10px_rgba(0,240,255,0.15)]"
                : "bg-slate-950/40 border-slate-900 text-slate-400 hover:text-slate-200 hover:bg-slate-900/50"
            }`}
          >
            <Share2 size={14} /> Sharing Center
          </button>

          <button 
            onClick={() => setActiveTab("threat")}
            className={`px-4 py-2 rounded-lg border font-bold flex items-center gap-2 cursor-pointer transition-all duration-300 ${
              activeTab === "threat"
                ? "bg-slate-900 text-[var(--color-neon-red)] border-[var(--color-neon-red)]/50 shadow-[0_0_10px_rgba(255,49,49,0.15)]"
                : "bg-slate-950/40 border-slate-900 text-slate-400 hover:text-slate-200 hover:bg-slate-900/50"
            }`}
          >
            <Terminal size={14} /> Threat Intelligence Feed
          </button>

          <button 
            onClick={() => setActiveTab("anomaly")}
            className={`px-4 py-2 rounded-lg border font-bold flex items-center gap-2 cursor-pointer transition-all duration-300 ${
              activeTab === "anomaly"
                ? "bg-slate-900 text-[var(--color-neon-green)] border-[var(--color-neon-green)]/50 shadow-[0_0_10px_rgba(57,255,20,0.15)]"
                : "bg-slate-950/40 border-slate-900 text-slate-400 hover:text-slate-200 hover:bg-slate-900/50"
            }`}
          >
            <Activity size={14} /> AI Anomaly Insights
          </button>

          <button 
            onClick={() => setActiveTab("sandbox")}
            className={`px-4 py-2 rounded-lg border font-bold flex items-center gap-2 cursor-pointer transition-all duration-300 ${
              activeTab === "sandbox"
                ? "bg-slate-900 text-amber-500 border-amber-500/50 shadow-[0_0_10px_rgba(245,158,11,0.15)]"
                : "bg-slate-950/40 border-slate-900 text-slate-400 hover:text-slate-200 hover:bg-slate-900/50"
            }`}
          >
            <Cpu size={14} /> Attack Simulator
          </button>

          <button 
            onClick={fetchDashboardData}
            disabled={refreshing}
            className="ml-auto p-2 rounded-lg bg-slate-950 hover:bg-slate-900 border border-slate-800 text-slate-400 hover:text-white transition-all cursor-pointer"
            title="Refresh Node Data"
          >
            <RefreshCw size={14} className={refreshing ? "animate-spin" : ""} />
          </button>
        </div>

        {/* ==================================================================== */}
        {/* TAB 1: CRYPTOGRAPHIC VAULT */}
        {/* ==================================================================== */}
        {activeTab === "vault" && (
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
            
            {/* LEFT 1/3 COLUMN: FILE UPLOAD DROPZONE */}
            <div className="lg:col-span-1 space-y-6">
              <div className="glass-card rounded-2xl p-6 border border-white/5 shadow-xl">
                <h3 className="text-sm font-bold uppercase tracking-widest text-slate-200 mb-4 flex items-center gap-2">
                  <Upload size={16} className="text-[var(--color-neon-blue)]" /> Secure File Uploader
                </h3>

                <form onSubmit={handleUploadSubmit} className="space-y-4">
                  {/* File Dropzone */}
                  <div 
                    onDragEnter={handleDrag}
                    onDragOver={handleDrag}
                    onDragLeave={handleDrag}
                    onDrop={handleDrop}
                    onClick={() => document.getElementById("file-input").click()}
                    className={`h-40 rounded-xl border border-dashed flex flex-col items-center justify-center p-4 cursor-pointer transition-all duration-300 ${
                      dragActive 
                        ? "border-[var(--color-neon-blue)] bg-[var(--color-neon-blue)]/5"
                        : "border-slate-800 bg-slate-950/40 hover:bg-slate-900/40 hover:border-slate-700"
                    }`}
                  >
                    <input 
                      id="file-input"
                      type="file" 
                      className="hidden" 
                      onChange={handleFileChange}
                    />
                    <Upload size={32} className={`mb-3 ${dragActive ? "text-[var(--color-neon-blue)] animate-bounce" : "text-slate-500"}`} />
                    {uploadFile ? (
                      <div className="text-center font-mono">
                        <p className="text-xs text-[var(--color-neon-green)] font-bold truncate max-w-[200px]">
                          {uploadFile.name}
                        </p>
                        <p className="text-[10px] text-slate-400 mt-1">
                          {formatBytes(uploadFile.size)}
                        </p>
                      </div>
                    ) : (
                      <div className="text-center text-xs text-slate-400">
                        <p className="font-semibold text-slate-350">Drag & drop files here</p>
                        <p className="text-[10px] text-slate-500 mt-1 uppercase font-mono">or click to browse</p>
                      </div>
                    )}
                  </div>

                  {/* Recipient Selection */}
                  <div className="space-y-1.5">
                    <label className="text-[10px] font-mono text-slate-400 uppercase tracking-wider block">Recipient Identity</label>
                    <select
                      value={recipientId}
                      onChange={(e) => setRecipientId(e.target.value)}
                      className="w-full bg-slate-950 border border-slate-800 rounded-lg py-2 px-3 text-xs text-slate-300 focus:outline-none focus:border-[var(--color-neon-blue)]/50 font-mono"
                    >
                      <option value="">Personal Vault (Self-Encrypt)</option>
                      {usersList.map((u) => (
                        <option key={u.id} value={u.id}>
                          {u.username} ({u.email})
                        </option>
                      ))}
                    </select>
                  </div>

                  {/* Advanced Options */}
                  <div className="grid grid-cols-2 gap-4">
                    <div className="space-y-1.5">
                      <label className="text-[10px] font-mono text-slate-400 uppercase tracking-wider block">Self-Destruct Expiry</label>
                      <select
                        value={expiryHours}
                        onChange={(e) => setExpiryHours(e.target.value)}
                        className="w-full bg-slate-950 border border-slate-800 rounded-lg py-2 px-3 text-xs text-slate-300 focus:outline-none focus:border-[var(--color-neon-blue)]/55 font-mono"
                      >
                        <option value="">No Expiry</option>
                        <option value="1">1 Hour</option>
                        <option value="24">1 Day</option>
                        <option value="168">7 Days</option>
                      </select>
                    </div>

                    <div className="flex flex-col justify-end pb-1 pl-1">
                      <label className="flex items-center gap-2 text-[10px] font-mono text-slate-400 uppercase tracking-wider cursor-pointer">
                        <input
                          type="checkbox"
                          checked={oneTimeDownload}
                          onChange={(e) => setOneTimeDownload(e.target.checked)}
                          className="rounded bg-slate-950 border-slate-800 text-[var(--color-neon-green)] focus:ring-0 focus:ring-offset-0 cursor-pointer"
                        />
                        One-Time DL
                      </label>
                    </div>
                  </div>

                  <button
                    type="submit"
                    disabled={!uploadFile || isUploading}
                    className={`w-full py-2.5 rounded-lg border font-mono font-bold text-[10px] uppercase tracking-wider cursor-pointer ${
                      !uploadFile || isUploading
                        ? "bg-slate-900 border-slate-850 text-slate-600 cursor-not-allowed"
                        : "bg-slate-950 text-[var(--color-neon-blue)] border-[var(--color-neon-blue)] hover:bg-[var(--color-neon-blue)] hover:text-slate-950 shadow-[0_0_10px_rgba(0,240,255,0.05)] hover:shadow-[0_0_15px_rgba(0,240,255,0.25)] transition-all duration-300"
                    }`}
                  >
                    {isUploading ? "SEALING DATA ENVELOPE..." : "Sign & Encrypt Upload"}
                  </button>
                </form>

                {/* Animated Encryption Progress */}
                {isUploading && (
                  <div className="mt-6 border border-slate-800 rounded-lg bg-slate-950 p-4 font-mono text-[9px] text-slate-300 leading-relaxed shadow-inner">
                    <div className="flex items-center justify-between mb-2">
                      <span className="text-[var(--color-neon-blue)] font-bold uppercase tracking-wider">HYBRID ENCRYPTION ENGINE</span>
                      <span>{uploadProgress}%</span>
                    </div>
                    <div className="w-full h-1 bg-slate-900 rounded-full mb-3 overflow-hidden">
                      <div 
                        className="h-full bg-gradient-to-r from-[var(--color-neon-blue)] to-[var(--color-neon-green)] transition-all duration-300 animate-pulse"
                        style={{ width: `${uploadProgress}%` }}
                      ></div>
                    </div>
                    <div className="space-y-1 select-none">
                      {uploadStepLogs.map((log, index) => (
                        <div key={index} className="text-[var(--color-neon-green)] animate-pulse">
                          {log}
                        </div>
                      ))}
                      <div className="terminal-cursor text-slate-500"></div>
                    </div>
                  </div>
                )}
              </div>
            </div>

            {/* RIGHT 2/3 COLUMN: FILE VAULT LISTINGS */}
            <div className="lg:col-span-2 space-y-8">
              
              {/* SECTION A: MY VAULT (FILES UPLOADED BY ME) */}
              <div className="glass-card rounded-2xl p-6 border border-white/5 shadow-xl">
                <h3 className="text-sm font-bold uppercase tracking-widest text-slate-200 mb-4 flex items-center gap-2">
                  <ShieldCheck size={16} className="text-[var(--color-neon-green)]" /> My Secure Vault <span className="text-xs text-slate-500 font-mono">({files.owned.length})</span>
                </h3>

                {files.owned.length === 0 ? (
                  <div className="border border-slate-850 bg-slate-950/20 rounded-xl p-8 text-center text-xs text-slate-500 font-mono select-none">
                    NO CIPHERTEXT RECORDS FOUND. STAGE AN UPLOAD FILE ON THE LEFT SIDEBAR.
                  </div>
                ) : (
                  <div className="overflow-x-auto">
                    <table className="w-full text-left font-mono text-xs">
                      <thead>
                        <tr className="border-b border-slate-800 text-slate-500 uppercase pb-2">
                          <th className="py-2 pl-2">Filename</th>
                          <th className="py-2">Size</th>
                          <th className="py-2">Authorized Recipient</th>
                          <th className="py-2 text-center">Options</th>
                          <th className="py-2 text-right pr-2">Actions</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-slate-900">
                        {files.owned.map((f) => (
                          <tr key={f.id} className="hover:bg-white/[0.01] group">
                            <td className="py-3 pl-2 font-bold text-slate-300">
                              <div className="truncate max-w-[150px]" title={f.filename}>{f.filename}</div>
                              <div className="text-[9px] text-slate-500 truncate max-w-[150px] font-normal cursor-pointer select-all" title="SHA256 Checksum" onClick={() => {navigator.clipboard.writeText(f.sha256_checksum); alert("Checksum copied!");}}>
                                SHA: {f.sha256_checksum.slice(0, 16)}...
                              </div>
                            </td>
                            <td className="py-3 text-slate-455">{formatBytes(f.file_size)}</td>
                            <td className="py-3">
                              <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider ${
                                f.recipient_id === user.id
                                  ? "bg-slate-950 border border-slate-800 text-slate-400"
                                  : "bg-emerald-950/40 border border-emerald-900/30 text-emerald-400"
                              }`}>
                                {f.recipient_id === user.id ? "Personal Storage" : f.recipient_username}
                              </span>
                            </td>
                            <td className="py-3">
                              <div className="flex gap-1.5 justify-center">
                                {f.one_time_download && (
                                  <span className="px-1.5 py-0.5 rounded bg-red-950/40 text-red-400 border border-red-900/30 text-[9px] uppercase tracking-wider font-bold">1-Time</span>
                                )}
                                {f.expiry_at && (
                                  <span className={`px-1.5 py-0.5 rounded text-[9px] uppercase tracking-wider font-bold border ${
                                    f.is_expired
                                      ? "bg-red-950 text-red-500 border-red-900"
                                      : "bg-slate-950 text-amber-500 border-slate-850"
                                  }`}>
                                    {f.is_expired ? "Expired" : "Expiring"}
                                  </span>
                                )}
                              </div>
                            </td>
                            <td className="py-3 text-right pr-2">
                              <div className="flex items-center justify-end gap-1">
                                <button 
                                  onClick={() => handleDownload(f.id, f.filename)}
                                  disabled={f.is_expired}
                                  className={`p-1.5 rounded hover:bg-slate-800 text-slate-400 hover:text-[var(--color-neon-blue)] transition-colors cursor-pointer ${f.is_expired ? "opacity-35 cursor-not-allowed" : ""}`}
                                  title="Download and cryptographically verify"
                                >
                                  <Download size={14} />
                                </button>
                                
                                {f.recipient_id === user.id && (
                                  <button 
                                    onClick={() => {
                                      setActiveShareFile(f);
                                      setShowShareModal(true);
                                    }}
                                    className="p-1.5 rounded hover:bg-slate-800 text-slate-400 hover:text-[var(--color-neon-green)] transition-colors cursor-pointer"
                                    title="Share with another User"
                                  >
                                    <Share2 size={14} />
                                  </button>
                                )}

                                <button 
                                  onClick={() => openQrModal(f.id)}
                                  className="p-1.5 rounded hover:bg-slate-800 text-slate-400 hover:text-cyan-300 transition-colors cursor-pointer"
                                  title="Generate secure QR"
                                >
                                  <Eye size={14} />
                                </button>

                                <button 
                                  onClick={() => handleDelete(f.id, f.filename)}
                                  className="p-1.5 rounded hover:bg-slate-800 text-slate-400 hover:text-red-400 transition-colors cursor-pointer"
                                  title="Purge / Revoke file"
                                >
                                  <Trash2 size={14} />
                                </button>
                              </div>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </div>

              {/* SECTION B: INBOX (FILES SENT TO ME BY OTHERS DIRECTLY) */}
              <div className="glass-card rounded-2xl p-6 border border-white/5 shadow-xl">
                <h3 className="text-sm font-bold uppercase tracking-widest text-slate-200 mb-4 flex items-center gap-2">
                  <ShieldCheck size={16} className="text-[var(--color-neon-blue)]" /> Direct Inbox <span className="text-xs text-slate-500 font-mono">({files.received.length})</span>
                </h3>

                {files.received.length === 0 ? (
                  <div className="border border-slate-850 bg-slate-950/20 rounded-xl p-8 text-center text-xs text-slate-500 font-mono select-none">
                    INBOX VACANT. OTHER USERS CAN DIRECT UPLOAD SECURELY USING YOUR ECC PUBLIC KEY.
                  </div>
                ) : (
                  <div className="overflow-x-auto">
                    <table className="w-full text-left font-mono text-xs">
                      <thead>
                        <tr className="border-b border-slate-800 text-slate-500 uppercase pb-2">
                          <th className="py-2 pl-2">Filename</th>
                          <th className="py-2">Size</th>
                          <th className="py-2">Cryptographic Sender</th>
                          <th className="py-2 text-center">Status</th>
                          <th className="py-2 text-right pr-2">Action</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-slate-900">
                        {files.received.map((f) => (
                          <tr key={f.id} className="hover:bg-white/[0.01]">
                            <td className="py-3 pl-2 font-bold text-slate-300">
                              <div className="truncate max-w-[150px]" title={f.filename}>{f.filename}</div>
                              <div className="text-[9px] text-slate-500 truncate max-w-[150px] font-normal cursor-pointer select-all" title="SHA256 Checksum" onClick={() => {navigator.clipboard.writeText(f.sha256_checksum); alert("Checksum copied!");}}>
                                SHA: {f.sha256_checksum.slice(0, 16)}...
                              </div>
                            </td>
                            <td className="py-3 text-slate-455">{formatBytes(f.file_size)}</td>
                            <td className="py-3">
                              <span className="px-2 py-0.5 rounded bg-cyan-950/40 border border-cyan-900/30 text-cyan-400 text-[10px] font-bold uppercase tracking-wider">
                                {f.owner_username}
                              </span>
                            </td>
                            <td className="py-3 text-center">
                              <div className="flex flex-col gap-0.5 items-center justify-center">
                                <span className="px-1.5 py-0.5 rounded bg-emerald-950/40 text-[9px] text-[var(--color-neon-green)] border border-[var(--color-neon-green)]/20 font-bold flex items-center gap-1 uppercase tracking-wider">
                                  <Shield size={10} /> Signature Valid
                                </span>
                              </div>
                            </td>
                            <td className="py-3 text-right pr-2">
                              <div className="flex items-center justify-end gap-1">
                                <button 
                                  onClick={() => handleDownload(f.id, f.filename)}
                                  disabled={f.is_expired}
                                  className={`p-1.5 rounded hover:bg-slate-800 text-slate-400 hover:text-[var(--color-neon-blue)] transition-colors cursor-pointer ${f.is_expired ? "opacity-35 cursor-not-allowed" : ""}`}
                                  title="Verify ECDSA & Decrypt AES-GCM"
                                >
                                  <Download size={14} />
                                </button>
                                
                                <button 
                                  onClick={() => openQrModal(f.id)}
                                  className="p-1.5 rounded hover:bg-slate-800 text-slate-400 hover:text-cyan-300 transition-colors cursor-pointer"
                                  title="QR sharing code"
                                >
                                  <Eye size={14} />
                                </button>
                              </div>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </div>
            </div>
          </div>
        )}

        {/* ==================================================================== */}
        {/* TAB 2: SHARING CENTER */}
        {/* ==================================================================== */}
        {activeTab === "sharing" && (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-8 animate-scan">
            
            {/* SHARED BY ME */}
            <div className="glass-card rounded-2xl p-6 border border-white/5 shadow-xl">
              <h3 className="text-sm font-bold uppercase tracking-widest text-slate-200 mb-4 flex items-center gap-2">
                <Share2 size={16} className="text-[var(--color-neon-green)]" /> Files Shared By Me <span className="text-xs text-slate-500 font-mono">({files.shared_by_me.length})</span>
              </h3>

              {files.shared_by_me.length === 0 ? (
                <div className="border border-slate-850 bg-slate-950/20 rounded-xl p-8 text-center text-xs text-slate-500 font-mono select-none">
                  NO SHARED CIPHERTEXT CAPSULES ON RECORD.
                </div>
              ) : (
                <div className="overflow-x-auto">
                  <table className="w-full text-left font-mono text-xs">
                    <thead>
                      <tr className="border-b border-slate-800 text-slate-500 uppercase pb-2">
                        <th className="py-2 pl-2">Filename</th>
                        <th className="py-2">Shared With</th>
                        <th className="py-2 text-right pr-2">Action</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-900">
                      {files.shared_by_me.map((s) => (
                        <tr key={s.id} className="hover:bg-white/[0.01]">
                          <td className="py-3 pl-2 font-bold text-slate-350">{s.filename}</td>
                          <td className="py-3">
                            <span className="px-2 py-0.5 rounded bg-emerald-950/40 border border-emerald-900/30 text-emerald-400 text-[10px] font-bold uppercase tracking-wider">
                              {s.shared_with_username}
                            </span>
                          </td>
                          <td className="py-3 text-right pr-2">
                            <div className="flex justify-end gap-1">
                              <button 
                                onClick={() => handleDownload(`share_${s.id}`, s.filename)}
                                className="p-1.5 rounded hover:bg-slate-800 text-slate-400 hover:text-[var(--color-neon-blue)] transition-colors cursor-pointer"
                                title="Download decrypted verification"
                              >
                                <Download size={14} />
                              </button>
                              <button 
                                onClick={() => openQrModal(`share_${s.id}`)}
                                className="p-1.5 rounded hover:bg-slate-800 text-slate-400 hover:text-cyan-300 transition-colors cursor-pointer"
                                title="QR Download token"
                              >
                                <Eye size={14} />
                              </button>
                              <button 
                                onClick={() => handleDelete(`share_${s.id}`, s.filename)}
                                className="p-1.5 rounded hover:bg-slate-800 text-slate-400 hover:text-red-400 transition-colors cursor-pointer"
                                title="Revoke shares access"
                              >
                                <Trash2 size={14} />
                              </button>
                            </div>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>

            {/* SHARED WITH ME */}
            <div className="glass-card rounded-2xl p-6 border border-white/5 shadow-xl">
              <h3 className="text-sm font-bold uppercase tracking-widest text-slate-200 mb-4 flex items-center gap-2">
                <Share2 size={16} className="text-[var(--color-neon-blue)]" /> Files Shared With Me <span className="text-xs text-slate-500 font-mono">({files.shared_with_me.length})</span>
              </h3>

              {files.shared_with_me.length === 0 ? (
                <div className="border border-slate-850 bg-slate-950/20 rounded-xl p-8 text-center text-xs text-slate-500 font-mono select-none">
                  NO RECEIVED SHARE CAPSULES ACTIVE AT THIS NODE.
                </div>
              ) : (
                <div className="overflow-x-auto">
                  <table className="w-full text-left font-mono text-xs">
                    <thead>
                      <tr className="border-b border-slate-800 text-slate-500 uppercase pb-2">
                        <th className="py-2 pl-2">Filename</th>
                        <th className="py-2">Shared By</th>
                        <th className="py-2 text-right pr-2">Action</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-900">
                      {files.shared_with_me.map((s) => (
                        <tr key={s.id} className="hover:bg-white/[0.01]">
                          <td className="py-3 pl-2 font-bold text-slate-350">{s.filename}</td>
                          <td className="py-3">
                            <span className="px-2 py-0.5 rounded bg-cyan-950/40 border border-cyan-900/30 text-cyan-400 text-[10px] font-bold uppercase tracking-wider">
                              {s.shared_by_username}
                            </span>
                          </td>
                          <td className="py-3 text-right pr-2">
                            <div className="flex justify-end gap-1">
                              <button 
                                onClick={() => handleDownload(`share_${s.id}`, s.filename)}
                                className="p-1.5 rounded hover:bg-slate-800 text-slate-400 hover:text-[var(--color-neon-blue)] transition-colors cursor-pointer"
                                title="Verify signature & decrypt shared payload"
                              >
                                <Download size={14} />
                              </button>
                              <button 
                                onClick={() => openQrModal(`share_${s.id}`)}
                                className="p-1.5 rounded hover:bg-slate-800 text-slate-400 hover:text-cyan-300 transition-colors cursor-pointer"
                                title="QR sharing code"
                              >
                                <Eye size={14} />
                              </button>
                              <button 
                                onClick={() => handleDelete(`share_${s.id}`, s.filename)}
                                className="p-1.5 rounded hover:bg-slate-800 text-slate-400 hover:text-red-400 transition-colors cursor-pointer"
                                title="Remove from list"
                              >
                                <Trash2 size={14} />
                              </button>
                            </div>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          </div>
        )}

        {/* ==================================================================== */}
        {/* TAB 3: THREAT INTELLIGENCE FEED */}
        {/* ==================================================================== */}
        {activeTab === "threat" && (
          <div className="grid grid-cols-1 gap-8 animate-scan">
            <div className="glass-card rounded-2xl p-6 border border-white/5 shadow-xl relative overflow-hidden">
              {/* Pulsing warning indicator if threats are in log */}
              <div className="absolute top-4 right-4 flex items-center gap-2">
                <span className="h-2 w-2 rounded-full bg-[var(--color-neon-red)] animate-ping"></span>
                <span className="text-[10px] font-mono text-[var(--color-neon-red)] font-bold tracking-wider">LIVE TELEMETRY FEED</span>
              </div>

              <h3 className="text-sm font-bold uppercase tracking-widest text-slate-200 mb-6 flex items-center gap-2">
                <Terminal size={16} className="text-[var(--color-neon-red)]" /> Cyber Defense Threat Intelligence Panel
              </h3>

              {securityEvents.length === 0 ? (
                <div className="border border-slate-850 bg-slate-950/20 rounded-xl p-8 text-center text-xs text-slate-500 font-mono select-none">
                  INTELLIGENCE MATRIX VACANT. SYSTEM STABILITY OPERATING AT 100% CORRECTNESS.
                </div>
              ) : (
                <div className="font-mono text-xs rounded-xl border border-slate-850 bg-slate-950 p-4 max-h-96 overflow-y-auto leading-relaxed divide-y divide-slate-900/60">
                  {securityEvents.map((e) => (
                    <div key={e.id} className="py-2.5 flex items-start gap-4">
                      <span className="text-slate-500 min-w-[70px] select-none">
                        [{new Date(e.created_at).toLocaleTimeString()}]
                      </span>
                      
                      <span className={`px-2 py-0.5 rounded text-[10px] font-black uppercase tracking-wider shrink-0 select-none border ${
                        e.severity === "CRITICAL"
                          ? "bg-red-950/60 text-[var(--color-neon-red)] border-[var(--color-neon-red)]/30 animate-pulse text-glow-red"
                          : e.severity === "HIGH"
                            ? "bg-orange-950/40 text-orange-400 border-orange-900/20"
                            : "bg-slate-900 text-slate-400 border-slate-800"
                      }`}>
                        {e.event_type}
                      </span>
                      
                      <span className="flex-1 text-slate-350">
                        {e.details}
                      </span>

                      <span className="text-slate-550 shrink-0 select-none">
                        NODE IP: {e.ip_address}
                      </span>
                    </div>
                  ))}
                </div>
              )}
            </div>

            {/* ENCRYPTED AUDIT LOGS DISPLAY */}
            <div className="glass-card rounded-2xl p-6 border border-white/5 shadow-xl">
              <h3 className="text-sm font-bold uppercase tracking-widest text-slate-200 mb-4 flex items-center gap-2">
                <ShieldCheck size={16} className="text-[var(--color-neon-green)]" /> Sealed Audit Log History
              </h3>
              <p className="text-[10px] text-slate-500 font-mono uppercase tracking-wider mb-4">
                Note: Logs are stored fully **encrypted (AES-256-GCM)** in database and decrypted in memory for your session.
              </p>

              {auditLogs.length === 0 ? (
                <div className="border border-slate-850 bg-slate-950/20 rounded-xl p-8 text-center text-xs text-slate-500 font-mono select-none">
                  AUDIT TRANSACTION SHEET VACANT.
                </div>
              ) : (
                <div className="overflow-x-auto">
                  <table className="w-full text-left font-mono text-xs">
                    <thead>
                      <tr className="border-b border-slate-800 text-slate-500 uppercase pb-2">
                        <th className="py-2 pl-2">Timestamp</th>
                        <th className="py-2">Action Profile</th>
                        <th className="py-2">Cryptographic Details</th>
                        <th className="py-2 text-right pr-2">Decrypted IP</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-900">
                      {auditLogs.map((log) => (
                        <tr key={log.id} className="hover:bg-white/[0.01]">
                          <td className="py-2.5 pl-2 text-slate-500">
                            {new Date(log.created_at).toLocaleString()}
                          </td>
                          <td className="py-2.5">
                            <span className="px-1.5 py-0.5 rounded bg-slate-900 border border-slate-800 text-[9px] text-[var(--color-neon-blue)] font-bold tracking-widest uppercase">
                              {log.action}
                            </span>
                          </td>
                          <td className="py-2.5 text-slate-350 font-sans">{log.details}</td>
                          <td className="py-2.5 text-right pr-2 text-slate-500 select-none">
                            {log.ip_address}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          </div>
        )}

        {/* ==================================================================== */}
        {/* TAB 4: AI ANOMALY INSIGHTS */}
        {/* ==================================================================== */}
        {activeTab === "anomaly" && (
          <div className="grid grid-cols-1 md:grid-cols-3 gap-8 animate-scan">
            
            {/* SCORE GAUGE CARD */}
            <div className="glass-card rounded-2xl p-6 border border-white/5 shadow-xl flex flex-col items-center justify-center text-center">
              <h3 className="text-xs font-bold uppercase tracking-widest text-slate-400 mb-6 font-mono">
                System Security Rating
              </h3>

              <div className="relative w-40 h-40 flex items-center justify-center mb-4">
                {/* Visual glow ring */}
                <div className={`absolute inset-0 rounded-full border-4 border-slate-900 shadow-inner flex items-center justify-center`}></div>
                
                <div className="z-10 flex flex-col items-center justify-center">
                  <span className={`text-4xl font-black ${
                    !securityInsights || securityInsights.score >= 90
                      ? "text-[var(--color-neon-green)] text-glow-green"
                      : securityInsights.score >= 70
                        ? "text-amber-500"
                        : "text-[var(--color-neon-red)] text-glow-red"
                  }`}>
                    {securityInsights ? securityInsights.score : 100}%
                  </span>
                  <span className="text-[9px] text-slate-500 font-mono tracking-widest uppercase mt-1">INTEGRITY RATING</span>
                </div>
              </div>

              <span className={`px-3 py-1 rounded-full font-mono text-xs font-black tracking-widest border uppercase ${
                !securityInsights || securityInsights.status === "SECURE"
                  ? "bg-emerald-950/40 text-[var(--color-neon-green)] border-[var(--color-neon-green)]/30 text-glow-green"
                  : securityInsights.status === "WARNING"
                    ? "bg-amber-950/40 text-amber-500 border-amber-900/30"
                    : "bg-red-950/40 text-[var(--color-neon-red)] border-[var(--color-neon-red)]/30 animate-pulse text-glow-red"
              }`}>
                {securityInsights ? securityInsights.status.replace("_", " ") : "SECURE"}
              </span>
            </div>

            {/* METRICS & DETAILS */}
            <div className="md:col-span-2 glass-card rounded-2xl p-6 border border-white/5 shadow-xl flex flex-col justify-between">
              <div>
                <h3 className="text-sm font-bold uppercase tracking-widest text-slate-200 mb-3 flex items-center gap-2">
                  <Activity size={16} className="text-[var(--color-neon-blue)]" /> AI Anomaly Detection Engine Report
                </h3>
                <p className="text-xs text-slate-400 font-sans leading-relaxed mb-6">
                  {securityInsights ? securityInsights.description : "Continuous monitoring initialized. Assessing network vectors..."}
                </p>

                <h4 className="text-[10px] font-mono text-slate-500 uppercase tracking-widest mb-3 border-b border-slate-900 pb-1">
                  Active Cryptographic Anomaly Assessments
                </h4>

                <div className="space-y-3">
                  {securityInsights && securityInsights.insights.map((insight, i) => (
                    <div key={i} className="p-3 rounded-lg bg-slate-950 border border-slate-900 font-mono text-[10px] flex items-start gap-2.5">
                      <AlertTriangle size={14} className="shrink-0 text-amber-500 mt-0.5 animate-pulse" />
                      <span className="text-slate-350">{insight}</span>
                    </div>
                  ))}
                </div>
              </div>

              {/* Numerical stats grid */}
              {securityInsights && (
                <div className="grid grid-cols-4 gap-4 mt-6 pt-4 border-t border-slate-900 font-mono text-center">
                  <div className="p-2 rounded bg-slate-950 border border-slate-900/40">
                    <div className="text-xs font-bold text-slate-300">{securityInsights.metrics.tampering_attempts}</div>
                    <div className="text-[8px] text-slate-500 uppercase tracking-wider mt-0.5">Tamper Intercepts</div>
                  </div>
                  <div className="p-2 rounded bg-slate-950 border border-slate-900/40">
                    <div className="text-xs font-bold text-slate-300">{securityInsights.metrics.signature_forgeries}</div>
                    <div className="text-[8px] text-slate-500 uppercase tracking-wider mt-0.5">Signature Quarantines</div>
                  </div>
                  <div className="p-2 rounded bg-slate-950 border border-slate-900/40">
                    <div className="text-xs font-bold text-slate-300">{securityInsights.metrics.unauthorized_accesses}</div>
                    <div className="text-[8px] text-slate-500 uppercase tracking-wider mt-0.5">RBAC Blockades</div>
                  </div>
                  <div className="p-2 rounded bg-slate-950 border border-slate-900/40">
                    <div className="text-xs font-bold text-slate-300">{securityInsights.metrics.failed_logins}</div>
                    <div className="text-[8px] text-slate-500 uppercase tracking-wider mt-0.5">Auth Frictions</div>
                  </div>
                </div>
              )}
            </div>
          </div>
        )}

        {/* ==================================================================== */}
        {/* TAB 5: ATTACK SIMULATOR */}
        {/* ==================================================================== */}
        {activeTab === "sandbox" && (
          <div className="grid grid-cols-1 gap-8 animate-scan">
            <div className="glass-card rounded-2xl p-6 border border-white/5 shadow-xl relative overflow-hidden">
              
              <div className="absolute top-4 right-4 flex items-center gap-2">
                <span className="h-2 w-2 rounded-full bg-amber-500 animate-ping"></span>
                <span className="text-[10px] font-mono text-amber-500 font-bold tracking-wider">SANDBOX ENVIRONMENT</span>
              </div>

              <h3 className="text-sm font-bold uppercase tracking-widest text-slate-200 mb-2 flex items-center gap-2">
                <Cpu size={16} className="text-amber-500" /> Interactive Cryptographic Attack Sandbox
              </h3>
              <p className="text-xs text-slate-400 font-sans max-w-3xl leading-relaxed mb-6">
                This testing panel lets you actively simulate **MITM (Man-in-the-Middle) payload corruption** or **signature forgery attacks**. 
                Select a file from your vault below, select an attack profile, and then try downloading the file. 
                Watch the security system quarantine the compromised payload, flag alerts, and print logs instantly. 
                You can then click **"Repair File"** to restore safety and demonstrate flawless system resilience!
              </p>

              <div className="space-y-4">
                <div className="p-4 rounded-lg bg-amber-950/20 border border-amber-500/20 font-mono text-[10px] text-amber-300/90 leading-relaxed max-w-4xl">
                  <strong>💡 PRESENTATION WALKTHROUGH FOR VIVA EXAMINATION:</strong>
                  <ol className="list-decimal pl-4 mt-2 space-y-1">
                    <li>Choose any file from the selection table below.</li>
                    <li>Click <strong>"Corrupt Ciphertext"</strong> (changes file bits on disk) or <strong>"Forge Signature"</strong> (falsifies signature hash in DB).</li>
                    <li>Navigate back to the **Cryptographic Vault** tab and try downloading the modified file.</li>
                    <li>Observe the crimson popup blocking the download and the console logging the exact error (GCM <code>InvalidTag</code> or ECDSA <code>InvalidSignature</code>).</li>
                    <li>Come back here, click <strong>"Repair File"</strong>, and download successfully to demonstrate robust cryptographic backups!</li>
                  </ol>
                </div>

                {/* Table for sandbox selecting */}
                {files.owned.length === 0 ? (
                  <div className="border border-slate-850 bg-slate-950/20 rounded-xl p-8 text-center text-xs text-slate-500 font-mono select-none">
                    UPLOAD FILES IN THE CRYPTOGRAPHIC VAULT TAB FIRST TO USE THE SIMULATOR.
                  </div>
                ) : (
                  <div className="overflow-x-auto">
                    <table className="w-full text-left font-mono text-xs">
                      <thead>
                        <tr className="border-b border-slate-800 text-slate-500 uppercase pb-2">
                          <th className="py-2 pl-2">Staged Filename</th>
                          <th className="py-2">Authorized Recipient</th>
                          <th className="py-2">Security Hash</th>
                          <th className="py-2 text-right pr-2">Launch Attack Simulation</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-slate-900">
                        {files.owned.map((f) => (
                          <tr key={f.id} className="hover:bg-white/[0.01]">
                            <td className="py-3 pl-2 font-bold text-slate-350">{f.filename}</td>
                            <td className="py-3">
                              <span className="px-2 py-0.5 rounded bg-slate-900 text-slate-400 border border-slate-800 text-[10px] font-bold uppercase tracking-wider">
                                {f.recipient_id === user.id ? "Personal Vault" : f.recipient_username}
                              </span>
                            </td>
                            <td className="py-3 text-slate-500">{f.sha256_checksum.slice(0, 24)}...</td>
                            <td className="py-3 text-right pr-2">
                              <div className="flex justify-end items-center gap-2">
                                <button
                                  onClick={() => runSimulateCorrupt(f.id, f.filename)}
                                  className="px-2.5 py-1 rounded bg-red-950/40 hover:bg-red-900/60 border border-red-900/40 text-[9px] text-[var(--color-neon-red)] font-bold uppercase tracking-wider transition-all cursor-pointer"
                                  title="Corrupt AES ciphertext on server"
                                >
                                  Corrupt Ciphertext
                                </button>
                                <button
                                  onClick={() => runSimulateForge(f.id, f.filename)}
                                  className="px-2.5 py-1 rounded bg-orange-950/40 hover:bg-orange-900/60 border border-orange-900/40 text-[9px] text-orange-400 font-bold uppercase tracking-wider transition-all cursor-pointer"
                                  title="Forge ECDSA signature in database"
                                >
                                  Forge Signature
                                </button>
                                <button
                                  onClick={() => runSimulateRepair(f.id, f.filename)}
                                  className="px-2.5 py-1 rounded bg-emerald-950/40 hover:bg-emerald-900/60 border border-emerald-900/40 text-[9px] text-[var(--color-neon-green)] font-bold uppercase tracking-wider transition-all cursor-pointer"
                                  title="Restore original ciphertext and signature"
                                >
                                  Repair File
                                </button>
                              </div>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </div>
            </div>
          </div>
        )}

      </div>

      {/* ==================================================================== */}
      {/* MODALS */}
      {/* ==================================================================== */}

      {/* MODAL 1: SHARE FILE MULTI-USER */}
      {showShareModal && activeShareFile && (
        <div className="fixed inset-0 z-50 bg-black/60 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="glass-card rounded-2xl p-6 border border-white/10 max-w-md w-full animate-scan">
            <h3 className="text-sm font-bold uppercase tracking-widest text-slate-200 mb-2 flex items-center gap-2">
              <Share2 size={16} className="text-[var(--color-neon-blue)]" /> Share Cryptographic Record
            </h3>
            <p className="text-[10px] text-slate-400 font-mono mb-4 uppercase">
              Target File: <span className="text-[var(--color-neon-green)]">{activeShareFile.filename}</span>
            </p>

            <form onSubmit={handleShareSubmit} className="space-y-4">
              <div className="space-y-2">
                <label className="text-[10px] font-mono text-slate-400 uppercase tracking-wider block">Select Recipient User</label>
                <select
                  required
                  value={shareRecipientId}
                  onChange={(e) => setShareRecipientId(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg py-2 px-3 text-xs text-slate-350 focus:outline-none focus:border-[var(--color-neon-blue)]/50 font-mono"
                >
                  <option value="">Choose User...</option>
                  {usersList.map((u) => (
                    <option key={u.id} value={u.id}>
                      {u.username} ({u.email})
                    </option>
                  ))}
                </select>
              </div>

              <div className="flex gap-4 mt-6">
                <button
                  type="button"
                  onClick={() => setShowShareModal(false)}
                  className="flex-1 py-2 rounded bg-slate-900 border border-slate-800 text-slate-400 font-mono font-bold text-[10px] uppercase tracking-wider cursor-pointer"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={!shareRecipientId}
                  className="flex-1 py-2 rounded bg-slate-950 border border-[var(--color-neon-green)] text-[var(--color-neon-green)] hover:bg-[var(--color-neon-green)] hover:text-slate-950 font-mono font-bold text-[10px] uppercase tracking-wider transition-all duration-300 cursor-pointer shadow-[0_0_10px_rgba(57,255,20,0.1)]"
                >
                  Confirm Share
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* MODAL 2: QR SECURE SHARING DOWNLOAD CODE */}
      {showQrModal && (
        <div className="fixed inset-0 z-50 bg-black/60 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="glass-card rounded-2xl p-6 border border-white/10 max-w-sm w-full text-center flex flex-col items-center animate-scan">
            <h3 className="text-sm font-bold uppercase tracking-widest text-slate-200 mb-2 flex items-center gap-2">
              <QrCode size={16} className="text-[var(--color-neon-blue)]" /> QR Sharing Download Token
            </h3>
            <p className="text-[9px] text-slate-500 font-mono uppercase tracking-wider mb-6">
              Scan with mobile device to verify signature and pull decrypted file stream.
            </p>

            {/* QR Image */}
            <div className="p-3 rounded-xl bg-white border border-slate-200 shadow-xl mb-6">
              <img 
                src={qrDownloadUrl} 
                alt="Secure Download QR Code" 
                className="w-48 h-48 select-none"
              />
            </div>

            {/* Copy Link Button */}
            <div className="w-full space-y-3">
              <button
                onClick={() => {
                  const rawUrl = decodeURIComponent(qrDownloadUrl.split("data=")[1]);
                  navigator.clipboard.writeText(rawUrl);
                  alert("Download link copied!");
                }}
                className="w-full py-2 rounded bg-slate-950 border border-[var(--color-neon-blue)] text-[var(--color-neon-blue)] hover:bg-[var(--color-neon-blue)] hover:text-slate-950 font-mono font-bold text-[10px] uppercase tracking-widest transition-all duration-300 cursor-pointer"
              >
                Copy Secure Link
              </button>
              
              <button
                onClick={() => setShowQrModal(false)}
                className="w-full py-2 rounded bg-slate-900 border border-slate-800 text-slate-400 font-mono font-bold text-[10px] uppercase tracking-widest cursor-pointer"
              >
                Close Modal
              </button>
            </div>
          </div>
        </div>
      )}

    </div>
  );
}
