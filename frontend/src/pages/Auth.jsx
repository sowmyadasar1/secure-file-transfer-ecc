import React, { useState } from "react";
import axios from "axios";
import { Shield, Lock, Mail, User, ShieldAlert, Cpu } from "lucide-react";

export default function Auth({ onAuthSuccess }) {
  const [isLogin, setIsLogin] = useState(true);
  const [username, setUsername] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const [cryptoLogs, setCryptoLogs] = useState([]);
  const [cryptoProgress, setCryptoProgress] = useState(0);

  const triggerCryptoAnimation = async () => {
    setCryptoLogs([]);
    setCryptoProgress(10);
    const steps = [
      { text: "⚡ Initializing high-entropy entropy pools...", delay: 200, pct: 20 },
      { text: "🔑 Spawning prime curve parameter: SECP256R1 (NIST-P256)...", delay: 400, pct: 40 },
      { text: "🔒 Formulating private coordinate scalar (256-bit exponent)...", delay: 300, pct: 60 },
      { text: "🌐 Computing coordinate mapping public point Q = d * G...", delay: 400, pct: 80 },
      { text: "🛡️ PEM Encapsulating private key with AES-256-GCM sealing envelope...", delay: 500, pct: 95 },
      { text: "🚀 Cryptographic keypair synchronized. Transmitting signed credentials...", delay: 300, pct: 100 }
    ];

    for (let i = 0; i < steps.length; i++) {
      await new Promise((resolve) => setTimeout(resolve, steps[i].delay));
      setCryptoLogs((prev) => [...prev, steps[i].text]);
      setCryptoProgress(steps[i].pct);
      if (window.addTerminalLog) {
        window.addTerminalLog(steps[i].text, "success-cyan");
      }
    }
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError("");
    setLoading(true);

    if (isLogin) {
      try {
        if (window.addTerminalLog) {
          window.addTerminalLog(`Authenticating user: ${username}...`, "info");
        }
        const res = await axios.post("/api/auth/login", { username, password });
        if (window.addTerminalLog) {
          window.addTerminalLog("JWT generated successfully. Decrypting user session keys.", "success");
        }
        
        // Save user and token
        localStorage.setItem("token", res.data.access_token);
        localStorage.setItem("user", JSON.stringify(res.data.user));
        
        // Update app state
        onAuthSuccess(res.data.user, res.data.access_token);
      } catch (err) {
        const msg = err.response?.data?.detail || "Authentication failed. Incorrect username or password.";
        setError(msg);
        if (window.addTerminalLog) {
          window.addTerminalLog(`[SECURITY BREACH WARNING] Failed authentication attempt: ${msg}`, "error");
        }
      } finally {
        setLoading(false);
      }
    } else {
      try {
        // Trigger visual ECC key generation in frontend before registration API is hit
        await triggerCryptoAnimation();

        if (window.addTerminalLog) {
          window.addTerminalLog(`Registering new user identity on the server: ${username}...`, "info");
        }

        const res = await axios.post("/api/auth/register", { username, email, password });
        
        if (window.addTerminalLog) {
          window.addTerminalLog(`Registration complete. ECC Public key registered: ${res.data.public_key.slice(0, 40)}...`, "success");
        }

        alert("ECC Registration Successful! You can now log in.");
        setIsLogin(true);
        setPassword("");
      } catch (err) {
        const msg = err.response?.data?.detail || "Registration failed. Try a different username/email.";
        setError(msg);
        if (window.addTerminalLog) {
          window.addTerminalLog(`[ERROR] Registration abort: ${msg}`, "error");
        }
      } finally {
        setLoading(false);
        setCryptoProgress(0);
        setCryptoLogs([]);
      }
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center p-4 relative bg-grid-cyber">
      {/* Background glowing decorations */}
      <div className="absolute top-1/4 left-1/4 w-96 h-96 bg-cyan-500/10 rounded-full blur-[100px] pointer-events-none animate-pulse-slow"></div>
      <div className="absolute bottom-1/4 right-1/4 w-96 h-96 bg-emerald-500/5 rounded-full blur-[120px] pointer-events-none animate-pulse-slow"></div>

      <div className="w-full max-w-lg z-10">
        {/* Brand Header */}
        <div className="flex flex-col items-center mb-8">
          <div className="w-16 h-16 rounded-2xl bg-slate-900 border border-[var(--color-neon-blue)]/50 shadow-[0_0_15px_rgba(0,240,255,0.3)] flex items-center justify-center mb-3 animate-pulse">
            <Shield className="text-[var(--color-neon-blue)]" size={32} />
          </div>
          <h1 className="text-2xl font-black tracking-widest text-slate-100 text-glow-blue">
            SAFESHARE <span className="text-[var(--color-neon-green)] text-glow-green">ECC</span>
          </h1>
          <p className="text-xs text-slate-500 tracking-wider mt-1 uppercase font-mono">
            Zero-Trust Encrypted Transfer System
          </p>
        </div>

        {/* Auth Glassmorphism Card */}
        <div className="glass-card rounded-2xl p-8 border border-white/5 shadow-2xl relative overflow-hidden animate-scan">
          {/* Card title */}
          <div className="flex justify-between items-center mb-6">
            <h2 className="text-lg font-bold text-slate-200 uppercase tracking-widest flex items-center gap-2">
              <Cpu size={16} className="text-[var(--color-neon-blue)]" />
              {isLogin ? "ONBOARD TERMINAL" : "CREATE CRYPTO IDENTITY"}
            </h2>
            <button
              onClick={() => {
                setIsLogin(!isLogin);
                setError("");
                setCryptoLogs([]);
              }}
              className="text-xs text-[var(--color-neon-blue)] hover:text-cyan-300 font-mono hover:underline uppercase transition-colors"
            >
              {isLogin ? "Generate keypair >>" : "<< Back to login"}
            </button>
          </div>

          {/* Form */}
          <form onSubmit={handleSubmit} className="space-y-4">
            {error && (
              <div className="p-3.5 rounded-lg bg-red-950/40 border border-red-500/30 text-red-300 text-xs flex items-start gap-2.5">
                <ShieldAlert size={16} className="shrink-0 text-red-400" />
                <span>{error}</span>
              </div>
            )}

            <div className="space-y-2">
              <label className="text-xs font-mono text-slate-400 uppercase tracking-wider block">Username</label>
              <div className="relative">
                <span className="absolute inset-y-0 left-0 pl-3.5 flex items-center text-slate-500">
                  <User size={14} />
                </span>
                <input
                  type="text"
                  required
                  placeholder="hacker_agent"
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  className="w-full bg-slate-950/60 border border-slate-800 rounded-lg py-2.5 pl-10 pr-4 text-sm text-slate-200 placeholder-slate-600 focus:outline-none focus:border-[var(--color-neon-blue)]/50 focus:ring-1 focus:ring-[var(--color-neon-blue)]/30 transition-all font-mono"
                />
              </div>
            </div>

            {!isLogin && (
              <div className="space-y-2">
                <label className="text-xs font-mono text-slate-400 uppercase tracking-wider block">Security Email</label>
                <div className="relative">
                  <span className="absolute inset-y-0 left-0 pl-3.5 flex items-center text-slate-500">
                    <Mail size={14} />
                  </span>
                  <input
                    type="email"
                    required
                    placeholder="agent@zero-trust.secure"
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    className="w-full bg-slate-950/60 border border-slate-800 rounded-lg py-2.5 pl-10 pr-4 text-sm text-slate-200 placeholder-slate-600 focus:outline-none focus:border-[var(--color-neon-blue)]/50 focus:ring-1 focus:ring-[var(--color-neon-blue)]/30 transition-all font-mono"
                  />
                </div>
              </div>
            )}

            <div className="space-y-2">
              <label className="text-xs font-mono text-slate-400 uppercase tracking-wider block">Passphrase</label>
              <div className="relative">
                <span className="absolute inset-y-0 left-0 pl-3.5 flex items-center text-slate-500">
                  <Lock size={14} />
                </span>
                <input
                  type="password"
                  required
                  placeholder="••••••••••••••"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  className="w-full bg-slate-950/60 border border-slate-800 rounded-lg py-2.5 pl-10 pr-4 text-sm text-slate-200 placeholder-slate-600 focus:outline-none focus:border-[var(--color-neon-blue)]/50 focus:ring-1 focus:ring-[var(--color-neon-blue)]/30 transition-all font-mono"
                />
              </div>
            </div>

            <button
              type="submit"
              disabled={loading}
              className={`w-full relative overflow-hidden group py-3 rounded-lg border font-mono font-bold text-xs uppercase tracking-widest mt-6 cursor-pointer ${
                loading
                  ? "bg-slate-900 border-slate-800 text-slate-600 cursor-not-allowed"
                  : "bg-slate-950 text-[var(--color-neon-green)] border-[var(--color-neon-green)] hover:bg-[var(--color-neon-green)] hover:text-slate-950 transition-all duration-300 shadow-[0_0_10px_rgba(57,255,20,0.1)] hover:shadow-[0_0_20px_rgba(57,255,20,0.3)]"
              }`}
            >
              {loading ? "PROCESSING CRYPTOGRAPHY..." : isLogin ? "Decrypt Session Keys" : "Generate SECP256R1 Keys"}
            </button>
          </form>

          {/* Keypair Generation Progress Terminal */}
          {cryptoProgress > 0 && (
            <div className="mt-6 border border-slate-800 rounded-lg bg-slate-950 p-4 font-mono text-[10px] text-slate-300 leading-relaxed shadow-inner">
              <div className="flex items-center justify-between mb-2 pb-1 border-b border-slate-900">
                <span className="text-[var(--color-neon-blue)] font-bold">CRYPTO ENGINE SIMULATOR</span>
                <span>{cryptoProgress}%</span>
              </div>
              <div className="w-full h-1.5 bg-slate-900 rounded-full mb-3 overflow-hidden">
                <div 
                  className="h-full bg-gradient-to-r from-[var(--color-neon-blue)] to-[var(--color-neon-green)] transition-all duration-300"
                  style={{ width: `${cryptoProgress}%` }}
                ></div>
              </div>
              <div className="space-y-1 max-h-32 overflow-y-auto">
                {cryptoLogs.map((log, index) => (
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
    </div>
  );
}
