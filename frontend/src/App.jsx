import React, { useState, useEffect } from "react";
import Auth from "./pages/Auth";
import Dashboard from "./pages/Dashboard";
import TerminalLogs from "./components/TerminalLogs";

export default function App() {
  const [user, setUser] = useState(null);
  const [token, setToken] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    // Check for cached cryptographic session
    const storedUser = localStorage.getItem("user");
    const storedToken = localStorage.getItem("token");

    if (storedUser && storedToken) {
      setUser(JSON.parse(storedUser));
      setToken(storedToken);
    }
    setLoading(false);
  }, []);

  const handleAuthSuccess = (authenticatedUser, jwtToken) => {
    setUser(authenticatedUser);
    setToken(jwtToken);
  };

  const handleLogout = () => {
    if (window.addTerminalLog) {
      window.addTerminalLog(`Terminating cryptographic session for user: ${user?.username || "identity"}...`, "warning");
      window.addTerminalLog("Purging transient session keys from local cache.", "warning");
    }
    
    // Clear cache
    localStorage.removeItem("user");
    localStorage.removeItem("token");
    
    // Reset state
    setUser(null);
    setToken(null);
  };

  if (loading) {
    return (
      <div className="min-h-screen bg-slate-950 flex flex-col items-center justify-center font-mono">
        <div className="flex items-center gap-2 mb-4 animate-pulse">
          <div className="w-8 h-8 rounded bg-slate-900 border border-[var(--color-neon-blue)]/50 flex items-center justify-center">
            <span className="text-[var(--color-neon-blue)] font-bold">Z</span>
          </div>
          <span className="text-sm font-bold text-slate-350 tracking-wider">SECURE SHIELD LOADING...</span>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen flex flex-col bg-slate-950/65 text-slate-200">
      {/* Dynamic Route Rendering */}
      {!token ? (
        <Auth onAuthSuccess={handleAuthSuccess} />
      ) : (
        <Dashboard user={user} token={token} onLogout={handleLogout} />
      )}

      {/* Floating Hacker Terminal Logs Shell */}
      <TerminalLogs />
    </div>
  );
}
