import React, { useState } from 'react';
import Upload from './pages/Upload';
import Dashboard from './pages/Dashboard';
import { AuthProvider, useAuth } from './context/AuthContext';
import Login from './pages/Login';
import Register from './pages/Register';
import './App.css';
//import { mockAnalysisResponse } from './utils/mockdata_v3.js';


function App() {
  const [showLoginPage, setShowLoginPage] = useState(true);
  const { isAuthenticated, isLoading, logout, user } = useAuth();
  const [analysisData, setAnalysisData] = useState(null);
  const tier = user?.is_premium ? 'pro' : 'free';
  //const [selectedTier, setSelectedTier] = useState('free'); // 'free' or 'pro'
  //const [isLoading, setIsLoading] = useState(false);

  /*useEffect(() => {
  setAnalysisData(mockAnalysisResponse);
  }, []); */


  const handleUploadSuccess = (data) => {
    setAnalysisData(data);
  };

  const handleReset = () => {
    setAnalysisData(null);
  };

  if (isLoading) {
  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-slate-800 to-slate-900 flex items-center justify-center">
      <div className="text-center">
        <div className="inline-block animate-spin text-4xl mb-4">⏳</div>
        <h1 className="text-2xl font-bold text-white">Loading LogLens...</h1>
        <p className="text-slate-400 mt-2">Initializing your session</p>
      </div>
    </div>
  );
  }


  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-slate-800 to-slate-900">
      {/* Header */}
      <header className="bg-slate-950 border-b border-slate-700 shadow-lg">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-4 flex items-center justify-between">

          {/* LEFT SIDE: App title */}
<div>
  <h1 className="text-5xl font-bold  bg-clip-text bg-gradient-to-r from-blue-400 to-cyan-400">
    LogLens
  </h1>
  <p className="text-slate-400 mt-1">
    Advanced Log Analysis & Threat Detection
  </p>
</div>

{/* RIGHT SIDE: User info + logout */}
{isAuthenticated && (
  <div className="flex items-center gap-4">
    {user && (
      <div className="text-right">
        <p className="text-slate-200 text-sm">👤 {user.email}</p>
        <p className="text-slate-400 text-xs">
          {user?.is_premium ? '⭐ Pro' : '📦 Free'} Tier
        </p>
      </div>
    )}
    <button
      onClick={logout}
      className="px-4 py-2 bg-slate-700 hover:bg-slate-600 text-white rounded-lg transition-colors text-sm font-medium"
    >
      🚪 Logout
    </button>
  </div>
)}

        </div>
      </header>

      {/* Main Content */}
      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-12">
  {!isAuthenticated ? (
    showLoginPage ? (
      <Login onSwitchToRegister={() => setShowLoginPage(false)} />
    ) : (
      <Register onSwitchToLogin={() => setShowLoginPage(true)} />
    )
  ) : !analysisData ? (
    <Upload
      onUploadSuccess={handleUploadSuccess}
      tier={user?.is_premium ? 'pro' : 'free'}
    />
  ) : (
    <div>
      <button
        onClick={handleReset}
        className="mb-6 px-4 py-2 bg-slate-700 hover:bg-slate-600 text-white rounded-lg transition-colors"
      >
        ← Back to Upload
      </button>
      <Dashboard data={analysisData} tier={user?.is_premium ? 'pro' : 'free'} />
    </div>
  )}
</main>


      {/* Footer */}
      <footer className="bg-slate-950 border-t border-slate-700 mt-12">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6 text-center text-slate-400">
          <p>© 2025 LogLens. Advanced threat detection for log analysis.</p>
        </div>
      </footer>
    </div>
  );
}

export default function AppWithAuth() {
  return (
    <AuthProvider>
      <App />
    </AuthProvider>
  );
}
