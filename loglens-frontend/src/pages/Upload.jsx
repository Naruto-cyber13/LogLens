import React from 'react';
import FileUpload from '../components/FileUpload';
//import TierSelector from '../components/TierSelector';

export default function Upload({ onUploadSuccess, tier, onTierChange }) {
  return (
    <div className="space-y-8">
      <div className="text-center mb-12">
        <h2 className="text-4xl font-bold text-white mb-4">
          Analyze Your Logs
        </h2>
        <p className="text-xl text-slate-400">
          Upload a log file to detect threats, identify suspicious IPs, and get detailed insights.
        </p>
      </div>

      
      <FileUpload onUploadSuccess={onUploadSuccess} tier={tier} />

      {/* Info Cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mt-12">
        <div className="bg-slate-800 border border-slate-700 rounded-lg p-6">
          <p className="text-2xl mb-2">🔍</p>
          <h3 className="font-semibold text-white mb-2">Real-time Detection</h3>
          <p className="text-slate-400 text-sm">Analyze logs instantly to identify security threats.</p>
        </div>
        <div className="bg-slate-800 border border-slate-700 rounded-lg p-6">
          <p className="text-2xl mb-2">📊</p>
          <h3 className="font-semibold text-white mb-2">Visual Reports</h3>
          <p className="text-slate-400 text-sm">Get comprehensive charts and statistics of threats.</p>
        </div>
        <div className="bg-slate-800 border border-slate-700 rounded-lg p-6">
          <p className="text-2xl mb-2">💾</p>
          <h3 className="font-semibold text-white mb-2">Export Reports</h3>
          <p className="text-slate-400 text-sm">Download results in JSON, CSV, or HTML format.</p>
        </div>
      </div>
    </div>
  );
}