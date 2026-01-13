import React from 'react';
import SummaryCards from '../components/SummaryCards';
import ThreatChart from '../components/ThreatChart';
import IPList from '../components/IPList';
import Timeline from '../components/Timeline';
import ExportReport from '../components/ExportReport';
import { useAuth } from '../context/AuthContext';


//const { user } = useAuth();


export default function Dashboard({ data, tier }) {
  const { user } = useAuth();
  return (
    <div className="space-y-8">
      {/* Header */}
      <div className="bg-slate-800 border border-slate-700 rounded-lg p-6 mb-8">
        <h2 className="text-3xl font-bold text-white mb-2">Analysis Results</h2>
        <p className="text-slate-400 font-bold">
          Analysis ID: <span className="font-semibold text-slate-300">#{data?.analysis_id}</span> | 
          Tier: <span className="font-semibold text-slate-300">{user?.is_premium ? 'PRO' : 'FREE'}</span> | 
          Generated: <span className="font-semibold text-slate-300">Just Now{/*data?.created_at ? new Date(data.created_at).toLocaleString() : 'N/A'*/}</span>
        </p>
      </div>

      {/* Summary Cards */}
      <SummaryCards data={data} />

      {/* Threat Chart */}
      {data?.top_threats && Object.keys(data.top_threats).length > 0 && (
        <ThreatChart data={data} />
      )}

      {/* Two-column layout for IP List and Timeline */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
        <IPList data={data} />
        <Timeline data={data} />
      </div>

      {/* Export Section */}
      <ExportReport data={data} tier={tier} />
    </div>
  );
}