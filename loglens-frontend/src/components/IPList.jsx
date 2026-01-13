import React from 'react';

export default function IPList({ data }) {
  const ips = data?.suspicious_ips || [];

  // Calculate threat level based on position in list
  const getThreatLevel = (index) => {
    if (index === 0) return 'high';
    if (index === 1) return 'medium';
    return 'low';
  };

  return (
    <div className="bg-slate-800 border border-slate-700 rounded-lg p-6 mb-8">
      <h2 className="text-xl font-bold text-white mb-4">Suspicious IP Addresses</h2>

      {ips.length === 0 ? (
        <p className="text-slate-400">✓ No suspicious IPs detected. </p>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-slate-700">
                <th className="text-left py-3 px-4 text-slate-300 font-semibold">#</th>
                <th className="text-left py-3 px-4 text-slate-300 font-semibold">IP Address</th>
                <th className="text-left py-3 px-4 text-slate-300 font-semibold">Risk Level</th>
                <th className="text-left py-3 px-4 text-slate-300 font-semibold">Action</th>
              </tr>
            </thead>
            <tbody>
              {ips. map((ip, idx) => {
                const threatLevel = getThreatLevel(idx);
                const threatColor =
                  threatLevel === 'high'
                    ? 'bg-red-900 text-red-200'
                    : threatLevel === 'medium'
                    ?  'bg-yellow-900 text-yellow-200'
                    : 'bg-blue-900 text-blue-200';

                return (
                  <tr key={idx} className="border-b border-slate-700 hover:bg-slate-700 transition-colors">
                    <td className="py-3 px-4 text-slate-400 text-xs font-bold">{idx + 1}</td>
                    <td className="py-3 px-4 text-slate-200 font-mono">{ip}</td>
                    <td className="py-3 px-4">
                      <span className={`px-2 py-1 rounded text-xs font-semibold ${threatColor}`}>
                        {threatLevel. toUpperCase()}
                      </span>
                    </td>
                    <td className="py-3 px-4">
                      <button className="text-blue-400 hover:text-blue-300 text-xs font-semibold">
                        Block
                      </button>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}