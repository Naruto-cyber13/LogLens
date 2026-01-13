import React from 'react';

export default function SummaryCards({ data }) {
  const cards = [
    {
      label: 'Total Log Lines',
      value: data?. total_lines || 0,
      icon: '📄',
      color: 'from-blue-600 to-blue-500',
    },
    {
      label: 'Threats Detected',
      value: data?. threats_count || 0,
      icon: '🚨',
      color: 'from-red-600 to-red-500',
    },
    {
      label: 'Suspicious IPs',
      value: data?.suspicious_ips?.length || 0,
      icon: '🌐',
      color: 'from-orange-600 to-orange-500',
    },
    {
      label: 'Threat Level',
      value: calculateThreatLevel(data),
      icon: '⚠️',
      color: 'from-purple-600 to-purple-500',
      
    },
  ];

  return (
    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 mb-8">
      {cards.map((card, idx) => (
        <div
          key={idx}
          className={`bg-gradient-to-br ${card.color} rounded-lg p-6 text-white shadow-lg`}
        >
          <div className='flex items-center gap-3 mb-3'>
            <span className="text-5xl">{card.icon}</span>
            <span className='text-slate-200 text-5xl font-bold tracking-wide'>
            {card.label}
            </span>
          </div>

<p className="mt-2 text-5xl font-extrabold">
  {card.value}
  </p>

        </div>
      ))}
    </div>
  );
}

function calculateThreatLevel(data) {
  if (!data?.threats_count) return 'Low';
  if (data.threats_count < 10) return 'Medium';
  if (data.threats_count < 50) return 'High';
  return 'Critical';
}