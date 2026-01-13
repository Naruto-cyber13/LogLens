import React from 'react';

export default function Timeline({ data }) {
  // Generate synthetic timeline events from threats data
  const generateTimeline = () => {
    const events = [];

    // Create events from top threats
    if (data?.top_threats) {
      Object.entries(data.top_threats).forEach(([threat, count], idx) => {
        for (let i = 0; i < count; i++) {
          events.push({
            /*timestamp: new Date(
              new Date(data.created_at).getTime() - (idx * 60 + i * 10) * 60000
            ).toLocaleString(), */
            event_type: threat,
            description: ` attempt detected`,
          });
        }
      });
    }

    // Sort by timestamp (newest first)
    return events//.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
  };

  const events = generateTimeline();
  const threatTypes = Object.keys(data?.top_threats || {});
  const [filter, setFilter] = React.useState('all');

  const filteredEvents = events.filter((event) => {
    if (filter === 'all') return true;
    return event.event_type === filter;
  });

  return (
    <div className="bg-slate-800 border border-slate-700 rounded-lg p-6">
      <div className="flex justify-between items-center mb-4">
        <h2 className="text-xl font-bold text-white">Event Timeline</h2>
        <select
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
          className="px-3 py-1 bg-slate-700 text-slate-200 rounded text-sm border border-slate-600"
        >
          <option value="all">All Events ({filteredEvents.length})</option>
          {threatTypes.map((type) => (
            <option key={type} value={type}>
              {type.replace(/_/g, ' ').toUpperCase()} ({data?.top_threats?.[type] || 0})
            </option>
          ))}
        </select>
      </div>

      {filteredEvents.length === 0 ? (
        <p className="text-slate-400">✓ No events found. </p>
      ) : (
        <div className="space-y-4 max-h-96 overflow-y-auto">
          {filteredEvents.slice(0, 50).map((event, idx) => (
            <div key={idx} className="flex gap-4 pb-4 border-b border-slate-700 last:border-b-0">
              <div className="flex flex-col items-center">
                <div className="w-3 h-3 bg-blue-500 rounded-full"></div>
                {idx < filteredEvents.length - 1 && <div className="w-0.5 h-12 bg-slate-700"></div>}
              </div>
              <div className="flex-1">
                <p className="text-slate-200 text-sm mt-1">
                  <span className="inline-block px-2 py-1 bg-blue-900 text-blue-200 rounded text-xs font-semibold mr-2">
                    {event.event_type. replace(/_/g, ' ').toUpperCase()}
                  </span>
                  {event.description}
                </p>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}