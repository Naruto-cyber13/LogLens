import React, { useEffect, useRef } from 'react';
import Chart from 'chart.js/auto';

export default function ThreatChart({ data }) {
  const chartRef = useRef(null);
  const chartInstance = useRef(null);

  useEffect(() => {
    if (! chartRef.current || !data?. top_threats) return;

    // Prepare chart data
    const labels = Object.keys(data.top_threats);
    const values = Object.values(data.top_threats);

    // Destroy previous chart instance
    if (chartInstance.current) {
      chartInstance.current.destroy();
    }

    // Create new chart
    const ctx = chartRef.current.getContext('2d');
    chartInstance.current = new Chart(ctx, {
      type: 'bar',
      data: {
        labels: labels. map(label => label.replace(/_/g, ' ').toUpperCase()),
        datasets: [
          {
            label: 'Threat Count',
            data: values,
            backgroundColor: [
              'rgba(59, 130, 246, 0.8)',   // blue
              'rgba(239, 68, 68, 0.8)',    // red
              'rgba(249, 115, 22, 0.8)',   // orange
              'rgba(168, 85, 247, 0.8)',   // purple
              'rgba(34, 197, 94, 0.8)',    // green
            ],
            borderColor: [
              'rgb(59, 130, 246)',
              'rgb(239, 68, 68)',
              'rgb(249, 115, 22)',
              'rgb(168, 85, 247)',
              'rgb(34, 197, 94)',
            ],
            borderWidth: 4,
            borderRadius: 6,
          },
        ],
      },
      options: {
        responsive: true,
        maintainAspectRatio: true,
        plugins: {
          legend: {
            display: true,
            labels: {
              color: '#161616ff',
              font: { size: 15 },
            },
          },
        },
        scales: {
          y: {
            beginAtZero: true,
            grid: { color: 'rgba(14, 63, 132, 0.2)' },
            ticks:  { color: '#0f0f0fff', font: { size: 15 } },
          },
          x: {
            grid: { display: false },
            ticks:  { color: '#0a0a0aff', font: { size: 15, weight: 'bold' } },
          },
        },
      },
    });

    return () => {
      if (chartInstance.current) {
        chartInstance.current.destroy();
      }
    };
  }, [data]);

  return (
    <div className="bg-slate-800 border border-slate-700 rounded-lg p-6 mb-8">
      <h2 className="text-xl font-bold text-white mb-4">Threat Distribution</h2>
      <div className="relative h-80">
        <canvas ref={chartRef}></canvas>
      </div>
    </div>
  );
}