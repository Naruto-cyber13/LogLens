import React from 'react';

export default function ExportReport({ data, tier }) {
  const handleExportJSON = () => {
    const jsonString = JSON.stringify(data, null, 2);
    downloadFile(jsonString, 'analysis-report.json', 'application/json');
  };

  const handleExportCSV = () => {
    let csv = 'LogLens Analysis Report\n\n';
    csv += `Generated:  ${new Date().toLocaleString()}\n`;
    csv += `Tier: ${tier.toUpperCase()}\n`;
    csv += `Analysis ID: ${data?. id || 'N/A'}\n\n`;

    csv += '=== SUMMARY ===\n';
    csv += `Total Log Lines,${data?.total_lines || 0}\n`;
    csv += `Threats Detected,${data?.threats_count || 0}\n`;
    csv += `Suspicious IPs,${data?.suspicious_ips?.length || 0}\n\n`;

    csv += '=== TOP THREATS ===\n';
    csv += 'Threat Type,Count\n';
    if (data?.top_threats) {
      Object.entries(data. top_threats).forEach(([threat, count]) => {
        csv += `"${threat.replace(/_/g, ' ')}",${count}\n`;
      });
    }

    csv += '\n=== SUSPICIOUS IPS ===\n';
    csv += 'IP Address\n';
    data?.suspicious_ips?.forEach((ip) => {
      csv += `${ip}\n`;
    });

    downloadFile(csv, 'analysis-report.csv', 'text/csv');
  };

  const handleExportHTML = () => {
    const html = `
<! DOCTYPE html>
<html>
<head>
  <title>LogLens Analysis Report</title>
  <style>
    body {
      font-family: Arial, sans-serif;
      max-width: 900px;
      margin: 40px auto;
      background:  #f3f4f6;
      padding: 20px;
    }
    .container {
      background: white;
      padding:  40px;
      border-radius:  8px;
      box-shadow: 0 2px 8px rgba(0,0,0,0.1);
    }
    h1 {
      color: #1f2937;
      border-bottom: 3px solid #3b82f6;
      padding-bottom: 10px;
    }
    h2 {
      color: #374151;
      margin-top:  30px;
    }
    .summary {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
      gap: 20px;
      margin:  20px 0;
    }
    .card {
      background: #f9fafb;
      padding:  20px;
      border-left: 4px solid #3b82f6;
      border-radius: 4px;
    }
    .card-label {
      font-size: 12px;
      color: #6b7280;
      font-weight: bold;
    }
    .card-value {
      font-size: 28px;
      font-weight:  bold;
      color: #1f2937;
      margin-top: 10px;
    }
    table {
      width: 100%;
      border-collapse: collapse;
      margin: 20px 0;
    }
    th, td {
      text-align: left;
      padding: 12px;
      border-bottom: 1px solid #e5e7eb;
    }
    th {
      background:  #f3f4f6;
      font-weight: bold;
      color: #374151;
    }
    . footer {
      text-align: center;
      color: #9ca3af;
      font-size: 12px;
      margin-top:  40px;
      padding-top: 20px;
      border-top: 1px solid #e5e7eb;
    }
  </style>
</head>
<body>
  <div class="container">
    <h1>LogLens - Log Analysis Report</h1>
    <p><strong>Generated: </strong> ${new Date().toLocaleString()}</p>
    <p><strong>Analysis ID:</strong> ${data?.id || 'N/A'}</p>
    <p><strong>Tier:</strong> ${tier.toUpperCase()}</p>
    <p><strong>Analysis Date:</strong> ${data?.created_at ?  new Date(data.created_at).toLocaleString() : 'N/A'}</p>

    <h2>Summary</h2>
    <div class="summary">
      <div class="card">
        <div class="card-label">Total Log Lines</div>
        <div class="card-value">${data?.total_lines || 0}</div>
      </div>
      <div class="card">
        <div class="card-label">Threats Detected</div>
        <div class="card-value">${data?. threats_count || 0}</div>
      </div>
      <div class="card">
        <div class="card-label">Suspicious IPs</div>
        <div class="card-value">${data?.suspicious_ips?.length || 0}</div>
      </div>
    </div>

    <h2>Threat Breakdown</h2>
    <table>
      <tr>
        <th>Threat Type</th>
        <th>Count</th>
        <th>Percentage</th>
      </tr>
      ${
        Object.entries(data?.top_threats || {})
          .map(
            ([threat, count]) => `
        <tr>
          <td>${threat.replace(/_/g, ' ').toUpperCase()}</td>
          <td>${count}</td>
          <td>${data.threats_count
  ? ((count / data.threats_count) * 100).toFixed(1)
  : '0.0'}%
</td>
        </tr>
      `
          )
          .join('')
      }
    </table>

    <h2>Suspicious IP Addresses</h2>
    <table>
      <tr>
        <th>#</th>
        <th>IP Address</th>
      </tr>
      ${
        (data?.suspicious_ips || [])
          .map(
            (ip, idx) => `
        <tr>
          <td>${idx + 1}</td>
          <td><code>${ip}</code></td>
        </tr>
      `
          )
          .join('')
      }
    </table>

    <div class="footer">
      <p>© 2025 LogLens.  Advanced threat detection for log analysis.</p>
      <p>This report is confidential and should be handled securely.</p>
    </div>
  </div>
</body>
</html>
    `;
    downloadFile(html, 'analysis-report.html', 'text/html');
  };

  const downloadFile = (content, filename, mimeType) => {
    const blob = new Blob([content], { type: mimeType });
    const url = window.URL.createObjectURL(blob);
    const a = document. createElement('a');
    a.href = url;
    a. download = filename;
    document.body.appendChild(a);
    a.click();
    window.URL.revokeObjectURL(url);
    document.body.removeChild(a);
  };

  return (
    <div className="bg-slate-800 border border-slate-700 rounded-lg p-6 mt-8">
      <h2 className="text-xl font-bold text-white mb-4">Export Report</h2>
      <div className="flex flex-wrap gap-3">
        <button
          onClick={handleExportJSON}
          className="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg transition-colors flex items-center gap-2"
        >
          📋 JSON
        </button>
        <button
          onClick={handleExportCSV}
          className="px-4 py-2 bg-green-600 hover:bg-green-700 text-white rounded-lg transition-colors flex items-center gap-2"
        >
          📊 CSV
        </button>
        <button
          onClick={handleExportHTML}
          className="px-4 py-2 bg-purple-600 hover:bg-purple-700 text-white rounded-lg transition-colors flex items-center gap-2"
        >
          📄 HTML
        </button>
        <button
          onClick={() => window.print()}
          className="px-4 py-2 bg-orange-600 hover:bg-orange-700 text-white rounded-lg transition-colors flex items-center gap-2"
        >
          🖨️ Print
        </button>
      </div>
    </div>
  );
}