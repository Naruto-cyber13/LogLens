export const mockAnalysisResponse = {
  id: 9,
  user_id: 1,
  total_lines: 46,
  threats_count: 9,
  top_threats: {
    sql_injection: 2,
    dir_traversal: 3,
  },
  suspicious_ips:  [
    '198.51.100.23',
    '45.33.32.200',
  ],
  created_at: '2025-01-02T10:15:30',
};