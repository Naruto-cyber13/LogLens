export const mockAnalysisResponse = {
  id: 42,
  user_id: 1,

  // Log statistics
  total_lines: 18734,
  threats_count: 66,

  // Threat breakdown (matches backend rules)
  top_threats: {
    sql_injection: 8,
    dir_traversal: 9,
    brute_force: 17,
    forbidden_spam: 11,
    not_found_spam: 21,
  },

  // Backend-style suspicious IP list (string[])
  suspicious_ips: [
    "198.51.100.23",
    "45.33.32.200",
    "203.0.113.10",
    "198.51.100.2",
    "198.51.100.3",
    "45.33.32.156",
  ],

  // Metadata
  created_at: "2025-01-02T18:22:45",

  // (Optional but realistic backend extension)
  processing_time_ms: 842,
  file_size_bytes: 8249134,
  tier_applied: "pro",
};
