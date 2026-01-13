export const API_BASE = "http://localhost:8000";
export async function apiRequest(endpoint, options = {}) {
  const token = localStorage.getItem("auth_token");

  const headers = {
    ...(token && { Authorization: `Bearer ${token}` }),
    ...options.headers,
  };

  const response = await fetch(`${API_BASE}${endpoint}`, {
    ...options,
    headers,
  });

  if (!response.ok) {
    const error = await response.json();
    throw new Error(error.detail || "API error");
  }

  return response.json();
}
