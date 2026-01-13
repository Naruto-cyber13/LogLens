/**
 * Utility functions for authentication
 */

/**
 * Check if token is expired (basic check)
 * JWT tokens are base64 encoded in 3 parts separated by dots
 */
export function isTokenExpired(token) {
  try {
    const payload = token.split('.')[1];
    const decoded = JSON.parse(atob(payload));
    const expirationTime = decoded.exp * 1000; // Convert to milliseconds
    return Date.now() >= expirationTime;
  } catch {
    // If decoding fails, assume token is invalid
    return true;
  }
}

/**
 * Validate email format
 */
export function isValidEmail(email) {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailRegex.test(email);
}

/**
 * Validate password strength
 */
export function isValidPassword(password) {
  return password && password.length >= 6;
}

/**
 * Get user from JWT token (without verification, client-side only)
 */
export function getUserFromToken(token) {
  try {
    const payload = token.split('.')[1];
    const decoded = JSON.parse(atob(payload));
    return decoded;
  } catch {
    return null;
  }
}