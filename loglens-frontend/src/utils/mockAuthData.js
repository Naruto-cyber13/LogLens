/**
 * Mock authentication responses for testing
 * Use this to test the frontend before the backend is ready
 */

export const mockLoginResponse = {
  access_token: 
    'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyQGV4YW1wbGUuY29tIiwiZXhwIjoxNzQxMDAwMDAwfQ.mock_signature',
  token_type: 'bearer',
};

export const mockRegisterResponse = {
  access_token:
    'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJuZXd1c2VyQGV4YW1wbGUuY29tIiwiZXhwIjoxNzQxMDAwMDAwfQ.mock_signature',
  token_type: 'bearer',
};

/**
 * To test with mock data, temporarily replace fetch calls in AuthContext. jsx: 
 * 
 * const data = mockLoginResponse; // Instead of:  const data = await response.json();
 */