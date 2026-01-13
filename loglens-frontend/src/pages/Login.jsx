import React, { useState } from 'react';
import { useAuth } from '../context/AuthContext';


export default function Login({ onSwitchToRegister }) {
  const { login, isLoading } = useAuth();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [showPassword, setShowPassword] = useState(false);

  const validateForm = () => {
    if (!email.trim()) {
      setError('Email is required.');
      return false;
    }
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      setError('Please enter a valid email address.');
      return false;
    }
    if (!password) {
      setError('Password is required.');
      return false;
    }
    if (password.length < 3) {
      setError('Password must be at least 4 characters long.');
      return false;
    }
    return true;
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');

    if (!validateForm()) return;

    const result = await login(email, password);
    if (!result.success) {
      setError(result.error || 'Login failed. Please try again.');
    }

  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-slate-800 to-slate-900 flex items-center justify-center px-4">
      {/* ✅ Card container */}
      <div className="w-full max-w-md bg-slate-900 border border-slate-700 rounded-xl p-8 shadow-lg">
      {/* ✅ LogLens Title (MOVED HERE) */}
      <div className="text-center mb-8">
      <h1 className="text-7xl font-extrabold tracking-tight bg-clip-text bg-gradient-to-r from-blue-400 to-cyan-400">
      LogLens
      </h1>
      <p className="mt-2 text-slate-400 text-sm">
        Advanced Log Analysis & Threat Detection
      </p>
      </div>


        {/* Login Card */}
        <div className="bg-slate-800 border border-slate-700 rounded-lg shadow-2xl p-8">
          <h2 className="text-2xl font-bold text-white mb-6">Welcome Back</h2>

          <form onSubmit={handleSubmit} className="space-y-4">
            {/* Email Field */}
            <div>
              <label htmlFor="email" className="block text-sm font-medium text-slate-200 mb-2">
                Email Address
              </label>
              <input
                id="email"
                type="email"
                placeholder="you@example.com"
                value={email}
                onChange={(e) => {
                  setEmail(e.target.value);
                  setError('');
                }}
                disabled={isLoading}
                className="w-full px-4 py-2 bg-slate-700 border border-slate-600 rounded-lg text-white placeholder-slate-500 focus:outline-none focus:border-blue-500 focus:ring-2 focus:ring-blue-500 focus:ring-opacity-20 transition-all disabled:opacity-50"
              />
            </div>

            {/* Password Field */}
            <div>
              <label htmlFor="password" className="block text-sm font-medium text-slate-200 mb-2">
                Password
              </label>
              <div className="relative">
                <input
                  id="password"
                  type={showPassword ? 'text' : 'password'}
                  placeholder="••••••••"
                  value={password}
                  onChange={(e) => {
                    setPassword(e.target.value);
                    setError('');
                  }}
                  disabled={isLoading}
                  className="w-full px-4 py-2 bg-slate-700 border border-slate-600 rounded-lg text-white placeholder-slate-500 focus:outline-none focus:border-blue-500 focus:ring-2 focus:ring-blue-500 focus:ring-opacity-20 transition-all disabled:opacity-50"
                />
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  className="absolute right-3 top-2 text-slate-400 hover:text-slate-300 text-sm"
                  disabled={isLoading}
                >
                  {showPassword ? '👁️' : '👁️‍🗨️'}
                </button>
              </div>
            </div>

            {/* Error Message */}
            {error && (
              <div className="p-3 bg-red-900 bg-opacity-50 border border-red-700 rounded-lg text-red-200 text-sm">
                ⚠️ {error}
              </div>
            )}

            {/* Submit Button */}
            <button
              type="submit"
              disabled={isLoading || !email || !password}
              className="w-full px-4 py-2 bg-gradient-to-r from-blue-600 to-cyan-600 hover:from-blue-700 hover:to-cyan-700 text-white font-semibold rounded-lg transition-all disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center gap-2 mt-6"
            >
              {isLoading ? (
                <>
                  <span className="animate-spin">⏳</span> Signing in...
                </>
              ) : (
                <>
                  🔐 Sign In
                </>
              )}
            </button>
          </form>

          {/* Divider */}
          <div className="relative my-6">
            <div className="absolute inset-0 flex items-center">
              <div className="w-full border-t border-slate-700"></div>
            </div>
            <div className="relative flex justify-center text-sm">
              <span className="px-2 bg-slate-800 text-slate-400">Don't have an account? </span>
            </div>
          </div>

          {/* Sign Up Link */}
          <button
            type="button"
            onClick={onSwitchToRegister}
            className="w-full px-4 py-2 bg-slate-700 hover:bg-slate-600 text-slate-200 font-semibold rounded-lg transition-all"
            disabled={isLoading}
          >
            Create an Account
          </button>
        </div>

        {/* Footer */}
        <div className="text-center mt-6 text-slate-500 text-xs">
          <p>© 2025 LogLens. All rights reserved.</p>
        </div>
      </div>
    </div>
  );
}