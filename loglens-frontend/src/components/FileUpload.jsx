import React, { useState } from 'react';
import { useAuth } from '../context/AuthContext';
import { API_BASE } from '../api/api';

export default function FileUpload({ onUploadSuccess, tier }) {
  const [file, setFile] = useState(null);
  const { token } = useAuth();
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [progress, setProgress] = useState(0);

  const MAX_FILE_SIZE_FREE = 10 * 1024 * 1024; // 10MB
  const MAX_FILE_SIZE_PRO = 500 * 1024 * 1024; // 500MB

  const maxSize = tier === 'pro' ? MAX_FILE_SIZE_PRO : MAX_FILE_SIZE_FREE;

  const handleFileChange = (e) => {
    const selectedFile = e.target.files[0];
    setError(null);

    if (!selectedFile) return;

    // Validate file type
    const validTypes = ['.log', '.txt'];
    const fileExtension = '.' + selectedFile.name.split('.').pop().toLowerCase();
    if (!validTypes.includes(fileExtension)) {
      setError('Invalid file type. Please upload a .log or .txt file.');
      setFile(null);
      return;
    }

    // Validate file size
    if (selectedFile.size > maxSize) {
      setError(
        `File size exceeds ${tier === 'pro' ? '500MB' : '10MB'} limit for ${tier} tier.`
      );
      setFile(null);
      return;
    }

    setFile(selectedFile);
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!file) {
      setError('Please select a file.');
      return;
    }

    if (!token) {
      setError('You must be logged in to upload a file.');
      return;
    }



    setLoading(true);
    setError(null);
    setProgress(0);

    try {
      const formData = new FormData();
      formData.append('file', file);
      //formData.append('tier', tier);

      // Replace with your actual backend URL
      //const BACKEND_URL = import.meta.env.VITE_BACKEND_URL || 'http://localhost:8000';
      const response = await fetch(`${API_BASE}/logs/upload`, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${token}`,
      },
      body: formData,
    }); 


      if (!response.ok) {
        const errorData = await response.json().catch(() => ({}));
        throw new Error(errorData.message || `Upload failed: ${response.status} ${response.statusText}`);
      }

      const data = await response.json();
      setFile(null);
      setProgress(100);
      onUploadSuccess(data);
    } catch (err) {
      setError(err.message || 'An error occurred during upload.');
      console.error('Upload error:', err);
    } finally {
      setLoading(false);
    }
  };

  return (
    <form onSubmit={handleSubmit} className="bg-slate-800 border border-slate-700 rounded-lg p-8">
      <h2 className="text-2xl font-bold text-white mb-6">Upload Log File</h2>

      {/* File Input */}
      <div className="mb-6">
        <label className="block text-sm font-medium text-slate-200 mb-3">
          Select Log File (. log or .txt)
        </label>
        <input
          type="file"
          accept=".log,.txt"
          onChange={handleFileChange}
          disabled={loading}
          className="w-full px-4 py-3 border-2 border-dashed border-slate-600 rounded-lg bg-slate-700 text-slate-200 file:bg-blue-600 file:text-white file:border-0 file:px-4 file:py-2 file:rounded file:cursor-pointer hover:border-slate-500 transition-colors disabled:opacity-50"
        />
        <p className="text-xs text-slate-400 mt-2">
          Max size: {tier === 'pro' ? '500MB' :  '10MB'} | Tier: <span className="font-semibold text-slate-300">{tier.toUpperCase()}</span>
        </p>
      </div>

      {/* File Preview */}
      {file && (
        <div className="mb-6 p-4 bg-slate-700 rounded-lg border border-slate-600">
          <p className="text-slate-200">
            <span className="font-semibold">Selected:  </span> {file.name} ({(file.size / 1024 / 1024).toFixed(2)}MB)
          </p>
        </div>
      )}

      {/* Error Message */}
      {error && (
        <div className="mb-6 p-4 bg-red-900 bg-opacity-50 border border-red-700 rounded-lg text-red-200 text-sm">
          ⚠️ {error}
        </div>
      )}

      {/* Progress Bar */}
      {loading && progress > 0 && (
        <div className="mb-6">
          <div className="w-full bg-slate-700 rounded-full h-2">
            <div
              className="bg-gradient-to-r from-blue-500 to-cyan-500 h-2 rounded-full transition-all duration-300"
              style={{ width: `${progress}%` }}
            ></div>
          </div>
          <p className="text-xs text-slate-400 mt-2">{progress}% uploaded</p>
        </div>
      )}

      {/* Submit Button */}
      <button
        type="submit"
        disabled={! file || loading}
        className="w-full px-6 py-3 bg-gradient-to-r from-blue-600 to-cyan-600 hover:from-blue-700 hover:to-cyan-700 text-white font-semibold rounded-lg transition-all disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center gap-2"
      >
        {loading ? (
          <>
            <span className="animate-spin">⏳</span> Analyzing...
          </>
        ) : (
          <>
            📤 Upload & Analyze
          </>
        )}
      </button>
    </form>
  );
}