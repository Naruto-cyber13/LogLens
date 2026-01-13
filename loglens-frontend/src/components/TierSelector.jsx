import React from 'react';

export default function TierSelector({ selectedTier, onTierChange }) {
  return (
    <div className="bg-slate-800 border border-slate-700 rounded-lg p-6 mb-8">
      <h2 className="text-xl font-bold text-white mb-4">Select Your Tier</h2>
      
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {/* Free Tier Card */}
        <div
          onClick={() => onTierChange('free')}
          className={`p-4 rounded-lg border-2 cursor-pointer transition-all ${
            selectedTier === 'free'
              ? 'border-blue-500 bg-blue-500 bg-opacity-10'
              : 'border-slate-600 bg-slate-700 bg-opacity-50 hover:border-slate-500'
          }`}
        >
          <h3 className="text-lg font-semibold text-white">Free Tier</h3>
          <p className="text-slate-300 text-sm mt-2">Perfect for getting started</p>
          <ul className="mt-3 space-y-1 text-slate-300 text-sm">
            <li>✓ Max 10MB file size</li>
            <li>✓ Basic threat detection</li>
            <li>✗ No analysis history</li>
            <li>✗ No custom rules</li>
          </ul>
        </div>

        {/* Pro Tier Card */}
        <div
          onClick={() => onTierChange('pro')}
          className={`p-4 rounded-lg border-2 cursor-pointer transition-all ${
            selectedTier === 'pro'
              ? 'border-purple-500 bg-purple-500 bg-opacity-10'
              : 'border-slate-600 bg-slate-700 bg-opacity-50 hover: border-slate-500'
          }`}
        >
          <h3 className="text-lg font-semibold text-white">Pro Tier</h3>
          <p className="text-slate-300 text-sm mt-2">Advanced threat detection</p>
          <ul className="mt-3 space-y-1 text-slate-300 text-sm">
            <li>✓ Unlimited file size</li>
            <li>✓ Advanced threat rules</li>
            <li>✓ Analysis history</li>
            <li>✓ Custom alert rules</li>
          </ul>
        </div>
      </div>
    </div>
  );
}