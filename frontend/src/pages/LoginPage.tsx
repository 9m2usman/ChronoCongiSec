import React, { useState } from 'react';
import { useNavigate, useLocation, Link } from 'react-router-dom';
import { apiClient } from '@/services/apiClient';
import { Shield, Lock, Mail, Building2, AlertTriangle, ArrowRight, CheckCircle2 } from 'lucide-react';

export const LoginPage: React.FC = () => {
  const navigate = useNavigate();
  const location = useLocation();
  const from = (location.state as any)?.from?.pathname || '/overview';

  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [tenantSlug, setTenantSlug] = useState('alphacorp');
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setIsLoading(true);

    try {
      await apiClient.login({
        email: email.trim(),
        password,
        tenant_slug: tenantSlug.trim(),
      });
      navigate(from, { replace: true });
    } catch (err: any) {
      setError(err.message || 'Authentication failed. Please verify your credentials and workspace.');
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="min-h-screen w-screen flex flex-col justify-center items-center bg-[#0B0F19] text-slate-100 font-mono px-4 py-8">
      {/* Container Card */}
      <div className="w-full max-w-md bg-[#111827] border border-slate-800 rounded-lg shadow-2xl p-6 sm:p-8 space-y-6">
        {/* Brand Header */}
        <div className="flex flex-col items-center text-center space-y-2">
          <div className="w-12 h-12 rounded-lg bg-blue-600/10 border border-blue-500/30 flex items-center justify-center text-blue-400">
            <Shield className="w-6 h-6" />
          </div>
          <h1 className="text-xl font-bold tracking-wider text-slate-100">CHRONOCOGNISEC</h1>
          <p className="text-xs text-slate-400">Agent Memory Security Center (AMSC) Workstation</p>
        </div>

        {/* Security Alert / Error Notice */}
        {error && (
          <div
            role="alert"
            className="p-3 bg-red-950/60 border border-red-500/40 rounded text-xs text-red-300 flex items-start gap-2"
          >
            <AlertTriangle className="w-4 h-4 text-red-400 shrink-0 mt-0.5" />
            <span className="leading-relaxed">{error}</span>
          </div>
        )}

        {/* Form */}
        <form onSubmit={handleSubmit} className="space-y-4 text-xs">
          <div>
            <label className="block text-slate-400 mb-1 font-semibold" htmlFor="login-email">
              Work Email Address
            </label>
            <div className="relative">
              <Mail className="w-4 h-4 text-slate-500 absolute left-3 top-2.5" />
              <input
                id="login-email"
                type="email"
                required
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="analyst@company.com"
                className="w-full pl-9 pr-3 py-2 bg-slate-950 border border-slate-700 rounded text-slate-100 placeholder-slate-600 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
              />
            </div>
          </div>

          <div>
            <label className="block text-slate-400 mb-1 font-semibold" htmlFor="login-password">
              Password
            </label>
            <div className="relative">
              <Lock className="w-4 h-4 text-slate-500 absolute left-3 top-2.5" />
              <input
                id="login-password"
                type="password"
                required
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="••••••••••••"
                className="w-full pl-9 pr-3 py-2 bg-slate-950 border border-slate-700 rounded text-slate-100 placeholder-slate-600 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
              />
            </div>
          </div>

          <div>
            <label className="block text-slate-400 mb-1 font-semibold" htmlFor="login-workspace">
              Company Workspace Slug
            </label>
            <div className="relative">
              <Building2 className="w-4 h-4 text-slate-500 absolute left-3 top-2.5" />
              <input
                id="login-workspace"
                type="text"
                required
                value={tenantSlug}
                onChange={(e) => setTenantSlug(e.target.value)}
                placeholder="alphacorp"
                className="w-full pl-9 pr-3 py-2 bg-slate-950 border border-slate-700 rounded text-slate-100 placeholder-slate-600 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
              />
            </div>
          </div>

          <button
            type="submit"
            disabled={isLoading}
            className="w-full mt-2 py-2.5 px-4 bg-blue-600 hover:bg-blue-500 text-white font-bold rounded flex items-center justify-center gap-2 transition-colors focus:outline-none focus:ring-2 focus:ring-blue-500 disabled:opacity-50"
          >
            {isLoading ? (
              <span>Authenticating...</span>
            ) : (
              <>
                <span>Authenticate into Workstation</span>
                <ArrowRight className="w-4 h-4" />
              </>
            )}
          </button>
        </form>

        {/* Self-registration & Bootstrap Links */}
        <div className="pt-4 border-t border-slate-800 flex flex-col gap-2 text-center text-xs">
          <p className="text-slate-400">
            Need employee workstation access?{' '}
            <Link to="/register" className="text-blue-400 hover:underline font-bold">
              Submit Access Request
            </Link>
          </p>
          <div className="flex items-center justify-center gap-1.5 text-[10px] text-slate-500 mt-2">
            <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
            <span>Strict Fail-Closed Mediation Active</span>
          </div>
        </div>
      </div>
    </div>
  );
};
