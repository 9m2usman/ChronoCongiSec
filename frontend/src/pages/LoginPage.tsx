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
    <div className="min-h-screen w-screen flex flex-col justify-center items-center bg-canvas text-ink font-mono px-4 py-8">
      {/* Container Card */}
      <div className="w-full max-w-md bg-surface border border-borderc rounded-lg shadow-xl p-6 sm:p-8 space-y-6">
        {/* Brand Header */}
        <div className="flex flex-col items-center text-center space-y-2">
          <div className="w-12 h-12 rounded-lg bg-brand-tint border border-brand/30 flex items-center justify-center text-brand">
            <Shield className="w-6 h-6" />
          </div>
          <h1 className="text-xl font-bold tracking-wider text-ink">CHRONOCOGNISEC</h1>
          <p className="text-xs text-ink-muted">Agent Memory Security Center (AMSC) Workstation</p>
        </div>

        {/* Security Alert / Error Notice */}
        {error && (
          <div
            role="alert"
            className="p-3 bg-status-criticalBg border border-status-critical/40 rounded text-xs text-status-critical flex items-start gap-2"
          >
            <AlertTriangle className="w-4 h-4 shrink-0 mt-0.5" />
            <span className="leading-relaxed">{error}</span>
          </div>
        )}

        {/* Form */}
        <form onSubmit={handleSubmit} className="space-y-4 text-xs">
          <div>
            <label className="block text-ink-muted mb-1 font-semibold" htmlFor="login-email">
              Work Email Address
            </label>
            <div className="relative">
              <Mail className="w-4 h-4 text-ink-muted absolute left-3 top-2.5" />
              <input
                id="login-email"
                type="email"
                required
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="analyst@company.com"
                className="w-full pl-9 pr-3 py-2 bg-canvas border border-borderc rounded text-ink placeholder-ink-muted focus:outline-none focus:ring-2 focus:ring-brand focus:border-brand"
              />
            </div>
          </div>

          <div>
            <label className="block text-ink-muted mb-1 font-semibold" htmlFor="login-password">
              Password
            </label>
            <div className="relative">
              <Lock className="w-4 h-4 text-ink-muted absolute left-3 top-2.5" />
              <input
                id="login-password"
                type="password"
                required
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="••••••••••••"
                className="w-full pl-9 pr-3 py-2 bg-canvas border border-borderc rounded text-ink placeholder-ink-muted focus:outline-none focus:ring-2 focus:ring-brand focus:border-brand"
              />
            </div>
          </div>

          <div>
            <label className="block text-ink-muted mb-1 font-semibold" htmlFor="login-workspace">
              Company Workspace Slug
            </label>
            <div className="relative">
              <Building2 className="w-4 h-4 text-ink-muted absolute left-3 top-2.5" />
              <input
                id="login-workspace"
                type="text"
                required
                value={tenantSlug}
                onChange={(e) => setTenantSlug(e.target.value)}
                placeholder="alphacorp"
                className="w-full pl-9 pr-3 py-2 bg-canvas border border-borderc rounded text-ink placeholder-ink-muted focus:outline-none focus:ring-2 focus:ring-brand focus:border-brand"
              />
            </div>
          </div>

          <button
            type="submit"
            disabled={isLoading}
            className="w-full mt-2 py-2.5 px-4 bg-brand hover:bg-brand-hover text-white font-bold rounded flex items-center justify-center gap-2 transition-colors focus:outline-none focus:ring-2 focus:ring-brand disabled:opacity-50"
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
        <div className="pt-4 border-t border-borderc flex flex-col gap-2 text-center text-xs">
          <p className="text-ink-muted">
            Need employee workstation access?{' '}
            <Link to="/register" className="text-brand hover:underline font-bold">
              Submit Access Request
            </Link>
          </p>
          <div className="flex items-center justify-center gap-1.5 text-[10px] text-ink-muted mt-2">
            <CheckCircle2 className="w-3.5 h-3.5 text-status-trusted" />
            <span>Strict Fail-Closed Mediation Active</span>
          </div>
        </div>
      </div>
    </div>
  );
};
