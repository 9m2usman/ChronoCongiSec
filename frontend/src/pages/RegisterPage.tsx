import React, { useEffect, useState } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { apiClient } from '@/services/apiClient';
import { BranchInfo } from '@/types';
import { Shield, Lock, Mail, User, Building, AlertTriangle, ArrowRight, CheckCircle2 } from 'lucide-react';

export const RegisterPage: React.FC = () => {
  const navigate = useNavigate();

  const [fullName, setFullName] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [requestedBranchCode, setRequestedBranchCode] = useState('HO');
  const tenantSlug = 'alphacorp';

  const [branches, setBranches] = useState<BranchInfo[]>([]);
  const [isLoadingBranches, setIsLoadingBranches] = useState(true);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let isMounted = true;
    async function fetchBranches() {
      try {
        const data = await apiClient.getBranches(tenantSlug);
        if (isMounted) {
          setBranches(data);
          if (data.length > 0) {
            setRequestedBranchCode(data[0].code);
          }
        }
      } catch {
        // Fallback default enterprise branches
        if (isMounted) {
          setBranches([
            { id: 'branch-ho-001', tenant_id: 'tenant-a-uuid-001', name: 'Head Office - Core Security', code: 'HO', status: 'ACTIVE' },
            { id: 'branch-lhr-002', tenant_id: 'tenant-a-uuid-001', name: 'Finance & Regional Operations Branch (Lahore)', code: 'LHR', status: 'ACTIVE' },
            { id: 'branch-khi-003', tenant_id: 'tenant-a-uuid-001', name: 'Maritime & Logistics Operations Branch (Karachi)', code: 'KHI', status: 'ACTIVE' },
            { id: 'branch-isb-004', tenant_id: 'tenant-a-uuid-001', name: 'Corporate Affairs & HR Branch (Islamabad)', code: 'ISB', status: 'ACTIVE' },
          ]);
        }
      } finally {
        if (isMounted) setIsLoadingBranches(false);
      }
    }
    fetchBranches();
    return () => {
      isMounted = false;
    };
  }, [tenantSlug]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);

    if (password.length < 8) {
      setError('Password must be at least 8 characters long.');
      return;
    }

    setIsSubmitting(true);

    try {
      const res = await apiClient.register({
        full_name: fullName.trim(),
        email: email.trim(),
        password,
        requested_branch_code: requestedBranchCode,
        tenant_slug: tenantSlug.trim(),
      });
      navigate(`/registration-status/${encodeURIComponent(res.request_id)}`);
    } catch (err: any) {
      setError(err.message || 'Registration request submission failed.');
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <div className="min-h-screen w-screen flex flex-col justify-center items-center bg-canvas text-ink font-mono px-4 py-8">
      <div className="w-full max-w-lg bg-surface border border-borderc rounded-lg shadow-xl p-6 sm:p-8 space-y-6">
        {/* Header */}
        <div className="flex flex-col items-center text-center space-y-2">
          <div className="w-12 h-12 rounded-lg bg-brand-tint border border-brand/30 flex items-center justify-center text-brand">
            <Shield className="w-6 h-6" />
          </div>
          <h1 className="text-xl font-bold tracking-wider text-ink">EMPLOYEE REGISTRATION</h1>
          <p className="text-xs text-ink-muted">Request Access to AMSC Security Operations Workstation</p>
        </div>

        {/* Informational Policy Banner */}
        <div className="p-3 bg-brand-tint border border-brand/30 rounded text-xs text-ink leading-relaxed">
          <p className="font-semibold text-brand mb-1 flex items-center gap-1.5">
            <Shield className="w-3.5 h-3.5" /> Administrative Approval Policy
          </p>
          Employee registration requests are reviewed by an authorized Tenant Administrator. You will be assigned a role
          and authorized branch upon approval.
        </div>

        {error && (
          <div
            role="alert"
            className="p-3 bg-status-criticalBg border border-status-critical/40 rounded text-xs text-status-critical flex items-start gap-2"
          >
            <AlertTriangle className="w-4 h-4 shrink-0 mt-0.5" />
            <span className="leading-relaxed">{error}</span>
          </div>
        )}

        <form onSubmit={handleSubmit} className="space-y-4 text-xs">
          <div>
            <label className="block text-ink-muted mb-1 font-semibold" htmlFor="reg-name">
              Full Name
            </label>
            <div className="relative">
              <User className="w-4 h-4 text-ink-muted absolute left-3 top-2.5" />
              <input
                id="reg-name"
                type="text"
                required
                value={fullName}
                onChange={(e) => setFullName(e.target.value)}
                placeholder="Jane Doe"
                className="w-full pl-9 pr-3 py-2 bg-canvas border border-borderc rounded text-ink placeholder-ink-muted focus:outline-none focus:ring-2 focus:ring-brand focus:border-brand"
              />
            </div>
          </div>

          <div>
            <label className="block text-ink-muted mb-1 font-semibold" htmlFor="reg-email">
              Enterprise Work Email
            </label>
            <div className="relative">
              <Mail className="w-4 h-4 text-ink-muted absolute left-3 top-2.5" />
              <input
                id="reg-email"
                type="email"
                required
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="jane.doe@company.com"
                className="w-full pl-9 pr-3 py-2 bg-canvas border border-borderc rounded text-ink placeholder-ink-muted focus:outline-none focus:ring-2 focus:ring-brand focus:border-brand"
              />
            </div>
          </div>

          <div>
            <label className="block text-ink-muted mb-1 font-semibold" htmlFor="reg-password">
              Password (minimum 8 characters)
            </label>
            <div className="relative">
              <Lock className="w-4 h-4 text-ink-muted absolute left-3 top-2.5" />
              <input
                id="reg-password"
                type="password"
                required
                minLength={8}
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="••••••••••••"
                className="w-full pl-9 pr-3 py-2 bg-canvas border border-borderc rounded text-ink placeholder-ink-muted focus:outline-none focus:ring-2 focus:ring-brand focus:border-brand"
              />
            </div>
          </div>

          <div>
            <label className="block text-ink-muted mb-1 font-semibold" htmlFor="reg-branch">
              Requested Branch Assignment
            </label>
            <div className="relative">
              <Building className="w-4 h-4 text-ink-muted absolute left-3 top-2.5" />
              <select
                id="reg-branch"
                value={requestedBranchCode}
                onChange={(e) => setRequestedBranchCode(e.target.value)}
                disabled={isLoadingBranches}
                className="w-full pl-9 pr-3 py-2 bg-canvas border border-borderc rounded text-ink focus:outline-none focus:ring-2 focus:ring-brand focus:border-brand"
              >
                {branches.map((b) => (
                  <option key={b.code} value={b.code}>
                    {b.name} ({b.code})
                  </option>
                ))}
              </select>
            </div>
          </div>

          <button
            type="submit"
            disabled={isSubmitting}
            className="w-full mt-2 py-2.5 px-4 bg-brand hover:bg-brand-hover text-white font-bold rounded flex items-center justify-center gap-2 transition-colors focus:outline-none focus:ring-2 focus:ring-brand disabled:opacity-50"
          >
            {isSubmitting ? (
              <span>Submitting Request...</span>
            ) : (
              <>
                <span>Submit Access Request</span>
                <ArrowRight className="w-4 h-4" />
              </>
            )}
          </button>
        </form>

        <div className="pt-4 border-t border-borderc flex flex-col gap-2 text-center text-xs">
          <p className="text-ink-muted">
            Already have an approved account?{' '}
            <Link to="/login" className="text-brand hover:underline font-bold">
              Sign In
            </Link>
          </p>
          <div className="flex items-center justify-center gap-1.5 text-[10px] text-ink-muted mt-2">
            <CheckCircle2 className="w-3.5 h-3.5 text-status-trusted" />
            <span>Server-Enforced Role & Branch Governance</span>
          </div>
        </div>
      </div>
    </div>
  );
};
