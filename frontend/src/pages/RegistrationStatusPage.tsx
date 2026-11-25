import React, { useState, useEffect, useCallback } from 'react';
import { useParams, Link } from 'react-router-dom';
import { Shield, Clock, CheckCircle2, XCircle, AlertCircle, RefreshCw, ArrowLeft } from 'lucide-react';
import { apiClient } from '@/services/apiClient';
import { RegistrationStatusResponse } from '@/types/auth';

export const RegistrationStatusPage: React.FC = () => {
  const { requestId } = useParams<{ requestId: string }>();
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const [statusData, setStatusData] = useState<RegistrationStatusResponse | null>(null);

  const fetchStatus = useCallback(async () => {
    if (!requestId) {
      setError('No request identifier provided.');
      setLoading(false);
      return;
    }

    try {
      setLoading(true);
      setError(null);
      const data = await apiClient.getRegistrationStatus(requestId);
      setStatusData(data);
    } catch (err: any) {
      setError(err?.message || 'Failed to retrieve registration status.');
    } finally {
      setLoading(false);
    }
  }, [requestId]);

  useEffect(() => {
    fetchStatus();
  }, [fetchStatus]);

  const renderStatusBadge = (status: string) => {
    switch (status) {
      case 'APPROVED':
        return (
          <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full bg-status-trustedBg text-status-trusted border border-status-trusted/40 text-xs font-bold">
            <CheckCircle2 className="w-3.5 h-3.5" /> APPROVED
          </span>
        );
      case 'REJECTED':
        return (
          <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full bg-status-criticalBg text-status-critical border border-status-critical/40 text-xs font-bold">
            <XCircle className="w-3.5 h-3.5" /> REJECTED
          </span>
        );
      case 'EXPIRED':
        return (
          <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full bg-status-unknownBg text-status-unknown border border-borderc text-xs font-bold">
            <AlertCircle className="w-3.5 h-3.5" /> EXPIRED
          </span>
        );
      case 'PENDING':
      default:
        return (
          <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full bg-status-warningBg text-status-warning border border-status-warning/40 text-xs font-bold">
            <Clock className="w-3.5 h-3.5" /> PENDING REVIEW
          </span>
        );
    }
  };

  return (
    <div className="min-h-screen w-screen bg-canvas text-ink flex flex-col justify-center items-center p-4 font-mono">
      <div className="w-full max-w-lg z-10 space-y-6">
        {/* Brand header */}
        <div className="text-center space-y-2">
          <div className="inline-flex items-center justify-center p-3 rounded-xl bg-surface border border-borderc shadow-md">
            <Shield className="w-8 h-8 text-brand" />
          </div>
          <h1 className="text-xl font-bold tracking-wider text-ink">CHRONOCOGNISEC AMSC</h1>
          <p className="text-xs text-ink-muted">Employee Registration Status Tracker</p>
        </div>

        {/* Status card */}
        <div className="p-6 bg-surface border border-borderc rounded-xl shadow-xl space-y-5">
          <div className="flex items-center justify-between pb-3 border-b border-borderc">
            <div className="text-xs text-ink-muted">
              Request ID: <span className="font-bold text-ink">{requestId}</span>
            </div>
            <button
              onClick={fetchStatus}
              disabled={loading}
              className="p-1.5 rounded hover:bg-elevated text-ink-muted hover:text-ink transition-colors"
              title="Refresh status"
            >
              <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
            </button>
          </div>

          {loading && (
            <div className="py-8 text-center text-ink-muted text-xs flex flex-col items-center gap-2">
              <RefreshCw className="w-6 h-6 animate-spin text-brand" />
              <span>Checking governance records...</span>
            </div>
          )}

          {error && !loading && (
            <div className="p-4 bg-status-criticalBg border border-status-critical/40 rounded-lg text-xs text-status-critical space-y-2">
              <div className="flex items-center gap-2 font-bold">
                <AlertCircle className="w-4 h-4 shrink-0" />
                <span>Unable to load request</span>
              </div>
              <p className="text-ink">{error}</p>
            </div>
          )}

          {statusData && !loading && (
            <div className="space-y-4">
              <div className="flex items-center justify-between">
                <span className="text-xs text-ink-muted">Current Status:</span>
                {renderStatusBadge(statusData.status)}
              </div>

              <div className="p-4 bg-canvas rounded-lg border border-borderc space-y-2.5 text-xs">
                <div className="flex justify-between">
                  <span className="text-ink-muted">Applicant Email:</span>
                  <span className="font-bold text-ink">{statusData.email_masked}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-ink-muted">Requested Branch:</span>
                  <span className="text-brand-teal font-bold">{statusData.requested_branch_code}</span>
                </div>
                {statusData.created_at && (
                  <div className="flex justify-between">
                    <span className="text-ink-muted">Submitted:</span>
                    <span className="text-ink-muted">{new Date(statusData.created_at).toLocaleString()}</span>
                  </div>
                )}
                {statusData.reviewed_at && (
                  <div className="flex justify-between">
                    <span className="text-ink-muted">Decision Date:</span>
                    <span className="text-ink-muted">{new Date(statusData.reviewed_at).toLocaleString()}</span>
                  </div>
                )}
                {statusData.reason && (
                  <div className="pt-2 border-t border-borderc">
                    <span className="text-ink-muted block mb-1">Administrative Note:</span>
                    <p className="text-ink italic bg-surface p-2 rounded border border-borderc">
                      {statusData.reason}
                    </p>
                  </div>
                )}
              </div>

              {/* Status explanation & call to action */}
              {statusData.status === 'PENDING' && (
                <div className="p-3 bg-status-warningBg border border-status-warning/30 rounded-lg text-xs text-ink flex items-start gap-2.5">
                  <Clock className="w-4 h-4 text-status-warning shrink-0 mt-0.5" />
                  <span>
                    Your request has been logged and is awaiting human review by a Tenant Administrator.
                    Once approved, your role and branch privileges will be activated.
                  </span>
                </div>
              )}

              {statusData.status === 'APPROVED' && (
                <div className="space-y-3">
                  <div className="p-3 bg-status-trustedBg border border-status-trusted/30 rounded-lg text-xs text-ink flex items-start gap-2.5">
                    <CheckCircle2 className="w-4 h-4 text-status-trusted shrink-0 mt-0.5" />
                    <span>
                      Your account has been approved and activated! You can now authenticate with your credentials.
                    </span>
                  </div>
                  <Link
                    to="/login"
                    className="w-full py-2.5 px-4 bg-brand hover:bg-brand-hover text-white rounded font-bold text-xs flex items-center justify-center gap-2 transition-colors shadow-sm"
                  >
                    Proceed to Login
                  </Link>
                </div>
              )}

              {statusData.status === 'REJECTED' && (
                <div className="p-3 bg-status-criticalBg border border-status-critical/30 rounded-lg text-xs text-ink flex items-start gap-2.5">
                  <XCircle className="w-4 h-4 text-status-critical shrink-0 mt-0.5" />
                  <span>
                    This registration request was rejected by the Tenant Administrator.
                    If you believe this is in error, contact your corporate security team.
                  </span>
                </div>
              )}
            </div>
          )}

          <div className="pt-2 border-t border-borderc flex justify-between items-center text-xs text-ink-muted">
            <Link to="/login" className="flex items-center gap-1 hover:text-ink transition-colors">
              <ArrowLeft className="w-3.5 h-3.5" /> Back to Login
            </Link>
            <Link to="/register" className="hover:text-ink transition-colors">
              Submit Another Request
            </Link>
          </div>
        </div>
      </div>
    </div>
  );
};
