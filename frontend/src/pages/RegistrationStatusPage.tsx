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
          <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full bg-emerald-950 text-emerald-400 border border-emerald-500/40 text-xs font-bold">
            <CheckCircle2 className="w-3.5 h-3.5" /> APPROVED
          </span>
        );
      case 'REJECTED':
        return (
          <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full bg-red-950 text-red-400 border border-red-500/40 text-xs font-bold">
            <XCircle className="w-3.5 h-3.5" /> REJECTED
          </span>
        );
      case 'EXPIRED':
        return (
          <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full bg-slate-800 text-slate-400 border border-slate-700 text-xs font-bold">
            <AlertCircle className="w-3.5 h-3.5" /> EXPIRED
          </span>
        );
      case 'PENDING':
      default:
        return (
          <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full bg-amber-950 text-amber-400 border border-amber-500/40 text-xs font-bold animate-pulse">
            <Clock className="w-3.5 h-3.5" /> PENDING REVIEW
          </span>
        );
    }
  };

  return (
    <div className="min-h-screen w-screen bg-[#0B0F19] text-slate-100 flex flex-col justify-center items-center p-4 font-mono">
      {/* Background radial gradient */}
      <div className="absolute inset-0 bg-[radial-gradient(ellipse_at_top,_var(--tw-gradient-stops))] from-blue-950/20 via-transparent to-transparent pointer-events-none" />

      <div className="w-full max-w-lg z-10 space-y-6">
        {/* Brand header */}
        <div className="text-center space-y-2">
          <div className="inline-flex items-center justify-center p-3 rounded-xl bg-slate-900 border border-slate-800 shadow-xl">
            <Shield className="w-8 h-8 text-blue-500" />
          </div>
          <h1 className="text-xl font-bold tracking-wider text-slate-100">CHRONOCOGNISEC AMSC</h1>
          <p className="text-xs text-slate-400">Employee Registration Status Tracker</p>
        </div>

        {/* Status card */}
        <div className="p-6 bg-slate-900 border border-slate-800 rounded-xl shadow-2xl space-y-5">
          <div className="flex items-center justify-between pb-3 border-b border-slate-800">
            <div className="text-xs text-slate-400">
              Request ID: <span className="font-bold text-slate-200">{requestId}</span>
            </div>
            <button
              onClick={fetchStatus}
              disabled={loading}
              className="p-1.5 rounded hover:bg-slate-800 text-slate-400 hover:text-slate-200 transition-colors"
              title="Refresh status"
            >
              <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
            </button>
          </div>

          {loading && (
            <div className="py-8 text-center text-slate-400 text-xs flex flex-col items-center gap-2">
              <RefreshCw className="w-6 h-6 animate-spin text-blue-500" />
              <span>Checking governance records...</span>
            </div>
          )}

          {error && !loading && (
            <div className="p-4 bg-red-950/60 border border-red-500/40 rounded-lg text-xs text-red-300 space-y-2">
              <div className="flex items-center gap-2 font-bold text-red-400">
                <AlertCircle className="w-4 h-4 shrink-0" />
                <span>Unable to load request</span>
              </div>
              <p>{error}</p>
            </div>
          )}

          {statusData && !loading && (
            <div className="space-y-4">
              <div className="flex items-center justify-between">
                <span className="text-xs text-slate-400">Current Status:</span>
                {renderStatusBadge(statusData.status)}
              </div>

              <div className="p-4 bg-slate-950 rounded-lg border border-slate-800 space-y-2.5 text-xs">
                <div className="flex justify-between">
                  <span className="text-slate-500">Applicant Email:</span>
                  <span className="font-bold text-slate-200">{statusData.email_masked}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-500">Requested Branch:</span>
                  <span className="text-cyan-400 font-bold">{statusData.requested_branch_code}</span>
                </div>
                {statusData.created_at && (
                  <div className="flex justify-between">
                    <span className="text-slate-500">Submitted:</span>
                    <span className="text-slate-400">{new Date(statusData.created_at).toLocaleString()}</span>
                  </div>
                )}
                {statusData.reviewed_at && (
                  <div className="flex justify-between">
                    <span className="text-slate-500">Decision Date:</span>
                    <span className="text-slate-400">{new Date(statusData.reviewed_at).toLocaleString()}</span>
                  </div>
                )}
                {statusData.reason && (
                  <div className="pt-2 border-t border-slate-800/80">
                    <span className="text-slate-500 block mb-1">Administrative Note:</span>
                    <p className="text-slate-300 italic bg-slate-900 p-2 rounded border border-slate-800">
                      {statusData.reason}
                    </p>
                  </div>
                )}
              </div>

              {/* Status explanation & call to action */}
              {statusData.status === 'PENDING' && (
                <div className="p-3 bg-amber-950/40 border border-amber-500/30 rounded-lg text-xs text-amber-300 flex items-start gap-2.5">
                  <Clock className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
                  <span>
                    Your request has been logged and is awaiting human review by a Tenant Administrator.
                    Once approved, your role and branch privileges will be activated.
                  </span>
                </div>
              )}

              {statusData.status === 'APPROVED' && (
                <div className="space-y-3">
                  <div className="p-3 bg-emerald-950/40 border border-emerald-500/30 rounded-lg text-xs text-emerald-300 flex items-start gap-2.5">
                    <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
                    <span>
                      Your account has been approved and activated! You can now authenticate with your credentials.
                    </span>
                  </div>
                  <Link
                    to="/login"
                    className="w-full py-2.5 px-4 bg-blue-600 hover:bg-blue-500 text-white rounded font-bold text-xs flex items-center justify-center gap-2 transition-colors shadow-sm"
                  >
                    Proceed to Login
                  </Link>
                </div>
              )}

              {statusData.status === 'REJECTED' && (
                <div className="p-3 bg-red-950/40 border border-red-500/30 rounded-lg text-xs text-red-300 flex items-start gap-2.5">
                  <XCircle className="w-4 h-4 text-red-400 shrink-0 mt-0.5" />
                  <span>
                    This registration request was rejected by the Tenant Administrator.
                    If you believe this is in error, contact your corporate security team.
                  </span>
                </div>
              )}
            </div>
          )}

          <div className="pt-2 border-t border-slate-800 flex justify-between items-center text-xs text-slate-500">
            <Link to="/login" className="flex items-center gap-1 hover:text-slate-300 transition-colors">
              <ArrowLeft className="w-3.5 h-3.5" /> Back to Login
            </Link>
            <Link to="/register" className="hover:text-slate-300 transition-colors">
              Submit Another Request
            </Link>
          </div>
        </div>
      </div>
    </div>
  );
};
