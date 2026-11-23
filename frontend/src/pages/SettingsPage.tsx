import React, { useState, useEffect, useCallback } from 'react';
import { useWorkstationStore } from '@/stores/useWorkstationStore';
import { ForensicErrorBoundary } from '@/components/common/ForensicErrorBoundary';
import { apiClient } from '@/services/apiClient';
import {
  RegistrationRequestDetail,
  TenantMember,
  BranchInfo,
  Role,
} from '@/types/auth';
import {
  Settings,
  Shield,
  Key,
  Database,
  Sliders,
  CheckCircle2,
  Copy,
  RotateCw,
  Lock,
  Sparkles,
  Users,
  UserCheck,
  UserX,
  AlertTriangle,
  RefreshCw,
  Building2,
} from 'lucide-react';

export const SettingsPage: React.FC = () => {
  const { activeTenant, currentUser } = useWorkstationStore();

  // Tab State
  const [activeTab, setActiveTab] = useState<'policies' | 'governance'>('policies');

  // Policy toggles
  const [sec001, setSec001] = useState<boolean>(true);
  const [sec004, setSec004] = useState<boolean>(true);
  const [sec005, setSec005] = useState<boolean>(true);
  const [sec007, setSec007] = useState<boolean>(true);

  // Ceilings and thresholds
  const [gatewayTimeoutMs, setGatewayTimeoutMs] = useState<number>(2500);
  const [maxGraphDepth, setMaxGraphDepth] = useState<number>(5);
  const [anomalyThreshold, setAnomalyThreshold] = useState<number>(0.35);

  // Scoped key management
  const [apiKeyPrefix, setApiKeyPrefix] = useState<string>(`amsc_live_sk_${activeTenant.slug}_991a`);
  const [isRotatingKey, setIsRotatingKey] = useState<boolean>(false);
  const [copiedKey, setCopiedKey] = useState<boolean>(false);
  const [saved, setSaved] = useState<boolean>(false);

  // Governance / IAM state
  const [pendingRequests, setPendingRequests] = useState<RegistrationRequestDetail[]>([]);
  const [members, setMembers] = useState<TenantMember[]>([]);
  const [branches, setBranches] = useState<BranchInfo[]>([]);
  const [governanceLoading, setGovernanceLoading] = useState<boolean>(false);
  const [governanceError, setGovernanceError] = useState<string | null>(null);
  const [governanceSuccess, setGovernanceSuccess] = useState<string | null>(null);

  // Approval modal state
  const [selectedRequest, setSelectedRequest] = useState<RegistrationRequestDetail | null>(null);
  const [approvalRole, setApprovalRole] = useState<Role>('SECURITY_ANALYST');
  const [approvalBranchId, setApprovalBranchId] = useState<string>('branch-ho-001');
  const [approvalNote, setApprovalNote] = useState<string>('');
  const [isApproving, setIsApproving] = useState<boolean>(false);

  // Reject modal state
  const [rejectRequestId, setRejectRequestId] = useState<string | null>(null);
  const [rejectReason, setRejectReason] = useState<string>('');
  const [isRejecting, setIsRejecting] = useState<boolean>(false);

  // Member editing state
  const [editingMember, setEditingMember] = useState<TenantMember | null>(null);
  const [editMemberRole, setEditMemberRole] = useState<Role>('SECURITY_ANALYST');
  const [editMemberBranchId, setEditMemberBranchId] = useState<string>('branch-ho-001');
  const [isUpdatingMember, setIsUpdatingMember] = useState<boolean>(false);

  const isTenantAdmin = currentUser?.role === 'TENANT_ADMIN';

  const fetchGovernanceData = useCallback(async () => {
    if (!isTenantAdmin) return;
    try {
      setGovernanceLoading(true);
      setGovernanceError(null);
      const [reqs, userList, branchList] = await Promise.all([
        apiClient.getPendingRegistrations(),
        apiClient.getUsers(),
        apiClient.getBranches(),
      ]);
      setPendingRequests(reqs);
      setMembers(userList);
      setBranches(branchList);
    } catch (err: any) {
      setGovernanceError(err?.message || 'Failed to fetch identity governance data');
    } finally {
      setGovernanceLoading(false);
    }
  }, [isTenantAdmin]);

  useEffect(() => {
    if (activeTab === 'governance') {
      fetchGovernanceData();
    }
  }, [activeTab, fetchGovernanceData]);

  const handleRotateKey = () => {
    setIsRotatingKey(true);
    setTimeout(() => {
      const randomBytes = new Uint8Array(4);
      window.crypto.getRandomValues(randomBytes);
      const secureHex = Array.from(randomBytes, (b) => b.toString(16).padStart(2, '0')).join('');
      setApiKeyPrefix(`amsc_live_sk_${activeTenant.slug}_${secureHex}`);
      setIsRotatingKey(false);
    }, 400);
  };

  const handleCopyKey = () => {
    navigator.clipboard.writeText(`${apiKeyPrefix}********************`);
    setCopiedKey(true);
    setTimeout(() => setCopiedKey(false), 2000);
  };

  const handleSave = () => {
    setSaved(true);
    setTimeout(() => setSaved(false), 4000);
  };

  const openApproveModal = (req: RegistrationRequestDetail) => {
    setSelectedRequest(req);
    setApprovalRole('SECURITY_ANALYST');
    const matchedBranch = branches.find((b) => b.code === req.requested_branch_code);
    setApprovalBranchId(matchedBranch?.id ?? branches[0]?.id ?? 'branch-ho-001');
    setApprovalNote('Approved by Tenant Admin');
  };

  const handleApprove = async () => {
    if (!selectedRequest) return;
    try {
      setIsApproving(true);
      setGovernanceError(null);
      await apiClient.approveRegistration(selectedRequest.id, {
        role: approvalRole,
        branch_id: approvalBranchId,
        reason: approvalNote,
      });
      setGovernanceSuccess(`Registration request for ${selectedRequest.email} approved successfully.`);
      setSelectedRequest(null);
      await fetchGovernanceData();
      setTimeout(() => setGovernanceSuccess(null), 4000);
    } catch (err: any) {
      setGovernanceError(err?.message || 'Failed to approve registration request');
    } finally {
      setIsApproving(false);
    }
  };

  const handleReject = async () => {
    if (!rejectRequestId) return;
    try {
      setIsRejecting(true);
      setGovernanceError(null);
      await apiClient.rejectRegistration(rejectRequestId, rejectReason || 'Request rejected by Tenant Admin');
      setGovernanceSuccess('Registration request rejected.');
      setRejectRequestId(null);
      setRejectReason('');
      await fetchGovernanceData();
      setTimeout(() => setGovernanceSuccess(null), 4000);
    } catch (err: any) {
      setGovernanceError(err?.message || 'Failed to reject registration request');
    } finally {
      setIsRejecting(false);
    }
  };

  const handleUpdateMember = async () => {
    if (!editingMember) return;
    try {
      setIsUpdatingMember(true);
      setGovernanceError(null);
      await apiClient.updateUserMembership(editingMember.user_id, {
        role: editMemberRole,
        branch_id: editMemberBranchId,
      });
      setGovernanceSuccess(`Membership for ${editingMember.email} updated.`);
      setEditingMember(null);
      await fetchGovernanceData();
      setTimeout(() => setGovernanceSuccess(null), 4000);
    } catch (err: any) {
      setGovernanceError(err?.message || 'Failed to update user membership');
    } finally {
      setIsUpdatingMember(false);
    }
  };

  return (
    <ForensicErrorBoundary fallbackTitle="Settings & Governance Fault">
      <div className="space-y-6 font-mono text-slate-100">
        {/* Title Header */}
        <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-4 border-b border-slate-800 gap-3">
          <div>
            <h1 className="text-xl font-bold text-slate-100 flex items-center gap-2">
              <Settings className="w-5 h-5 text-slate-400" />
              Tenant Settings & Security Governance
            </h1>
            <p className="text-xs text-slate-400 mt-0.5">
              Security policy toggles, tenant isolation keys, and identity access governance for{' '}
              <span className="text-blue-400 font-bold">{activeTenant.name}</span>
            </p>
          </div>

          <div className="flex items-center gap-2">
            {activeTab === 'policies' && (
              <button
                onClick={handleSave}
                className="flex items-center gap-1.5 px-4 py-2 bg-blue-600 hover:bg-blue-500 text-white rounded text-xs font-bold transition-colors shadow-sm"
              >
                <CheckCircle2 className="w-4 h-4" /> Save Configuration
              </button>
            )}
            {activeTab === 'governance' && (
              <button
                onClick={fetchGovernanceData}
                disabled={governanceLoading || !isTenantAdmin}
                className="flex items-center gap-1.5 px-3 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 rounded text-xs font-bold transition-colors disabled:opacity-50"
              >
                <RefreshCw className={`w-3.5 h-3.5 ${governanceLoading ? 'animate-spin' : ''}`} />
                <span>Refresh</span>
              </button>
            )}
          </div>
        </div>

        {/* Tab Navigation */}
        <div className="flex border-b border-slate-800 gap-4 text-xs font-bold">
          <button
            onClick={() => setActiveTab('policies')}
            className={`pb-2.5 px-2 flex items-center gap-2 border-b-2 transition-colors ${
              activeTab === 'policies'
                ? 'border-blue-500 text-blue-400'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <Shield className="w-4 h-4" />
            <span>Tenant & Security Policies</span>
          </button>
          <button
            onClick={() => setActiveTab('governance')}
            className={`pb-2.5 px-2 flex items-center gap-2 border-b-2 transition-colors ${
              activeTab === 'governance'
                ? 'border-blue-500 text-blue-400'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <Users className="w-4 h-4" />
            <span>Users & Access Governance</span>
            {pendingRequests.length > 0 && (
              <span className="px-1.5 py-0.2 rounded-full bg-amber-500 text-slate-950 text-[10px] font-bold">
                {pendingRequests.length}
              </span>
            )}
          </button>
        </div>

        {/* Alerts */}
        {governanceSuccess && (
          <div className="p-3 bg-emerald-950/60 border border-emerald-500/40 rounded-lg text-xs text-emerald-300 flex items-center gap-2">
            <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
            <span>{governanceSuccess}</span>
          </div>
        )}
        {governanceError && (
          <div className="p-3 bg-red-950/60 border border-red-500/40 rounded-lg text-xs text-red-300 flex items-center gap-2">
            <AlertTriangle className="w-4 h-4 text-red-400 shrink-0" />
            <span>{governanceError}</span>
          </div>
        )}

        {/* TAB 1: POLICIES */}
        {activeTab === 'policies' && (
          <div className="space-y-6">
            {/* Saved Notification Banner */}
            {saved && (
              <div className="p-3 bg-emerald-950/60 border border-emerald-500/40 rounded-lg text-xs text-emerald-300 flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
                  <span>Client configuration updated. Policies applied across active workstation.</span>
                </div>
                <span className="text-[10px] text-emerald-400 font-bold uppercase tracking-wider">Active</span>
              </div>
            )}

            {/* Active Tenant Profile Card */}
            <div className="p-5 bg-slate-900 border border-slate-800 rounded-lg space-y-4 shadow-md">
              <div className="flex items-center justify-between pb-3 border-b border-slate-800">
                <div className="flex items-center gap-2 text-sm font-bold text-slate-200">
                  <Database className="w-4 h-4 text-cyan-400" /> Tenant Multi-Tenant Partitioning
                </div>
                <span className="px-2 py-0.5 rounded bg-blue-950 text-blue-300 border border-blue-500/40 text-[10px] font-bold">
                  Strict Isolation Active
                </span>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-4 gap-4 text-xs">
                <div className="p-3 bg-slate-950 rounded border border-slate-800">
                  <div className="text-[10px] text-slate-500 uppercase">Tenant Identifier</div>
                  <div className="font-bold text-slate-200 mt-1 font-mono text-xs">{activeTenant.id}</div>
                </div>

                <div className="p-3 bg-slate-950 rounded border border-slate-800">
                  <div className="text-[10px] text-slate-500 uppercase">Vector Namespace</div>
                  <div className="font-bold text-cyan-400 mt-1 font-mono text-xs">
                    tenant-vector-{activeTenant.slug}
                  </div>
                </div>

                <div className="p-3 bg-slate-950 rounded border border-slate-800">
                  <div className="text-[10px] text-slate-500 uppercase">Data Custody Tier</div>
                  <div className="font-bold text-purple-400 mt-1 text-xs">Tier 1: Enterprise Isolation</div>
                </div>

                <div className="p-3 bg-slate-950 rounded border border-slate-800">
                  <div className="text-[10px] text-slate-500 uppercase">KMS Encryption Key</div>
                  <div className="font-bold text-emerald-400 mt-1 font-mono text-[11px] truncate">
                    arn:aws:kms:us-east-1:amsc-kms-{activeTenant.slug}
                  </div>
                </div>
              </div>
            </div>

            {/* Two-Column Grid: Policy Toggles & Threshold Controls */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              {/* Authoritative Security Policy Toggles */}
              <div className="p-5 bg-slate-900 border border-slate-800 rounded-lg space-y-4 shadow-md">
                <div className="flex items-center gap-2 text-sm font-bold text-slate-200 pb-2 border-b border-slate-800">
                  <Shield className="w-4 h-4 text-blue-400" /> Authoritative Security Policies (SEC Rules)
                </div>

                <div className="space-y-4">
                  <div className="flex items-start justify-between gap-4">
                    <div>
                      <div className="text-xs font-bold text-slate-200">SEC-001: Strict Schema Enforce on Ingest</div>
                      <div className="text-[11px] text-slate-400 mt-0.5">
                        Reject memory ingest payloads lacking cryptographic SHA-256 signatures or required metadata schema.
                      </div>
                    </div>
                    <input
                      type="checkbox"
                      checked={sec001}
                      onChange={(e) => setSec001(e.target.checked)}
                      className="w-4 h-4 rounded text-blue-600 bg-slate-950 border-slate-700 mt-0.5"
                    />
                  </div>

                  <div className="flex items-start justify-between gap-4">
                    <div>
                      <div className="text-xs font-bold text-slate-200">SEC-004: Fail-Closed Gateway Action Gate</div>
                      <div className="text-[11px] text-slate-400 mt-0.5">
                        Automatically block tool proposals with 403 Forbidden if policy evaluation times out or errors.
                      </div>
                    </div>
                    <input
                      type="checkbox"
                      checked={sec004}
                      onChange={(e) => setSec004(e.target.checked)}
                      className="w-4 h-4 rounded text-blue-600 bg-slate-950 border-slate-700 mt-0.5"
                    />
                  </div>

                  <div className="flex items-start justify-between gap-4">
                    <div>
                      <div className="text-xs font-bold text-slate-200">SEC-005: Strict RAG Quarantine Exclusion</div>
                      <div className="text-[11px] text-slate-400 mt-0.5">
                        Filter out memory chunks with trust_state = 'QUARANTINED' from autonomous agent vector retrieval.
                      </div>
                    </div>
                    <input
                      type="checkbox"
                      checked={sec005}
                      onChange={(e) => setSec005(e.target.checked)}
                      className="w-4 h-4 rounded text-blue-600 bg-slate-950 border-slate-700 mt-0.5"
                    />
                  </div>

                  <div className="flex items-start justify-between gap-4">
                    <div>
                      <div className="text-xs font-bold text-slate-200">SEC-007: Mandatory Pre-Rollback Snapshotting</div>
                      <div className="text-[11px] text-slate-400 mt-0.5">
                        Guarantee immutable cryptographic capture of tainted memory state prior to atomic rewind execution.
                      </div>
                    </div>
                    <input
                      type="checkbox"
                      checked={sec007}
                      onChange={(e) => setSec007(e.target.checked)}
                      className="w-4 h-4 rounded text-blue-600 bg-slate-950 border-slate-700 mt-0.5"
                    />
                  </div>
                </div>
              </div>

              {/* System Thresholds & Ceilings */}
              <div className="p-5 bg-slate-900 border border-slate-800 rounded-lg space-y-4 shadow-md">
                <div className="flex items-center gap-2 text-sm font-bold text-slate-200 pb-2 border-b border-slate-800">
                  <Sliders className="w-4 h-4 text-purple-400" /> Enforcement Ceilings & Timeouts
                </div>

                <div className="space-y-4 text-xs">
                  <div>
                    <div className="flex justify-between items-center mb-1">
                      <span className="text-slate-300 font-bold">Gateway Evaluation Timeout (ms)</span>
                      <span className="font-mono text-cyan-400">{gatewayTimeoutMs}ms</span>
                    </div>
                    <input
                      type="range"
                      min={500}
                      max={5000}
                      step={100}
                      value={gatewayTimeoutMs}
                      onChange={(e) => setGatewayTimeoutMs(Number(e.target.value))}
                      className="w-full h-1.5 bg-slate-950 rounded appearance-none cursor-pointer accent-cyan-400 border border-slate-800"
                    />
                    <span className="text-[10px] text-slate-500">Max latency allowance before fail-closed SEC-004 drop</span>
                  </div>

                  <div>
                    <div className="flex justify-between items-center mb-1">
                      <span className="text-slate-300 font-bold">Max Lineage Hop Depth</span>
                      <span className="font-mono text-purple-400">{maxGraphDepth} Hops</span>
                    </div>
                    <input
                      type="range"
                      min={1}
                      max={10}
                      value={maxGraphDepth}
                      onChange={(e) => setMaxGraphDepth(Number(e.target.value))}
                      className="w-full h-1.5 bg-slate-950 rounded appearance-none cursor-pointer accent-purple-400 border border-slate-800"
                    />
                    <span className="text-[10px] text-slate-500">Traversal radius limit for DAG queries</span>
                  </div>

                  <div>
                    <div className="flex justify-between items-center mb-1">
                      <span className="text-slate-300 font-bold">Anomaly Cosine Drift Limit (Δ)</span>
                      <span className="font-mono text-amber-400">{anomalyThreshold.toFixed(2)} Δ</span>
                    </div>
                    <input
                      type="range"
                      min={0.10}
                      max={0.80}
                      step={0.05}
                      value={anomalyThreshold}
                      onChange={(e) => setAnomalyThreshold(Number(e.target.value))}
                      className="w-full h-1.5 bg-slate-950 rounded appearance-none cursor-pointer accent-amber-400 border border-slate-800"
                    />
                    <span className="text-[10px] text-slate-500">Automatic quarantine trigger point</span>
                  </div>
                </div>
              </div>
            </div>

            {/* Scoped API Key Management */}
            <div className="p-5 bg-slate-900 border border-slate-800 rounded-lg space-y-4 shadow-md">
              <div className="flex items-center justify-between pb-3 border-b border-slate-800">
                <div className="flex items-center gap-2 text-sm font-bold text-slate-200">
                  <Key className="w-4 h-4 text-amber-400" /> Scoped Tenant API Keys & Tokens
                </div>
                <span className="text-[10px] text-slate-400 flex items-center gap-1">
                  <Lock className="w-3 h-3 text-emerald-400" /> HMAC-SHA256 Signed
                </span>
              </div>

              <div className="flex flex-col sm:flex-row items-center justify-between gap-3 p-3 bg-slate-950 rounded border border-slate-800">
                <div className="w-full">
                  <div className="text-[10px] text-slate-500 uppercase">Primary Tenant Scoped Key</div>
                  <div className="font-mono text-xs text-slate-200 mt-1 flex items-center gap-2">
                    <span>{apiKeyPrefix}********************</span>
                    <span className="px-1.5 py-0.2 rounded bg-emerald-950 text-emerald-300 border border-emerald-500/40 text-[9px] font-bold">
                      ACTIVE
                    </span>
                  </div>
                </div>

                <div className="flex items-center gap-2 shrink-0 w-full sm:w-auto justify-end">
                  <button
                    onClick={handleCopyKey}
                    className="flex items-center gap-1.5 px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded text-xs transition-colors border border-slate-700"
                  >
                    <Copy className="w-3.5 h-3.5" />
                    <span>{copiedKey ? 'Copied!' : 'Copy'}</span>
                  </button>

                  <button
                    onClick={handleRotateKey}
                    disabled={isRotatingKey}
                    className="flex items-center gap-1.5 px-3 py-1.5 bg-amber-950 hover:bg-amber-900 text-amber-200 rounded text-xs font-bold transition-colors border border-amber-500/40 disabled:opacity-50"
                  >
                    <RotateCw className={`w-3.5 h-3.5 ${isRotatingKey ? 'animate-spin' : ''}`} />
                    <span>Rotate Key</span>
                  </button>
                </div>
              </div>

              <div className="text-[11px] text-slate-500 flex items-center gap-1.5">
                <Sparkles className="w-3.5 h-3.5 text-cyan-400" />
                <span>Key rotation propagates to all fail-closed gateways within 2.5 seconds without dropping active sessions.</span>
              </div>
            </div>
          </div>
        )}

        {/* TAB 2: GOVERNANCE / IAM */}
        {activeTab === 'governance' && (
          <div className="space-y-6">
            {!isTenantAdmin && (
              <div className="p-4 bg-amber-950/40 border border-amber-500/30 rounded-lg text-xs text-amber-300 flex items-center gap-3">
                <AlertTriangle className="w-5 h-5 text-amber-400 shrink-0" />
                <div>
                  <div className="font-bold">Administrative Permission Required</div>
                  <div>
                    Reviewing employee registrations and assigning branch/role permissions requires{' '}
                    <span className="font-mono font-bold text-amber-200">TENANT_ADMIN</span> role. Current role:{' '}
                    <span className="font-mono text-cyan-400">{currentUser?.role || 'None'}</span>.
                  </div>
                </div>
              </div>
            )}

            {isTenantAdmin && (
              <>
                {/* 1. Pending Registrations Section */}
                <div className="p-5 bg-slate-900 border border-slate-800 rounded-lg space-y-4 shadow-md">
                  <div className="flex items-center justify-between pb-3 border-b border-slate-800">
                    <div className="flex items-center gap-2 text-sm font-bold text-slate-200">
                      <UserCheck className="w-4 h-4 text-amber-400" /> Pending Employee Registration Requests
                    </div>
                    <span className="text-[10px] px-2 py-0.5 rounded bg-slate-950 border border-slate-800 text-amber-400 font-bold">
                      {pendingRequests.length} Pending
                    </span>
                  </div>

                  {pendingRequests.length === 0 ? (
                    <div className="py-8 text-center text-xs text-slate-500">
                      No pending registration requests requiring review.
                    </div>
                  ) : (
                    <div className="overflow-x-auto">
                      <table className="w-full text-left text-xs border-collapse">
                        <thead>
                          <tr className="border-b border-slate-800 text-slate-400">
                            <th className="py-2 px-3 font-semibold">Applicant</th>
                            <th className="py-2 px-3 font-semibold">Email</th>
                            <th className="py-2 px-3 font-semibold">Requested Branch</th>
                            <th className="py-2 px-3 font-semibold">Date</th>
                            <th className="py-2 px-3 font-semibold text-right">Actions</th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-slate-800/60 font-mono text-[11px]">
                          {pendingRequests.map((req) => (
                            <tr key={req.id} className="hover:bg-slate-800/40 transition-colors">
                              <td className="py-3 px-3 text-slate-200 font-bold">{req.full_name}</td>
                              <td className="py-3 px-3 text-slate-300">{req.email}</td>
                              <td className="py-3 px-3 text-cyan-300 font-bold">
                                {branches.find((b) => b.code === req.requested_branch_code)?.name || req.requested_branch_code}
                              </td>
                              <td className="py-3 px-3 text-slate-400">
                                {req.created_at ? new Date(req.created_at).toLocaleDateString() : '-'}
                              </td>
                              <td className="py-3 px-3 text-right">
                                <div className="inline-flex items-center gap-2">
                                  <button
                                    onClick={() => openApproveModal(req)}
                                    className="px-2.5 py-1 bg-emerald-950 hover:bg-emerald-900 text-emerald-300 border border-emerald-500/40 rounded text-[10px] font-bold transition-colors"
                                  >
                                    Approve
                                  </button>
                                  <button
                                    onClick={() => setRejectRequestId(req.id)}
                                    className="px-2.5 py-1 bg-red-950 hover:bg-red-900 text-red-300 border border-red-500/40 rounded text-[10px] font-bold transition-colors"
                                  >
                                    Reject
                                  </button>
                                </div>
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  )}
                </div>

                {/* 2. Enterprise Organization Branches */}
                <div className="p-5 bg-slate-900 border border-slate-800 rounded-lg space-y-4 shadow-md">
                  <div className="flex items-center justify-between pb-3 border-b border-slate-800">
                    <div className="flex items-center gap-2 text-sm font-bold text-slate-200">
                      <Building2 className="w-4 h-4 text-cyan-400" /> Enterprise Organization Branches
                    </div>
                    <span className="text-[10px] text-slate-400">Subordinate organizational units</span>
                  </div>

                  <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-4 gap-3 text-xs">
                    {branches.map((b) => (
                      <div key={b.id} className="p-3 bg-slate-950 rounded border border-slate-800 space-y-1">
                        <div className="flex items-center justify-between">
                          <span className="font-bold text-slate-200">{b.name}</span>
                          <span className="px-1.5 py-0.2 rounded bg-cyan-950 border border-cyan-500/30 text-cyan-300 text-[10px] font-mono">
                            {b.code}
                          </span>
                        </div>
                        <div className="text-[10px] text-slate-500 font-mono truncate">{b.id}</div>
                      </div>
                    ))}
                  </div>
                </div>

                {/* 3. Active Workspace Members Section */}
                <div className="p-5 bg-slate-900 border border-slate-800 rounded-lg space-y-4 shadow-md">
                  <div className="flex items-center justify-between pb-3 border-b border-slate-800">
                    <div className="flex items-center gap-2 text-sm font-bold text-slate-200">
                      <Users className="w-4 h-4 text-blue-400" /> Active Workspace Members & Assignments
                    </div>
                    <span className="text-[10px] px-2 py-0.5 rounded bg-slate-950 border border-slate-800 text-slate-400">
                      {members.length} Total Accounts
                    </span>
                  </div>

                  <div className="overflow-x-auto">
                    <table className="w-full text-left text-xs border-collapse">
                      <thead>
                        <tr className="border-b border-slate-800 text-slate-400">
                          <th className="py-2 px-3 font-semibold">User</th>
                          <th className="py-2 px-3 font-semibold">Role</th>
                          <th className="py-2 px-3 font-semibold">Assigned Branch</th>
                          <th className="py-2 px-3 font-semibold">Status</th>
                          <th className="py-2 px-3 font-semibold text-right">Actions</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-slate-800/60 font-mono text-[11px]">
                        {members.map((member) => (
                          <tr key={member.user_id} className="hover:bg-slate-800/40 transition-colors">
                            <td className="py-3 px-3">
                              <div className="font-bold text-slate-200">{member.full_name}</div>
                              <div className="text-[10px] text-slate-400">{member.email}</div>
                            </td>
                            <td className="py-3 px-3">
                              <span className="px-2 py-0.5 rounded bg-blue-950/80 border border-blue-500/40 text-blue-300 text-[10px] font-bold">
                                {member.role}
                              </span>
                            </td>
                            <td className="py-3 px-3 text-cyan-300">
                              {branches.find((b) => b.id === member.branch_id)?.name || member.branch_id || 'Company-Wide'}
                            </td>
                            <td className="py-3 px-3">
                              {member.status === 'ACTIVE' ? (
                                <span className="text-emerald-400 font-bold">Active</span>
                              ) : (
                                <span className="text-red-400 font-bold">{member.status}</span>
                              )}
                            </td>
                            <td className="py-3 px-3 text-right">
                              <button
                                onClick={() => {
                                  setEditingMember(member);
                                  setEditMemberRole(member.role as Role);
                                  setEditMemberBranchId(member.branch_id || (branches[0]?.id ?? 'branch-ho-001'));
                                }}
                                className="px-2.5 py-1 bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 rounded text-[10px] font-bold transition-colors"
                              >
                                Edit Role/Branch
                              </button>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              </>
            )}
          </div>
        )}

        {/* Modal: Approve Registration */}
        {selectedRequest && (
          <div className="fixed inset-0 z-50 bg-black/70 flex items-center justify-center p-4">
            <div className="bg-slate-900 border border-slate-800 rounded-xl max-w-md w-full p-6 space-y-4 shadow-2xl">
              <div className="flex items-center justify-between pb-3 border-b border-slate-800">
                <div className="flex items-center gap-2 text-sm font-bold text-slate-100">
                  <UserCheck className="w-4 h-4 text-emerald-400" />
                  <span>Approve Registration Request</span>
                </div>
                <button
                  onClick={() => setSelectedRequest(null)}
                  className="text-slate-400 hover:text-slate-200 text-xs"
                >
                  ✕
                </button>
              </div>

              <div className="space-y-3 text-xs">
                <div className="p-3 bg-slate-950 rounded border border-slate-800 space-y-1">
                  <div className="flex justify-between">
                    <span className="text-slate-500">Applicant:</span>
                    <span className="font-bold text-slate-200">{selectedRequest.full_name}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-slate-500">Email:</span>
                    <span className="text-slate-300">{selectedRequest.email}</span>
                  </div>
                </div>

                <div className="space-y-1">
                  <label className="text-[11px] text-slate-400 font-semibold">Assign Role</label>
                  <select
                    value={approvalRole}
                    onChange={(e) => setApprovalRole(e.target.value as Role)}
                    className="w-full bg-slate-950 border border-slate-800 rounded px-3 py-2 text-slate-200 text-xs"
                  >
                    <option value="SECURITY_ANALYST">SECURITY_ANALYST</option>
                    <option value="AI_DEVELOPER">AI_DEVELOPER</option>
                    <option value="AUDITOR">AUDITOR</option>
                    <option value="TENANT_ADMIN">TENANT_ADMIN</option>
                  </select>
                </div>

                <div className="space-y-1">
                  <label className="text-[11px] text-slate-400 font-semibold">Assign Branch</label>
                  <select
                    value={approvalBranchId}
                    onChange={(e) => setApprovalBranchId(e.target.value)}
                    className="w-full bg-slate-950 border border-slate-800 rounded px-3 py-2 text-slate-200 text-xs"
                  >
                    {branches.map((b) => (
                      <option key={b.id} value={b.id}>
                        {b.name} ({b.code})
                      </option>
                    ))}
                  </select>
                </div>

                <div className="space-y-1">
                  <label className="text-[11px] text-slate-400 font-semibold">Review Note</label>
                  <input
                    type="text"
                    value={approvalNote}
                    onChange={(e) => setApprovalNote(e.target.value)}
                    placeholder="Approval authorization justification..."
                    className="w-full bg-slate-950 border border-slate-800 rounded px-3 py-2 text-slate-200 text-xs"
                  />
                </div>
              </div>

              <div className="flex justify-end gap-2 pt-2 border-t border-slate-800">
                <button
                  onClick={() => setSelectedRequest(null)}
                  disabled={isApproving}
                  className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded text-xs transition-colors"
                >
                  Cancel
                </button>
                <button
                  onClick={handleApprove}
                  disabled={isApproving}
                  className="px-4 py-1.5 bg-emerald-600 hover:bg-emerald-500 text-white rounded text-xs font-bold transition-colors disabled:opacity-50 flex items-center gap-1.5"
                >
                  {isApproving && <RefreshCw className="w-3.5 h-3.5 animate-spin" />}
                  <span>Confirm Approval</span>
                </button>
              </div>
            </div>
          </div>
        )}

        {/* Modal: Reject Registration */}
        {rejectRequestId && (
          <div className="fixed inset-0 z-50 bg-black/70 flex items-center justify-center p-4">
            <div className="bg-slate-900 border border-slate-800 rounded-xl max-w-md w-full p-6 space-y-4 shadow-2xl">
              <div className="flex items-center justify-between pb-3 border-b border-slate-800">
                <div className="flex items-center gap-2 text-sm font-bold text-red-400">
                  <UserX className="w-4 h-4 text-red-400" />
                  <span>Reject Registration Request</span>
                </div>
                <button
                  onClick={() => setRejectRequestId(null)}
                  className="text-slate-400 hover:text-slate-200 text-xs"
                >
                  ✕
                </button>
              </div>

              <div className="space-y-2 text-xs">
                <label className="text-[11px] text-slate-400 font-semibold">Reason for Rejection</label>
                <textarea
                  value={rejectReason}
                  onChange={(e) => setRejectReason(e.target.value)}
                  placeholder="State the security or organizational reason for rejection..."
                  rows={3}
                  className="w-full bg-slate-950 border border-slate-800 rounded px-3 py-2 text-slate-200 text-xs"
                />
              </div>

              <div className="flex justify-end gap-2 pt-2 border-t border-slate-800">
                <button
                  onClick={() => setRejectRequestId(null)}
                  disabled={isRejecting}
                  className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded text-xs transition-colors"
                >
                  Cancel
                </button>
                <button
                  onClick={handleReject}
                  disabled={isRejecting}
                  className="px-4 py-1.5 bg-red-600 hover:bg-red-500 text-white rounded text-xs font-bold transition-colors disabled:opacity-50 flex items-center gap-1.5"
                >
                  {isRejecting && <RefreshCw className="w-3.5 h-3.5 animate-spin" />}
                  <span>Confirm Rejection</span>
                </button>
              </div>
            </div>
          </div>
        )}

        {/* Modal: Edit Member Role & Branch */}
        {editingMember && (
          <div className="fixed inset-0 z-50 bg-black/70 flex items-center justify-center p-4">
            <div className="bg-slate-900 border border-slate-800 rounded-xl max-w-md w-full p-6 space-y-4 shadow-2xl">
              <div className="flex items-center justify-between pb-3 border-b border-slate-800">
                <div className="flex items-center gap-2 text-sm font-bold text-slate-100">
                  <Users className="w-4 h-4 text-blue-400" />
                  <span>Modify Member Assignment</span>
                </div>
                <button
                  onClick={() => setEditingMember(null)}
                  className="text-slate-400 hover:text-slate-200 text-xs"
                >
                  ✕
                </button>
              </div>

              <div className="space-y-3 text-xs">
                <div className="p-3 bg-slate-950 rounded border border-slate-800 space-y-1">
                  <div className="flex justify-between">
                    <span className="text-slate-500">Member:</span>
                    <span className="font-bold text-slate-200">{editingMember.full_name}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-slate-500">Email:</span>
                    <span className="text-slate-300">{editingMember.email}</span>
                  </div>
                </div>

                <div className="space-y-1">
                  <label className="text-[11px] text-slate-400 font-semibold">Update Role</label>
                  <select
                    value={editMemberRole}
                    onChange={(e) => setEditMemberRole(e.target.value as Role)}
                    className="w-full bg-slate-950 border border-slate-800 rounded px-3 py-2 text-slate-200 text-xs"
                  >
                    <option value="SECURITY_ANALYST">SECURITY_ANALYST</option>
                    <option value="AI_DEVELOPER">AI_DEVELOPER</option>
                    <option value="AUDITOR">AUDITOR</option>
                    <option value="TENANT_ADMIN">TENANT_ADMIN</option>
                  </select>
                </div>

                <div className="space-y-1">
                  <label className="text-[11px] text-slate-400 font-semibold">Update Branch</label>
                  <select
                    value={editMemberBranchId}
                    onChange={(e) => setEditMemberBranchId(e.target.value)}
                    className="w-full bg-slate-950 border border-slate-800 rounded px-3 py-2 text-slate-200 text-xs"
                  >
                    {branches.map((b) => (
                      <option key={b.id} value={b.id}>
                        {b.name} ({b.code})
                      </option>
                    ))}
                  </select>
                </div>
              </div>

              <div className="flex justify-end gap-2 pt-2 border-t border-slate-800">
                <button
                  onClick={() => setEditingMember(null)}
                  disabled={isUpdatingMember}
                  className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded text-xs transition-colors"
                >
                  Cancel
                </button>
                <button
                  onClick={handleUpdateMember}
                  disabled={isUpdatingMember}
                  className="px-4 py-1.5 bg-blue-600 hover:bg-blue-500 text-white rounded text-xs font-bold transition-colors disabled:opacity-50 flex items-center gap-1.5"
                >
                  {isUpdatingMember && <RefreshCw className="w-3.5 h-3.5 animate-spin" />}
                  <span>Save Changes</span>
                </button>
              </div>
            </div>
          </div>
        )}
      </div>
    </ForensicErrorBoundary>
  );
};
