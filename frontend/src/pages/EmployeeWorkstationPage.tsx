import React, { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { apiClient } from '@/services/apiClient';
import { useWorkstationStore } from '@/stores/useWorkstationStore';
import { StateBanner } from '@/components/common/StateBanner';
import {
  Briefcase,
  FileText,
  Send,
  CheckSquare,
  Mail,
  Bell,
  Bot,
  Plus,
  RefreshCw,
  Trash2,
  RotateCcw,
  Check,
  X,
  History,
  Radio,
} from 'lucide-react';

export type WorkstationTab = 'workspaces' | 'files' | 'tasks' | 'messages' | 'agent-exec';

interface EmployeeWorkstationPageProps {
  initialTab?: WorkstationTab;
}

export const EmployeeWorkstationPage: React.FC<EmployeeWorkstationPageProps> = ({
  initialTab = 'workspaces',
}) => {
  const queryClient = useQueryClient();
  const activeTenant = useWorkstationStore((s) => s.activeTenant);
  const realtimeConnected = useWorkstationStore((s) => s.realtimeConnected);
  const realtimeEvents = useWorkstationStore((s) => s.realtimeEvents);

  const [activeTab, setActiveTab] = useState<WorkstationTab>(initialTab);
  const [selectedWorkspaceId, setSelectedWorkspaceId] = useState<string>('');
  const [selectedFileId, setSelectedFileId] = useState<string>('');
  const [selectedTaskId, setSelectedTaskId] = useState<string>('');
  const [feedback, setFeedback] = useState<{ type: 'ok' | 'err'; msg: string } | null>(null);

  // Forms
  const [wsName, setWsName] = useState('');
  const [wsDesc, setWsDesc] = useState('');
  const [wsVisibility, setWsVisibility] = useState<'BRANCH' | 'PRIVATE'>('BRANCH');

  const [fileName, setFileName] = useState('');
  const [fileContent, setFileContent] = useState('');
  const [editContent, setEditContent] = useState('');
  const [transferRecipient, setTransferRecipient] = useState('');
  const [transferMsg, setTransferMsg] = useState('');

  const [taskTitle, setTaskTitle] = useState('');
  const [taskDesc, setTaskDesc] = useState('');
  const [taskAssignee, setTaskAssignee] = useState('');
  const [taskPriority, setTaskPriority] = useState<'LOW' | 'NORMAL' | 'HIGH' | 'URGENT'>('NORMAL');

  const [msgRecipient, setMsgRecipient] = useState('');
  const [msgSubject, setMsgSubject] = useState('');
  const [msgBody, setMsgBody] = useState('');

  const [gwAgentId, setGwAgentId] = useState('');
  const [gwOp, setGwOp] = useState('list_workspaces');
  const [gwParamsJson, setGwParamsJson] = useState('{}');
  const [gwResult, setGwResult] = useState<any>(null);

  const notify = (type: 'ok' | 'err', msg: string) => setFeedback({ type, msg });

  // Queries
  const workspacesQ = useQuery({
    queryKey: ['company', 'workspaces', activeTenant.id],
    queryFn: () => apiClient.listWorkspaces(),
  });

  const filesQ = useQuery({
    queryKey: ['company', 'files', activeTenant.id, selectedWorkspaceId],
    queryFn: () => apiClient.listCompanyFiles(selectedWorkspaceId || undefined, true),
  });

  const fileDetailQ = useQuery({
    queryKey: ['company', 'file-detail', activeTenant.id, selectedFileId],
    queryFn: () => apiClient.readCompanyFile(selectedFileId),
    enabled: Boolean(selectedFileId),
  });

  const fileVersionsQ = useQuery({
    queryKey: ['company', 'file-versions', activeTenant.id, selectedFileId],
    queryFn: () => apiClient.listFileVersions(selectedFileId),
    enabled: Boolean(selectedFileId),
  });

  const transfersQ = useQuery({
    queryKey: ['company', 'transfers', activeTenant.id],
    queryFn: () => apiClient.listFileTransfers('all'),
  });

  const tasksQ = useQuery({
    queryKey: ['company', 'tasks', activeTenant.id, selectedWorkspaceId],
    queryFn: () => apiClient.listCompanyTasks(selectedWorkspaceId || undefined),
  });

  const taskEventsQ = useQuery({
    queryKey: ['company', 'task-events', activeTenant.id, selectedTaskId],
    queryFn: () => apiClient.listTaskEvents(selectedTaskId),
    enabled: Boolean(selectedTaskId),
  });

  const messagesQ = useQuery({
    queryKey: ['company', 'messages', activeTenant.id],
    queryFn: () => apiClient.listCompanyMessages('all'),
  });

  const notificationsQ = useQuery({
    queryKey: ['company', 'notifications', activeTenant.id],
    queryFn: () => apiClient.listCompanyNotifications(false),
  });

  const activityQ = useQuery({
    queryKey: ['company', 'activity', activeTenant.id],
    queryFn: () => apiClient.listCompanyActivity(30),
  });

  const agentsQ = useQuery({
    queryKey: ['agents', activeTenant.id],
    queryFn: () => apiClient.listAgents(activeTenant.id),
  });

  const refreshCompany = () => queryClient.invalidateQueries({ queryKey: ['company'] });

  // Mutations
  const createWsMut = useMutation({
    mutationFn: () => apiClient.createWorkspace({ name: wsName, description: wsDesc || undefined, visibility: wsVisibility }),
    onSuccess: (d) => {
      setWsName('');
      setWsDesc('');
      setSelectedWorkspaceId(d.id);
      refreshCompany();
      notify('ok', `Workspace '${d.name}' created.`);
    },
    onError: (e: any) => notify('err', e?.message || 'Failed to create workspace.'),
  });

  const createFileMut = useMutation({
    mutationFn: () =>
      apiClient.createCompanyFile({
        workspace_id: selectedWorkspaceId,
        name: fileName,
        content: fileContent,
      }),
    onSuccess: (d) => {
      setFileName('');
      setFileContent('');
      setSelectedFileId(d.id);
      refreshCompany();
      notify('ok', `File '${d.name}' created (v${d.current_version}).`);
    },
    onError: (e: any) => notify('err', e?.message || 'Failed to create file.'),
  });

  const updateFileMut = useMutation({
    mutationFn: () => apiClient.updateCompanyFile(selectedFileId, editContent),
    onSuccess: (d) => {
      refreshCompany();
      notify('ok', `File updated to v${d.current_version}.`);
    },
    onError: (e: any) => notify('err', e?.message || 'Failed to update file.'),
  });

  const deleteFileMut = useMutation({
    mutationFn: (fid: string) => apiClient.deleteCompanyFile(fid),
    onSuccess: () => {
      refreshCompany();
      notify('ok', 'File soft-deleted.');
    },
    onError: (e: any) => notify('err', e?.message || 'Failed to delete file.'),
  });

  const restoreFileMut = useMutation({
    mutationFn: ({ fid, ver }: { fid: string; ver?: number }) => apiClient.restoreCompanyFile(fid, ver),
    onSuccess: (d) => {
      refreshCompany();
      notify('ok', `File restored (v${d.current_version}).`);
    },
    onError: (e: any) => notify('err', e?.message || 'Failed to restore file.'),
  });

  const transferMut = useMutation({
    mutationFn: () =>
      apiClient.createFileTransfer({
        file_id: selectedFileId,
        recipient_user_id: transferRecipient,
        message: transferMsg || undefined,
      }),
    onSuccess: () => {
      setTransferRecipient('');
      setTransferMsg('');
      refreshCompany();
      notify('ok', 'File transfer initiated.');
    },
    onError: (e: any) => notify('err', e?.message || 'Failed to create transfer.'),
  });

  const createTaskMut = useMutation({
    mutationFn: () =>
      apiClient.createCompanyTask({
        workspace_id: selectedWorkspaceId,
        title: taskTitle,
        description: taskDesc || undefined,
        priority: taskPriority,
        assigned_to_user_id: taskAssignee || undefined,
      }),
    onSuccess: (d) => {
      setTaskTitle('');
      setTaskDesc('');
      setSelectedTaskId(d.id);
      refreshCompany();
      notify('ok', `Task '${d.title}' created.`);
    },
    onError: (e: any) => notify('err', e?.message || 'Failed to create task.'),
  });

  const sendMsgMut = useMutation({
    mutationFn: () =>
      apiClient.sendCompanyMessage({
        recipient_user_id: msgRecipient,
        subject: msgSubject,
        body: msgBody,
      }),
    onSuccess: () => {
      setMsgSubject('');
      setMsgBody('');
      refreshCompany();
      notify('ok', 'Message sent.');
    },
    onError: (e: any) => notify('err', e?.message || 'Failed to send message.'),
  });

  const execGatewayMut = useMutation({
    mutationFn: async () => {
      let parsed: Record<string, any> = {};
      try {
        parsed = JSON.parse(gwParamsJson || '{}');
      } catch {
        throw new Error('Parameters must be valid JSON.');
      }
      return apiClient.proposeGatewayAction({
        agent_id: gwAgentId,
        tool_name: 'company_workspace',
        operation: gwOp,
        parameters: parsed,
      });
    },
    onSuccess: (res) => {
      setGwResult(res);
      refreshCompany();
      notify('ok', `Gateway action ${res.decision || 'PROCESSED'} (${res.execution_status || 'N/A'}).`);
    },
    onError: (e: any) => notify('err', e?.message || 'Gateway action failed.'),
  });

  const workspaces = workspacesQ.data?.items || [];
  const files = filesQ.data?.items || [];
  const transfers = transfersQ.data?.items || [];
  const tasks = tasksQ.data?.items || [];
  const messages = messagesQ.data?.items || [];
  const notifications = notificationsQ.data?.items || [];
  const activity = activityQ.data?.items || [];
  const agents = agentsQ.data || [];

  const TABS: { id: WorkstationTab; label: string; icon: React.ComponentType<any> }[] = [
    { id: 'workspaces', label: 'Workspaces', icon: Briefcase },
    { id: 'files', label: 'Files & Transfers', icon: FileText },
    { id: 'tasks', label: 'Tasks & Handoffs', icon: CheckSquare },
    { id: 'messages', label: 'Inbox & Alerts', icon: Mail },
    { id: 'agent-exec', label: 'Agent Execution', icon: Bot },
  ];

  return (
    <div className="space-y-6 font-mono text-ink">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-3 pb-3 border-b border-borderc">
        <div>
          <h1 className="text-xl font-bold flex items-center gap-2">
            <Briefcase className="w-5 h-5 text-brand" />
            Employee Company Workstation
          </h1>
          <p className="text-xs text-ink-muted mt-0.5">
            Branch-scoped workspaces, versioned files, transfers, tasks, messaging, and governed agent execution
          </p>
        </div>
        <div className="flex items-center gap-3">
          <span
            className={`px-2.5 py-1 rounded text-[11px] border flex items-center gap-1.5 ${
              realtimeConnected
                ? 'bg-status-trusted/10 text-status-trusted border-status-trusted/30'
                : 'bg-surface-hover text-ink-muted border-borderc'
            }`}
          >
            <Radio className="w-3 h-3" />
            {realtimeConnected ? 'LIVE STREAM' : 'STREAM STANDBY'}
          </span>
          <button
            type="button"
            onClick={refreshCompany}
            className="px-2.5 py-1.5 rounded bg-surface border border-borderc hover:border-brand text-xs flex items-center gap-1.5"
          >
            <RefreshCw className="w-3.5 h-3.5" />
            Refresh
          </button>
        </div>
      </div>

      {/* Feedback Banner */}
      {feedback && (
        <div
          role="status"
          className={`p-3 rounded border text-xs flex items-center justify-between ${
            feedback.type === 'ok'
              ? 'bg-status-trusted/10 border-status-trusted/30 text-status-trusted'
              : 'bg-status-quarantined/10 border-status-quarantined/30 text-status-quarantined'
          }`}
        >
          <span>{feedback.msg}</span>
          <button type="button" onClick={() => setFeedback(null)} aria-label="Dismiss">
            <X className="w-3.5 h-3.5" />
          </button>
        </div>
      )}

      {/* Navigation Tabs */}
      <div className="flex flex-wrap gap-2 border-b border-borderc pb-2" role="tablist">
        {TABS.map((t) => {
          const Icon = t.icon;
          const active = activeTab === t.id;
          return (
            <button
              key={t.id}
              type="button"
              role="tab"
              aria-selected={active}
              onClick={() => setActiveTab(t.id)}
              className={`px-3 py-1.5 rounded text-xs flex items-center gap-1.5 border transition-colors ${
                active
                  ? 'bg-brand text-white border-brand'
                  : 'bg-surface text-ink-muted border-borderc hover:text-ink'
              }`}
            >
              <Icon className="w-3.5 h-3.5" />
              {t.label}
            </button>
          );
        })}
      </div>

      {/* Tab 1: Workspaces */}
      {activeTab === 'workspaces' && (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
          <div className="bg-surface border border-borderc rounded-lg p-4 space-y-3">
            <h2 className="text-sm font-bold flex items-center gap-1.5">
              <Plus className="w-4 h-4 text-brand" /> Create Workspace
            </h2>
            <input
              type="text"
              placeholder="Workspace name"
              value={wsName}
              onChange={(e) => setWsName(e.target.value)}
              className="w-full bg-bg border border-borderc rounded px-3 py-1.5 text-xs"
            />
            <textarea
              placeholder="Description (optional)"
              value={wsDesc}
              onChange={(e) => setWsDesc(e.target.value)}
              className="w-full bg-bg border border-borderc rounded px-3 py-1.5 text-xs"
              rows={2}
            />
            <select
              value={wsVisibility}
              onChange={(e) => setWsVisibility(e.target.value as 'BRANCH' | 'PRIVATE')}
              className="w-full bg-bg border border-borderc rounded px-3 py-1.5 text-xs"
            >
              <option value="BRANCH">BRANCH (Shared in Branch)</option>
              <option value="PRIVATE">PRIVATE (Owner Only)</option>
            </select>
            <button
              type="button"
              disabled={!wsName.trim() || createWsMut.isPending}
              onClick={() => createWsMut.mutate()}
              className="w-full py-1.5 rounded bg-brand text-white text-xs font-bold disabled:opacity-50"
            >
              Create Workspace
            </button>
          </div>

          <div className="lg:col-span-2 bg-surface border border-borderc rounded-lg p-4 space-y-3">
            <h2 className="text-sm font-bold">Branch Workspaces ({workspaces.length})</h2>
            {workspacesQ.isLoading ? (
              <StateBanner type="loading" />
            ) : workspacesQ.isError ? (
              <StateBanner type="unavailable" message="Could not load company workspaces." />
            ) : workspaces.length === 0 ? (
              <StateBanner type="empty" message="No workspaces in your branch yet." />
            ) : (
              <div className="space-y-2">
                {workspaces.map((w: any) => (
                  <div
                    key={w.id}
                    className={`p-3 rounded border flex items-center justify-between ${
                      selectedWorkspaceId === w.id ? 'border-brand bg-brand/5' : 'border-borderc bg-bg'
                    }`}
                  >
                    <div>
                      <div className="text-xs font-bold">{w.name}</div>
                      <div className="text-[11px] text-ink-muted">
                        ID: {w.id} · Branch: {w.branch_id} · {w.visibility}
                      </div>
                    </div>
                    <button
                      type="button"
                      onClick={() => {
                        setSelectedWorkspaceId(w.id);
                        setActiveTab('files');
                      }}
                      className="px-2.5 py-1 rounded bg-surface border border-borderc hover:border-brand text-xs"
                    >
                      Open Files
                    </button>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      )}

      {/* Tab 2: Files, Versions & Transfers */}
      {activeTab === 'files' && (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
          <div className="space-y-4">
            <div className="bg-surface border border-borderc rounded-lg p-4 space-y-3">
              <h2 className="text-sm font-bold">New File</h2>
              <select
                value={selectedWorkspaceId}
                onChange={(e) => setSelectedWorkspaceId(e.target.value)}
                className="w-full bg-bg border border-borderc rounded px-3 py-1.5 text-xs"
              >
                <option value="">Select workspace...</option>
                {workspaces.map((w: any) => (
                  <option key={w.id} value={w.id}>{w.name}</option>
                ))}
              </select>
              <input
                type="text"
                placeholder="File name (e.g. q4-report.md)"
                value={fileName}
                onChange={(e) => setFileName(e.target.value)}
                className="w-full bg-bg border border-borderc rounded px-3 py-1.5 text-xs"
              />
              <textarea
                placeholder="File content"
                value={fileContent}
                onChange={(e) => setFileContent(e.target.value)}
                rows={4}
                className="w-full bg-bg border border-borderc rounded px-3 py-1.5 text-xs"
              />
              <button
                type="button"
                disabled={!selectedWorkspaceId || !fileName.trim() || createFileMut.isPending}
                onClick={() => createFileMut.mutate()}
                className="w-full py-1.5 rounded bg-brand text-white text-xs font-bold disabled:opacity-50"
              >
                Create File
              </button>
            </div>

            <div className="bg-surface border border-borderc rounded-lg p-4 space-y-2">
              <h2 className="text-sm font-bold">File Transfers ({transfers.length})</h2>
              {transfers.length === 0 ? (
                <p className="text-xs text-ink-muted">No transfers.</p>
              ) : (
                transfers.map((tr: any) => (
                  <div key={tr.id} className="p-2 rounded border border-borderc bg-bg text-xs space-y-1">
                    <div className="font-bold">{tr.file_id} · {tr.status}</div>
                    <div className="text-[11px] text-ink-muted">
                      {tr.sender_user_id} → {tr.recipient_user_id}
                    </div>
                    {tr.status === 'PENDING' && (
                      <div className="flex gap-2 pt-1">
                        <button
                          type="button"
                          onClick={() => apiClient.acceptFileTransfer(tr.id).then(refreshCompany)}
                          className="px-2 py-0.5 rounded bg-status-trusted/20 text-status-trusted text-[11px] flex items-center gap-1"
                        >
                          <Check className="w-3 h-3" /> Accept
                        </button>
                        <button
                          type="button"
                          onClick={() => apiClient.rejectFileTransfer(tr.id).then(refreshCompany)}
                          className="px-2 py-0.5 rounded bg-status-quarantined/20 text-status-quarantined text-[11px] flex items-center gap-1"
                        >
                          <X className="w-3 h-3" /> Reject
                        </button>
                      </div>
                    )}
                  </div>
                ))
              )}
            </div>
          </div>

          <div className="lg:col-span-2 space-y-4">
            <div className="bg-surface border border-borderc rounded-lg p-4 space-y-2">
              <h2 className="text-sm font-bold">Files ({files.length})</h2>
              {files.length === 0 ? (
                <StateBanner type="empty" message="No files found." />
              ) : (
                files.map((f: any) => (
                  <div
                    key={f.id}
                    className={`p-3 rounded border flex items-center justify-between ${
                      selectedFileId === f.id ? 'border-brand bg-brand/5' : 'border-borderc bg-bg'
                    }`}
                  >
                    <div>
                      <div className="text-xs font-bold">
                        {f.name} <span className="text-ink-muted">(v{f.current_version} · {f.status})</span>
                      </div>
                      <div className="text-[11px] text-ink-muted">ID: {f.id}</div>
                    </div>
                    <div className="flex items-center gap-2">
                      <button
                        type="button"
                        onClick={() => setSelectedFileId(f.id)}
                        className="px-2 py-1 rounded border border-borderc text-xs"
                      >
                        Inspect
                      </button>
                      {f.status === 'ACTIVE' ? (
                        <button
                          type="button"
                          onClick={() => deleteFileMut.mutate(f.id)}
                          className="p-1 rounded border border-borderc text-status-quarantined"
                          aria-label="Delete file"
                        >
                          <Trash2 className="w-3.5 h-3.5" />
                        </button>
                      ) : (
                        <button
                          type="button"
                          onClick={() => restoreFileMut.mutate({ fid: f.id })}
                          className="p-1 rounded border border-borderc text-status-trusted"
                          aria-label="Restore file"
                        >
                          <RotateCcw className="w-3.5 h-3.5" />
                        </button>
                      )}
                    </div>
                  </div>
                ))
              )}
            </div>

            {selectedFileId && fileDetailQ.data && (
              <div className="bg-surface border border-borderc rounded-lg p-4 space-y-3">
                <div className="flex items-center justify-between">
                  <h3 className="text-sm font-bold">
                    {fileDetailQ.data.name} (v{fileDetailQ.data.current_version})
                  </h3>
                  <span className="text-[11px] text-ink-muted">SHA-256: {fileDetailQ.data.checksum?.slice(0, 16)}...</span>
                </div>
                <pre className="p-3 rounded bg-bg border border-borderc text-xs overflow-x-auto whitespace-pre-wrap">
                  {fileDetailQ.data.content}
                </pre>
                <div className="space-y-2">
                  <textarea
                    placeholder="New content for next version..."
                    value={editContent}
                    onChange={(e) => setEditContent(e.target.value)}
                    rows={3}
                    className="w-full bg-bg border border-borderc rounded px-3 py-1.5 text-xs"
                  />
                  <button
                    type="button"
                    disabled={!editContent || updateFileMut.isPending}
                    onClick={() => updateFileMut.mutate()}
                    className="px-3 py-1.5 rounded bg-brand text-white text-xs font-bold disabled:opacity-50"
                  >
                    Save New Version
                  </button>
                </div>

                <div className="pt-2 border-t border-borderc space-y-2">
                  <div className="text-xs font-bold flex items-center gap-1.5">
                    <Send className="w-3.5 h-3.5" /> Transfer File
                  </div>
                  <div className="flex gap-2">
                    <input
                      type="text"
                      placeholder="Recipient user ID"
                      value={transferRecipient}
                      onChange={(e) => setTransferRecipient(e.target.value)}
                      className="flex-1 bg-bg border border-borderc rounded px-2 py-1 text-xs"
                    />
                    <input
                      type="text"
                      placeholder="Message (optional)"
                      value={transferMsg}
                      onChange={(e) => setTransferMsg(e.target.value)}
                      className="flex-1 bg-bg border border-borderc rounded px-2 py-1 text-xs"
                    />
                    <button
                      type="button"
                      disabled={!transferRecipient.trim()}
                      onClick={() => transferMut.mutate()}
                      className="px-3 py-1 rounded bg-brand text-white text-xs font-bold disabled:opacity-50"
                    >
                      Send
                    </button>
                  </div>
                </div>

                {fileVersionsQ.data?.items && (
                  <div className="pt-2 border-t border-borderc space-y-1">
                    <div className="text-xs font-bold flex items-center gap-1.5">
                      <History className="w-3.5 h-3.5" /> Version History
                    </div>
                    {fileVersionsQ.data.items.map((v: any) => (
                      <div key={v.id} className="flex items-center justify-between text-[11px] bg-bg p-2 rounded border border-borderc">
                        <span>v{v.version_number} · {v.checksum.slice(0, 14)}...</span>
                        <button
                          type="button"
                          onClick={() => restoreFileMut.mutate({ fid: selectedFileId, ver: v.version_number })}
                          className="text-brand hover:underline"
                        >
                          Restore v{v.version_number}
                        </button>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            )}
          </div>
        </div>
      )}

      {/* Tab 3: Tasks & Handoffs */}
      {activeTab === 'tasks' && (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
          <div className="bg-surface border border-borderc rounded-lg p-4 space-y-3">
            <h2 className="text-sm font-bold">Create Task</h2>
            <select
              value={selectedWorkspaceId}
              onChange={(e) => setSelectedWorkspaceId(e.target.value)}
              className="w-full bg-bg border border-borderc rounded px-3 py-1.5 text-xs"
            >
              <option value="">Select workspace...</option>
              {workspaces.map((w: any) => (
                <option key={w.id} value={w.id}>{w.name}</option>
              ))}
            </select>
            <input
              type="text"
              placeholder="Task title"
              value={taskTitle}
              onChange={(e) => setTaskTitle(e.target.value)}
              className="w-full bg-bg border border-borderc rounded px-3 py-1.5 text-xs"
            />
            <textarea
              placeholder="Description"
              value={taskDesc}
              onChange={(e) => setTaskDesc(e.target.value)}
              rows={2}
              className="w-full bg-bg border border-borderc rounded px-3 py-1.5 text-xs"
            />
            <input
              type="text"
              placeholder="Assign to user ID (optional)"
              value={taskAssignee}
              onChange={(e) => setTaskAssignee(e.target.value)}
              className="w-full bg-bg border border-borderc rounded px-3 py-1.5 text-xs"
            />
            <select
              value={taskPriority}
              onChange={(e) => setTaskPriority(e.target.value as any)}
              className="w-full bg-bg border border-borderc rounded px-3 py-1.5 text-xs"
            >
              <option value="LOW">LOW</option>
              <option value="NORMAL">NORMAL</option>
              <option value="HIGH">HIGH</option>
              <option value="URGENT">URGENT</option>
            </select>
            <button
              type="button"
              disabled={!selectedWorkspaceId || !taskTitle.trim() || createTaskMut.isPending}
              onClick={() => createTaskMut.mutate()}
              className="w-full py-1.5 rounded bg-brand text-white text-xs font-bold disabled:opacity-50"
            >
              Create Task
            </button>
          </div>

          <div className="lg:col-span-2 bg-surface border border-borderc rounded-lg p-4 space-y-3">
            <h2 className="text-sm font-bold">Tasks ({tasks.length})</h2>
            {tasks.length === 0 ? (
              <StateBanner type="empty" message="No tasks found in this branch." />
            ) : (
              tasks.map((t: any) => (
                <div key={t.id} className="p-3 rounded border border-borderc bg-bg space-y-2">
                  <div className="flex items-center justify-between">
                    <div className="text-xs font-bold">{t.title}</div>
                    <span className="text-[11px] px-2 py-0.5 rounded border border-borderc">{t.status} · {t.priority}</span>
                  </div>
                  <div className="text-[11px] text-ink-muted">
                    ID: {t.id} · Assignee: {t.assigned_to_user_id || 'Unassigned'}
                  </div>
                  <div className="flex flex-wrap gap-2">
                    <button
                      type="button"
                      onClick={() => apiClient.updateCompanyTask(t.id, { status: 'IN_PROGRESS' }).then(refreshCompany)}
                      className="px-2 py-0.5 rounded border border-borderc text-[11px]"
                    >
                      Start
                    </button>
                    <button
                      type="button"
                      onClick={() => apiClient.updateCompanyTask(t.id, { status: 'COMPLETED' }).then(refreshCompany)}
                      className="px-2 py-0.5 rounded border border-borderc text-[11px] text-status-trusted"
                    >
                      Complete
                    </button>
                    <button
                      type="button"
                      onClick={() => setSelectedTaskId(t.id)}
                      className="px-2 py-0.5 rounded border border-borderc text-[11px]"
                    >
                      Events
                    </button>
                  </div>
                </div>
              ))
            )}
            {selectedTaskId && taskEventsQ.data?.items && (
              <div className="pt-2 border-t border-borderc space-y-1">
                <div className="text-xs font-bold">Task History ({selectedTaskId})</div>
                {taskEventsQ.data.items.map((e: any) => (
                  <div key={e.id} className="text-[11px] text-ink-muted">
                    {e.created_at} · {e.event_type} by {e.actor_user_id}
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      )}

      {/* Tab 4: Messages, Inbox & Notifications */}
      {activeTab === 'messages' && (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
          <div className="bg-surface border border-borderc rounded-lg p-4 space-y-3">
            <h2 className="text-sm font-bold">Send Message</h2>
            <input
              type="text"
              placeholder="Recipient user ID"
              value={msgRecipient}
              onChange={(e) => setMsgRecipient(e.target.value)}
              className="w-full bg-bg border border-borderc rounded px-3 py-1.5 text-xs"
            />
            <input
              type="text"
              placeholder="Subject"
              value={msgSubject}
              onChange={(e) => setMsgSubject(e.target.value)}
              className="w-full bg-bg border border-borderc rounded px-3 py-1.5 text-xs"
            />
            <textarea
              placeholder="Message body"
              value={msgBody}
              onChange={(e) => setMsgBody(e.target.value)}
              rows={3}
              className="w-full bg-bg border border-borderc rounded px-3 py-1.5 text-xs"
            />
            <button
              type="button"
              disabled={!msgRecipient.trim() || !msgBody.trim() || sendMsgMut.isPending}
              onClick={() => sendMsgMut.mutate()}
              className="w-full py-1.5 rounded bg-brand text-white text-xs font-bold disabled:opacity-50"
            >
              Send Message
            </button>
          </div>

          <div className="bg-surface border border-borderc rounded-lg p-4 space-y-2">
            <h2 className="text-sm font-bold flex items-center gap-1.5">
              <Mail className="w-4 h-4 text-brand" /> Messages ({messages.length})
            </h2>
            {messages.length === 0 ? (
              <p className="text-xs text-ink-muted">No messages.</p>
            ) : (
              messages.map((m: any) => (
                <div key={m.id} className="p-2.5 rounded border border-borderc bg-bg space-y-1 text-xs">
                  <div className="flex justify-between font-bold">
                    <span>{m.subject || '(No Subject)'}</span>
                    <span className="text-[11px] text-ink-muted">{m.status}</span>
                  </div>
                  <div className="text-[11px] text-ink-muted">{m.sender_user_id} → {m.recipient_user_id}</div>
                  <p className="text-xs">{m.body}</p>
                  {m.status === 'SENT' && (
                    <button
                      type="button"
                      onClick={() => apiClient.markMessageRead(m.id).then(refreshCompany)}
                      className="text-[11px] text-brand hover:underline"
                    >
                      Mark as read
                    </button>
                  )}
                </div>
              ))
            )}
          </div>

          <div className="bg-surface border border-borderc rounded-lg p-4 space-y-2">
            <h2 className="text-sm font-bold flex items-center gap-1.5">
              <Bell className="w-4 h-4 text-brand" /> Notifications ({notifications.length})
            </h2>
            {notifications.length === 0 ? (
              <p className="text-xs text-ink-muted">No notifications.</p>
            ) : (
              notifications.map((n: any) => (
                <div key={n.id} className="p-2.5 rounded border border-borderc bg-bg space-y-1 text-xs">
                  <div className="font-bold">{n.title}</div>
                  <p className="text-[11px] text-ink-muted">{n.body}</p>
                  {!n.read_at && (
                    <button
                      type="button"
                      onClick={() => apiClient.markNotificationRead(n.id).then(refreshCompany)}
                      className="text-[11px] text-brand hover:underline"
                    >
                      Mark read
                    </button>
                  )}
                </div>
              ))
            )}
          </div>
        </div>
      )}

      {/* Tab 5: Agent Task Execution via Protected Gateway */}
      {activeTab === 'agent-exec' && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          <div className="bg-surface border border-borderc rounded-lg p-4 space-y-3">
            <h2 className="text-sm font-bold flex items-center gap-1.5">
              <Bot className="w-4 h-4 text-brand" /> Execute Governed Agent Task
            </h2>
            <select
              value={gwAgentId}
              onChange={(e) => setGwAgentId(e.target.value)}
              className="w-full bg-bg border border-borderc rounded px-3 py-1.5 text-xs"
            >
              <option value="">Select governed agent...</option>
              {agents.map((a: any) => (
                <option key={a.id} value={a.id}>{a.name} ({a.id})</option>
              ))}
            </select>
            <select
              value={gwOp}
              onChange={(e) => setGwOp(e.target.value)}
              className="w-full bg-bg border border-borderc rounded px-3 py-1.5 text-xs"
            >
              <option value="list_workspaces">list_workspaces</option>
              <option value="list_files">list_files</option>
              <option value="read_file">read_file</option>
              <option value="create_file">create_file</option>
              <option value="update_file">update_file</option>
              <option value="transfer_file">transfer_file</option>
              <option value="create_task">create_task</option>
              <option value="update_task_status">update_task_status</option>
              <option value="handoff_task">handoff_task</option>
              <option value="send_message">send_message</option>
              <option value="read_inbox">read_inbox</option>
            </select>
            <textarea
              value={gwParamsJson}
              onChange={(e) => setGwParamsJson(e.target.value)}
              rows={5}
              placeholder='{"workspace_id": "..."}'
              className="w-full bg-bg border border-borderc rounded px-3 py-1.5 text-xs font-mono"
            />
            <button
              type="button"
              disabled={!gwAgentId || execGatewayMut.isPending}
              onClick={() => execGatewayMut.mutate()}
              className="w-full py-1.5 rounded bg-brand text-white text-xs font-bold disabled:opacity-50"
            >
              Propose & Execute via Gateway
            </button>

            {gwResult && (
              <pre className="p-3 rounded bg-bg border border-borderc text-[11px] overflow-x-auto">
                {JSON.stringify(gwResult, null, 2)}
              </pre>
            )}
          </div>

          <div className="bg-surface border border-borderc rounded-lg p-4 space-y-3">
            <h2 className="text-sm font-bold">Live Activity & Real-Time Events</h2>
            <div className="space-y-2 max-h-96 overflow-y-auto">
              {realtimeEvents.map((ev) => (
                <div key={ev.id} className="p-2 rounded border border-brand/30 bg-brand/5 text-[11px]">
                  <div className="font-bold text-brand">{ev.event_type}</div>
                  <div className="text-ink-muted">{ev.created_at}</div>
                </div>
              ))}
              {activity.map((act: any) => (
                <div key={act.id} className="p-2 rounded border border-borderc bg-bg text-[11px]">
                  <div className="font-bold">{act.summary}</div>
                  <div className="text-ink-muted">{act.event_type} · {act.created_at}</div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
