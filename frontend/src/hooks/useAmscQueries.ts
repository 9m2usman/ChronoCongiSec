import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { useWorkstationStore } from '@/stores/useWorkstationStore';
import { apiClient } from '@/services/apiClient';
import {
  MemoryIngestRequest,
  QuarantineRequest,
} from '@/types';

export function useTenantContext() {
  const { activeTenant } = useWorkstationStore();
  return activeTenant;
}

// 1. Liveness & Health Probe
export function useHealthCheck() {
  return useQuery({
    queryKey: ['health'],
    queryFn: () => apiClient.checkHealth(),
    refetchInterval: 30000,
  });
}

// 2. Tenants
export function useTenants() {
  return useQuery({
    queryKey: ['tenants'],
    queryFn: () => apiClient.listTenants(),
  });
}

export function useTenantDetails(tenantId?: string) {
  const active = useTenantContext();
  const id = tenantId || active.id;
  return useQuery({
    queryKey: ['tenant', id],
    queryFn: () => apiClient.getTenant(id),
  });
}

// 3. Agents
export function useAgents() {
  const active = useTenantContext();
  return useQuery({
    queryKey: ['agents', active.id],
    queryFn: () => apiClient.listAgents(active.id),
  });
}

// 4. Memory & Provenance
export function useMemories() {
  const active = useTenantContext();
  return useQuery({
    queryKey: ['memories', active.id],
    queryFn: () => apiClient.listMemories(active.id),
  });
}

export function useMemoryDetail(recordId: string) {
  const active = useTenantContext();
  return useQuery({
    queryKey: ['memory', active.id, recordId],
    queryFn: () => apiClient.getMemoryDetail(recordId, active.id),
    enabled: Boolean(recordId),
  });
}

export function useIngestMemoryMutation() {
  const active = useTenantContext();
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (payload: MemoryIngestRequest) => apiClient.ingestMemory(payload, active.id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['memories', active.id] });
    },
  });
}

export function useQuarantineMutation() {
  const active = useTenantContext();
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: ({ recordId, payload }: { recordId: string; payload: QuarantineRequest }) =>
      apiClient.quarantineMemory(recordId, payload, active.id),
    onSuccess: (_data, variables) => {
      queryClient.invalidateQueries({ queryKey: ['memories', active.id] });
      queryClient.invalidateQueries({ queryKey: ['memory', active.id, variables.recordId] });
      queryClient.invalidateQueries({ queryKey: ['alerts', active.id] });
      queryClient.invalidateQueries({ queryKey: ['audit', active.id] });
    },
  });
}

// 5. Gateway Activity & Decisions
export function useGatewayDecisions() {
  const active = useTenantContext();
  return useQuery({
    queryKey: ['gateway-decisions', active.id],
    queryFn: () => apiClient.listGatewayDecisions(active.id),
    refetchInterval: 5000,
  });
}

// 6. Security Center & Incidents
export function useSecurityIncidents() {
  const active = useTenantContext();
  return useQuery({
    queryKey: ['incidents', active.id],
    queryFn: () => apiClient.listIncidents(active.id),
  });
}

export function useSecurityAlerts() {
  const active = useTenantContext();
  return useQuery({
    queryKey: ['alerts', active.id],
    queryFn: () => apiClient.getSecurityAlerts(active.id),
  });
}

// 7. Dual Trace Scrubber
export function useDualTrace(traceId = 'trace-default') {
  const active = useTenantContext();
  return useQuery({
    queryKey: ['dual-trace', active.id, traceId],
    queryFn: () => apiClient.getDualTrace(traceId, active.id),
  });
}

// 8. ChroniMem Timeline
export function useChroniMemTimeline(recordId = 'rec-8812-441a') {
  const active = useTenantContext();
  return useQuery({
    queryKey: ['chronimem', active.id, recordId],
    queryFn: () => apiClient.getChroniMemTimeline(recordId, active.id),
  });
}

// 9. Drift Monitor
export function useDriftObservations() {
  const active = useTenantContext();
  return useQuery({
    queryKey: ['drift', active.id],
    queryFn: () => apiClient.listDriftObservations(active.id),
  });
}

// 10. Agent Rewinding & Atomic Recovery
/** Step 1: ask the server for a real recovery plan (blast radius, irreversible actions, risk). */
export function usePreviewRecoveryMutation() {
  const active = useTenantContext();
  return useMutation({
    mutationFn: ({ checkpointId, targetRecordId }: { checkpointId: string; targetRecordId: string }) =>
      apiClient.previewRecoveryPlan(checkpointId, targetRecordId, active.id),
  });
}

/** Step 2: execute exactly the plan the server previewed (the plan fixes the target records). */
export function useAtomicRewindMutation() {
  const active = useTenantContext();
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: ({ planId }: { planId: string }) => apiClient.executeAtomicRewind(planId, active.id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['memories', active.id] });
      queryClient.invalidateQueries({ queryKey: ['chronimem', active.id] });
      queryClient.invalidateQueries({ queryKey: ['alerts', active.id] });
      queryClient.invalidateQueries({ queryKey: ['audit', active.id] });
    },
  });
}

// 11. Audit Center Events
export function useAuditEvents() {
  const active = useTenantContext();
  return useQuery({
    queryKey: ['audit', active.id],
    queryFn: () => apiClient.listAuditEvents(active.id),
  });
}

// 12. Enterprise Baseline (Phase 1 §2)
export function useBaselineRecords(category?: string, lifecycleStatus?: string, branchId?: string) {
  const active = useTenantContext();
  return useQuery({
    queryKey: ['baseline-records', active.id, category, lifecycleStatus, branchId],
    queryFn: () => apiClient.listBaselineRecords(category, lifecycleStatus, branchId, active.id),
  });
}

// 13. Observation & Telemetry Foundation (Phase 1 §3)
export function useObservationEvents(agentId?: string, eventCategory?: string, traceId?: string) {
  const active = useTenantContext();
  return useQuery({
    queryKey: ['observation-events', active.id, agentId, eventCategory, traceId],
    queryFn: () => apiClient.listObservationEvents(agentId, eventCategory, traceId, active.id),
  });
}

// 14. Agent Security Profile (Phase 1 §2)
export function useAgentProfile(agentId: string) {
  const active = useTenantContext();
  return useQuery({
    queryKey: ['agent-profile', active.id, agentId],
    queryFn: () => apiClient.getAgentProfile(agentId, active.id),
    enabled: Boolean(agentId),
  });
}
