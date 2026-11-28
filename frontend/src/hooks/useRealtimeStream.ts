import { useEffect } from 'react';
import { useQueryClient } from '@tanstack/react-query';
import { useWorkstationStore } from '@/stores/useWorkstationStore';

export function useRealtimeStream(enabled = true) {
  const queryClient = useQueryClient();
  const authToken = useWorkstationStore((s) => s.authToken);
  const activeTenantId = useWorkstationStore((s) => s.activeTenant.id);
  const setRealtimeConnected = useWorkstationStore((s) => s.setRealtimeConnected);
  const pushRealtimeEvent = useWorkstationStore((s) => s.pushRealtimeEvent);

  useEffect(() => {
    if (!enabled || !authToken || !activeTenantId) {
      setRealtimeConnected(false);
      return;
    }

    let cancelled = false;
    let controller: AbortController | null = null;
    let reconnectTimer: ReturnType<typeof setTimeout> | null = null;
    let attempt = 0;

    const connect = async () => {
      if (cancelled) return;
      controller = new AbortController();
      const lastId = useWorkstationStore.getState().lastRealtimeEventId;
      const headers: Record<string, string> = {
        Authorization: `Bearer ${authToken}`,
        'X-Tenant-ID': activeTenantId,
      };
      if (lastId) {
        headers['Last-Event-ID'] = lastId;
      }

      try {
        const res = await fetch('/api/v1/realtime/events', {
          headers,
          signal: controller.signal,
        });
        if (!res.ok || !res.body) {
          throw new Error(`SSE HTTP ${res.status}`);
        }
        attempt = 0;
        setRealtimeConnected(true);

        const reader = res.body.getReader();
        const decoder = new TextDecoder();
        let buffer = '';

        while (!cancelled) {
          const { done, value } = await reader.read();
          if (done) break;
          buffer += decoder.decode(value, { stream: true });
          const frames = buffer.split('\n\n');
          buffer = frames.pop() || '';

          for (const frame of frames) {
            const lines = frame.split('\n');
            let dataStr = '';
            for (const line of lines) {
              if (line.startsWith('data:')) {
                dataStr += line.slice(5).trim();
              }
            }
            if (!dataStr) continue;
            try {
              const parsed = JSON.parse(dataStr);
              if (parsed?.id && parsed?.event_type) {
                pushRealtimeEvent(parsed);
                const et = String(parsed.event_type);
                if (et.startsWith('COMPANY_')) {
                  queryClient.invalidateQueries({ queryKey: ['company'] });
                } else if (et.startsWith('SECURITY_') || et.startsWith('RECOVERY_') || et.startsWith('GATEWAY_')) {
                  queryClient.invalidateQueries({ queryKey: ['incidents'] });
                  queryClient.invalidateQueries({ queryKey: ['alerts'] });
                  queryClient.invalidateQueries({ queryKey: ['detections'] });
                  queryClient.invalidateQueries({ queryKey: ['audit'] });
                  queryClient.invalidateQueries({ queryKey: ['recovery'] });
                }
              }
            } catch {
              // ignore malformed keepalive/JSON frames
            }
          }
        }
      } catch {
        setRealtimeConnected(false);
      }

      if (!cancelled) {
        const delayMs = Math.min(15000, 1000 * Math.pow(2, attempt));
        attempt += 1;
        reconnectTimer = setTimeout(connect, delayMs);
      }
    };

    connect();

    return () => {
      cancelled = true;
      setRealtimeConnected(false);
      controller?.abort();
      if (reconnectTimer) clearTimeout(reconnectTimer);
    };
  }, [enabled, authToken, activeTenantId, queryClient, setRealtimeConnected, pushRealtimeEvent]);
}
