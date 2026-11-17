import { createBrowserRouter } from 'react-router-dom';
import { AppShell } from '@/layouts/AppShell';
import { OverviewPage } from '@/pages/OverviewPage';
import { AgentRegistryPage } from '@/pages/AgentRegistryPage';
import { MemoryExplorerPage } from '@/pages/MemoryExplorerPage';
import { SecurityCenterPage } from '@/pages/SecurityCenterPage';
import { DualTracePage } from '@/pages/DualTracePage';
import { ChroniMemPage } from '@/pages/ChroniMemPage';
import { KnowledgeGraphPage } from '@/pages/KnowledgeGraphPage';
import { DriftMonitorPage } from '@/pages/DriftMonitorPage';
import { AgentRewindingPage } from '@/pages/AgentRewindingPage';
import { AuditCenterPage } from '@/pages/AuditCenterPage';
import { SettingsPage } from '@/pages/SettingsPage';

export const router = createBrowserRouter([
  {
    path: '/',
    element: <AppShell />,
    children: [
      { index: true, element: <OverviewPage /> },
      { path: 'overview', element: <OverviewPage /> },
      { path: 'agents', element: <AgentRegistryPage /> },
      { path: 'memory', element: <MemoryExplorerPage /> },
      { path: 'security', element: <SecurityCenterPage /> },
      { path: 'traces', element: <DualTracePage /> },
      { path: 'chronimem', element: <ChroniMemPage /> },
      { path: 'knowledge-graph', element: <KnowledgeGraphPage /> },
      { path: 'drift', element: <DriftMonitorPage /> },
      { path: 'rewind', element: <AgentRewindingPage /> },
      { path: 'audit', element: <AuditCenterPage /> },
      { path: 'settings', element: <SettingsPage /> },
    ],
  },
]);
