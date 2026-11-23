import React, { useEffect, useState } from 'react';
import { Navigate, useLocation } from 'react-router-dom';
import { useWorkstationStore } from '@/stores/useWorkstationStore';
import { apiClient } from '@/services/apiClient';
import { Shield } from 'lucide-react';

interface AuthGuardProps {
  children: React.ReactNode;
}

export const AuthGuard: React.FC<AuthGuardProps> = ({ children }) => {
  const { authToken, currentUser, setAuth, logout } = useWorkstationStore();
  const location = useLocation();
  const [isValidating, setIsValidating] = useState<boolean>(!currentUser && !!authToken);

  useEffect(() => {
    let isMounted = true;

    async function restoreSession() {
      if (authToken && !currentUser) {
        try {
          const profile = await apiClient.getMe();
          if (isMounted) {
            setAuth(authToken, profile);
            setIsValidating(false);
          }
        } catch {
          if (isMounted) {
            logout();
            setIsValidating(false);
          }
        }
      } else {
        setIsValidating(false);
      }
    }

    restoreSession();

    return () => {
      isMounted = false;
    };
  }, [authToken, currentUser, setAuth, logout]);

  if (!authToken) {
    return <Navigate to="/login" state={{ from: location }} replace />;
  }

  if (isValidating) {
    return (
      <div
        className="flex h-screen w-screen items-center justify-center bg-[#0B0F19] text-slate-100 font-mono"
        role="status"
        aria-live="polite"
      >
        <div className="flex flex-col items-center gap-3">
          <Shield className="w-8 h-8 text-blue-500 animate-pulse" />
          <span className="text-xs text-slate-400">Verifying security credentials & session state...</span>
        </div>
      </div>
    );
  }

  return <>{children}</>;
};
