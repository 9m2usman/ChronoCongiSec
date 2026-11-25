import React from 'react';

export interface StatusBadgeProps {
  status: string;
  size?: 'xs' | 'sm';
  className?: string;
}

const TRUSTED_STATES = new Set([
  'TRUSTED',
  'ALLOW',
  'ALLOWED',
  'ACTIVE',
  'APPROVED',
  'VERIFIED',
  'COMPLETED',
  'SUCCESS',
  'NORMAL',
]);

const WARNING_STATES = new Set([
  'SUSPICIOUS',
  'REQUIRES_APPROVAL',
  'WARNING',
  'PENDING',
  'PENDING_REVIEW',
  'MODERATE_DRIFT',
  'TAINTED',
]);

const CRITICAL_STATES = new Set([
  'QUARANTINED',
  'BLOCK',
  'BLOCKED',
  'CRITICAL',
  'REJECTED',
  'FAILED',
  'FAILURE',
  'HIGH_DRIFT',
  'INTERCEPTED',
]);

const INFO_STATES = new Set([
  'SUPERSEDED',
  'INFO',
  'INFORMATION',
  'RECOVERY_STAGED',
]);

export const StatusBadge: React.FC<StatusBadgeProps> = ({
  status,
  size = 'xs',
  className = '',
}) => {
  const normalized = (status || 'UNKNOWN').toUpperCase();

  let toneClasses = 'bg-status-unknownBg border-status-unknown/40 text-status-unknown';
  if (TRUSTED_STATES.has(normalized)) {
    toneClasses = 'bg-status-trustedBg border-status-trusted/40 text-status-trusted';
  } else if (CRITICAL_STATES.has(normalized)) {
    toneClasses = 'bg-status-criticalBg border-status-critical/40 text-status-critical';
  } else if (WARNING_STATES.has(normalized)) {
    toneClasses = 'bg-status-warningBg border-status-warning/40 text-status-warning';
  } else if (INFO_STATES.has(normalized)) {
    toneClasses = 'bg-status-infoBg border-status-info/40 text-status-info';
  }

  const sizeClasses = size === 'sm' ? 'px-2.5 py-0.5 text-[11px]' : 'px-2 py-0.5 text-[10px]';

  return (
    <span
      className={`inline-flex items-center rounded border font-mono font-bold tracking-wide ${sizeClasses} ${toneClasses} ${className}`}
    >
      {status}
    </span>
  );
};
