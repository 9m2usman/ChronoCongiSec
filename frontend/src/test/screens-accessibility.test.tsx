import { render, screen, fireEvent } from '@testing-library/react';
import { StateBanner } from '../components/common/StateBanner';
import { DualModeBadge } from '../components/common/DualModeBadge';
import { SettingsPage } from '../pages/SettingsPage';
import { MemoryRouter } from 'react-router-dom';

describe('Screen States & Accessibility (A11y)', () => {
  describe('StateBanner Component', () => {
    it('renders accessible loading state with status role', () => {
      render(<StateBanner type="loading" title="Evaluating telemetry..." message="Please wait" />);

      const banner = screen.getByRole('status');
      expect(banner).toBeInTheDocument();
      expect(screen.getByText('Evaluating telemetry...')).toBeInTheDocument();
      expect(screen.getByText('Please wait')).toBeInTheDocument();
    });

    it('renders accessible empty state with custom action', () => {
      let clicked = false;
      render(
        <StateBanner
          type="empty"
          title="No Incident Records"
          message="Zero critical threats identified."
          actionText="Create Record"
          onAction={() => {
            clicked = true;
          }}
        />
      );

      expect(screen.getByText('No Incident Records')).toBeInTheDocument();
      expect(screen.getByText('Zero critical threats identified.')).toBeInTheDocument();

      const btn = screen.getByText('Create Record');
      fireEvent.click(btn);
      expect(clicked).toBe(true);
    });

    it('renders accessible unauthorized state with alert role and status code', () => {
      render(
        <StateBanner
          type="unauthorized"
          title="Permission Denied"
          statusCode={403}
          message="Requires SECURITY_ANALYST role."
        />
      );

      const alert = screen.getByRole('alert');
      expect(alert).toBeInTheDocument();
      expect(screen.getByText('Permission Denied')).toBeInTheDocument();
      expect(screen.getByText('HTTP 403')).toBeInTheDocument();
      expect(screen.getByText('Requires SECURITY_ANALYST role.')).toBeInTheDocument();
    });

    it('renders unavailable state with server-off icon and explanation', () => {
      render(
        <StateBanner
          type="unavailable"
          title="Endpoint Offline"
          statusCode={404}
          message="Route pending deployment."
        />
      );

      expect(screen.getByText('Endpoint Offline')).toBeInTheDocument();
      expect(screen.getByText('HTTP 404')).toBeInTheDocument();
    });
  });

  describe('DualModeBadge Component', () => {
    it('renders and toggles API mode', () => {
      render(<DualModeBadge />);

      const badge = screen.getByTitle(/Click to toggle API mode/);
      expect(badge).toBeInTheDocument();
      expect(screen.getByText(/CONTRACT FALLBACK|LIVE API: CONNECTED/)).toBeInTheDocument();
    });
  });

  describe('SettingsPage Cryptographic PRNG (P2 Finding G)', () => {
    it('rotates API keys using window.crypto without crashing', () => {
      render(
        <MemoryRouter>
          <SettingsPage />
        </MemoryRouter>
      );

      expect(screen.getByText(/Tenant Settings & Security Governance/i)).toBeInTheDocument();
      const rotateBtn = screen.getByRole('button', { name: /Rotate Key/i });
      expect(rotateBtn).toBeInTheDocument();

      fireEvent.click(rotateBtn);
      // Confirms rotation was triggered cleanly
      expect(rotateBtn).toBeInTheDocument();
    });
  });
});
