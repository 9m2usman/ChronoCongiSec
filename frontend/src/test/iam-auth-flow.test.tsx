import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { LoginPage } from '../pages/LoginPage';
import { RegisterPage } from '../pages/RegisterPage';
import { RegistrationStatusPage } from '../pages/RegistrationStatusPage';
import { SettingsPage } from '../pages/SettingsPage';
import { apiClient } from '../services/apiClient';
import { useWorkstationStore } from '../stores/useWorkstationStore';

describe('Phase 1 IAM Frontend Flow', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    useWorkstationStore.getState().logout();
  });

  describe('LoginPage Component', () => {
    it('renders login form and invokes apiClient.login with user inputs', async () => {
      const loginSpy = vi.spyOn(apiClient, 'login').mockResolvedValue({
        access_token: 'test-token-123',
        token_type: 'bearer',
        user_id: 'usr-1',
        active_tenant: { id: 'tenant-alphacorp', name: 'AlphaCorp', slug: 'alphacorp' },
        role: 'SECURITY_ANALYST',
        branch_id: 'branch-lhr-002',
        expires_in: 3600,
      });

      render(
        <MemoryRouter initialEntries={['/login']}>
          <Routes>
            <Route path="/login" element={<LoginPage />} />
            <Route path="/" element={<div>Dashboard Home</div>} />
          </Routes>
        </MemoryRouter>
      );

      expect(screen.getByText('CHRONOCOGNISEC')).toBeInTheDocument();
      expect(screen.getByText(/Agent Memory Security Center \(AMSC\) Workstation/i)).toBeInTheDocument();

      fireEvent.change(screen.getByLabelText(/Work Email Address/i), {
        target: { value: 'analyst@alphacorp.com' },
      });
      fireEvent.change(screen.getByLabelText(/^Password$/i), {
        target: { value: 'SecretPassword123!' },
      });

      const submitBtn = screen.getByRole('button', { name: /Authenticate into Workstation/i });
      fireEvent.click(submitBtn);

      await waitFor(() => {
        expect(loginSpy).toHaveBeenCalledWith(
          expect.objectContaining({
            email: 'analyst@alphacorp.com',
            password: 'SecretPassword123!',
            tenant_slug: 'alphacorp',
          })
        );
      });
    });

    it('displays error message on authentication failure', async () => {
      vi.spyOn(apiClient, 'login').mockRejectedValue(new Error('Invalid corporate credentials'));

      render(
        <MemoryRouter initialEntries={['/login']}>
          <Routes>
            <Route path="/login" element={<LoginPage />} />
          </Routes>
        </MemoryRouter>
      );

      fireEvent.change(screen.getByLabelText(/Work Email Address/i), {
        target: { value: 'unknown@alphacorp.com' },
      });
      fireEvent.change(screen.getByLabelText(/^Password$/i), {
        target: { value: 'badpass' },
      });

      fireEvent.click(screen.getByRole('button', { name: /Authenticate into Workstation/i }));

      await waitFor(() => {
        expect(screen.getByRole('alert')).toBeInTheDocument();
        expect(screen.getByText(/Invalid corporate credentials/i)).toBeInTheDocument();
      });
    });
  });

  describe('RegisterPage Component', () => {
    it('submits registration request with full name and email', async () => {
      vi.spyOn(apiClient, 'getBranches').mockResolvedValue([
        { id: 'branch-ho-001', tenant_id: 'tenant-alphacorp', code: 'HO', name: 'Head Office', status: 'ACTIVE' },
      ]);

      const registerSpy = vi.spyOn(apiClient, 'register').mockResolvedValue({
        request_id: 'req-new-999',
        status: 'PENDING',
        email: 'newuser@alphacorp.com',
        requested_branch_code: 'HO',
        created_at: new Date().toISOString(),
        message: 'Registration request submitted.',
      });

      render(
        <MemoryRouter initialEntries={['/register']}>
          <Routes>
            <Route path="/register" element={<RegisterPage />} />
            <Route path="/registration-status/:requestId" element={<div>Status Page View</div>} />
          </Routes>
        </MemoryRouter>
      );

      fireEvent.change(screen.getByLabelText(/Full Name/i), {
        target: { value: 'John Doe' },
      });
      fireEvent.change(screen.getByLabelText(/Enterprise Work Email/i), {
        target: { value: 'newuser@alphacorp.com' },
      });
      fireEvent.change(screen.getByLabelText(/Password \(minimum 8 characters\)/i), {
        target: { value: 'SecretPassword123!' },
      });

      fireEvent.click(screen.getByRole('button', { name: /Submit Access Request/i }));

      await waitFor(() => {
        expect(registerSpy).toHaveBeenCalledWith(
          expect.objectContaining({
            email: 'newuser@alphacorp.com',
            full_name: 'John Doe',
          })
        );
      });
    });
  });

  describe('RegistrationStatusPage Component', () => {
    it('displays PENDING status and review information', async () => {
      vi.spyOn(apiClient, 'getRegistrationStatus').mockResolvedValue({
        request_id: 'req-12345',
        status: 'PENDING',
        email_masked: 'a***t@alphacorp.com',
        requested_branch_code: 'KHI',
        created_at: new Date().toISOString(),
        reviewed_at: null,
        reason: null,
      });

      render(
        <MemoryRouter initialEntries={['/registration-status/req-12345']}>
          <Routes>
            <Route path="/registration-status/:requestId" element={<RegistrationStatusPage />} />
          </Routes>
        </MemoryRouter>
      );

      await waitFor(() => {
        expect(screen.getByText(/PENDING REVIEW/i)).toBeInTheDocument();
        expect(screen.getByText('a***t@alphacorp.com')).toBeInTheDocument();
        expect(screen.getByText('KHI')).toBeInTheDocument();
      });
    });

    it('displays APPROVED status with Proceed to Login action', async () => {
      vi.spyOn(apiClient, 'getRegistrationStatus').mockResolvedValue({
        request_id: 'req-approved-1',
        status: 'APPROVED',
        email_masked: 'a***d@alphacorp.com',
        requested_branch_code: 'HO',
        created_at: new Date().toISOString(),
        reviewed_at: new Date().toISOString(),
        reason: 'Identity verified',
      });

      render(
        <MemoryRouter initialEntries={['/registration-status/req-approved-1']}>
          <Routes>
            <Route path="/registration-status/:requestId" element={<RegistrationStatusPage />} />
          </Routes>
        </MemoryRouter>
      );

      await waitFor(() => {
        expect(screen.getByText('APPROVED')).toBeInTheDocument();
        expect(screen.getByRole('link', { name: /Proceed to Login/i })).toBeInTheDocument();
      });
    });
  });

  describe('SettingsPage Governance Tab', () => {
    it('loads governance data when switching to Users & Access Governance tab as TENANT_ADMIN', async () => {
      useWorkstationStore.getState().setAuth('admin-token', {
        user_id: 'usr-admin-1',
        email: 'sarah.admin@alphacorp.com',
        full_name: 'Sarah Admin',
        active_tenant: { id: 'tenant-alphacorp', name: 'AlphaCorp', slug: 'alphacorp' },
        role: 'TENANT_ADMIN',
        branch_id: 'branch-ho-001',
      });

      vi.spyOn(apiClient, 'getPendingRegistrations').mockResolvedValue([
        {
          id: 'req-1',
          tenant_id: 'tenant-alphacorp',
          email: 'bob@alphacorp.com',
          full_name: 'Bob Candidate',
          requested_branch_code: 'LHR',
          created_at: new Date().toISOString(),
          status: 'PENDING',
        },
      ]);

      vi.spyOn(apiClient, 'getUsers').mockResolvedValue([
        {
          user_id: 'usr-admin-1',
          email: 'sarah.admin@alphacorp.com',
          full_name: 'Sarah Admin',
          role: 'TENANT_ADMIN',
          branch_id: 'branch-ho-001',
          status: 'ACTIVE',
        },
      ]);

      vi.spyOn(apiClient, 'getBranches').mockResolvedValue([
        { id: 'branch-ho-001', tenant_id: 'tenant-alphacorp', code: 'HO', name: 'Head Office', status: 'ACTIVE' },
        { id: 'branch-lhr-002', tenant_id: 'tenant-alphacorp', code: 'LHR', name: 'Lahore Branch', status: 'ACTIVE' },
      ]);

      const approveSpy = vi.spyOn(apiClient, 'approveRegistration').mockResolvedValue({
        message: 'Employee registration request approved successfully.',
        user_id: 'usr-bob',
        membership_id: 'mem-bob',
        role: 'SECURITY_ANALYST',
        branch_id: 'branch-lhr-002',
      });

      render(
        <MemoryRouter>
          <SettingsPage />
        </MemoryRouter>
      );

      // Click tab
      const govTab = screen.getByRole('button', { name: /Users & Access Governance/i });
      fireEvent.click(govTab);

      await waitFor(() => {
        expect(screen.getByText('Bob Candidate')).toBeInTheDocument();
        expect(screen.getByText(/Pending Employee Registration Requests/i)).toBeInTheDocument();
        expect(screen.getByText(/Active Workspace Members & Assignments/i)).toBeInTheDocument();
      });

      // Click Approve button to open modal
      const approveBtn = screen.getByRole('button', { name: /^Approve$/i });
      fireEvent.click(approveBtn);

      await waitFor(() => {
        expect(screen.getByText(/Approve Registration Request/i)).toBeInTheDocument();
      });

      // Confirm approval
      const confirmBtn = screen.getByRole('button', { name: /Confirm Approval/i });
      fireEvent.click(confirmBtn);

      await waitFor(() => {
        expect(approveSpy).toHaveBeenCalledWith(
          'req-1',
          expect.objectContaining({
            role: 'SECURITY_ANALYST',
            branch_id: 'branch-lhr-002',
          })
        );
      });
    });
  });
});
