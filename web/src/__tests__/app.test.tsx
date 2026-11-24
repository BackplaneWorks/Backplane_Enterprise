import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { App } from '../App';

describe('Backplane Enterprise Web Portal E2E Workflows', () => {
  beforeEach(() => {
    vi.stubEnv('VITE_ENABLE_SANDBOX', '1');
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue({
        ok: false,
        status: 401,
        statusText: 'Unauthorized',
        json: async () => ({ error: { code: 'unauthenticated', message: 'Login required' } }),
      }),
    );
  });

  afterEach(() => {
    vi.unstubAllEnvs();
    vi.unstubAllGlobals();
  });

  it('renders OAuth/SSO login and supports Engineer Co-Dev pin-drop comments, DEMO DATA banner & ECO creation', async () => {
    render(<App />);
    await waitFor(() => {
      expect(screen.getByText('Continue with Google Workspace')).toBeInTheDocument();
    });

    fireEvent.click(screen.getByText('Enter as Engineer'));
    await waitFor(() => {
      expect(screen.getByText('Co-Development & Design Review')).toBeInTheDocument();
    });
    expect(screen.getByText(/DEMO DATA — Sandbox preview active/i)).toBeInTheDocument();

    // Drop a pin on the SVG board viewport
    const svg = screen.getByRole('img', { name: /Aether Flight Controller v4 pcb viewport/i });
    vi.spyOn(svg, 'getBoundingClientRect').mockReturnValue({
      left: 0,
      top: 0,
      width: 500,
      height: 360,
      right: 500,
      bottom: 360,
      x: 0,
      y: 0,
      toJSON: () => ({}),
    });
    fireEvent.click(svg, { clientX: 250, clientY: 180 });

    const commentBox = screen.getByPlaceholderText(/Write review feedback/i);
    fireEvent.change(commentBox, { target: { value: 'Check via stitching density under U1.' } });
    fireEvent.click(screen.getByText('Post Pin Comment'));
    expect(screen.getByText('Check via stitching density under U1.')).toBeInTheDocument();

    // Open an ECO
    fireEvent.change(screen.getByPlaceholderText('New ECO title...'), {
      target: { value: 'Add TVS on CAN-H/CAN-L' },
    });
    fireEvent.change(screen.getByPlaceholderText('Engineering rationale...'), {
      target: { value: 'ISO 11898 surge protection' },
    });
    fireEvent.click(screen.getByText('Open ECO'));
    expect(screen.getByText('Add TVS on CAN-H/CAN-L')).toBeInTheDocument();
  });

  it('supports Librarian part creation, lifecycle release, and .kicad_httplib token generation', async () => {
    render(<App />);
    await waitFor(() => {
      expect(screen.getByText('Enter as Librarian')).toBeInTheDocument();
    });

    fireEvent.click(screen.getByText('Enter as Librarian'));
    await waitFor(() => {
      expect(screen.getByText(/Web Librarian & Private KiCad HTTP Library/i)).toBeInTheDocument();
    });

    fireEvent.click(screen.getByText('+ New Library Part'));
    fireEvent.change(screen.getByPlaceholderText('RP2350A'), { target: { value: 'RP2350B' } });
    fireEvent.change(screen.getByPlaceholderText('Raspberry Pi'), {
      target: { value: 'Raspberry Pi' },
    });
    fireEvent.click(screen.getByText('Save Part to Tenant Library'));

    expect(screen.getAllByText('RP2350B').length).toBeGreaterThan(0);

    fireEvent.click(screen.getByText('Approve & Release'));
    expect(screen.getByText('RP2350B moved to Released.')).toBeInTheDocument();

    fireEvent.click(screen.getByText('Generate .kicad_httplib'));
    expect(screen.getByRole('dialog', { name: 'KiCad HTTP Library Setup' })).toBeInTheDocument();
    fireEvent.click(screen.getByText('Mint Scoped Bearer Token'));
    expect(screen.getByText(/bpe_usr_/)).toBeInTheDocument();
  });

  it('supports Purchasing BOM alternate swap and PO approval', async () => {
    render(<App />);
    await waitFor(() => {
      expect(screen.getByText('Enter as Purchasing')).toBeInTheDocument();
    });

    fireEvent.click(screen.getByText('Enter as Purchasing'));
    await waitFor(() => {
      expect(screen.getByText(/Purchasing, BOM & Encrypted Orders/i)).toBeInTheDocument();
    });

    const altButtons = screen.getAllByText(/1 Alternate\(s\)/);
    fireEvent.click(altButtons[altButtons.length - 1]);
    fireEvent.click(screen.getByText('Swap into BOM'));
    expect(screen.getByText('AMS1117-3.3')).toBeInTheDocument();

    fireEvent.click(screen.getByText('Approve & Place PO'));
    expect(screen.getByText('ORD-2026-0901 transitioned to ordered.')).toBeInTheDocument();
  });

  it('supports Org Admin ZDR toggle, Boat VM wake, approval queue, and KMS DEK rotation', async () => {
    render(<App />);
    await waitFor(() => {
      expect(screen.getByText('Enter as Org Admin')).toBeInTheDocument();
    });

    fireEvent.click(screen.getByText('Enter as Org Admin'));
    await waitFor(() => {
      expect(screen.getByText('Enterprise Admin Console')).toBeInTheDocument();
    });

    // LLM Policy & ZDR toggle
    fireEvent.click(screen.getByText('ZDR-Only Enforced: OFF'));
    expect(screen.getByText('ZDR-Only Enforced: ON')).toBeInTheDocument();

    // Boat VMs wake
    fireEvent.click(screen.getByText('Boat VMs'));
    fireEvent.click(screen.getByText('Wake VM'));
    expect(screen.getByText(/connected via outbound mTLS/)).toBeInTheDocument();

    // Approval Gates
    fireEvent.click(screen.getByText('Approval Gates'));
    fireEvent.click(screen.getByText('Approve'));
    expect(screen.getByText('Approval request apr-51 marked approved.')).toBeInTheDocument();

    // KMS & Audit Log
    fireEvent.click(screen.getByText('KMS & Audit Log'));
    fireEvent.click(screen.getByText('Rotate Tenant DEK'));
    expect(screen.getByText('Tenant DEK rotated to version 4.')).toBeInTheDocument();

    // External Bridges & Scoped Agent Peers
    fireEvent.click(screen.getByText('External Bridges'));
    expect(screen.getByText('Dots + Grok Hardware Ops')).toBeInTheDocument();

    fireEvent.change(screen.getByPlaceholderText('Dots + Grok Hardware Bot'), {
      target: { value: 'n8n Build Alerts' },
    });
    fireEvent.change(screen.getByPlaceholderText('https://bots.example.com/dots/inbound'), {
      target: { value: 'https://n8n.example.com/webhook/bp' },
    });
    fireEvent.click(screen.getByText('Create Bridge'));

    expect(screen.getByText('n8n Build Alerts')).toBeInTheDocument();
    expect(screen.getByRole('region', { name: 'One-time bridge secret' })).toBeInTheDocument();
    fireEvent.click(screen.getByText('Dismiss Secret'));
    expect(screen.queryByRole('region', { name: 'One-time bridge secret' })).not.toBeInTheDocument();
  });
});
