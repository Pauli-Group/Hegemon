import { afterEach, describe, expect, it } from 'vitest';
import { MemoryRouter, Link } from 'react-router-dom';
import { cleanup, render, screen, fireEvent } from '@testing-library/react';
import { DataStatusBanner } from './DataStatusBanner';

const mockResult = { data: {}, source: 'mock' as const };

afterEach(() => {
  cleanup();
});

describe('DataStatusBanner', () => {
  it('renders a CTA when mock data is in use', () => {
    render(
      <MemoryRouter>
        <DataStatusBanner
          label="Network telemetry feed"
          result={mockResult}
          cta={<Link to="/network">Join a network</Link>}
        />
      </MemoryRouter>,
    );

    expect(screen.getByRole('status', { name: /network telemetry feed/i })).toBeInTheDocument();
    expect(screen.getByText(/mock data in use/i)).toBeVisible();
    expect(screen.getByRole('link', { name: /join a network/i })).toHaveAttribute('href', '/network');
  });

  it('shows the error variant without a CTA when live data errors', () => {
    render(
      <MemoryRouter>
        <DataStatusBanner
          label="Node metrics feed"
          result={{ data: {}, source: 'live', error: new Error('Proxy unreachable') }}
        />
      </MemoryRouter>,
    );

    expect(screen.getByText(/encountered an error/i)).toBeVisible();
    expect(screen.queryByRole('link')).not.toBeInTheDocument();
  });

  it('is dismissible for accessibility and repeated visits', () => {
    render(
      <MemoryRouter>
        <DataStatusBanner label="Miner status feed" result={mockResult} cta={<Link to="/wallet">Open wallet</Link>} />
      </MemoryRouter>,
    );

    const banner = screen.getByRole('status', { name: /miner status feed/i });
    expect(banner).toBeInTheDocument();

    fireEvent.click(screen.getByRole('button', { name: /dismiss miner status feed/i }));
    expect(screen.queryByRole('status', { name: /miner status feed/i })).not.toBeInTheDocument();
  });

  it('does not render when placeholder data is supplied', () => {
    render(
      <MemoryRouter>
        <DataStatusBanner label="Wallet notes" result={mockResult} isPlaceholder />
      </MemoryRouter>,
    );

    expect(screen.queryByRole('status')).not.toBeInTheDocument();
  });
});
