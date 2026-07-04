import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen } from '@testing-library/react';
import { ReleasesView } from '../../../src/components/ReleasesView';

describe('ReleasesView', () => {
  beforeEach(() => {
    global.fetch = vi.fn().mockResolvedValue({ ok: true, status: 200, json: () => Promise.resolve([]) });
  });

  it('renders the heading and a single release block scoped to this repo', () => {
    const { container } = render(<ReleasesView />);
    expect(screen.getByRole('heading', { level: 2, name: /Releases/ })).toBeInTheDocument();
    // Scoped to this repository only — exactly one library release block.
    expect(container.querySelectorAll('.rel-lib').length).toBe(1);
    expect(screen.getByRole('heading', { name: 'Passport' })).toBeInTheDocument();
  });
});
