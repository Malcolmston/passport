import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen } from '@testing-library/react';
import { Overview } from '../../../src/components/Overview';
import { LIB } from '../../../src/data';

describe('Overview', () => {
  beforeEach(() => {
    // Hero's VersionBadge fetches on mount; keep it pending.
    global.fetch = vi.fn().mockReturnValue(new Promise(() => {}));
  });

  it('composes the hero, blurb, install, quick start, comparison and features', () => {
    const { container } = render(<Overview lib={LIB} />);
    expect(container.querySelector('#view-overview')).not.toBeNull();
    expect(screen.getByRole('heading', { level: 1, name: /Passport/ })).toBeInTheDocument();
    expect(screen.getByText(LIB.blurb)).toBeInTheDocument();
    expect(screen.getByRole('heading', { name: 'Install' })).toBeInTheDocument();
    expect(screen.getByRole('heading', { name: 'Quick start' })).toBeInTheDocument();
    expect(screen.getByRole('heading', { name: 'Features' })).toBeInTheDocument();
    expect(container.querySelectorAll('ul.feat li').length).toBe(LIB.features.length);
  });
});
