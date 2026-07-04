import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen } from '@testing-library/react';
import { Hero } from '../../../src/components/Hero';
import { LIB } from '../../../src/data';

describe('Hero', () => {
  beforeEach(() => {
    // VersionBadge fetches on mount; keep it pending so the hero renders cleanly.
    global.fetch = vi.fn().mockReturnValue(new Promise(() => {}));
  });

  it('renders the library title, module path and tagline', () => {
    render(<Hero lib={LIB} />);
    expect(screen.getByRole('heading', { level: 1, name: /Passport/ })).toBeInTheDocument();
    expect(screen.getByText(LIB.pkg)).toBeInTheDocument();
    expect(screen.getByText(LIB.tagline)).toBeInTheDocument();
  });

  it('renders the GitHub link opening safely in a new tab', () => {
    render(<Hero lib={LIB} />);
    const github = screen.getByRole('link', { name: /GitHub/ });
    expect(github).toHaveAttribute('href', LIB.repo);
    expect(github).toHaveAttribute('target', '_blank');
    expect(github).toHaveAttribute('rel', expect.stringContaining('noopener'));
  });
});
