import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen } from '@testing-library/react';
import { DocsView } from '../../../src/components/DocsView';
import { LIB } from '../../../src/data';

describe('DocsView', () => {
  beforeEach(() => {
    // VersionBadge fetches on mount; keep it pending.
    global.fetch = vi.fn().mockReturnValue(new Promise(() => {}));
  });

  it('renders the docs heading, the API reference link and the usage snippets', () => {
    const { container } = render(<DocsView lib={LIB} />);
    expect(container.querySelector('#view-docs')).not.toBeNull();
    expect(screen.getByRole('heading', { level: 2, name: 'Documentation' })).toBeInTheDocument();
    // Links to the generated API reference served alongside the site at ./api/.
    const apiLink = screen.getByRole('link', { name: /Open the API reference/ });
    expect(apiLink).toHaveAttribute('href', './api/');
    expect(apiLink).toHaveAttribute('target', '_blank');
    expect(screen.getByRole('heading', { name: 'Install' })).toBeInTheDocument();
    expect(screen.getByRole('heading', { name: 'Usage' })).toBeInTheDocument();
    expect(screen.getByText(new RegExp(`go get ${LIB.pkg}`))).toBeInTheDocument();
  });
});
