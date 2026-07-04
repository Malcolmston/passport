import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/react';
import { NodeVsGo } from '../../../src/components/NodeVsGo';
import { LIB } from '../../../src/data';

describe('NodeVsGo', () => {
  it('renders the comparison heading and both language columns', () => {
    const { container } = render(<NodeVsGo lib={LIB} />);
    expect(screen.getByRole('heading', { name: /Node.js/ })).toBeInTheDocument();
    expect(screen.getByText('Node.js')).toBeInTheDocument();
    expect(screen.getByText('Go')).toBeInTheDocument();
    // Two compare code cards, side by side.
    expect(container.querySelectorAll('.compare .code').length).toBe(2);
  });
});
