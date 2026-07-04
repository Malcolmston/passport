import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/react';
import { QuickStart } from '../../../src/components/QuickStart';
import { LIB } from '../../../src/data';

describe('QuickStart', () => {
  it('renders the Quick start heading and a highlighted Go snippet', () => {
    const { container } = render(<QuickStart lib={LIB} />);
    expect(screen.getByRole('heading', { name: 'Quick start' })).toBeInTheDocument();
    // The highlighter emits token spans into the code card.
    expect(container.querySelector('.code code')).not.toBeNull();
    expect(container.querySelector('.code .tok-k')).not.toBeNull();
  });
});
