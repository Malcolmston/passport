import type { Lib } from '../data';
import { Hero } from './Hero';
import { Install } from './Install';
import { QuickStart } from './QuickStart';
import { NodeVsGo } from './NodeVsGo';
import { Features } from './Features';

export interface OverviewProps {
  lib: Lib;
}

// Overview is the default tab: hero + blurb + an on-this-page jump nav, then
// the install command, quick start, Node → Go comparison and feature list.
export function Overview({ lib }: OverviewProps) {
  const idb = lib.id;
  return (
    <section className="view active" id="view-overview">
      <Hero lib={lib} />
      <p className="muted">{lib.blurb}</p>
      <div className="onthispage">
        <a href={`#${idb}-install`}>Install</a>
        <a href={`#${idb}-quick`}>Quick start</a>
        <a href={`#${idb}-cmp`}>Node → Go</a>
        <a href={`#${idb}-feat`}>Features</a>
      </div>
      <Install lib={lib} />
      <QuickStart lib={lib} />
      <NodeVsGo lib={lib} />
      <Features lib={lib} />
      <div className="note">Full API reference &amp; runnable examples live under{' '}
        <a href="./api/" target="_blank" rel="noopener">./api/</a>.</div>
    </section>
  );
}
